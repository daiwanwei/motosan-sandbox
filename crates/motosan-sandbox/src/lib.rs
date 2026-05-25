//! `motosan-sandbox` — run a command under a filesystem/network policy.
//!
//! Phase 0: core types + macOS Seatbelt. Phase 1 adds Linux Landlock + seccomp
//! via the re-exec helper hook. Phase 2 adds the `proxy` feature:
//! `NetworkPolicy::Proxied { allowlist }` is hard on macOS (Seatbelt restricts
//! egress to the proxy port) and `Error::Unsupported` on Linux until Phase 3.

mod denial;
mod error;
mod policy;
#[cfg(feature = "proxy")]
mod proxy_bridge;
mod reexec;
mod spawn;
mod transform;
mod types;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_bwrap;
#[cfg(target_os = "macos")]
mod seatbelt;

pub mod helper;

pub use denial::is_likely_sandbox_denied;
pub use error::Error;
pub use policy::{HostPattern, NetworkPolicy, SandboxPolicy, WorkspaceWrite};
pub use transform::NETWORK_DISABLED_ENV;
pub use types::{
    ExecOutput, ProxyHandle, RunOpts, SandboxCommand, SandboxKind, SpawnRequest, TransformCtx,
};

/// Entry point: detect the platform backend, transform a command under a
/// policy, and run it.
#[derive(Debug, Default)]
pub struct Sandbox {
    /// Path to the binary hosting `helper::run_if_invoked()`. `None` → resolve
    /// `std::env::current_exe()` lazily in `transform()` (self-reexec). `Some` →
    /// "external-helper mode" (tests point this at the `motosan-sandbox-helper`
    /// bin).
    helper_exe: Option<std::path::PathBuf>,
}

impl Sandbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use an explicit helper binary instead of `current_exe()`.
    pub fn with_helper_exe(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.helper_exe = Some(path.into());
        self
    }

    /// Which backend this build will use, decided by the compile target.
    pub fn detect() -> SandboxKind {
        // Use `return` so each cfg'd line is unambiguous, and keep an
        // always-present fallback as the block's tail expression. The
        // `#[cfg] { expr }`-as-tail form is NOT used here: the trailing
        // expression is chosen by source position before cfg-stripping, so a
        // cfg'd-out tail would make this function return `()`.
        #[cfg(target_os = "macos")]
        {
            return SandboxKind::MacosSeatbelt;
        }
        #[cfg(target_os = "linux")]
        {
            return SandboxKind::LinuxSeccomp;
        }
        #[allow(unreachable_code)]
        {
            SandboxKind::None
        }
    }
}

/// RAII slot holding the optional proxy server. Feature-gated so the rest of
/// `run()` stays cfg-clean. `Drop` aborts the serving task on EVERY exit path
/// (success, `?` early return, panic) — see spec §5.
struct ProxyGuard {
    #[cfg(feature = "proxy")]
    _server: Option<motosan_sandbox_proxy::ProxyServerHandle>,
}

impl Sandbox {
    /// Start the local proxy iff the policy is `Proxied`. Returns the lightweight
    /// address-carrier (borrowed by `TransformCtx`) plus the RAII server slot.
    async fn maybe_start_proxy(
        &self,
        policy: &SandboxPolicy,
        kind: SandboxKind,
    ) -> Result<(Option<ProxyHandle>, ProxyGuard), Error> {
        let NetworkPolicy::Proxied { allowlist } = policy.network() else {
            return Ok((
                None,
                ProxyGuard {
                    #[cfg(feature = "proxy")]
                    _server: None,
                },
            ));
        };
        // Linux Proxied is Unsupported until Phase 3 (no cooperative fallback).
        if kind == SandboxKind::LinuxSeccomp {
            return Err(Error::Unsupported(SandboxKind::LinuxSeccomp));
        }
        #[cfg(feature = "proxy")]
        {
            let patterns: Vec<String> = allowlist.iter().map(|p| p.to_pattern_string()).collect();
            let server =
                motosan_sandbox_proxy::ProxyServer::start(motosan_sandbox_proxy::ProxyConfig {
                    allowlist: patterns,
                })
                .await
                .map_err(Error::Spawn)?;
            let addr = server.addr;
            Ok((
                Some(ProxyHandle { addr }),
                ProxyGuard {
                    _server: Some(server),
                },
            ))
        }
        #[cfg(not(feature = "proxy"))]
        {
            let _ = allowlist;
            Err(Error::Transform(
                "Proxied policy requires the `proxy` feature".into(),
            ))
        }
    }

    /// Detect the backend, transform under `policy`, spawn, and capture.
    pub async fn run(
        &self,
        cmd: SandboxCommand,
        policy: &SandboxPolicy,
        opts: RunOpts,
    ) -> Result<ExecOutput, Error> {
        let kind = Self::detect();
        let helper_reexec = kind == SandboxKind::LinuxSeccomp && !policy.is_full_access();

        // Start the proxy iff the policy is Proxied. `addr_carrier` is borrowed
        // by `ctx`; `_guard` is the RAII slot whose Drop aborts the proxy task
        // on EVERY exit path (success, `?`, panic). Both must live until after
        // `spawn_and_capture` returns.
        let (addr_carrier, _guard) = self.maybe_start_proxy(policy, kind).await?;
        let ctx = TransformCtx {
            proxy: addr_carrier.as_ref(),
        };

        let req = self.transform(&cmd, policy, &ctx)?;
        spawn::spawn_and_capture(req, &opts, helper_reexec).await
        // `_guard` drops here (and on any `?` above) → proxy task aborted.
    }
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn detect_matches_target() {
        let kind = Sandbox::detect();
        #[cfg(target_os = "macos")]
        assert_eq!(kind, SandboxKind::MacosSeatbelt);
        #[cfg(target_os = "linux")]
        assert_eq!(kind, SandboxKind::LinuxSeccomp);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert_eq!(kind, SandboxKind::None);
    }
}
