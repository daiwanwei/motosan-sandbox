//! `motosan-sandbox` — run a command under a filesystem/network policy.
//!
//! Phase 0: core types + macOS Seatbelt. Linux enforcement arrives in Phase 1
//! (until then [`Sandbox::run`] returns [`Error::Unsupported`] on Linux).

mod denial;
mod error;
mod policy;
mod spawn;
mod transform;
mod types;

#[cfg(target_os = "macos")]
mod seatbelt;

pub mod helper;

pub use denial::is_likely_sandbox_denied;
pub use error::Error;
pub use policy::{NetworkPolicy, SandboxPolicy, WorkspaceWrite};
pub use transform::NETWORK_DISABLED_ENV;
pub use types::{
    ExecOutput, ProxyHandle, RunOpts, SandboxCommand, SandboxKind, SpawnRequest, TransformCtx,
};

/// Entry point: detect the platform backend, transform a command under a
/// policy, and run it.
#[derive(Debug, Default)]
pub struct Sandbox {
    _private: (),
}

impl Sandbox {
    pub fn new() -> Self {
        Self::default()
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

impl Sandbox {
    /// Detect the backend, transform under `policy`, spawn, and capture.
    pub async fn run(
        &self,
        cmd: SandboxCommand,
        policy: &SandboxPolicy,
        opts: RunOpts,
    ) -> Result<ExecOutput, Error> {
        // Phase 0: no proxy lifecycle yet (NetworkPolicy has no Proxied variant).
        let ctx = TransformCtx::default();
        let req = self.transform(&cmd, policy, &ctx)?;
        spawn::spawn_and_capture(req, &opts).await
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
