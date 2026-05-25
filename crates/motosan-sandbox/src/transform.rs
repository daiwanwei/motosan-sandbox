//! Pure command transformation: (command, policy, ctx) -> SpawnRequest.
//! No spawning, no privileges, no port allocation. See design §5/§8.

use std::collections::BTreeMap;
use std::ffi::OsString;

use crate::error::Error;
use crate::policy::{NetworkPolicy, SandboxPolicy};
use crate::types::{SandboxCommand, SandboxKind, SpawnRequest, TransformCtx};
use crate::Sandbox;

/// Env var set on the child when network is blocked, so cooperative tools can
/// self-restrict. Mirrors Codex's `CODEX_SANDBOX_NETWORK_DISABLED`.
pub const NETWORK_DISABLED_ENV: &str = "MOTOSAN_SANDBOX_NETWORK_DISABLED";

impl Sandbox {
    /// Build the concrete command to spawn. Pure given its inputs.
    pub fn transform(
        &self,
        cmd: &SandboxCommand,
        policy: &SandboxPolicy,
        #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] ctx: &TransformCtx<'_>,
    ) -> Result<SpawnRequest, Error> {
        let kind = Self::detect();

        // Full access or no backend → run unwrapped.
        if policy.is_full_access() || kind == SandboxKind::None {
            return Ok(passthrough(cmd, policy));
        }

        // `#[cfg]` goes on the match ARMS (not on blocks inside one arm): cfg
        // removes exactly one `MacosSeatbelt` arm per target, leaving a single,
        // unambiguous expression — no statement-vs-tail-expression footgun.
        match kind {
            SandboxKind::None => Ok(passthrough(cmd, policy)), // unreachable; handled above
            SandboxKind::LinuxSeccomp => {
                // Phase 2: Proxied is rejected on Linux (until Phase 3 ships
                // netns-based hard egress control). Belt-and-braces: `run()`
                // also rejects it before starting any proxy.
                if matches!(policy.network(), NetworkPolicy::Proxied { .. }) {
                    return Err(Error::Unsupported(SandboxKind::LinuxSeccomp));
                }
                use crate::reexec::{build_reexec_request, HelperPolicy};
                let helper = HelperPolicy::from_policy(policy)?;
                let helper_exe = match &self.helper_exe {
                    Some(p) => p.clone(),
                    None => std::env::current_exe()
                        .map_err(|e| Error::Transform(format!("resolve current_exe: {e}")))?,
                };
                build_reexec_request(cmd, &helper, &helper_exe)
            }
            #[cfg(target_os = "macos")]
            SandboxKind::MacosSeatbelt => {
                let proxy_addr = ctx.proxy.map(|h| h.addr);
                let mut req = crate::seatbelt::transform_seatbelt(cmd, policy, proxy_addr)?;
                // Layer proxy env on top, sourced from the ctx (the pure
                // build_env() helper has no ctx and stays untouched).
                if let NetworkPolicy::Proxied { .. } = policy.network() {
                    let addr = proxy_addr.ok_or_else(|| {
                        Error::Transform("proxied policy needs a running proxy".into())
                    })?;
                    inject_proxy_env(&mut req.env, addr);
                }
                Ok(req)
            }
            #[cfg(not(target_os = "macos"))]
            // detect() only returns MacosSeatbelt on macOS, so this is unreachable,
            // but keep the match total without panicking.
            SandboxKind::MacosSeatbelt => Err(Error::Unsupported(SandboxKind::MacosSeatbelt)),
        }
    }
}

/// Insert the cooperative HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY env vars
/// pointing at the local proxy. Seatbelt makes this hard (the child can only
/// reach this exact port); the env vars exist so cooperative tools know where
/// to go. macOS-only — Linux Proxied is `Unsupported` until Phase 3.
#[cfg(target_os = "macos")]
fn inject_proxy_env(env: &mut BTreeMap<OsString, OsString>, addr: std::net::SocketAddr) {
    let url = format!("http://127.0.0.1:{}", addr.port());
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        env.insert(k.into(), url.clone().into());
    }
    env.insert("NO_PROXY".into(), "localhost,127.0.0.1,::1".into());
}

/// Build the child env: a clone of the command's env, plus the network-disabled
/// marker when the policy blocks network.
pub(crate) fn build_env(
    cmd: &SandboxCommand,
    policy: &SandboxPolicy,
) -> BTreeMap<OsString, OsString> {
    let mut env = cmd.env.clone();
    // Only `Blocked` sets the marker. `Proxied` does NOT — the network is
    // proxied, not off — and `Allowed` is unrestricted.
    if policy.network() == NetworkPolicy::Blocked {
        env.insert(NETWORK_DISABLED_ENV.into(), "1".into());
    }
    env
}

/// Run the command unwrapped (no sandbox-exec / helper).
fn passthrough(cmd: &SandboxCommand, policy: &SandboxPolicy) -> SpawnRequest {
    SpawnRequest {
        program: cmd.program.clone(),
        args: cmd.args.clone(),
        cwd: cmd.cwd.clone(),
        env: build_env(cmd, policy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cmd() -> SandboxCommand {
        SandboxCommand {
            program: "echo".into(),
            args: vec!["hi".into()],
            cwd: PathBuf::from("/tmp"),
            env: BTreeMap::new(),
        }
    }

    // build_env is pure + platform-independent, so this runs on every target —
    // unlike the backend-specific behavior, which is exercised by the
    // per-platform integration tests.
    #[test]
    fn build_env_sets_marker_when_network_blocked() {
        let env = build_env(
            &cmd(),
            &SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Blocked,
            },
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new(NETWORK_DISABLED_ENV))
                .map(|v| v.as_os_str()),
            Some(std::ffi::OsStr::new("1"))
        );
    }

    #[test]
    fn build_env_omits_marker_when_network_allowed() {
        let env = build_env(
            &cmd(),
            &SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Allowed,
            },
        );
        assert!(!env.contains_key(std::ffi::OsStr::new(NETWORK_DISABLED_ENV)));
    }

    #[test]
    fn build_env_omits_marker_when_proxied() {
        // Proxied is NOT "network off" — the marker must not be set, otherwise
        // cooperative tools would self-restrict and refuse to use the proxy.
        let env = build_env(
            &cmd(),
            &SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Proxied { allowlist: vec![] },
            },
        );
        assert!(!env.contains_key(std::ffi::OsStr::new(NETWORK_DISABLED_ENV)));
    }
}
