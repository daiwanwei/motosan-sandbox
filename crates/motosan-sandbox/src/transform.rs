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

/// Resolve deny-read globs to absolute form against `cwd`. Glob already
/// starting with `/` is kept; otherwise `cwd` is prepended so relative globs
/// anchor under the command's working directory (spec: relative globs resolve
/// against SandboxCommand::cwd). Done ONCE here so Seatbelt and bwrap agree.
///
/// Both callers live behind `macos` / `(linux, proxy)` cfgs, so on the
/// linux-no-proxy cross-section this is dead — allow it there (mirrors the
/// `ctx` cfg_attr below; guarded by CI's `clippy --no-default-features` cell).
#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", feature = "proxy"))),
    allow(dead_code)
)]
pub(crate) fn resolve_deny_globs(globs: &[String], cwd: &std::path::Path) -> Vec<String> {
    globs
        .iter()
        .map(|g| {
            if g.starts_with('/') {
                g.clone()
            } else {
                format!("{}/{}", cwd.to_string_lossy().trim_end_matches('/'), g)
            }
        })
        .collect()
}

impl Sandbox {
    /// Build the concrete command to spawn. Pure given its inputs.
    pub fn transform(
        &self,
        cmd: &SandboxCommand,
        policy: &SandboxPolicy,
        #[cfg_attr(
            not(any(target_os = "macos", all(target_os = "linux", feature = "proxy"))),
            allow(unused_variables)
        )]
        ctx: &TransformCtx<'_>,
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
                use crate::reexec::{build_reexec_request, HelperPolicy};
                if matches!(policy.network(), NetworkPolicy::Proxied { .. }) {
                    // Phase 3: build the ProxiedOuter re-exec. Requires the
                    // `proxy` feature (without it, `run()` rejects upstream).
                    // The Landlock path's `read_only_subpaths` rejection is
                    // bypassed here on purpose — bwrap CAN express ro-binds
                    // inside a writable root (spec §5). The `route_spec`
                    // field on `TransformCtx` only exists on the
                    // `(linux, proxy)` cfg cross-section, so this whole
                    // arm is similarly gated; other cfg combinations fall
                    // through to `Unsupported`.
                    #[cfg(all(target_os = "linux", feature = "proxy"))]
                    {
                        let route_spec = ctx.route_spec.cloned().ok_or_else(|| {
                            Error::Transform(
                                "Linux Proxied transform needs route_spec (run() bug)".into(),
                            )
                        })?;
                        let (writable_roots, read_only_subpaths) = match policy {
                            SandboxPolicy::WorkspaceWrite(w) => {
                                (w.writable_roots.clone(), w.read_only_subpaths.clone())
                            }
                            _ => (Vec::new(), Vec::new()),
                        };
                        let helper = HelperPolicy::for_proxied(
                            writable_roots,
                            read_only_subpaths,
                            resolve_deny_globs(policy.deny_read_globs(), &cmd.cwd),
                            route_spec,
                        );
                        let helper_exe = match &self.helper_exe {
                            Some(p) => p.clone(),
                            None => std::env::current_exe().map_err(|e| {
                                Error::Transform(format!("resolve current_exe: {e}"))
                            })?,
                        };
                        return build_reexec_request(cmd, &helper, &helper_exe);
                    }
                    #[cfg(not(all(target_os = "linux", feature = "proxy")))]
                    {
                        return Err(Error::Unsupported(SandboxKind::LinuxSeccomp));
                    }
                }
                // Phase 1 Landlock path (Blocked/Allowed).
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
                let deny = resolve_deny_globs(policy.deny_read_globs(), &cmd.cwd);
                let mut req = crate::seatbelt::transform_seatbelt(cmd, policy, proxy_addr, &deny)?;
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
    use crate::policy::ReadOnly;
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
            &SandboxPolicy::ReadOnly(ReadOnly::new(NetworkPolicy::Blocked)),
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
            &SandboxPolicy::ReadOnly(ReadOnly::new(NetworkPolicy::Allowed)),
        );
        assert!(!env.contains_key(std::ffi::OsStr::new(NETWORK_DISABLED_ENV)));
    }

    #[test]
    fn build_env_omits_marker_when_proxied() {
        // Proxied is NOT "network off" — the marker must not be set, otherwise
        // cooperative tools would self-restrict and refuse to use the proxy.
        let env = build_env(
            &cmd(),
            &SandboxPolicy::ReadOnly(ReadOnly::new(NetworkPolicy::Proxied { allowlist: vec![] })),
        );
        assert!(!env.contains_key(std::ffi::OsStr::new(NETWORK_DISABLED_ENV)));
    }
}
