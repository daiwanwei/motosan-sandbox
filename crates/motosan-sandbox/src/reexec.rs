//! Cross-platform pieces of the Linux re-exec helper protocol: the sentinel,
//! env keys, reserved exit codes, the policy IPC struct, the re-exec request
//! builder, and the exit-code classifier. The actual enforcement (Landlock +
//! seccomp; Phase 3: bwrap + ProxyRouted) lives in `linux.rs`
//! (`#[cfg(target_os = "linux")]`).

use crate::error::Error;
use crate::policy::SandboxPolicy;
use crate::types::{SandboxCommand, SpawnRequest};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// `argv[0]` the parent sets so the re-exec'd process knows it is the helper
/// **on the parent → outer path**. Phase 3: bwrap does NOT preserve our arg0
/// for its inner command — the bwrap → inner stage is detected by the env
/// marker `MOTOSAN_SANDBOX_STAGE=inner` instead (see `STAGE_ENV` /
/// `STAGE_INNER` below).
pub(crate) const HELPER_ARG0: &str = "__motosan_sandbox_helper";
/// Env var carrying the JSON policy across the re-exec boundary.
pub(crate) const POLICY_ENV: &str = "MOTOSAN_SANDBOX_POLICY";
/// Env var carrying the helper stage marker. Phase 3 uses
/// `MOTOSAN_SANDBOX_STAGE=inner` to detect the bwrap → inner stage, since
/// bwrap replaces `argv[0]` with the inner program path (our `HELPER_ARG0`
/// sentinel does not survive bwrap).
#[allow(dead_code)] // wired by Task 6 (helper::run_if_invoked dispatch)
pub(crate) const STAGE_ENV: &str = "MOTOSAN_SANDBOX_STAGE";
/// Stage marker value the inner helper looks for. Outer/Landlock paths leave
/// `STAGE_ENV` unset (they are detected via `arg0 == HELPER_ARG0`).
#[allow(dead_code)] // wired by Task 6 (helper::run_if_invoked dispatch)
pub(crate) const STAGE_INNER: &str = "inner";

// Reserved exit codes the helper uses to signal setup failure before the target
// runs. Chosen to avoid 0/1/2/126/127 and the 128+signal range.
pub(crate) const HELPER_EXIT_NOT_ENFORCED: i32 = 121;
pub(crate) const HELPER_EXIT_BAD_POLICY: i32 = 122;
pub(crate) const HELPER_EXIT_EXEC_FAILED: i32 = 123;

/// Map a child exit code to a helper-setup `Error`, or `None` if the code is a
/// genuine command result.
pub(crate) fn classify_helper_exit(code: Option<i32>, stderr: &[u8]) -> Option<Error> {
    let detail = helper_stderr_detail(stderr);
    match code {
        Some(HELPER_EXIT_NOT_ENFORCED) => Some(Error::NotEnforced(format!(
            "landlock/seccomp could not be enforced{detail}"
        ))),
        Some(HELPER_EXIT_BAD_POLICY) => Some(Error::Transform(format!(
            "sandbox helper rejected the policy{detail}"
        ))),
        Some(HELPER_EXIT_EXEC_FAILED) => Some(Error::Transform(format!(
            "sandbox helper failed to exec the target{detail}"
        ))),
        _ => None,
    }
}

fn helper_stderr_detail(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_reserved_codes() {
        assert!(matches!(
            classify_helper_exit(Some(121), b"motosan-sandbox: landlock failed"),
            Some(Error::NotEnforced(_))
        ));
        assert!(matches!(
            classify_helper_exit(Some(122), b"bad policy"),
            Some(Error::Transform(_))
        ));
        assert!(matches!(
            classify_helper_exit(Some(123), b"exec failed"),
            Some(Error::Transform(_))
        ));
    }

    #[test]
    fn passes_through_normal_codes() {
        assert!(classify_helper_exit(Some(0), b"").is_none());
        assert!(classify_helper_exit(Some(1), b"").is_none());
        assert!(classify_helper_exit(Some(127), b"").is_none());
        assert!(classify_helper_exit(None, b"").is_none()); // killed by signal
    }
}

/// One proxy-env route: which env var the target should see pointing at the
/// in-netns loopback bridge, and the host UDS that bridge connects to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProxyRouteEntry {
    /// The env var (e.g. `HTTP_PROXY`) the inner stage rewrites to
    /// `http://127.0.0.1:<local_port>` after binding the loopback listener.
    pub env_key: String,
    /// Path to the host UDS the in-netns bridge connects out to. The host
    /// bridge (tokio, parent) listens on this UDS and forwards to the proxy.
    pub uds_path: PathBuf,
}

/// All proxy-env routes for one `Proxied` run. Carried inside `HelperMode`
/// variants so the helper knows what bridge endpoints to bind.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProxyRouteSpec {
    pub routes: Vec<ProxyRouteEntry>,
}

/// Which enforcement path the re-exec'd helper takes. The same JSON blob in
/// `POLICY_ENV` carries this — the helper dispatches on `mode`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum HelperMode {
    /// Phase 1: Landlock + (optional) network-seccomp, single re-exec.
    /// (`SandboxPolicy::*` with `NetworkPolicy::{Blocked, Allowed}`.)
    Landlock { network_blocked: bool },
    /// Phase 3 outer: build bwrap argv + execv bwrap. (Linux `Proxied`.)
    ProxiedOuter { route_spec: ProxyRouteSpec },
    /// Phase 3 inner: bind loopback listeners, fork the sync bridge child,
    /// install `ProxyRouted` seccomp, then execvp the target. (Inside bwrap.)
    ProxiedInner { route_spec: ProxyRouteSpec },
}

/// The policy as the re-exec'd helper needs it: which roots are writable,
/// which subpaths to re-protect read-only (Phase 3 bwrap path), and which
/// enforcement mode to take. Serialized to JSON in `POLICY_ENV`.
///
/// `read_only_subpaths` is non-empty only on the `ProxiedOuter`/`ProxiedInner`
/// modes — bwrap can express read-only carveouts inside a writable bind
/// (spec §5); the Landlock path still rejects them in `from_policy`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HelperPolicy {
    pub writable_roots: Vec<PathBuf>,
    pub read_only_subpaths: Vec<PathBuf>,
    pub mode: HelperMode,
}

impl HelperPolicy {
    /// Build the **Landlock** variant from a `SandboxPolicy`. Errors if the
    /// policy uses a feature the Landlock path cannot express
    /// (`read_only_subpaths`, or `NetworkPolicy::Proxied` — the latter must
    /// go through `for_proxied` from `run()` instead, since it needs a
    /// route_spec from the started proxy + host bridge).
    pub(crate) fn from_policy(policy: &SandboxPolicy) -> Result<Self, Error> {
        use crate::policy::NetworkPolicy;
        // Proxied has no Landlock backend: `run()` must construct via
        // `for_proxied` after starting the proxy + host bridge.
        if matches!(policy.network(), NetworkPolicy::Proxied { .. }) {
            return Err(Error::Unsupported(crate::SandboxKind::LinuxSeccomp));
        }
        let network_blocked = policy.network() == NetworkPolicy::Blocked;
        let writable_roots = match policy {
            // DangerFullAccess never reaches the helper (transform passes through).
            SandboxPolicy::DangerFullAccess => Vec::new(),
            SandboxPolicy::ReadOnly { .. } => Vec::new(),
            SandboxPolicy::WorkspaceWrite(w) => {
                if !w.read_only_subpaths.is_empty() {
                    // Landlock is allow-only: you cannot carve a read-only
                    // hole inside a writable root. The Proxied/bwrap path
                    // CAN express it (spec §5) — this restriction is
                    // Landlock-only.
                    return Err(Error::Unsupported(crate::SandboxKind::LinuxSeccomp));
                }
                w.writable_roots.clone()
            }
        };
        Ok(Self {
            writable_roots,
            read_only_subpaths: Vec::new(),
            mode: HelperMode::Landlock { network_blocked },
        })
    }

    /// Build the **ProxiedOuter** variant — used by `run()` on Linux
    /// `NetworkPolicy::Proxied` after starting the proxy + host bridge.
    /// Accepts `read_only_subpaths` because bwrap can express them.
    #[allow(dead_code)] // wired by Task 7 (run() Linux Proxied integration)
    pub(crate) fn for_proxied(
        writable_roots: Vec<PathBuf>,
        read_only_subpaths: Vec<PathBuf>,
        route_spec: ProxyRouteSpec,
    ) -> Self {
        Self {
            writable_roots,
            read_only_subpaths,
            mode: HelperMode::ProxiedOuter { route_spec },
        }
    }

    /// Reserialize as the **ProxiedInner** variant. Used by the outer helper
    /// stage just before `execv(bwrap, ...)`, so the inner stage (which
    /// re-reads `POLICY_ENV`) takes the inner branch.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)] // wired by Task 6 (helper::run_if_invoked ProxiedOuter dispatch)
    pub(crate) fn into_proxied_inner(mut self) -> Self {
        if let HelperMode::ProxiedOuter { route_spec } = self.mode {
            self.mode = HelperMode::ProxiedInner { route_spec };
        }
        self
    }
}

#[cfg(test)]
mod ipc_tests {
    use super::*;
    use crate::policy::{NetworkPolicy, WorkspaceWrite};

    #[test]
    fn workspace_write_maps_roots_and_network() {
        let p = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).network(NetworkPolicy::Blocked),
        );
        let h = HelperPolicy::from_policy(&p).unwrap();
        assert_eq!(h.writable_roots, vec![PathBuf::from("/ws")]);
        assert!(h.read_only_subpaths.is_empty());
        assert_eq!(
            h.mode,
            HelperMode::Landlock {
                network_blocked: true
            }
        );
    }

    #[test]
    fn read_only_maps_to_no_roots() {
        let h = HelperPolicy::from_policy(&SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Allowed,
        })
        .unwrap();
        assert!(h.writable_roots.is_empty());
        assert_eq!(
            h.mode,
            HelperMode::Landlock {
                network_blocked: false
            }
        );
    }

    #[test]
    fn read_only_subpaths_rejected_on_landlock_path() {
        // The Landlock path still cannot express ro-carveouts — only the
        // Proxied/bwrap path (spec §5) supports them.
        let p = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).read_only("/ws/secret"),
        );
        assert!(matches!(
            HelperPolicy::from_policy(&p),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn proxied_rejected_in_from_policy() {
        // `from_policy` is for the Landlock path only; Proxied must go
        // through `for_proxied` so a `route_spec` is supplied.
        let p = SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Proxied { allowlist: vec![] },
        };
        assert!(matches!(
            HelperPolicy::from_policy(&p),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn for_proxied_carries_roots_ro_and_route_spec() {
        let spec = ProxyRouteSpec {
            routes: vec![ProxyRouteEntry {
                env_key: "HTTP_PROXY".into(),
                uds_path: "/tmp/x.sock".into(),
            }],
        };
        let h = HelperPolicy::for_proxied(
            vec!["/ws".into()],
            vec!["/ws/secret".into()],
            spec.clone(),
        );
        assert_eq!(h.writable_roots, vec![PathBuf::from("/ws")]);
        assert_eq!(h.read_only_subpaths, vec![PathBuf::from("/ws/secret")]);
        assert_eq!(h.mode, HelperMode::ProxiedOuter { route_spec: spec });
    }

    #[test]
    fn json_round_trips_each_mode() {
        let landlock = HelperPolicy {
            writable_roots: vec!["/a".into()],
            read_only_subpaths: vec![],
            mode: HelperMode::Landlock {
                network_blocked: true,
            },
        };
        let spec = ProxyRouteSpec {
            routes: vec![ProxyRouteEntry {
                env_key: "HTTPS_PROXY".into(),
                uds_path: "/tmp/r.sock".into(),
            }],
        };
        let outer = HelperPolicy::for_proxied(
            vec!["/ws".into()],
            vec!["/ws/.git".into()],
            spec.clone(),
        );
        let inner = HelperPolicy {
            writable_roots: vec!["/ws".into()],
            read_only_subpaths: vec!["/ws/.git".into()],
            mode: HelperMode::ProxiedInner { route_spec: spec },
        };
        for h in [landlock, outer, inner] {
            let s = serde_json::to_string(&h).unwrap();
            let back: HelperPolicy = serde_json::from_str(&s).unwrap();
            assert_eq!(h, back);
        }
    }
}

/// Build the `SpawnRequest` that re-execs `helper_exe` to enforce + run `cmd`.
/// Pure given `helper_exe`; cross-platform so it is unit-testable on macOS.
pub(crate) fn build_reexec_request(
    cmd: &SandboxCommand,
    helper: &HelperPolicy,
    helper_exe: &Path,
) -> Result<SpawnRequest, Error> {
    let policy_json = serde_json::to_string(helper)
        .map_err(|e| Error::Transform(format!("serialize policy: {e}")))?;

    let mut env = cmd.env.clone();
    env.insert(POLICY_ENV.into(), policy_json.into());
    // Only the Landlock path (which can install the network-seccomp filter
    // before exec) advertises NETWORK_DISABLED to the target. Proxied modes
    // explicitly do NOT set this marker — see `build_env` in transform.rs.
    if let HelperMode::Landlock {
        network_blocked: true,
    } = helper.mode
    {
        env.insert(crate::NETWORK_DISABLED_ENV.into(), "1".into());
    }

    // argv layout the helper expects: [<real program>, <real args>...].
    // `Sandbox::run` tells `spawn` when to override argv[0] to the sentinel.
    let mut args: Vec<OsString> = Vec::with_capacity(1 + cmd.args.len());
    args.push(cmd.program.clone());
    args.extend(cmd.args.iter().cloned());

    Ok(SpawnRequest {
        program: helper_exe.as_os_str().to_os_string(),
        args,
        cwd: cmd.cwd.clone(),
        env,
    })
}

#[cfg(test)]
mod build_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cmd() -> SandboxCommand {
        SandboxCommand {
            program: "/bin/echo".into(),
            args: vec!["hi".into()],
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn builds_reexec_argv_and_env_for_landlock() {
        let helper = HelperPolicy {
            writable_roots: vec!["/ws".into()],
            read_only_subpaths: vec![],
            mode: HelperMode::Landlock {
                network_blocked: true,
            },
        };
        let req = build_reexec_request(&cmd(), &helper, Path::new("/usr/bin/myhelper")).unwrap();

        assert_eq!(req.program, OsString::from("/usr/bin/myhelper"));
        assert_eq!(req.args[0], OsString::from("/bin/echo"));
        assert_eq!(req.args[1], OsString::from("hi"));
        assert!(req.env.contains_key(std::ffi::OsStr::new(POLICY_ENV)));
        assert!(req
            .env
            .contains_key(std::ffi::OsStr::new(crate::NETWORK_DISABLED_ENV)));
        // policy JSON round-trips
        let json = req
            .env
            .get(std::ffi::OsStr::new(POLICY_ENV))
            .unwrap()
            .to_string_lossy();
        let parsed: HelperPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, helper);
    }

    #[test]
    fn proxied_outer_does_not_set_network_disabled_marker() {
        // Spec: Proxied is NOT "network off" — the marker must not be set, or
        // cooperative tools would self-restrict and refuse to use the proxy.
        let helper = HelperPolicy::for_proxied(
            vec!["/ws".into()],
            vec![],
            ProxyRouteSpec {
                routes: vec![ProxyRouteEntry {
                    env_key: "HTTP_PROXY".into(),
                    uds_path: "/tmp/x.sock".into(),
                }],
            },
        );
        let req = build_reexec_request(&cmd(), &helper, Path::new("/usr/bin/myhelper")).unwrap();
        assert!(!req
            .env
            .contains_key(std::ffi::OsStr::new(crate::NETWORK_DISABLED_ENV)));
    }
}
