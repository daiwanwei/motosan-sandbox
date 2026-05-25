//! Cross-platform pieces of the Linux re-exec helper protocol: the sentinel,
//! env keys, reserved exit codes, the policy IPC struct, the re-exec request
//! builder, and the exit-code classifier. The actual enforcement (Landlock +
//! seccomp) lives in `linux.rs` (`#[cfg(target_os = "linux")]`).

use crate::error::Error;
use crate::policy::SandboxPolicy;
use crate::types::{SandboxCommand, SpawnRequest};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// `argv[0]` the parent sets so the re-exec'd process knows it is the helper.
pub(crate) const HELPER_ARG0: &str = "__motosan_sandbox_helper";
/// Env var carrying the JSON policy across the re-exec boundary.
pub(crate) const POLICY_ENV: &str = "MOTOSAN_SANDBOX_POLICY";

// Reserved exit codes the helper uses to signal setup failure before the target
// runs. Chosen to avoid 0/1/2/126/127 and the 128+signal range.
pub(crate) const HELPER_EXIT_NOT_ENFORCED: i32 = 121;
pub(crate) const HELPER_EXIT_BAD_POLICY: i32 = 122;
pub(crate) const HELPER_EXIT_EXEC_FAILED: i32 = 123;

/// Map a child exit code to a helper-setup `Error`, or `None` if the code is a
/// genuine command result.
pub(crate) fn classify_helper_exit(code: Option<i32>) -> Option<Error> {
    match code {
        Some(HELPER_EXIT_NOT_ENFORCED) => Some(Error::NotEnforced(
            "landlock/seccomp could not be enforced (see child stderr)".into(),
        )),
        Some(HELPER_EXIT_BAD_POLICY) => Some(Error::Transform(
            "sandbox helper rejected the policy (see child stderr)".into(),
        )),
        Some(HELPER_EXIT_EXEC_FAILED) => Some(Error::Transform(
            "sandbox helper failed to exec the target (see child stderr)".into(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_reserved_codes() {
        assert!(matches!(
            classify_helper_exit(Some(121)),
            Some(Error::NotEnforced(_))
        ));
        assert!(matches!(
            classify_helper_exit(Some(122)),
            Some(Error::Transform(_))
        ));
        assert!(matches!(
            classify_helper_exit(Some(123)),
            Some(Error::Transform(_))
        ));
    }

    #[test]
    fn passes_through_normal_codes() {
        assert!(classify_helper_exit(Some(0)).is_none());
        assert!(classify_helper_exit(Some(1)).is_none());
        assert!(classify_helper_exit(Some(127)).is_none());
        assert!(classify_helper_exit(None).is_none()); // killed by signal
    }
}

/// The policy as the re-exec'd helper needs it: which roots are writable and
/// whether network is blocked. Read-everywhere is implicit (Phase 0 semantics).
/// Serialized to JSON in `POLICY_ENV`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HelperPolicy {
    pub writable_roots: Vec<PathBuf>,
    pub network_blocked: bool,
}

impl HelperPolicy {
    /// Build from a `SandboxPolicy`. Errors if the policy uses a feature the
    /// Linux backend cannot express.
    pub(crate) fn from_policy(policy: &SandboxPolicy) -> Result<Self, Error> {
        use crate::policy::NetworkPolicy;
        let network_blocked = policy.network() == NetworkPolicy::Blocked;
        let writable_roots = match policy {
            // DangerFullAccess never reaches the helper (transform passes through).
            SandboxPolicy::DangerFullAccess => Vec::new(),
            SandboxPolicy::ReadOnly { .. } => Vec::new(),
            SandboxPolicy::WorkspaceWrite(w) => {
                if !w.read_only_subpaths.is_empty() {
                    // Landlock is allow-only: you cannot carve a read-only hole
                    // inside a writable root. macOS Seatbelt supports this; Linux
                    // does not. Fail loud rather than silently under-enforce.
                    return Err(Error::Unsupported(crate::SandboxKind::LinuxSeccomp));
                }
                w.writable_roots.clone()
            }
        };
        Ok(Self {
            writable_roots,
            network_blocked,
        })
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
        assert!(h.network_blocked);
    }

    #[test]
    fn read_only_maps_to_no_roots() {
        let h = HelperPolicy::from_policy(&SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Allowed,
        })
        .unwrap();
        assert!(h.writable_roots.is_empty());
        assert!(!h.network_blocked);
    }

    #[test]
    fn read_only_subpaths_rejected() {
        let p = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).read_only("/ws/secret"),
        );
        assert!(matches!(
            HelperPolicy::from_policy(&p),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn json_round_trips() {
        let h = HelperPolicy {
            writable_roots: vec!["/a".into(), "/b".into()],
            network_blocked: true,
        };
        let s = serde_json::to_string(&h).unwrap();
        let back: HelperPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(h, back);
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
    if helper.network_blocked {
        env.insert(crate::NETWORK_DISABLED_ENV.into(), "1".into());
    }

    // argv layout the helper expects: [<real program>, <real args>...]; arg0 is
    // overridden to the sentinel so run_if_invoked() recognizes the re-exec.
    let mut args: Vec<OsString> = Vec::with_capacity(1 + cmd.args.len());
    args.push(cmd.program.clone());
    args.extend(cmd.args.iter().cloned());

    Ok(SpawnRequest {
        program: helper_exe.as_os_str().to_os_string(),
        args,
        cwd: cmd.cwd.clone(),
        env,
        arg0: Some(HELPER_ARG0.into()),
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
    fn builds_reexec_argv_and_env() {
        let helper = HelperPolicy {
            writable_roots: vec!["/ws".into()],
            network_blocked: true,
        };
        let req = build_reexec_request(&cmd(), &helper, Path::new("/usr/bin/myhelper")).unwrap();

        assert_eq!(req.program, OsString::from("/usr/bin/myhelper"));
        assert_eq!(req.arg0, Some(OsString::from(HELPER_ARG0)));
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
}
