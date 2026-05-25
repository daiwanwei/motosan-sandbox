//! macOS Seatbelt backend: assemble an SBPL profile + the `sandbox-exec` argv.
//! See design §6.1. Phase 0 policy is minimal-but-functional: read-everywhere,
//! write-scoped, network all-or-nothing.

use std::ffi::OsString;
use std::path::Path;

use crate::error::Error;
use crate::policy::{NetworkPolicy, SandboxPolicy};
use crate::transform::build_env;
use crate::types::{SandboxCommand, SpawnRequest};

pub(crate) const SEATBELT_EXE: &str = "/usr/bin/sandbox-exec";

const BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");

/// One `-D NAME=VALUE` parameter binding fed to `sandbox-exec`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Param {
    pub name: String,
    pub value: String,
}

/// Assemble the full SBPL policy text + the `-D` params it references, for the
/// given policy. Returns `(policy_text, params)`.
pub(crate) fn build_policy(policy: &SandboxPolicy) -> (String, Vec<Param>) {
    let mut sections: Vec<String> = vec![BASE_POLICY.to_string()];
    let mut params: Vec<Param> = Vec::new();

    match policy {
        // DangerFullAccess never reaches here (transform() passes it through).
        SandboxPolicy::DangerFullAccess => {}
        SandboxPolicy::ReadOnly { .. } => {
            // Read-everywhere is already in the base; writes stay denied.
        }
        SandboxPolicy::WorkspaceWrite(w) => {
            for (i, root) in w.writable_roots.iter().enumerate() {
                let name = format!("WRITABLE_ROOT_{i}");
                sections.push(format!("(allow file-write* (subpath (param \"{name}\")))"));
                params.push(Param {
                    name,
                    value: path_str(root),
                });
            }
            for (i, ro) in w.read_only_subpaths.iter().enumerate() {
                let name = format!("READONLY_SUB_{i}");
                sections.push(format!("(deny file-write* (subpath (param \"{name}\")))"));
                params.push(Param {
                    name,
                    value: path_str(ro),
                });
            }
        }
    }

    // Network: only add an allow rule when enabled; base (deny default) blocks it.
    if policy.network() == NetworkPolicy::Allowed {
        sections.push("(allow network*)".to_string());
    }

    (sections.join("\n"), params)
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Build the full `SpawnRequest` wrapping the command in `sandbox-exec`.
pub(crate) fn transform_seatbelt(
    cmd: &SandboxCommand,
    policy: &SandboxPolicy,
) -> Result<SpawnRequest, Error> {
    let (policy_text, params) = build_policy(policy);

    let mut args: Vec<OsString> = Vec::new();
    args.push("-p".into());
    args.push(policy_text.into());
    for p in &params {
        args.push("-D".into());
        args.push(format!("{}={}", p.name, p.value).into());
    }
    // Terminate option parsing before the target command. Validated by the
    // enforcement integration test (Task 12); drop this if sandbox-exec rejects it.
    args.push("--".into());
    args.push(cmd.program.clone());
    args.extend(cmd.args.iter().cloned());

    Ok(SpawnRequest {
        program: SEATBELT_EXE.into(),
        args,
        cwd: cmd.cwd.clone(),
        env: build_env(cmd, policy),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::WorkspaceWrite;

    #[test]
    fn base_policy_denies_by_default() {
        let (text, params) = build_policy(&SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Blocked,
        });
        assert!(text.contains("(deny default)"));
        assert!(text.contains("(allow file-read*)"));
        assert!(!text.contains("(allow network*)"));
        assert!(!text.contains("file-write* (subpath"));
        assert!(params.is_empty());
    }

    #[test]
    fn read_only_with_network_adds_network_rule() {
        let (text, _) = build_policy(&SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Allowed,
        });
        assert!(text.contains("(allow network*)"));
    }

    #[test]
    fn workspace_write_emits_writable_and_readonly_params() {
        let w = WorkspaceWrite::new(vec!["/ws".into(), "/cache".into()]).read_only("/ws/secrets");
        let (text, params) = build_policy(&SandboxPolicy::WorkspaceWrite(w));

        assert!(text.contains("(allow file-write* (subpath (param \"WRITABLE_ROOT_0\")))"));
        assert!(text.contains("(allow file-write* (subpath (param \"WRITABLE_ROOT_1\")))"));
        assert!(text.contains("(deny file-write* (subpath (param \"READONLY_SUB_0\")))"));

        assert_eq!(params.len(), 3);
        assert_eq!(
            params[0],
            Param {
                name: "WRITABLE_ROOT_0".into(),
                value: "/ws".into()
            }
        );
        assert_eq!(
            params[1],
            Param {
                name: "WRITABLE_ROOT_1".into(),
                value: "/cache".into()
            }
        );
        assert_eq!(
            params[2],
            Param {
                name: "READONLY_SUB_0".into(),
                value: "/ws/secrets".into()
            }
        );
    }
}
