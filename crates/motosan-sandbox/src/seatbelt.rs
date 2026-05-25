//! macOS Seatbelt backend: assemble an SBPL profile + the `sandbox-exec` argv.
//! See design §6.1. Phase 0 policy is minimal-but-functional: read-everywhere,
//! write-scoped, network all-or-nothing.

use std::ffi::OsString;
use std::net::SocketAddr;
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
/// given policy. `proxy` MUST be `Some(addr)` when the policy is `Proxied`
/// (fail-closed: a `Proxied` policy without an address is a transform error).
pub(crate) fn build_policy(
    policy: &SandboxPolicy,
    proxy: Option<SocketAddr>,
) -> Result<(String, Vec<Param>), Error> {
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
    match policy.network() {
        NetworkPolicy::Blocked => {}
        NetworkPolicy::Allowed => {
            sections.push("(allow network*)".to_string());
        }
        NetworkPolicy::Proxied { .. } => {
            // Fail-closed: no allow-all without a known proxy port (spec §7).
            let addr = proxy
                .ok_or_else(|| Error::Transform("proxied policy needs a running proxy".into()))?;
            // VERIFIED rule form (see seatbelt_proxy_probe.rs): sandbox-exec
            // rejects numeric IPs in `(remote ip …)` with `host must be * or
            // localhost in network address`; only the `localhost:<port>` form
            // is accepted, and it matches the child's actual `127.0.0.1:<port>`
            // dial. No additional `network-bind`/`network-inbound` loopback
            // rules are required.
            sections.push(format!(
                "(allow network-outbound (remote ip \"localhost:{}\"))",
                addr.port()
            ));
        }
    }

    Ok((sections.join("\n"), params))
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Build the full `SpawnRequest` wrapping the command in `sandbox-exec`.
/// `proxy` is `Some(addr)` iff the policy is `Proxied`; passed through to
/// [`build_policy`].
pub(crate) fn transform_seatbelt(
    cmd: &SandboxCommand,
    policy: &SandboxPolicy,
    proxy: Option<SocketAddr>,
) -> Result<SpawnRequest, Error> {
    let (policy_text, params) = build_policy(policy, proxy)?;

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
    use crate::policy::{HostPattern, WorkspaceWrite};

    #[test]
    fn base_policy_denies_by_default() {
        let (text, params) = build_policy(
            &SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Blocked,
            },
            None,
        )
        .unwrap();
        assert!(text.contains("(deny default)"));
        assert!(text.contains("(allow file-read*)"));
        assert!(!text.contains("(allow network*)"));
        assert!(!text.contains("file-write* (subpath"));
        assert!(params.is_empty());
    }

    #[test]
    fn read_only_with_network_adds_network_rule() {
        let (text, _) = build_policy(
            &SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Allowed,
            },
            None,
        )
        .unwrap();
        assert!(text.contains("(allow network*)"));
    }

    #[test]
    fn workspace_write_emits_writable_and_readonly_params() {
        let w = WorkspaceWrite::new(vec!["/ws".into(), "/cache".into()]).read_only("/ws/secrets");
        let (text, params) = build_policy(&SandboxPolicy::WorkspaceWrite(w), None).unwrap();

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

    #[test]
    fn proxied_emits_localhost_port_rule() {
        let policy = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).network(NetworkPolicy::Proxied {
                allowlist: vec![HostPattern::parse("*.example.com")],
            }),
        );
        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let (text, _) = build_policy(&policy, Some(addr)).unwrap();
        assert!(
            text.contains("(allow network-outbound (remote ip \"localhost:54321\"))"),
            "got: {text}"
        );
        // No allow-all network rule must appear.
        assert!(!text.contains("(allow network*)"));
    }

    #[test]
    fn proxied_without_addr_fails_closed() {
        let policy = SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Proxied { allowlist: vec![] },
        };
        let err = build_policy(&policy, None).unwrap_err();
        assert!(
            matches!(err, Error::Transform(ref m) if m.contains("proxied")),
            "expected Transform error, got {err:?}"
        );
    }
}
