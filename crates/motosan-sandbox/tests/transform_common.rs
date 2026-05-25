use motosan_sandbox::{Sandbox, SandboxCommand, SandboxPolicy, TransformCtx, NETWORK_DISABLED_ENV};
// Only the Linux-gated test uses these; cfg the import so macOS has no unused-import warning.
#[cfg(target_os = "linux")]
use motosan_sandbox::{NetworkPolicy, SandboxKind};
use std::collections::BTreeMap;

fn cmd(program: &str, args: &[&str]) -> SandboxCommand {
    SandboxCommand {
        program: program.into(),
        args: args.iter().map(|s| (*s).into()).collect(),
        cwd: std::env::temp_dir(),
        env: BTreeMap::new(),
    }
}

#[test]
fn danger_full_access_is_passthrough() {
    let sb = Sandbox::new();
    let req = sb
        .transform(
            &cmd("echo", &["hi"]),
            &SandboxPolicy::DangerFullAccess,
            &TransformCtx::default(),
        )
        .expect("full access transforms");
    assert_eq!(req.program, std::ffi::OsString::from("echo"));
    assert_eq!(req.args, vec![std::ffi::OsString::from("hi")]);
    // Full access ⇒ network allowed ⇒ no disabled marker.
    assert!(!req
        .env
        .contains_key(std::ffi::OsStr::new(NETWORK_DISABLED_ENV)));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_is_unsupported_in_phase0() {
    let sb = Sandbox::new();
    let err = sb
        .transform(
            &cmd("echo", &["hi"]),
            &SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Blocked,
            },
            &TransformCtx::default(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        motosan_sandbox::Error::Unsupported(SandboxKind::LinuxSeccomp)
    ));
}
