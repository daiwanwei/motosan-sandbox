#![cfg(target_os = "macos")]

use motosan_sandbox::{
    NetworkPolicy, Sandbox, SandboxCommand, SandboxPolicy, TransformCtx, WorkspaceWrite,
};
use std::collections::BTreeMap;
use std::ffi::OsString;

fn cmd() -> SandboxCommand {
    SandboxCommand {
        program: "/bin/echo".into(),
        args: vec!["hello".into()],
        cwd: "/tmp".into(),
        env: BTreeMap::new(),
    }
}

#[test]
fn seatbelt_argv_wraps_sandbox_exec() {
    let sb = Sandbox::new();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec!["/tmp/ws".into()]).network(NetworkPolicy::Blocked),
    );
    let req = sb
        .transform(&cmd(), &policy, &TransformCtx::default())
        .unwrap();

    assert_eq!(req.program, OsString::from("/usr/bin/sandbox-exec"));
    // first two args are the inline policy
    assert_eq!(req.args[0], OsString::from("-p"));
    let policy_text = req.args[1].to_string_lossy();
    assert!(policy_text.contains("(deny default)"));
    assert!(policy_text.contains("WRITABLE_ROOT_0"));

    // a -D binding for the writable root must be present
    let has_root = req.args.windows(2).any(|w| {
        w[0] == *std::ffi::OsStr::new("-D")
            && w[1] == *std::ffi::OsStr::new("WRITABLE_ROOT_0=/tmp/ws")
    });
    assert!(
        has_root,
        "expected -D WRITABLE_ROOT_0=/tmp/ws in {:?}",
        req.args
    );

    // the real command appears after the "--" terminator
    let dd = req
        .args
        .iter()
        .position(|a| a == &OsString::from("--"))
        .unwrap();
    assert_eq!(req.args[dd + 1], OsString::from("/bin/echo"));
    assert_eq!(req.args[dd + 2], OsString::from("hello"));

    // network blocked ⇒ marker env present
    assert!(req
        .env
        .contains_key(std::ffi::OsStr::new(motosan_sandbox::NETWORK_DISABLED_ENV)));
}
