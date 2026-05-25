//! Behavioral Linux enforcement tests. Run in Docker
//! (`--security-opt seccomp=unconfined`) and on CI ubuntu-latest. Exit-code based:
//! "exit 0 where it should fail == sandbox breach".
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use motosan_sandbox::{
    Error, NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy, WorkspaceWrite,
};

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_motosan-sandbox-helper"))
}

fn sandbox() -> Sandbox {
    Sandbox::new().with_helper_exe(helper_exe())
}

fn workspace() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

fn sh(script: &str, cwd: &std::path::Path) -> SandboxCommand {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    SandboxCommand {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: cwd.to_path_buf(),
        env,
    }
}

fn ws_policy(root: &std::path::Path, network: NetworkPolicy) -> SandboxPolicy {
    SandboxPolicy::WorkspaceWrite(WorkspaceWrite::new(vec![root.to_path_buf()]).network(network))
}

/// True if Landlock isn't enforced here (e.g. Docker default seccomp profile
/// blocking landlock_* syscalls, or kernel < 5.13). Used to SKIP — but NOT by
/// `landlock_actually_enforces`, which must fail instead.
async fn landlock_unavailable(sb: &Sandbox, ws: &std::path::Path) -> bool {
    let (_o, other) = workspace();
    let target = other.join("probe.txt");
    let script = format!("echo x > {}", target.display());
    match sb
        .run(
            sh(&script, ws),
            &ws_policy(ws, NetworkPolicy::Blocked),
            RunOpts::default(),
        )
        .await
    {
        Err(Error::NotEnforced(_)) => true,
        _ => target.exists(), // if the out-of-root write SUCCEEDED, enforcement isn't happening
    }
}

#[tokio::test]
async fn landlock_actually_enforces() {
    // Guard against a silently-skipped suite: this test MUST prove enforcement,
    // never skip. (In Docker, run with --security-opt seccomp=unconfined.)
    let (_g, ws) = workspace();
    let sb = sandbox();
    assert!(
        !landlock_unavailable(&sb, &ws).await,
        "Landlock not enforced here — run the container with --security-opt seccomp=unconfined; \
         a skipped suite must not be mistaken for success"
    );
}

#[tokio::test]
async fn write_inside_workspace_succeeds() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await {
        eprintln!("skip: landlock unavailable");
        return;
    }
    let out = sb
        .run(
            sh("echo hi > inside.txt", &ws),
            &ws_policy(&ws, NetworkPolicy::Blocked),
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        out.exit_code,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ws.join("inside.txt").exists());
}

#[tokio::test]
async fn write_outside_workspace_denied() {
    let (_g, ws) = workspace();
    let (_o, other) = workspace();
    let escape = other.join("escape.txt");
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await {
        eprintln!("skip: landlock unavailable");
        return;
    }
    let out = sb
        .run(
            sh(&format!("echo x > {}", escape.display()), &ws),
            &ws_policy(&ws, NetworkPolicy::Blocked),
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_ne!(out.exit_code, Some(0));
    assert!(!escape.exists());
}

#[tokio::test]
async fn read_outside_workspace_allowed() {
    let (_g, ws) = workspace();
    let (_s, src) = workspace();
    std::fs::write(src.join("data.txt"), b"payload").unwrap();
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await {
        eprintln!("skip: landlock unavailable");
        return;
    }
    let out = sb
        .run(
            sh(&format!("cat {}", src.join("data.txt").display()), &ws),
            &ws_policy(&ws, NetworkPolicy::Blocked),
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "payload");
}

#[tokio::test]
async fn network_blocked() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await {
        eprintln!("skip: landlock unavailable");
        return;
    }
    // Use BASH explicitly: `/dev/tcp` is a bash builtin that calls
    // socket(AF_INET)+connect → our seccomp denies socket(AF_INET) → EPERM →
    // nonzero. `/bin/sh` on Debian is dash, which has NO /dev/tcp, so it would
    // exit nonzero for the wrong reason (feature absent, not network blocked).
    // Bind a real listener first: connecting to a closed port would also fail
    // without seccomp, giving a false positive.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");

    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    let cmd = || SandboxCommand {
        program: "/bin/bash".into(),
        args: vec!["-c".into(), script.clone().into()],
        cwd: ws.clone(),
        env: env.clone(),
    };

    let allowed = sb
        .run(
            cmd(),
            &ws_policy(&ws, NetworkPolicy::Allowed),
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        allowed.exit_code,
        Some(0),
        "control connect should succeed when network is allowed; stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    let blocked = sb
        .run(
            cmd(),
            &ws_policy(&ws, NetworkPolicy::Blocked),
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_ne!(
        blocked.exit_code,
        Some(0),
        "network egress should be blocked (socket(AF_INET) denied)"
    );
}

#[tokio::test]
async fn read_only_subpaths_rejected() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).read_only(ws.join("secret")),
    );
    let err = sb
        .run(sh("true", &ws), &policy, RunOpts::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)));
}

#[tokio::test]
async fn danger_full_access_runs_unsandboxed() {
    let (_g, ws) = workspace();
    let (_o, other) = workspace();
    let escape = other.join("danger.txt");
    let sb = sandbox();
    // DangerFullAccess is passthrough — even an out-of-root write succeeds.
    let out = sb
        .run(
            sh(&format!("echo x > {}", escape.display()), &ws),
            &SandboxPolicy::DangerFullAccess,
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert!(escape.exists());
}
