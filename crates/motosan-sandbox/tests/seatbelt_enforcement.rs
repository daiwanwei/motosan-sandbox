#![cfg(target_os = "macos")]

use motosan_sandbox::{
    NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy, WorkspaceWrite,
};
use std::collections::BTreeMap;

fn sh(script: &str, cwd: &std::path::Path) -> SandboxCommand {
    SandboxCommand {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: cwd.to_path_buf(),
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn write_inside_writable_root_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    // macOS /var → /private/var; Seatbelt matches resolved paths.
    let root = dir.path().canonicalize().unwrap();
    let sb = Sandbox::new();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![root.clone()]).network(NetworkPolicy::Blocked),
    );
    let out = sb
        .run(sh("echo hi > inside.txt", &root), &policy, RunOpts::default())
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(root.join("inside.txt").exists());
}

#[tokio::test]
async fn write_outside_writable_root_is_denied() {
    let ws = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let ws_root = ws.path().canonicalize().unwrap();
    let other_root = other.path().canonicalize().unwrap();
    let sb = Sandbox::new();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws_root.clone()]).network(NetworkPolicy::Blocked),
    );
    let target = other_root.join("escape.txt");
    let script = format!("echo hi > {}", target.display());
    let out = sb.run(sh(&script, &ws_root), &policy, RunOpts::default()).await.unwrap();

    assert_ne!(out.exit_code, Some(0), "write outside root should fail");
    assert!(!target.exists());
    assert!(motosan_sandbox::is_likely_sandbox_denied(&out, Sandbox::detect()));
}

#[tokio::test]
async fn read_outside_root_is_allowed() {
    // Phase 0 policy allows reading the whole filesystem.
    let ws = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let ws_root = ws.path().canonicalize().unwrap();
    let src_root = src.path().canonicalize().unwrap();
    std::fs::write(src_root.join("data.txt"), b"payload").unwrap();
    let sb = Sandbox::new();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws_root.clone()]).network(NetworkPolicy::Blocked),
    );
    let script = format!("cat {}", src_root.join("data.txt").display());
    let out = sb.run(sh(&script, &ws_root), &policy, RunOpts::default()).await.unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "payload");
}
