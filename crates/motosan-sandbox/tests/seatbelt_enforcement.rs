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
        .run(
            sh("echo hi > inside.txt", &root),
            &policy,
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
    let out = sb
        .run(sh(&script, &ws_root), &policy, RunOpts::default())
        .await
        .unwrap();

    assert_ne!(out.exit_code, Some(0), "write outside root should fail");
    assert!(!target.exists());
    assert!(motosan_sandbox::is_likely_sandbox_denied(
        &out,
        Sandbox::detect()
    ));
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
    let out = sb
        .run(sh(&script, &ws_root), &policy, RunOpts::default())
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "payload");
}

/// Resolve `python3` from PATH, or `None` so the test can skip cleanly on
/// runners without it. (The Seatbelt enforcement suite is macOS-only; CI
/// macOS runners have system python3.)
fn python3() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|c| c.is_file())
}

/// Curated env carrying only PATH — never forward the parent environment.
fn path_env() -> BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    env
}

#[tokio::test]
async fn python_posix_semaphore_is_allowed() {
    let Some(py) = python3() else {
        eprintln!("skip: python3 not on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    let sb = Sandbox::new();
    // ReadOnly is enough: a POSIX semaphore is IPC, not a filesystem write.
    let policy = SandboxPolicy::ReadOnly {
        network: NetworkPolicy::Blocked,
    };
    let out = sb
        .run(
            SandboxCommand {
                program: py.into(),
                args: vec![
                    "-c".into(),
                    "import multiprocessing as mp; mp.Lock(); print('ok')".into(),
                ],
                cwd,
                env: path_env(),
            },
            &policy,
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        out.exit_code,
        Some(0),
        "POSIX semaphore must be allowed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ok"));
}

/// The narrow shm grant covers only the OpenMP lib name. General
/// `multiprocessing.shared_memory` (random `/psm_*` names) must STAY denied —
/// this pins the deliberate scope decision (see plan §Scope). NOTE: Apple's
/// `python3` shim prints a harmless `xcrun ... Operation not permitted` banner
/// on stderr even on success, so we assert on the distinctive `/psm_*` name +
/// a non-zero exit, NOT on the generic "Operation not permitted" string.
#[tokio::test]
async fn python_general_shared_memory_stays_denied() {
    let Some(py) = python3() else {
        eprintln!("skip: python3 not on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    let sb = Sandbox::new();
    let policy = SandboxPolicy::ReadOnly {
        network: NetworkPolicy::Blocked,
    };
    // SharedMemory(create=True) calls shm_open(O_CREAT) on a /psm_* name,
    // which the narrow OpenMP-only grant does not cover.
    let script = "import multiprocessing.shared_memory as sm; \
                  sm.SharedMemory(create=True, size=64); print('UNEXPECTED ok')";
    let out = sb
        .run(
            SandboxCommand {
                program: py.into(),
                args: vec!["-c".into(), script.into()],
                cwd,
                env: path_env(),
            },
            &policy,
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_ne!(
        out.exit_code,
        Some(0),
        "general shared_memory must stay denied; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("psm_"),
        "expected the POSIX shared-memory (/psm_*) denial; stderr: {stderr}"
    );
}
