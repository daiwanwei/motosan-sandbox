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
async fn proxied_unsupported_without_bwrap() {
    // PATH manipulation: a Proxied policy must degrade to `Unsupported`
    // when `bwrap` is not on PATH (spec §3, no silent weakening).
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Proxied { allowlist: vec![] }),
    );
    // Save & clear PATH so `find_bwrap` returns None (no /bin or /usr/bin
    // either, so the test stays honest). `Sandbox::run` resolves bwrap via
    // PATH lookup at run() time.
    let original = std::env::var_os("PATH");
    std::env::set_var("PATH", "");
    let err = sb.run(sh("true", &ws), &policy, RunOpts::default()).await;
    if let Some(p) = original {
        std::env::set_var("PATH", p);
    } else {
        std::env::remove_var("PATH");
    }
    let err = err.expect_err("Proxied with no bwrap on PATH must error");
    assert!(
        matches!(err, Error::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

// ============================================================================
// Phase 3 (bwrap netns + transparent proxy bridge)
//
// Requires `--features proxy` and a Docker / CI env where bwrap can run an
// unprivileged userns + netns (Task 1 found `--privileged` is needed on
// Docker-on-Mac with OrbStack). Without bwrap, all `proxied_*` tests except
// `proxied_unsupported_without_bwrap` (above) skip via `bwrap_unavailable`.
//
// The `proxied_non_cooperative_egress_is_blocked` test is the MUST-ENFORCE
// guard (spec §9): it FAILS rather than skips when isolation isn't actually
// happening, so a misconfigured CI can't green a degraded suite.
// ============================================================================

/// True if `bwrap` is missing OR a basic `--unshare-net` invocation cannot
/// even start in this env (e.g. user namespaces disabled). Used to SKIP the
/// optional Phase-3 tests, but NEVER consulted by
/// `proxied_non_cooperative_egress_is_blocked` (must-enforce).
#[cfg(feature = "proxy")]
fn bwrap_unavailable() -> bool {
    let Ok(which) = std::process::Command::new("sh")
        .arg("-c")
        .arg("command -v bwrap")
        .output()
    else {
        return true;
    };
    if !which.status.success() {
        return true;
    }
    let bwrap = String::from_utf8_lossy(&which.stdout).trim().to_string();
    // Smoke probe: a trivial bwrap netns must at least exit 0.
    let Ok(s) = std::process::Command::new(&bwrap)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--",
            "/bin/true",
        ])
        .status()
    else {
        return true;
    };
    !s.success()
}

/// MUST-ENFORCE guard (spec §9): a tool that ignores `HTTP_PROXY` and dials a
/// raw, non-routable, non-loopback address under a `Proxied` policy MUST be
/// blocked. If this passes (i.e. the connect succeeds), the netns is NOT
/// isolating and the whole Phase-3 enforcement story is broken — so we FAIL
/// loudly rather than skip. 203.0.113.0/24 is TEST-NET-3 (RFC 5737): never
/// routable; in an empty netns the connect must fail with `ENETUNREACH`.
#[cfg(feature = "proxy")]
#[tokio::test]
async fn proxied_non_cooperative_egress_is_blocked() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Proxied {
            allowlist: vec![motosan_sandbox::HostPattern::parse("127.0.0.1")],
        }),
    );
    // python3's `socket.connect` ignores HTTP_PROXY — exactly the
    // non-cooperative tool we need to wall off.
    let script = "import socket,sys\n\
                  s=socket.socket();s.settimeout(2)\n\
                  try:\n  s.connect(('203.0.113.1',80))\n  print('REACHED');sys.exit(0)\n\
                  except OSError as e:\n  print('BLOCKED',e);sys.exit(7)\n";
    let cmd = SandboxCommand {
        program: "/usr/bin/python3".into(),
        args: vec!["-c".into(), script.into()],
        cwd: ws.clone(),
        env: {
            let mut e = BTreeMap::new();
            if let Some(p) = std::env::var_os("PATH") {
                e.insert("PATH".into(), p);
            }
            e
        },
    };
    let out = sb.run(cmd, &policy, RunOpts::default()).await.expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("REACHED"),
        "raw-IP connect SUCCEEDED inside Proxied netns — sandbox is NOT \
         enforcing. stdout={stdout:?} stderr={stderr:?}"
    );
    // The probe printed BLOCKED + exit 7 → script actually ran. Anything
    // else (exit 127, missing python3, helper-setup error) would mean the
    // test isn't proving what it claims, so we fail.
    assert_eq!(
        out.exit_code,
        Some(7),
        "expected probe exit 7 (script ran and reported BLOCKED), got \
         exit={:?} signal={:?} stdout={stdout:?} stderr={stderr:?}",
        out.exit_code,
        out.signal
    );
    assert!(
        stdout.contains("BLOCKED"),
        "probe did not print BLOCKED; stdout={stdout:?} stderr={stderr:?}"
    );
}

/// Validates `ensure_loopback_up` (Task 5) + the bridge round-trip: a
/// Proxied invocation that simply runs `/bin/true` proves bwrap setup +
/// loopback-up + listener bind + fork + seccomp + execvp all succeed end
/// to end. If `libc::ifreq` field names / byte order were wrong, the bind
/// inside the inner stage would fail with `EADDRNOTAVAIL` and `run()` would
/// surface `Error::NotEnforced`.
#[cfg(feature = "proxy")]
#[tokio::test]
async fn proxied_allowed_host_reachable() {
    if bwrap_unavailable() {
        eprintln!("skip: bwrap not available");
        return;
    }
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Proxied {
            allowlist: vec![motosan_sandbox::HostPattern::parse("example.com")],
        }),
    );
    let out = sb
        .run(sh("true", &ws), &policy, RunOpts::default())
        .await
        .expect("run");
    assert_eq!(
        out.exit_code,
        Some(0),
        "/bin/true under Proxied must exit 0 (proves lo-up + bind + fork + \
         seccomp + execvp). stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Phase 2 + Phase 3: a denied host triggers a CONNECT 403 at the proxy. We
/// can't easily round-trip TLS in a test, but we can verify the proxy
/// rejects denied hosts at the protocol level — the proxy crate's own tests
/// cover the wire form; here we just confirm that running curl with the
/// denied host yields a nonzero exit (and didn't leak through bwrap to a
/// raw connect, since lookup for arbitrary names doesn't resolve either).
#[cfg(feature = "proxy")]
#[tokio::test]
async fn proxied_denied_host_refused() {
    if bwrap_unavailable() {
        eprintln!("skip: bwrap not available");
        return;
    }
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Proxied {
            allowlist: vec![motosan_sandbox::HostPattern::parse("example.com")],
        }),
    );
    // curl --proxy uses HTTP_PROXY semantics; the denied host is NOT in the
    // allowlist, so the proxy must refuse CONNECT. Use --connect-timeout to
    // bound the wait; -k tolerates self-signed if TLS reaches a peer (it
    // shouldn't here).
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    let cmd = SandboxCommand {
        program: "/usr/bin/curl".into(),
        args: vec![
            "-sS".into(),
            "--max-time".into(),
            "5".into(),
            "https://denied.invalid/".into(),
        ],
        cwd: ws.clone(),
        env,
    };
    let out = sb.run(cmd, &policy, RunOpts::default()).await.expect("run");
    assert_ne!(
        out.exit_code,
        Some(0),
        "curl to a denied host should fail; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// bwrap `--ro-bind / /` makes the outer FS read-only; only `--bind`'d
/// writable_roots get write back. A write OUTSIDE the writable root must
/// fail with EROFS, not silently succeed.
#[cfg(feature = "proxy")]
#[tokio::test]
async fn proxied_fs_write_outside_root_denied() {
    if bwrap_unavailable() {
        eprintln!("skip: bwrap not available");
        return;
    }
    let (_g, ws) = workspace();
    let (_o, other) = workspace();
    let escape = other.join("escape.txt");
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Proxied { allowlist: vec![] }),
    );
    let out = sb
        .run(
            sh(&format!("echo x > {}", escape.display()), &ws),
            &policy,
            RunOpts::default(),
        )
        .await
        .expect("run");
    assert_ne!(out.exit_code, Some(0));
    assert!(
        !escape.exists(),
        "bwrap --ro-bind should have blocked the write at {}",
        escape.display()
    );
}

/// bwrap `--ro-bind <subpath> <subpath>` re-protects a path INSIDE a
/// writable_root (the Linux gap the Landlock path can't close — spec §5).
#[cfg(feature = "proxy")]
#[tokio::test]
async fn proxied_read_only_subpath_denied() {
    if bwrap_unavailable() {
        eprintln!("skip: bwrap not available");
        return;
    }
    let (_g, ws) = workspace();
    let secret = ws.join("secret");
    std::fs::create_dir(&secret).unwrap();
    std::fs::write(secret.join("readme"), b"original").unwrap();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()])
            .read_only(secret.clone())
            .network(NetworkPolicy::Proxied { allowlist: vec![] }),
    );
    let out = sb
        .run(
            sh(
                &format!("echo modified > {}/readme", secret.display()),
                &ws,
            ),
            &policy,
            RunOpts::default(),
        )
        .await
        .expect("run");
    assert_ne!(out.exit_code, Some(0));
    // File contents must remain untouched.
    assert_eq!(
        std::fs::read_to_string(secret.join("readme")).unwrap(),
        "original",
        "ro-bind carveout failed to protect the file"
    );
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
