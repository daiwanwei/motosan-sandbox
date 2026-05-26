//! GATE (spec §9): can we run a bwrap network namespace in THIS env, and does it
//! produce a hard wall (ENETUNREACH for non-loopback)? If this can't pass in the
//! iteration env (Docker-on-Mac nested userns often can't), STOP — Phase 3's
//! whole approach depends on it.
#![cfg(target_os = "linux")]

use std::process::Command;

fn bwrap() -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg("command -v bwrap")
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

#[test]
fn bwrap_netns_is_usable_and_hard() {
    let Some(bwrap) = bwrap() else {
        eprintln!("SKIP: no bwrap on PATH — Phase 3 needs it");
        return;
    };

    // (a) a bwrap netns can run at all
    let basic = Command::new(&bwrap)
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
        .expect("spawn bwrap");
    assert!(
        basic.success(),
        "bwrap --unshare-net failed in this env. Try the container with \
         --security-opt seccomp=unconfined --security-opt apparmor=unconfined, \
         then --privileged. If none work (common for Docker-on-Mac nested userns), \
         STOP and switch to a bare Linux runner — do NOT proceed to Task 2."
    );

    // (b) inside the netns, a connect to a NON-loopback address must be unreachable
    // (the hard wall). python3 is the most portable connector in the rust image.
    let script = "import socket,sys\n\
                  s=socket.socket();s.settimeout(2)\n\
                  try:\n  s.connect(('203.0.113.1',80))\n  print('REACHED');sys.exit(0)\n\
                  except OSError as e:\n  print('BLOCKED',e);sys.exit(7)\n";
    let hard = Command::new(&bwrap)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
            "python3",
            "-c",
            script,
        ])
        .output()
        .expect("spawn bwrap python");
    let stdout = String::from_utf8_lossy(&hard.stdout);
    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — never routable. In an empty netns
    // the connect must fail. Assert the SCRIPT ACTUALLY RAN AND REPORTED BLOCKED
    // (exit 7 / "BLOCKED") — NOT merely a nonzero exit, which would also happen if
    // python3 is missing (command-not-found), giving a false "blocked" pass.
    assert!(
        !stdout.contains("REACHED"),
        "direct connect to a non-loopback addr SUCCEEDED inside --unshare-net — netns NOT isolating"
    );
    assert!(
        stdout.contains("BLOCKED") && hard.status.code() == Some(7),
        "the probe script did not run/report blocked (is python3 installed?). \
         exit={:?} stdout={stdout:?} stderr={:?}",
        hard.status.code(),
        String::from_utf8_lossy(&hard.stderr)
    );

    // (c) inside the netns, binding 127.0.0.1 must SUCCEED. The Phase 3 in-netns
    // bridge binds loopback listeners; this fails if bwrap doesn't bring `lo`
    // up (or the payload would need CAP_NET_ADMIN to do it). Without this check
    // the probe is green while the real bridge dies with EPERM (regression that
    // shipped once — see fix/phase3-loopback-caps). The payload has NO
    // CAP_NET_ADMIN, so a passing bind proves bwrap configured `lo` for us.
    let bind_script = "import socket,sys\n\
                       s=socket.socket()\n\
                       try:\n  s.bind(('127.0.0.1',0));print('BOUND',s.getsockname()[1]);sys.exit(0)\n\
                       except OSError as e:\n  print('BINDFAIL',e);sys.exit(8)\n";
    let lo = Command::new(&bwrap)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
            "python3",
            "-c",
            bind_script,
        ])
        .output()
        .expect("spawn bwrap python (loopback bind)");
    let lo_stdout = String::from_utf8_lossy(&lo.stdout);
    assert!(
        lo_stdout.contains("BOUND") && lo.status.code() == Some(0),
        "binding 127.0.0.1 inside the bwrap netns FAILED — `lo` is not usable \
         without CAP_NET_ADMIN, so the Phase 3 bridge cannot bind its listeners. \
         exit={:?} stdout={lo_stdout:?} stderr={:?}",
        lo.status.code(),
        String::from_utf8_lossy(&lo.stderr)
    );
}
