//! Linchpin verification (spec §7): which Seatbelt rule restricts a child to
//! exactly the loopback proxy port? Hand-rolls a `.sb` policy + sandbox-exec so
//! it's independent of the crate's policy builder; the verified rule is then
//! used by the real seatbelt.rs Proxied branch (Task 6).
#![cfg(target_os = "macos")]

use std::net::TcpListener;
use std::process::Command;

/// Run a TCP connect to `connect_port` under a Seatbelt policy that allows
/// outbound only per `allow_rule`. Returns the child's exit code.
///
/// Uses `/usr/bin/nc` (reliably present on macOS) — NOT bash `/dev/tcp`, whose
/// support in macOS's bash 3.2 is not guaranteed (a missing /dev/tcp would fail
/// for the wrong reason and break the verification). `nc -z` exits 0 on a
/// successful connect, nonzero on refusal/deny. `-w 2`/`-G 2` bound the wait.
fn run_under_policy(allow_rule: &str, connect_port: u16) -> (i32, String, String) {
    let policy = format!(
        "(version 1)\n(deny default)\n(allow process-exec)(allow process-fork)\n\
         (allow file-read*)(allow sysctl-read)(allow mach-lookup)\n{allow_rule}\n"
    );
    let port = connect_port.to_string();
    let out = Command::new("/usr/bin/sandbox-exec")
        .args([
            "-p",
            &policy,
            "--",
            "/usr/bin/nc",
            "-z",
            "-w",
            "2",
            "127.0.0.1",
            &port,
        ])
        .output()
        .expect("spawn sandbox-exec");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn seatbelt_restricts_to_proxy_port() {
    // A real listener stands in for the proxy.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    // A second listener on a different port = "the rest of the network".
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port();
    // Accept in background so connects complete.
    std::thread::spawn(move || for _ in listener.incoming() {});
    std::thread::spawn(move || for _ in other.incoming() {});

    // VERIFIED rule form: sandbox-exec rejects numeric IPs in `(remote ip …)` —
    // it errors `host must be * or localhost in network address` for
    // `"127.0.0.1:<port>"`. Only `localhost:<port>` (or `*:…`) is accepted, and
    // `localhost` matches the child's actual dial to `127.0.0.1:<port>`.
    let rule = format!("(allow network-outbound (remote ip \"localhost:{proxy_port}\"))");

    let (to_proxy, _so, se) = run_under_policy(&rule, proxy_port);
    eprintln!("rule = {rule}");
    eprintln!("to_proxy stderr = {se}");
    assert_eq!(
        to_proxy, 0,
        "child MUST reach the proxy port under the rule; if this fails, the rule \
         form is wrong (try \"localhost:{proxy_port}\", or add \
         (allow network-bind (local ip \"localhost:*\")) and \
         (allow network-inbound (local ip \"localhost:*\")))"
    );

    let (to_other, _so, se2) = run_under_policy(&rule, other_port);
    eprintln!("to_other stderr = {se2}");
    assert_ne!(
        to_other, 0,
        "child MUST be blocked from any other port — this proves hard enforcement"
    );

    // RECORD: the working rule form is
    //   (allow network-outbound (remote ip "localhost:<port>"))
    // sandbox-exec REJECTS numeric `127.0.0.1` in `(remote ip …)` with
    // `host must be * or localhost in network address`. The `localhost` form
    // DOES match the child's numeric `127.0.0.1:<port>` dial, and no
    // additional `network-bind`/`network-inbound` loopback rules are required.
    // Task 6's seatbelt.rs Proxied branch uses this verbatim.
}
