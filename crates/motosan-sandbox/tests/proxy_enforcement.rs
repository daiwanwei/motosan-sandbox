#![cfg(all(target_os = "macos", feature = "proxy"))]

//! macOS hard-enforcement proof for `NetworkPolicy::Proxied`.
//!
//! Load-bearing test: `direct_connection_blocked_by_seatbelt` — proves the
//! child cannot bypass the proxy with a raw socket. The gating logic itself is
//! proven at the proxy-crate level (`proxy_gate.rs`).

use motosan_sandbox::{
    HostPattern, NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy, WorkspaceWrite,
};
use std::collections::BTreeMap;

fn proxied(allow: &[&str]) -> SandboxPolicy {
    let allowlist = allow.iter().map(|s| HostPattern::parse(s)).collect();
    // workspace-write so the command can run; the interesting axis is network.
    SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![std::env::temp_dir().canonicalize().unwrap()])
            .network(NetworkPolicy::Proxied { allowlist }),
    )
}

fn env_with_path() -> BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    env
}

/// A command that does a direct TCP connect via `nc` (reliable on macOS; bash
/// /dev/tcp support is not guaranteed). `nc -z` exits 0 on connect, nonzero on
/// refusal/deny. `-w 2` bounds the wait.
fn nc_connect(port: u16) -> SandboxCommand {
    SandboxCommand {
        program: "/usr/bin/nc".into(),
        args: vec![
            "-z".into(),
            "-w".into(),
            "2".into(),
            "127.0.0.1".into(),
            port.to_string().into(),
        ],
        cwd: std::env::temp_dir().canonicalize().unwrap(),
        env: env_with_path(),
    }
}

#[tokio::test]
async fn direct_connection_blocked_by_seatbelt() {
    // A direct (non-proxy) connect to a NON-proxy port must be DENIED by
    // Seatbelt — proving Proxied is HARD on macOS, not merely cooperative.
    //
    // Without the sandbox this `nc -z` would succeed (exit 0) because a real
    // listener is bound and accepting. Seatbelt must block the connect so the
    // child exits nonzero. That nonzero exit is the load-bearing proof.
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port();
    std::thread::spawn(move || for _ in other.incoming() {});

    let sb = Sandbox::new();
    let out = sb
        .run(
            nc_connect(other_port),
            &proxied(&["example.com"]),
            RunOpts::default(),
        )
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Defensive: a `sandbox-exec: …` prefix means the policy itself was
    // parse-rejected — the child would exit nonzero for the wrong reason and
    // we'd be "passing" without actually proving Seatbelt blocked a connect.
    // Pinning the wire form lives in seatbelt.rs unit tests; this assert keeps
    // THIS test honest at the integration boundary.
    assert!(
        !stderr.contains("sandbox-exec:"),
        "sandbox-exec rejected the policy — test would be passing for the \
         wrong reason; stderr: {stderr}"
    );
    assert_ne!(
        out.exit_code,
        Some(0),
        "direct connect to a NON-proxy port must be blocked by Seatbelt; \
         stderr: {stderr}"
    );
}

#[tokio::test]
async fn proxied_run_sets_up_cleanly() {
    // SMOKE CHECK (not a full allow-path proof): a Proxied policy must
    // successfully set up — proxy started, env injected, Seatbelt policy
    // assembled, child spawned. We can't easily check end-to-end TLS without
    // a rustls upstream; the hardness proof is `direct_connection_blocked_by_seatbelt`
    // and the gating proof is `proxy_gate.rs::denied_host_refused`.
    let sb = Sandbox::new();
    let res = sb
        .run(
            nc_connect(9),
            &proxied(&["example.com"]),
            RunOpts::default(),
        )
        .await;
    assert!(
        res.is_ok(),
        "Proxied run should set up cleanly (proxy started, policy ok): {res:?}"
    );
}
