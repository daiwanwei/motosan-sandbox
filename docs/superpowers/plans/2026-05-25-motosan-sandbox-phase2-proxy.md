# motosan-sandbox Phase 2 — Allowlist proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Per-host allowlist egress via a local proxy — **hard on macOS** (Seatbelt restricts egress to the proxy endpoint), **`Error::Unsupported` on Linux** until Phase 3.

**Authoritative spec:** `docs/superpowers/specs/2026-05-25-motosan-sandbox-phase2-proxy-design.md` (read it; this plan implements it). Build in `/Users/daiwanwei/Projects/wade/motosan-sandbox`. Do NOT touch `motosan-agent-loop`.

**Architecture (non-circular — see spec §4):**
- `motosan-sandbox-proxy` is a **leaf crate** (no dep on core): owns the `CONNECT`-only HTTP proxy + its allowlist matcher (takes pattern *strings*) + an RAII `ProxyServerHandle` (Drop aborts the task).
- core (`motosan-sandbox`): `NetworkPolicy::Proxied { allowlist: Vec<HostPattern> }` + `HostPattern` (policy API, renders to strings); the existing `ProxyHandle { addr }` is the address-carrier for `TransformCtx`; the `proxy` feature pulls in the proxy crate; `run()` (feature-gated) starts the proxy, threads the addr through `transform()`, holds the `ProxyServerHandle` for the run.

**Platform:** proxy enforcement is macOS-only in Phase 2. Tests that prove hardness are `#[cfg(target_os = "macos")]` and run on this Mac. Linux just asserts `Proxied → Error::Unsupported`.

**Order matters:** Task 1 *verifies the Seatbelt rule against real `sandbox-exec`* before any proxy code — it's the linchpin of the whole "macOS is hard" claim (spec §7).

---

## File map

```
motosan-sandbox/
├── Cargo.toml                              # +member motosan-sandbox-proxy
└── crates/
    ├── motosan-sandbox/
    │   ├── Cargo.toml                      # +proxy feature → dep motosan-sandbox-proxy
    │   └── src/
    │       ├── policy.rs                   # +HostPattern, +NetworkPolicy::Proxied
    │       ├── types.rs                    # ProxyHandle stays { addr } (carrier)
    │       ├── transform.rs                # Proxied: env inject + (macOS) seatbelt rule; (Linux) Unsupported
    │       ├── seatbelt.rs                 # +Proxied network branch (verified rule from Task 1)
    │       ├── lib.rs                       # run(): proxy lifecycle under `proxy` feature
    │       └── error.rs                     # reuse Unsupported / add ProxyUnavailable if needed
    │   └── tests/
    │       ├── seatbelt_proxy_probe.rs      (NEW, macOS) Task 1 — verify the rule
    │       └── proxy_enforcement.rs         (NEW, macOS) Task 7 — hard-enforcement proof
    └── motosan-sandbox-proxy/               (NEW leaf crate)
        ├── Cargo.toml
        └── src/
            ├── lib.rs                       # ProxyServer, ProxyServerHandle, ProxyConfig
            ├── matcher.rs                   # DomainPattern parse + match (the real semantics)
            └── connect.rs                   # CONNECT parse + tunnel
        └── tests/
            └── proxy_gate.rs                # through-proxy allowed/denied
```

---

## Task 1: Verify the macOS Seatbelt-to-proxy rule (the linchpin)

**Files:** `crates/motosan-sandbox/tests/seatbelt_proxy_probe.rs` (new, macOS)

Goal: empirically determine the Seatbelt rule that lets the child reach `127.0.0.1:<proxyport>` and **nothing else**, before building anything. This test becomes a permanent regression guard for the rule form.

- [ ] **Step 1: Write the probe test**

Create `crates/motosan-sandbox/tests/seatbelt_proxy_probe.rs`:

```rust
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
fn run_under_policy(allow_rule: &str, connect_port: u16) -> i32 {
    let policy = format!(
        "(version 1)\n(deny default)\n(allow process-exec)(allow process-fork)\n\
         (allow file-read*)(allow sysctl-read)(allow mach-lookup)\n{allow_rule}\n"
    );
    let port = connect_port.to_string();
    let out = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &policy, "--", "/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", &port])
        .output()
        .expect("spawn sandbox-exec");
    out.status.code().unwrap_or(-1)
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

    // Candidate rule — try numeric 127.0.0.1 first (that's what the child dials).
    let rule = format!("(allow network-outbound (remote ip \"127.0.0.1:{proxy_port}\"))");

    let to_proxy = run_under_policy(&rule, proxy_port);
    assert_eq!(to_proxy, 0,
        "child MUST reach the proxy port under the rule; if this fails, the rule \
         form is wrong (try \"localhost:{proxy_port}\", or add \
         (allow network-bind (local ip \"localhost:*\")) and \
         (allow network-inbound (local ip \"localhost:*\")))");

    let to_other = run_under_policy(&rule, other_port);
    assert_ne!(to_other, 0,
        "child MUST be blocked from any other port — this proves hard enforcement");

    // RECORD the working rule form in this test's name/comment; Task 6 uses it.
}
```

- [ ] **Step 2: Run it (macOS)**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --test seatbelt_proxy_probe -- --nocapture`
Expected: PASS. **If `to_proxy` fails:** the numeric rule didn't match — change `rule` to `"localhost:{proxy_port}"` and/or add the `network-bind`/`network-inbound` loopback lines (per the assert message), re-run until both asserts hold. **Record the exact working rule** — Task 6's `seatbelt.rs` branch must use that form verbatim.

- [ ] **Step 3: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/tests/seatbelt_proxy_probe.rs
git commit -m "test(proxy): verify Seatbelt restricts child to the proxy port (linchpin)"
```

---

## Task 2: Core policy model — `HostPattern` + `NetworkPolicy::Proxied`

**Files:** `crates/motosan-sandbox/src/policy.rs`

- [ ] **Step 1: Write the failing tests + the types**

Append to `crates/motosan-sandbox/src/policy.rs`:

```rust
/// An allowlist entry. Matching itself lives in the proxy crate; here we model
/// the policy API and render to the canonical string the proxy parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    Exact(String),
    SubdomainsOnly(String),   // "*.example.com" — excludes the apex
    ApexAndSubdomains(String), // "**.example.com" — includes the apex
    Any,                       // "*"
}

impl HostPattern {
    /// Parse `"example.com"` / `"*.example.com"` / `"**.example.com"` / `"*"`.
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "*" {
            HostPattern::Any
        } else if let Some(rest) = s.strip_prefix("**.") {
            HostPattern::ApexAndSubdomains(rest.to_ascii_lowercase())
        } else if let Some(rest) = s.strip_prefix("*.") {
            HostPattern::SubdomainsOnly(rest.to_ascii_lowercase())
        } else {
            HostPattern::Exact(s.to_ascii_lowercase())
        }
    }

    /// Canonical string form (round-trips with `parse`). This is what `run()`
    /// passes to the proxy crate, which does the actual matching.
    pub fn to_pattern_string(&self) -> String {
        match self {
            HostPattern::Exact(h) => h.clone(),
            HostPattern::SubdomainsOnly(h) => format!("*.{h}"),
            HostPattern::ApexAndSubdomains(h) => format!("**.{h}"),
            HostPattern::Any => "*".to_string(),
        }
    }
}

#[cfg(test)]
mod host_pattern_tests {
    use super::*;

    #[test]
    fn parses_each_shape() {
        assert_eq!(HostPattern::parse("example.com"), HostPattern::Exact("example.com".into()));
        assert_eq!(HostPattern::parse("*.example.com"), HostPattern::SubdomainsOnly("example.com".into()));
        assert_eq!(HostPattern::parse("**.example.com"), HostPattern::ApexAndSubdomains("example.com".into()));
        assert_eq!(HostPattern::parse("*"), HostPattern::Any);
    }

    #[test]
    fn round_trips_to_string() {
        for s in ["example.com", "*.example.com", "**.example.com", "*"] {
            assert_eq!(HostPattern::parse(s).to_pattern_string(), s);
        }
    }

    #[test]
    fn lowercases_host() {
        assert_eq!(HostPattern::parse("Example.COM"), HostPattern::Exact("example.com".into()));
    }
}
```

- [ ] **Step 2: Add the `Proxied` variant**

Edit the `NetworkPolicy` enum (still `#[non_exhaustive]`):

```rust
#[non_exhaustive]
pub enum NetworkPolicy {
    Blocked,
    Allowed,
    /// Egress only to allowlisted hosts, via a local proxy. Hard on macOS;
    /// `Error::Unsupported` on Linux until Phase 3.
    Proxied { allowlist: Vec<HostPattern> },
}
```

Export `HostPattern` from `lib.rs`: add to the `pub use policy::{...}` line.

- [ ] **Step 3: Fix internal matches that became non-exhaustive**

`cargo build` will now error on internal `match`es over `NetworkPolicy` that lack a `Proxied` arm (and any `== Blocked`/`== Allowed` is fine, but matches must be total). Find them (`transform.rs::build_env`, `seatbelt.rs`, `reexec.rs::HelperPolicy::from_policy`) and add `Proxied` arms:
- `build_env`: `Proxied` → do NOT set `MOTOSAN_SANDBOX_NETWORK_DISABLED` (network is proxied, not off); the proxy env is injected in the ctx-aware path (Task 6), not here.
- `seatbelt.rs` network section: handled in Task 6.
- `reexec.rs` `HelperPolicy::from_policy` (Linux): `Proxied` → `Err(Error::Unsupported(SandboxKind::LinuxSeccomp))` (Task 6 also guards in `run()`).

For this task, the minimal change to keep it compiling: add `NetworkPolicy::Proxied { .. } => { /* handled in Task 6 */ }` arms that are correct-by-construction (e.g. `build_env` simply doesn't add the disabled marker). Don't implement the macOS rule yet.

- [ ] **Step 4: Run + commit**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --lib policy && cargo build`
Expected: policy tests pass; crate builds (macOS + Linux).

```bash
git add crates/motosan-sandbox/src/policy.rs crates/motosan-sandbox/src/lib.rs crates/motosan-sandbox/src/transform.rs crates/motosan-sandbox/src/reexec.rs
git commit -m "feat(proxy): add HostPattern + NetworkPolicy::Proxied (policy model)"
```

---

## Task 3: Scaffold the `motosan-sandbox-proxy` leaf crate + wire the feature

**Files:** workspace `Cargo.toml`, `crates/motosan-sandbox-proxy/{Cargo.toml,src/lib.rs}`, `crates/motosan-sandbox/Cargo.toml`

- [ ] **Step 1: Create the leaf crate**

`crates/motosan-sandbox-proxy/Cargo.toml`:

```toml
[package]
name = "motosan-sandbox-proxy"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "Local allowlist HTTP CONNECT proxy for motosan-sandbox"

[dependencies]
tokio = { version = "1", features = ["net", "io-util", "rt", "macros"] }
tracing = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["net", "io-util", "rt-multi-thread", "macros", "time"] }
```

`crates/motosan-sandbox-proxy/src/lib.rs`:

```rust
//! Local allowlist HTTP CONNECT proxy. Leaf crate — no dependency on
//! motosan-sandbox (avoids a circular dep with core's `proxy` feature). Takes
//! the allowlist as pattern strings and matches them internally.
mod matcher;
mod connect;

use std::net::SocketAddr;

pub struct ProxyConfig {
    /// Pattern strings: "example.com", "*.x.com", "**.x.com", "*".
    pub allowlist: Vec<String>,
}

pub struct ProxyServerHandle {
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl ProxyServerHandle {
    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

impl Drop for ProxyServerHandle {
    fn drop(&mut self) {
        self.task.abort(); // cleanup guarantee on every exit path
    }
}

pub struct ProxyServer;
impl ProxyServer {
    /// Bind a loopback listener and start serving; returns once bound.
    pub async fn start(config: ProxyConfig) -> std::io::Result<ProxyServerHandle> {
        let allow = std::sync::Arc::new(matcher::Allowlist::parse(&config.allowlist));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let allow = allow.clone();
                        tokio::spawn(async move {
                            if let Err(e) = connect::handle_conn(stream, &allow).await {
                                tracing::debug!("proxy conn ended: {e}");
                            }
                        });
                    }
                    Err(e) => { tracing::warn!("accept failed: {e}"); break; }
                }
            }
        });
        Ok(ProxyServerHandle { addr, task })
    }
}
```

- [ ] **Step 2: Wire the workspace + feature**

Workspace `Cargo.toml`: add `"crates/motosan-sandbox-proxy"` to `members`.

`crates/motosan-sandbox/Cargo.toml`: add the optional dep + feature:
```toml
[features]
# ... existing ...
proxy = ["dep:motosan-sandbox-proxy"]

[dependencies]
motosan-sandbox-proxy = { version = "0.1", path = "../motosan-sandbox-proxy", optional = true }
```

- [ ] **Step 3: Build (matcher/connect are stubs for now)**

Create stub `matcher.rs` (`pub struct Allowlist; impl Allowlist { pub fn parse(_: &[String]) -> Self { Allowlist } pub fn allows(&self, _host: &str) -> bool { false } }`) and `connect.rs` (`pub async fn handle_conn(_: tokio::net::TcpStream, _: &crate::matcher::Allowlist) -> std::io::Result<()> { Ok(()) }`) so it compiles. Real impls in Tasks 4–5.

Run: `cargo build -p motosan-sandbox-proxy && cargo build -p motosan-sandbox --features proxy`
Expected: both build.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/motosan-sandbox-proxy crates/motosan-sandbox/Cargo.toml
git commit -m "feat(proxy): scaffold motosan-sandbox-proxy leaf crate + proxy feature"
```

---

## Task 4: The allowlist matcher (in the proxy crate)

**Files:** `crates/motosan-sandbox-proxy/src/matcher.rs`

- [ ] **Step 1: Write the matcher + tests (TDD: write tests first, watch fail)**

Replace `crates/motosan-sandbox-proxy/src/matcher.rs`:

```rust
//! Allowlist matching. Mirrors Codex's semantics:
//! exact / `*.` subdomains-only (excludes apex) / `**.` apex+subdomains / `*` any.

enum Pattern {
    Exact(String),
    SubdomainsOnly(String),
    ApexAndSubdomains(String),
    Any,
}

impl Pattern {
    fn parse(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        if s == "*" {
            Pattern::Any
        } else if let Some(r) = s.strip_prefix("**.") {
            Pattern::ApexAndSubdomains(r.to_string())
        } else if let Some(r) = s.strip_prefix("*.") {
            Pattern::SubdomainsOnly(r.to_string())
        } else {
            Pattern::Exact(s)
        }
    }
    fn matches(&self, host: &str) -> bool {
        match self {
            Pattern::Any => true,
            Pattern::Exact(h) => host == h,
            Pattern::ApexAndSubdomains(h) => host == h || host.ends_with(&format!(".{h}")),
            Pattern::SubdomainsOnly(h) => host.ends_with(&format!(".{h}")), // NOT the apex
        }
    }
}

pub struct Allowlist(Vec<Pattern>);

impl Allowlist {
    pub fn parse(patterns: &[String]) -> Self {
        Allowlist(patterns.iter().map(|p| Pattern::parse(p)).collect())
    }
    /// Block-by-default: host is allowed only if some pattern matches.
    pub fn allows(&self, host: &str) -> bool {
        let host = normalize(host);
        self.0.iter().any(|p| p.matches(&host))
    }
}

/// Strip a trailing `:port`, surrounding brackets, lowercase.
///
/// NOTE: bracketless IPv6 literals (`::1`) get mangled by the `:port` split —
/// acceptable because it's **fail-closed** (a mangled IPv6 literal won't match a
/// hostname allowlist → denied). Hostnames are the real case here; tighten IPv6
/// parsing only if literal-IPv6 allowlisting is ever needed.
fn normalize(host: &str) -> String {
    let h = host.trim().trim_start_matches('[');
    let h = h.split(']').next().unwrap_or(h);   // [::1]:443 → ::1
    let h = h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h); // host:443 → host (IPv4/name)
    h.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn al(p: &[&str]) -> Allowlist { Allowlist::parse(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>()) }

    #[test]
    fn exact_only_matches_host() {
        let a = al(&["example.com"]);
        assert!(a.allows("example.com"));
        assert!(!a.allows("a.example.com"));
        assert!(!a.allows("evil.com"));
    }
    #[test]
    fn subdomains_only_excludes_apex() {
        let a = al(&["*.example.com"]);
        assert!(a.allows("a.example.com"));
        assert!(a.allows("b.a.example.com"));
        assert!(!a.allows("example.com"));
    }
    #[test]
    fn apex_and_subdomains_includes_apex() {
        let a = al(&["**.example.com"]);
        assert!(a.allows("example.com"));
        assert!(a.allows("a.example.com"));
        assert!(!a.allows("notexample.com"));
    }
    #[test]
    fn any_allows_all() {
        assert!(al(&["*"]).allows("whatever.com"));
    }
    #[test]
    fn block_by_default_empty() {
        assert!(!al(&[]).allows("example.com"));
    }
    #[test]
    fn strips_port_and_lowercases() {
        assert!(al(&["example.com"]).allows("Example.com:443"));
    }
    #[test]
    fn substring_attack_blocked() {
        // "evil-example.com" must NOT match "*.example.com" or "**.example.com"
        assert!(!al(&["*.example.com"]).allows("evilexample.com"));
        assert!(!al(&["**.example.com"]).allows("evilexample.com"));
    }
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo test -p motosan-sandbox-proxy matcher`
Expected: PASS (incl. `substring_attack_blocked` — the `.{h}` suffix check prevents `evilexample.com` matching `example.com`).

```bash
git add crates/motosan-sandbox-proxy/src/matcher.rs
git commit -m "feat(proxy): allowlist matcher (exact/*./**./* + block-by-default)"
```

---

## Task 5: The CONNECT proxy + through-proxy integration test

**Files:** `crates/motosan-sandbox-proxy/src/connect.rs`, `crates/motosan-sandbox-proxy/tests/proxy_gate.rs`

- [ ] **Step 1: Implement `handle_conn` (CONNECT-only)**

Replace `crates/motosan-sandbox-proxy/src/connect.rs`:

```rust
//! CONNECT-only HTTP proxy connection handling. Plain-HTTP (forward) is NOT
//! proxied in Phase 2 — non-CONNECT methods get 405.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::matcher::Allowlist;

pub async fn handle_conn(mut client: TcpStream, allow: &Allowlist) -> std::io::Result<()> {
    // Read the request line + headers (until CRLFCRLF). Cap to avoid abuse.
    // `header_end` = index just past the blank line; bytes after it are payload
    // the client pipelined (e.g. an early TLS ClientHello) and must be forwarded.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(()); // client closed
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            break buf.len();
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]);
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or(""); // "host:port" for CONNECT

    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\nplain HTTP not proxied in this phase\r\n").await;
        return Ok(());
    }

    // `allows` normalizes (strips the port) internally, so pass the full target.
    if !allow.allows(target) {
        tracing::info!(%target, "proxy DENY");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return Ok(());
    }
    tracing::info!(%target, "proxy ALLOW");

    // Connect upstream (the proxy — in the unsandboxed parent — resolves DNS).
    let mut upstream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(e);
        }
    };
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    // Forward any bytes the client pipelined after the CONNECT headers (rare —
    // most clients wait for the 200 — but correct).
    if header_end < buf.len() {
        upstream.write_all(&buf[header_end..]).await?;
    }
    // Blind-tunnel both directions (no MITM).
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
```

> Note: `allow.allows(target)` normalizes the `host:port` internally (strips the
> port), so we pass the full CONNECT target. `copy_bidirectional` handles the
> TLS bytes opaquely.

- [ ] **Step 2: Through-proxy integration test**

Create `crates/motosan-sandbox-proxy/tests/proxy_gate.rs`:

```rust
use motosan_sandbox_proxy::{ProxyConfig, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Minimal upstream that accepts a connection and echoes "ok".
async fn upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let _ = s.write_all(b"ok").await;
        }
    });
    (addr, h)
}

/// Send a CONNECT for `target` to the proxy; return the proxy's status line.
async fn connect_via(proxy: std::net::SocketAddr, target: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string()
}

#[tokio::test]
async fn allowed_host_connects() {
    let (up, _h) = upstream().await;
    // Allow the loopback upstream by exact host:port-stripped host = "127.0.0.1".
    let proxy = ProxyServer::start(ProxyConfig { allowlist: vec!["127.0.0.1".into()] }).await.unwrap();
    let status = connect_via(proxy.addr, &format!("127.0.0.1:{}", up.port())).await;
    assert!(status.contains("200"), "got: {status}");
}

#[tokio::test]
async fn denied_host_refused() {
    let (up, _h) = upstream().await;
    let proxy = ProxyServer::start(ProxyConfig { allowlist: vec!["example.com".into()] }).await.unwrap();
    let status = connect_via(proxy.addr, &format!("127.0.0.1:{}", up.port())).await;
    assert!(status.contains("403"), "got: {status}");
}

#[tokio::test]
async fn non_connect_method_405() {
    let proxy = ProxyServer::start(ProxyConfig { allowlist: vec!["*".into()] }).await.unwrap();
    let mut s = TcpStream::connect(proxy.addr).await.unwrap();
    s.write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("405"));
}
```

- [ ] **Step 3: Run + commit**

Run: `cargo test -p motosan-sandbox-proxy`
Expected: matcher + the 3 gate tests pass.

```bash
git add crates/motosan-sandbox-proxy/src/connect.rs crates/motosan-sandbox-proxy/tests/proxy_gate.rs
git commit -m "feat(proxy): CONNECT-only allowlist proxy + through-proxy tests"
```

---

## Task 6: Wire `run()` lifecycle + `transform()` Proxied branch

**Files:** `crates/motosan-sandbox/src/lib.rs`, `transform.rs`, `seatbelt.rs`, `reexec.rs`

- [ ] **Step 1: thread the proxy address into the macOS path + inject env**

The proxy port must reach two places that the *pure* `build_env(cmd, policy)`
(no ctx) can't supply: the Seatbelt rule (the port) and the proxy env vars. So
**change `seatbelt::transform_seatbelt` to take the proxy address**, and do the
env injection in the ctx-aware `transform()` (which has `ctx.proxy`). Concretely:

1. `transform_seatbelt` signature gains the proxy addr:
   ```rust
   pub(crate) fn transform_seatbelt(
       cmd: &SandboxCommand,
       policy: &SandboxPolicy,
       proxy: Option<std::net::SocketAddr>,   // Some(addr) iff policy is Proxied
   ) -> Result<SpawnRequest, Error>
   ```
   The macOS arm of `transform()` passes `ctx.proxy.map(|h| h.addr)`.

2. **Seatbelt network section** (`build_policy`/the network branch in `seatbelt.rs`)
   gains a `Proxied` case keyed on the passed `proxy`:
   - `Proxied` + `Some(addr)` → emit **the rule Task 1 verified**, e.g.
     `format!("(allow network-outbound (remote ip \"127.0.0.1:{}\"))", addr.port())`
     (use whatever address-form/extra bind-rules Task 1 proved). No other network allows.
   - `Proxied` + `None` → **fail-closed**: `Err(Error::Transform("proxied policy needs a running proxy".into()))` (never emit an allow-all). Spec §7.
   - `Blocked`/`Allowed` unchanged.

3. **Env injection** happens in `transform()`'s macOS Proxied path (it has
   `ctx`): after building the base `SpawnRequest` via `transform_seatbelt`, insert
   into `req.env` (or fold into a small helper the macOS arm calls):
   ```rust
   if let NetworkPolicy::Proxied { .. } = policy.network() {
       let addr = ctx.proxy.ok_or_else(|| Error::Transform("proxied policy needs a running proxy".into()))?.addr;
       let url = format!("http://127.0.0.1:{}", addr.port());
       for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] { req.env.insert(k.into(), url.clone().into()); }
       req.env.insert("NO_PROXY".into(), "localhost,127.0.0.1,::1".into());
   }
   ```
   (`build_env` stays pure and untouched; the proxy env is layered on here.)

4. **Linux:** `Proxied` → `Err(Error::Unsupported(SandboxKind::LinuxSeccomp))` (the
   Linux arm; also guarded earlier in `run()` Step 2 so the proxy is never started).

(Exact code depends on the current `transform.rs`/`seatbelt.rs` shape; keep the macOS arm's existing structure and add the `Proxied` case to the network-policy builder.)

- [ ] **Step 2: `run()` proxy lifecycle (feature-gated)**

In `lib.rs::run`, before `transform`, start the proxy for `Proxied` policies and
keep both the core address-carrier and the RAII server-handle alive as locals
through `spawn_and_capture`. Resolve the conditional-init cleanly with a helper
that returns `(Option<ProxyHandle>, Option<ProxyServerHandle>)`:

```rust
    pub async fn run(&self, cmd: SandboxCommand, policy: &SandboxPolicy, opts: RunOpts)
        -> Result<ExecOutput, Error>
    {
        let kind = Self::detect();
        let helper_reexec = kind == SandboxKind::LinuxSeccomp && !policy.is_full_access();

        // Start the proxy iff the policy is Proxied. Both bindings live to the
        // end of run(): `addr_carrier` is borrowed by ctx; `_server` is the RAII
        // ProxyServerHandle whose Drop aborts the proxy task on EVERY exit path.
        let (addr_carrier, _server) = self.maybe_start_proxy(policy, kind).await?;
        let ctx = TransformCtx { proxy: addr_carrier.as_ref() };

        let req = self.transform(&cmd, policy, &ctx)?;
        spawn::spawn_and_capture(req, &opts, helper_reexec).await
        // `_server` drops here (and on any `?` above) → proxy task aborted.
    }

    async fn maybe_start_proxy(&self, policy: &SandboxPolicy, kind: SandboxKind)
        -> Result<(Option<ProxyHandle>, Option<MaybeServer>), Error>
    {
        let NetworkPolicy::Proxied { allowlist } = policy.network() else {
            return Ok((None, None));
        };
        if kind == SandboxKind::LinuxSeccomp {
            return Err(Error::Unsupported(SandboxKind::LinuxSeccomp)); // until Phase 3
        }
        #[cfg(feature = "proxy")]
        {
            let patterns: Vec<String> = allowlist.iter().map(|p| p.to_pattern_string()).collect();
            let server = motosan_sandbox_proxy::ProxyServer::start(
                motosan_sandbox_proxy::ProxyConfig { allowlist: patterns },
            ).await.map_err(Error::Spawn)?;
            Ok((Some(ProxyHandle { addr: server.addr }), Some(server)))
        }
        #[cfg(not(feature = "proxy"))]
        {
            let _ = allowlist;
            Err(Error::Transform("Proxied policy requires the `proxy` feature".into()))
        }
    }
```

`MaybeServer` is `motosan_sandbox_proxy::ProxyServerHandle` under `#[cfg(feature = "proxy")]`
and an uninhabited/`()` placeholder otherwise — define a small `type` alias so the
signature compiles in both feature configs (or duplicate the fn body per cfg).
The point is: **`_server` is a local in `run()`, so its `Drop` runs on success and
on every early `?`** — no proxy leaks. `ProxyHandle` here is the core
`{ addr }` carrier (Phase 0 type), borrowed by `ctx` for the duration.

- [ ] **Step 3: Build both feature configs + both platforms**

Run:
```bash
cargo build -p motosan-sandbox
cargo build -p motosan-sandbox --features proxy
```
Expected: both compile on macOS. (`cargo build` on Linux too — the Linux arm returns Unsupported.)

- [ ] **Step 4: Commit**

```bash
git add crates/motosan-sandbox/src/lib.rs crates/motosan-sandbox/src/transform.rs crates/motosan-sandbox/src/seatbelt.rs crates/motosan-sandbox/src/reexec.rs
git commit -m "feat(proxy): run() proxy lifecycle + transform Proxied branch (macOS hard, Linux Unsupported)"
```

---

## Task 7: macOS hard-enforcement integration test + Linux Unsupported

**Files:** `crates/motosan-sandbox/tests/proxy_enforcement.rs` (new)

- [ ] **Step 1: Write the suite**

Create `crates/motosan-sandbox/tests/proxy_enforcement.rs`:

```rust
#![cfg(all(target_os = "macos", feature = "proxy"))]

use motosan_sandbox::{HostPattern, NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy, WorkspaceWrite};
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
    if let Some(p) = std::env::var_os("PATH") { env.insert("PATH".into(), p); }
    env
}

/// A command that does a direct TCP connect via `nc` (reliable on macOS; bash
/// /dev/tcp support is not guaranteed). `nc -z` exits 0 on connect.
fn nc_connect(port: u16) -> SandboxCommand {
    SandboxCommand {
        program: "/usr/bin/nc".into(),
        args: vec!["-z".into(), "-w".into(), "2".into(), "127.0.0.1".into(), port.to_string().into()],
        cwd: std::env::temp_dir().canonicalize().unwrap(),
        env: env_with_path(),
    }
}

#[tokio::test]
async fn direct_connection_blocked_by_seatbelt() {
    // A direct (non-proxy) connect to a non-proxy port must be DENIED by
    // Seatbelt — proving Proxied is HARD on macOS, not merely cooperative.
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port();
    std::thread::spawn(move || for _ in other.incoming() {});

    let sb = Sandbox::new();
    let out = sb.run(nc_connect(other_port), &proxied(&["example.com"]), RunOpts::default())
        .await.unwrap();
    // Without the sandbox this nc would connect (exit 0); Seatbelt must block it.
    assert_ne!(out.exit_code, Some(0), "direct connect must be blocked by Seatbelt");
}

#[tokio::test]
async fn child_can_reach_the_proxy_endpoint() {
    // SMOKE CHECK (not a full allow-path proof): with a Proxied policy, the child
    // CAN reach the proxy's loopback port (Seatbelt allows exactly that). We
    // connect with `nc` to the proxy port itself. The denied/allowed *gating*
    // logic is proven at the proxy-crate level (Task 5 `denied_host_refused`);
    // the *hardness* is proven by `direct_connection_blocked_by_seatbelt`. A
    // strict end-to-end allow assert would need a TLS upstream (rustls) — optional.
    let sb = Sandbox::new();
    // We don't know the proxy port up front (run() picks it), so this test instead
    // asserts the run COMPLETES without a transform/Seatbelt error for a Proxied
    // policy — i.e. the proxy started, env injected, policy assembled. `nc` to a
    // closed port returns nonzero, which is fine; we only assert run() returned Ok.
    let res = sb.run(nc_connect(9), &proxied(&["example.com"]), RunOpts::default()).await;
    assert!(res.is_ok(), "Proxied run should set up cleanly (proxy started, policy ok): {res:?}");
}
```

> The hard-enforcement proof is `direct_connection_blocked_by_seatbelt`. The
> "reachable through proxy" test is softer (curl + a non-TLS local upstream can't
> complete a real HTTPS handshake); keep it as a smoke check that the proxy env +
> Seatbelt rule let the child reach the proxy at all. If you want a strict
> positive assert, stand up a TLS upstream (rustls) in the test — optional.

- [ ] **Step 2: Linux Unsupported test**

Add to `crates/motosan-sandbox/tests/linux_enforcement.rs`:

```rust
#[tokio::test]
async fn proxied_is_unsupported_on_linux() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()])
            .network(NetworkPolicy::Proxied { allowlist: vec![] }),
    );
    let err = sb.run(sh("true", &ws), &policy, RunOpts::default()).await.unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)));
}
```
(Add `NetworkPolicy` to the imports if needed.)

- [ ] **Step 3: Run + commit**

macOS: `cargo test --features proxy --test proxy_enforcement -- --test-threads=1`
Expected: `direct_connection_blocked_by_seatbelt` passes (hard proof). Docker (Linux): the new `proxied_is_unsupported_on_linux` passes.

```bash
git add crates/motosan-sandbox/tests/proxy_enforcement.rs crates/motosan-sandbox/tests/linux_enforcement.rs
git commit -m "test(proxy): macOS hard-enforcement proof + Linux Unsupported"
```

---

## Task 8: README + CI + final gates

**Files:** `crates/motosan-sandbox/README.md`, `.github/workflows/ci.yml`

- [ ] **Step 1: README**

Append a "Network allowlist (Phase 2)" section: `NetworkPolicy::Proxied { allowlist }` with the matcher syntax; **hard on macOS** (Seatbelt restricts egress to the proxy), **`Error::Unsupported` on Linux until Phase 3**; needs the `proxy` feature; `CONNECT`-only (HTTPS) — plain HTTP not proxied yet; consumer should pass canonical hosts.

- [ ] **Step 2: CI**

Ensure the macOS CI job runs `cargo test --features proxy` (so `proxy_enforcement` runs). Add `--features proxy` to the existing test invocations (or a dedicated step). The Linux job already runs `cargo test` (picks up `proxied_is_unsupported_on_linux`); add `--features proxy` there too so the Unsupported path is exercised with the feature on.

- [ ] **Step 3: Full gates**

macOS:
```bash
cargo test
cargo test --features proxy
cargo test --features cancellation
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```
Docker (Linux): `cargo test --features proxy && cargo clippy --all-features --all-targets -- -D warnings`
Expected: all green; `direct_connection_blocked_by_seatbelt` proves macOS hardness; `proxied_is_unsupported_on_linux` green.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "docs(proxy): README Phase 2 section + CI --features proxy"
```

---

## Done criteria

- macOS: `Proxied` is **hard** — `direct_connection_blocked_by_seatbelt` passes (a non-proxy connect is blocked by Seatbelt), allowlisted CONNECTs reach the proxy; proxy gates by host (allowed 200 / denied 403); non-CONNECT → 405.
- Linux: `Proxied` → `Error::Unsupported` (proven in `linux_enforcement.rs`); no bypassable mode ships.
- `proxy` feature off: `Proxied` at `run()` → clear `Error`; crate still builds.
- No regression: Phase 0/1 + spike suites green on both platforms; clippy `-D warnings` + fmt clean (incl. `--features proxy`).
- `motosan-sandbox-proxy` is a leaf crate (no core dep); `TransformCtx` unchanged.

## Notes for the executor

- **Task 1 first, always.** If the Seatbelt rule form differs from the guess, record the working form and use it verbatim in Task 6's `seatbelt.rs`.
- The `run()` borrow choreography in Task 6 (keeping `core_handle` + `ProxyServerHandle` alive across `spawn_and_capture`, with `ctx.proxy` borrowing `core_handle`) will need lifetime fiddling — the shape shown is illustrative; make the borrow checker happy without changing the contract (`TransformCtx.proxy: Option<&ProxyHandle>`).
- Don't touch `motosan-agent-loop`. Don't add `macos`/`linux` Cargo features. Don't ship a cooperative/bypassable Linux mode.
- If a strict positive HTTPS-through-proxy assert is wanted, add a rustls upstream in Task 7; otherwise the hard-enforcement proof is the load-bearing test.
