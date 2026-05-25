# motosan-sandbox Phase 2 — Allowlist network proxy — Design

**Date:** 2026-05-25
**Status:** Draft for review
**Decision:** Ship the per-host allowlist proxy as **hard enforcement on macOS** (Seatbelt restricts egress to the proxy endpoint) + cooperative env-injection; **Linux `Proxied` returns `Error::Unsupported` until Phase 3** (hard Linux egress control inherently needs a network namespace, which is deferred). Implements the reserved `NetworkPolicy::Proxied` from the overall design.

## 1. Why this scope (evidence from Codex)

Researching `codex-rs` settled the core tension — *a cooperative env-var proxy is bypassable; what makes it hard?*

- **Linux hard enforcement requires a network namespace.** Codex's seccomp `ProxyRouted` mode *deliberately allows arbitrary `AF_INET` `connect()` to any IP*; what makes egress unbypassable is bubblewrap `--unshare-net` leaving the child's netns with **no route except a loopback bridge** to the proxy (no iptables). seccomp cannot filter by destination. So a **no-bubblewrap Linux proxy can only ever be cooperative/bypassable** — hard Linux egress control is inherently a netns feature, and we deferred netns to **Phase 3**.
- **macOS hard enforcement is pure Seatbelt, no namespace.** `(deny default)` + `(allow network-outbound (remote ip "localhost:<proxyport>"))` blocks a non-cooperative tool's direct socket to the internet at the OS level. So macOS Proxied is **hard in Phase 2** without any namespace.

Therefore: **macOS Proxied is hard now; Linux Proxied is `Unsupported` until Phase 3** (consistent with the project's fail-loud stance — we already return `Error::Unsupported` for `read_only_subpaths` on Linux, rather than silently under-enforcing). We do **not** ship a bypassable Linux mode that could mislead.

## 2. Scope

In scope:
- `NetworkPolicy::Proxied { allowlist }` variant + `HostPattern` matcher.
- `motosan-sandbox-proxy` crate: an **HTTP proxy** (`CONNECT` for HTTPS + forward for HTTP), **no MITM**, gating by host against the allowlist, block-by-default, bound to loopback.
- `run()` proxy lifecycle (start → inject env → transform → spawn → stop).
- macOS Seatbelt hard enforcement (egress only to the proxy endpoint).
- Linux `Proxied` → `Error::Unsupported`.

Out of scope (later): SOCKS5, TLS MITM / per-path or per-method policy, **hard Linux enforcement (Phase 3 — netns + loopback bridge)**, DNS allowance (`*:53`), proxy reuse across many `run()`s (Phase 2 starts one per `run()`; a reuse path is noted but not built).

## 3. Policy model

Add the reserved variant to `NetworkPolicy` (`policy.rs`), already `#[non_exhaustive]` so this is additive:

```rust
#[non_exhaustive]
pub enum NetworkPolicy {
    Blocked,
    Allowed,
    /// Egress allowed only to hosts matching the allowlist, routed through a
    /// local allowlist proxy. Hard on macOS (Seatbelt); `Unsupported` on Linux
    /// until Phase 3.
    Proxied { allowlist: Vec<HostPattern> },
}

/// Allowlist entry. Matching mirrors Codex's proven semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Exactly this host (`example.com` matches only `example.com`).
    Exact(String),
    /// Subdomains only (`*.example.com` matches `a.example.com`, NOT the apex).
    SubdomainsOnly(String),
    /// Apex + subdomains (`**.example.com` matches `example.com` and `a.example.com`).
    ApexAndSubdomains(String),
    /// Any host. Allowlist-only (meaningless/forbidden as a denial).
    Any,
}

impl HostPattern {
    /// Parse `"example.com"` / `"*.example.com"` / `"**.example.com"` / `"*"`.
    pub fn parse(s: &str) -> Self { /* prefix-dispatch, mirror Codex */ }
    /// Does `host` (port-stripped, lowercased) match?
    pub fn matches(&self, host: &str) -> bool { /* … */ }
}
```

`SandboxPolicy::network()` already returns `NetworkPolicy`; the new variant flows through it. Anything that currently matches `Blocked`/`Allowed` exhaustively must gain a `Proxied` arm (the `#[non_exhaustive]` `_` arms already exist in external consumers; the crate's own internal matches need updating).

## 4. The proxy crate: `motosan-sandbox-proxy`

A new workspace crate, pulled in by `motosan-sandbox`'s **`proxy` feature** (the reserved optional dep). Dependencies: `tokio` (net/io), `hyper`/`http` *or* a hand-rolled minimal HTTP parser — **decision: hand-roll the minimal `CONNECT`/request-line parsing** to avoid a heavy hyper dependency for what is a tiny gateway (revisit if forward-proxy HTTP/1.1 edge cases pile up).

Surface (in the leaf crate `motosan-sandbox-proxy` — no dep on core; allowlist
arrives as pattern strings, parsed by the crate's own matcher):

```rust
pub struct ProxyConfig { pub allowlist: Vec<String> }   // "example.com", "*.x.com", "**.x.com", "*"

pub struct ProxyServer { /* … */ }
impl ProxyServer {
    /// Bind a loopback listener and start serving. Returns once bound.
    pub async fn start(config: ProxyConfig) -> io::Result<ProxyServerHandle>;
}

/// The proxy crate's OWN RAII handle. **`Drop` aborts the serving task** (the
/// cleanup guarantee for every exit path); `shutdown().await` is the graceful
/// path. `run()` holds this for the run's duration.
pub struct ProxyServerHandle {
    pub addr: SocketAddr,   // 127.0.0.1:<ephemeral>
    // shutdown signal + JoinHandle (aborted on Drop)
}
impl ProxyServerHandle { pub async fn shutdown(self); }
impl Drop for ProxyServerHandle { /* abort the serving task — see §5 */ }
```

core's `run()` reads `handle.addr` into the lightweight core `ProxyHandle { addr }`
for `TransformCtx`, and keeps the `ProxyServerHandle` alive for the run.

> **Dependency direction (avoid a circular dep).** core's `proxy` feature
> depends on `motosan-sandbox-proxy`, so the proxy crate must be a **leaf** — it
> must NOT depend on core. Therefore:
> - **`HostPattern` lives in core** (it's part of the public policy API and
>   `NetworkPolicy::Proxied` needs it even without the `proxy` feature). core's
>   `HostPattern` renders to the canonical string form (`*.example.com`).
> - **The matcher + server live in the proxy crate** (the leaf): `ProxyServer`
>   takes the allowlist as **pattern strings** (`Vec<String>`), parses + matches
>   them internally, and returns its OWN RAII `ProxyServerHandle` (Drop aborts
>   the serving task).
> - **core keeps the lightweight `ProxyHandle { addr }`** (Phase 0 stub) purely
>   as the address-carrier for `TransformCtx`. `run()` (under the `proxy`
>   feature) starts the proxy, reads its bound `addr` into a core `ProxyHandle`
>   for `TransformCtx`, and holds the proxy crate's `ProxyServerHandle` for the
>   run's duration (its Drop is the cleanup). No circular dep, `TransformCtx`
>   unchanged. (This refines the earlier "one type" idea, which would have been
>   circular.)

**Per-connection logic — `CONNECT`-only for Phase 2 (HTTPS):**
- **HTTPS / `CONNECT`:** client sends `CONNECT host:443 HTTP/1.1`. Parse `host`. If `allowlist` matches → reply `200 Connection Established`, then **blind-tunnel** bytes both ways (no MITM — we never see TLS plaintext, and don't need to: host-level policy is fully decided from the `CONNECT` line). Else → `403 Forbidden`, close.
- **Plain HTTP (forward) is NOT proxied in Phase 2.** A `GET http://…` absolute-form request gets `405 Method Not Allowed` (or `403`) with a clear body: "plain HTTP not proxied in this phase." Rationale: the common allowlist case (npm/pip/git/`curl https://…`) is all HTTPS → all `CONNECT`; plain-HTTP forwarding is where the HTTP/1.1 hand-rolling risk lives (chunked, keep-alive, absolute-form parsing). Deferred as a fast-follow — keeps the Phase 2 proxy genuinely tiny (parse one `CONNECT` line, gate, tunnel). Documented limitation.
- **Block-by-default:** anything not matched by the allowlist (and any non-`CONNECT` method) is denied. Log allow/deny decisions via `tracing`.
- The proxy resolves DNS itself (upstream connect), so the **child never needs to resolve names** — see §6.

## 5. Lifecycle: `run()` owns the proxy (per-run)

`run()` gains proxy management for `Proxied` policies:

```
run(cmd, policy, opts)
  └─ if policy.network() is Proxied { allowlist }:
       • require the `proxy` feature (else Error::Unsupported-ish / clear Error)
       • on Linux → return Err(Error::Unsupported(LinuxSeccomp))   // until Phase 3
       • on macOS → ProxyServer::start(allowlist) → ProxyHandle { addr }
  └─ ctx = TransformCtx { proxy: Some(&handle) }
  └─ transform(cmd, policy, &ctx) → SpawnRequest:
       • env += HTTP_PROXY/HTTPS_PROXY/ALL_PROXY = http://127.0.0.1:<port>,
                NO_PROXY = "localhost,127.0.0.1,::1"
       • macOS Seatbelt policy: egress only to localhost:<port> (see §7)
  └─ spawn + capture                       // `handle` is a local; held across the await
  └─ (handle dropped here on EVERY return path — Drop aborts the serving task)
```

**Cleanup must cover every exit path, not just success.** If the command errors,
times out, or is cancelled, an explicit `shutdown().await` after `spawn` would be
skipped and the proxy task would leak. The guarantee is therefore
**`ProxyHandle::Drop`** (synchronously aborts the serving task) — `handle` is a
local in `run()`, so it drops on success *and* on every early `?`/return. An
optional `handle.shutdown().await` on the happy path gives a graceful close, but
Drop is the safety net that must exist.

`transform()` stays pure given `TransformCtx` (the proxy address is injected, not discovered — exactly the contract reserved in the overall design §5). Starting the proxy is `run()`'s side effect. A caller that wants to **reuse** one proxy across many commands constructs the `ProxyHandle` itself and calls `transform()` + a spawn — noted as an advanced path, not built in Phase 2.

**Feature interaction:** `Proxied` is only constructible by consumers regardless of features (it's a public enum variant), but *enforcing* it needs the `proxy` feature. If a `Proxied` policy reaches `run()` without the `proxy` feature compiled in → `Error` (clear message: "enable the `proxy` feature"). Document this.

## 6. Env injection

Inject a focused set (broader than strictly needed, for tool compatibility) into
`SpawnRequest.env`. **This injection needs the proxy address from `TransformCtx`,
so it lives in the ctx-aware `transform()` path — NOT in the pure
`build_env(cmd, policy)` helper (which has no ctx).** A `Proxied` branch in
`transform()` reads `ctx.proxy.addr` and sets:
- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` = `http://127.0.0.1:<port>`
- `NO_PROXY` = `localhost,127.0.0.1,::1`
- (optional, later: the npm/pip/yarn variants Codex sets — add if a target tool ignores the standard vars)

**DNS (platform-specific):** the child connects only to the proxy and passes
hostnames via `CONNECT`; the proxy resolves. So the child needs no name
resolution. The "no `*:53`" point is really a **Linux/Phase-3** concern (where
egress is UDP/socket-level) — on macOS, name resolution goes through
`mDNSResponder` (a mach service), not UDP:53, and a pure `CONNECT`-via-proxy
child resolves nothing anyway. If a real tool turns out to resolve locally before
proxying, revisit per-platform.

## 7. macOS Seatbelt — hard enforcement

**⚠️ This rule is the linchpin of the whole macOS-hard claim — the plan MUST
verify it against real `sandbox-exec` as its FIRST task, before building the
proxy.** If the rule doesn't match the child's actual connection, either the
child can't reach the proxy (everything breaks) or it's silently not hard.

The Seatbelt `Proxied` branch (in `seatbelt.rs`) emits, on top of the base `(deny default)`:
```scheme
(allow network-outbound (remote ip "localhost:<proxyport>"))
; plus, if a client needs to bind its source socket, the loopback-scoped:
;   (allow network-bind   (local ip "localhost:*"))
;   (allow network-inbound (local ip "localhost:*"))
```
and nothing else network-related. Because the base denies by default, a tool that
ignores `HTTP_PROXY` and opens a raw socket to a public IP is **blocked by the
kernel**, not merely un-proxied.

Two things the verification task must pin down:
1. **Address form.** The child dials `127.0.0.1:<port>` (from `HTTP_PROXY=http://127.0.0.1:port`).
   Confirm whether Seatbelt's `(remote ip "localhost:<port>")` matches the numeric
   `127.0.0.1` form, or whether the rule must use `(remote ip "127.0.0.1:<port>")`
   to match what the child actually connects to. Codex uses `localhost`; we use
   whatever the test proves matches the numeric dial.
2. **Bind/inbound.** Whether a loopback client socket needs the `network-bind` /
   `network-inbound` rules above (Codex's proxy policy includes them). Add them —
   scoped to loopback only, so it stays hard — only if the test shows the connect
   fails without them.

The proxy port is known at `transform()` time (`TransformCtx.proxy.addr.port()`),
interpolated into the policy. **Fail-closed:** if `Proxied` but no proxy address
is in `TransformCtx`, `transform()` returns `Err` (never emits an allow-all).

## 8. Linux

`transform()` (or the `HelperPolicy` mapping) rejects `Proxied` on Linux:
```rust
NetworkPolicy::Proxied { .. } => return Err(Error::Unsupported(SandboxKind::LinuxSeccomp)),
```
Documented: hard Linux egress control arrives in Phase 3 (netns + loopback bridge); a cooperative-only Linux proxy is deliberately NOT shipped (it would be false security for untrusted code).

## 9. Testing

- **Unit:** `HostPattern::parse` + `matches` for all four shapes (exact; `*.` excludes apex; `**.` includes apex; `*`); allowlist block-by-default; port/host normalization.
- **Proxy crate:** spawn `ProxyServer`, point a client at it: allowed host `CONNECT`/forward succeeds, denied host → 403. (Use a local test upstream server as the "allowed host".)
- **macOS integration (hard-enforcement proof):** with a `Proxied` policy, (a) a command using `HTTP_PROXY` reaches an allowed local upstream; (b) a denied host is refused; (c) **a command that ignores the proxy and connects directly to a socket is blocked by Seatbelt** (the proof it's hard, not cooperative). Bind real local listeners as endpoints (mirror the Phase 1 network test's two-sided approach).
- **Linux:** `Proxied` → `Error::Unsupported` (behavioral, in `linux_enforcement.rs`).

## 10. Risks / open items

- **macOS `localhost:port` Seatbelt rule:** confirm Seatbelt restricts to the exact loopback port and that the proxy's own upstream connections (made from the *parent*, outside the sandbox) are unaffected (they are — the proxy runs in the unsandboxed parent). Verify the `(remote ip "localhost:<port>")` syntax against `sandbox-exec` in the integration test.
- **Per-run proxy overhead:** starting/stopping a proxy per `run()` adds latency for agent loops issuing many commands. Acceptable for MVP; a reuse path is the optimization.
- **HTTP parsing is now trivial** — `CONNECT`-only means parse one request line + headers to the blank line, then blind-tunnel. **No `hyper` dependency, no HTTP/1.1 forward-path edge cases** (that risk was eliminated by deferring plain-HTTP forward, §4). Hand-roll it.
- **`ProxyHandle` duplication** between core (stub) and the proxy crate — collapse to one type (§4) to keep `TransformCtx` stable.
