# motosan-sandbox Phase 3 — Hard Linux egress (bwrap netns + transparent proxy) — Design

**Date:** 2026-05-25
**Status:** Draft for review
**Decision:** Make Linux `NetworkPolicy::Proxied` **hard** (today it returns `Error::Unsupported`) by running the command in a bubblewrap network namespace whose only route is a loopback bridge to the Phase-2 allowlist proxy. Filesystem isolation on this path uses **bwrap mounts** (design **B1** — only the `Proxied` path; Phase 1's Landlock+seccomp is untouched for Blocked/Allowed). Requires **system `bwrap`**; degrade to `Unsupported` if absent (no vendoring/C-build).

## 1. Why this shape (Codex evidence)

Researching `codex-rs` settled the architecture:

- **Landlock and bwrap are strictly mutually exclusive in Codex** — the bwrap inner stage passes `apply_landlock_fs = false`; `restrict_self` never runs inside a bwrap'd child. FS-under-bwrap is 100% mount-based. So "Landlock inside a bwrap netns" (the rejected design A) is unsupported/pointless — the bwrap mount namespace already gives a complete FS view.
- **Hard Linux egress requires a network namespace.** seccomp can't filter destination; the unbypassable property comes from `--unshare-net` leaving the netns with **no route except a manually-upped `lo`** + a loopback→UDS→host-bridge→proxy path. **No iptables/nft/netlink** — a non-cooperative tool dialing a raw IP just gets `ENETUNREACH`.
- bwrap dependency: Codex prefers system `bwrap` (PATH), falls back to a vendored+compiled bundle. **We take system-only** for the MVP (degrade to `Unsupported` if absent) — vendoring a C build is deferrable.

**B1 rationale:** Phase 1/2 stay untouched; Phase 3 adds exactly one net-new path (Linux `Proxied`, previously `Unsupported`). The Landlock path remains the default for Blocked/Allowed; bwrap is confined to `Proxied`. This mirrors Codex's `use_legacy_landlock` split (with Landlock as our non-bwrap default).

## 2. Scope

In scope: Linux `Proxied` enforced via bwrap netns + the transparent proxy bridge; system-`bwrap` detection with graceful `Unsupported` fallback; reuse of the Phase-2 `motosan-sandbox-proxy` crate; bwrap-mount FS isolation on this path (incl. `read_only_subpaths`, which bwrap *can* express — closing that Linux gap on the Proxied path).

Out of scope: bundling/compiling bwrap; changing Phase 1 (Blocked/Allowed stay Landlock+seccomp); macOS (Phase 2 Seatbelt unchanged); SOCKS/MITM (Phase 2 scope); Windows.

## 3. Dependency: system `bwrap`, fail-loud if absent

At `run()` time for a Linux `Proxied` policy: locate `bwrap` on `PATH`. If found → use the bwrap path. If **not** found → `Err(Error::Unsupported(SandboxKind::LinuxSeccomp))` with a message ("hard egress on Linux needs bubblewrap; install `bwrap`"). So hard egress is *conditional on `bwrap` being installed* — documented; the project degrades cleanly rather than silently weakening. (A future phase may vendor+compile a bundled bwrap as Codex does.)

## 4. Execution flow (Codex-faithful two-stage)

Linux `Proxied` (previously `Unsupported`) now:

```
run(cmd, WorkspaceWrite{roots, network: Proxied{allowlist}}, opts)   [parent, unsandboxed]
  └─ locate bwrap; absent → Err(Unsupported)
  └─ start motosan-sandbox-proxy (Phase 2 crate) on 127.0.0.1:<pport>  (allowlist gating)
  └─ build the HOST bridge BEFORE unshare: per-proxy-endpoint UDS; fork a host bridge
       (UnixListener(uds) → per-accept TcpStream::connect(127.0.0.1:pport) → proxy_bidirectional)
     → ProxyRouteSpec JSON { routes: [{ env_key: "HTTP_PROXY", uds_path }] }
  └─ transform() (Linux Proxied arm) builds a SpawnRequest that re-execs the helper-exe
       with arg0 sentinel + HelperPolicy{ writable_roots, read_only_subpaths, mode: ProxiedOuter, route_spec }
  └─ spawn
       │
       ▼  helper OUTER stage (arg0 == sentinel, mode == ProxiedOuter)
          build bwrap argv (FS mounts §5 + --unshare-user/--unshare-pid/--unshare-net + --proc)
          inner command = <helper-exe> with mode=ProxiedInner + route_spec + -- + real cmd
          execv bwrap   (never returns)
       │
       ▼  bwrap establishes the mount + net namespaces, runs the inner command
       │
       ▼  helper INNER stage (mode == ProxiedInner, now inside the netns)
          1. activate_in_netns_bridge(route_spec): bring up `lo` (ioctl), bind 127.0.0.1:0 →
             per-accept UnixStream::connect(uds) → proxy_bidirectional; rewrite HTTP_PROXY env
             to 127.0.0.1:<local_port>
          2. prctl(PR_SET_NO_NEW_PRIVS) + install seccomp ProxyRouted (allow AF_INET/AF_INET6
             socket; deny AF_UNIX + other families — so the child can't reach the host UDS directly)
          3. execvp(real cmd)   [enforced: empty netns + seccomp + bwrap FS view]
```

Traffic: `child → 127.0.0.1:<local_port> (netns lo) → UnixStream → host UDS → host bridge → TCP → proxy → upstream`. The netns has no other route, so a tool ignoring `HTTP_PROXY` and dialing a raw IP gets `ENETUNREACH`.

This reuses the Phase-1 helper machinery (arg0 sentinel, `run_if_invoked`, the JSON `HelperPolicy` IPC) — extended with a **mode** (`Landlock` | `ProxiedOuter` | `ProxiedInner`) and a `route_spec`. Blocked/Allowed keep `mode: Landlock` (Phase 1, unchanged).

## 5. bwrap filesystem mounts (Proxied path)

Replicate Phase-0/1 semantics (read-everywhere / write-scoped), expressed as bwrap mounts:
- `--ro-bind / /` (whole FS read-only) + `--dev /dev` + `--proc /proc`.
- per `writable_root`: `--bind <root> <root>` (re-enable write).
- per `read_only_subpath`: `--ro-bind <subpath> <subpath>` (re-protect inside a writable root). **bwrap can express this** — so `read_only_subpaths` is **supported** on the Linux Proxied path (it's `Unsupported` only on the Landlock path).
- depth-ordered so narrower rules override broader (writable under read-only under …).

(Restricted-read / path-hiding via `--tmpfs /` is *available* with bwrap but out of scope — Phase 3 keeps read-everywhere to match macOS + the Landlock path.)

## 6. seccomp `ProxyRouted`

Distinct from Phase 1's `Blocked` filter. `ProxyRouted` (Codex-faithful): allow `socket`/`socketpair` only for `AF_INET`/`AF_INET6`; **deny `AF_UNIX`** (so the child can't bypass the bridge by talking to the host UDS directly) and other families. It does **not** restrict `connect` destination — the empty netns does that. Plus the always-denies (`ptrace`, `io_uring*`) if Phase 1 added them. Applied in the inner stage, after `no_new_privs`, before `execvp`.

## 7. The bridge topology (reuse Codex's pattern; no iptables)

- `ProxyRouteSpec { routes: Vec<ProxyRouteEntry> }`, `ProxyRouteEntry { env_key: String, uds_path: PathBuf }` (serde, passed via env or argv to the helper).
- **Host bridge** (parent — **tokio**): runs in the async parent before unshare. Per endpoint, create a UDS in a temp dir; spawn a tokio task: `UnixListener::bind(uds)` → per-accept `TcpStream::connect(127.0.0.1:<pport>)` → `tokio::io::copy_bidirectional`.
- **In-netns bridge** (inner stage — **synchronous std, NOT tokio**): per UDS, `std::net::TcpListener::bind((127.0.0.1, 0))` (bring `lo` up via `SIOCSIFFLAGS`/`SIOCSIFADDR` ioctls if needed) → per-accept `std::os::unix::net::UnixStream::connect(uds)` → forward with **blocking `std::io::copy` on two threads** (one per direction); then rewrite the proxy env var to `127.0.0.1:<local_port>`.
- The proxy and host bridge live in the unsandboxed parent; the only netns crossing is the UDS, reached via the in-netns loopback listener.

**Why synchronous (no tokio) in the netns bridge:** the re-exec'd helper is **synchronous** — Phase 1's `run_if_invoked`/`linux.rs` use no tokio (just `prctl`/`landlock`/`seccomp`/`execvp`). That matters because the in-netns bridge is created by `fork()`, and **`fork()` + a tokio runtime is unsafe** (the child inherits broken runtime/lock state). Keeping the helper single-threaded + synchronous makes the fork safe and lets the bridge child use plain `std::net` + threads. **Do NOT introduce tokio into the re-exec'd helper.**

**Critical: the in-netns bridge must be a separate process that survives `execvp`.** The inner stage `execvp`s the target, replacing the whole process image — a *thread* running the bridge would die the instant the target execs, breaking all egress. So the bridge runs in a **`fork()`ed child** that persists in the netns. Ordering inside the inner stage:
1. `fork()` the in-netns bridge child (binds `127.0.0.1:0`, forwards to the UDS over `AF_UNIX`, sync `std`). Runs *before* seccomp, so it may use `AF_UNIX`.
2. In the parent (soon-to-be-target) only: `no_new_privs` + seccomp `ProxyRouted` (**denies `AF_UNIX`** — so the *target* can't reach the host UDS directly, only the bridge can).
3. `execvp` the target.

**Bridge cleanup = `--unshare-pid` (load-bearing, not just isolation).** Because bwrap runs the inner command under `--unshare-pid`, the target is **pid 1** of the new pid namespace; the bridge child (forked inside it) is pid 2. When the target (pid 1) exits, the kernel SIGKILLs the entire pidns — including the bridge. So no bridge leaks, with no explicit reaping needed. (Confirm the bridge is forked *inside* bwrap's pidns — i.e. in the inner stage — so it's covered.)

This fork-before-seccomp/exec ordering is the reason `AF_UNIX`-deny-on-target + a UDS bridge is coherent — and it's the single most error-prone part; the plan's Task-1 spike must validate the bridge actually survives and carries traffic after the target execs.

## 8. `run()` / `transform()` integration

- `run()`'s `maybe_start_proxy`: today Linux `Proxied` → `Err(Unsupported)` *before* starting the proxy. Phase 3: on Linux `Proxied`, locate `bwrap`; if present, start the proxy (as macOS does) **and** build the host bridge + route-spec, threading them into `TransformCtx`/the `HelperPolicy`. If `bwrap` absent → `Err(Unsupported)`.
- `transform()` Linux `Proxied` arm: build the bwrap-outer re-exec `SpawnRequest` (helper-exe, sentinel arg0, `HelperPolicy{ mode: ProxiedOuter, …, route_spec }`). (Blocked/Allowed unchanged — Landlock path.)
- `helper::run_if_invoked` / `linux.rs`: dispatch on `HelperPolicy.mode` → Landlock path (Phase 1) | ProxiedOuter (build+exec bwrap) | ProxiedInner (bridge+seccomp+execvp).
- The Phase-2 `proxy` feature gates all of this; without it, Linux `Proxied` stays `Unsupported` (as Phase 2).

## 9. Testing

- **Task 1 — viability spike (do this FIRST; it may change the whole execution plan):** before any code, determine **where Phase 3 can even run**. Codex's bwrap tests run on *bare* `ubuntu-latest` runners, NOT nested Docker — and **nested unprivileged user namespaces inside a Docker-on-macOS container frequently do NOT work** (even with `seccomp=unconfined`; may need `--privileged`, and can still fail). The spike must, in the actual iteration env:
  1. Get `bwrap --unshare-net --ro-bind / / -- /bin/true` to run (try plain → `--security-opt seccomp=unconfined --security-opt apparmor=unconfined` → `--privileged`); record which is needed.
  2. Bring `lo` up inside the netns and bind a loopback listener.
  3. Prove a direct connect to a **non-loopback** address gets `ENETUNREACH` (the hard wall).
  **If none of these work in Docker-on-Mac, STOP and decide the iteration strategy** (bare Linux CI only — slow; or a remote/real Linux host) before building the bridge. Discovering this after writing the machinery is the worst outcome.
- **Behavioral suite** (`#[cfg(target_os="linux")]`, Docker): allowed host reachable through the proxy via `HTTP_PROXY`; **a non-cooperative tool (ignores `HTTP_PROXY`, dials a raw IP) is blocked (`ENETUNREACH`)** — the hardness proof that distinguishes Phase 3 from a cooperative proxy; denied host refused by the proxy; FS write-outside-root still denied (bwrap mounts); `read_only_subpaths` write denied (bwrap ro-bind).
- **Must-enforce guard:** a test that FAILS (not skips) if the netns isn't actually isolating (e.g. the raw-IP dial succeeds) — so a misconfigured CI can't green a non-enforcing suite.
- **Fallback:** `bwrap` absent → `Proxied` returns `Unsupported` (test by PATH manipulation).

## 10. CI cost (inherited — the price of Phase 3)

Unlike Phase 1 (Landlock needs nothing special), the bwrap netns path needs the CI/Docker env to provide: **`bwrap` installed**, **unprivileged user namespaces enabled** (`sysctl kernel.unprivileged_userns_clone=1`), and **AppArmor userns restriction relaxed** (`kernel.apparmor_restrict_unprivileged_userns=0` on Ubuntu 24.04) — exactly the provisioning Codex documents. Plus a runtime skip-probe (`should_skip_bwrap_tests`) so the suite degrades where namespaces are unavailable, with the must-enforce guard ensuring a fully-skipped run isn't mistaken for success. The `.devcontainer` + CI workflow gain these.

## 11. Risks / open items

- **bwrap-in-Docker (the dominant execution risk):** nested unprivileged userns inside a Docker-on-macOS container frequently does NOT work — Codex runs bwrap on *bare* ubuntu runners, not nested Docker. **Task 1 must settle this before any other work** (see §9). Likely outcomes: works with `--privileged`; or only on bare CI (`ubuntu-latest`) / a real Linux host. The iteration loop and CI strategy depend on the answer, so resolve it up front, not after building the bridge.
- **Two FS models on Linux** (Landlock for Blocked/Allowed, bwrap-mounts for Proxied) — accepted (B1). Semantics stay aligned (read-all / write-scoped); the only divergence is `read_only_subpaths` works on the Proxied path but not the Landlock path — documented.
- **Helper mode dispatch** adds a third+fourth code path to the re-exec helper; keep the `HelperPolicy.mode` enum the single source of truth.
- **`ENETUNREACH` vs `EPERM`:** a non-cooperative dial fails via *routing* (no route in the netns), surfacing as a connection error, not a seccomp `SIGSYS`. `is_likely_sandbox_denied` should treat the relevant connection-refused/unreachable patterns as denial for `LinuxSeccomp` Proxied, or the consumer keys off exit≠0. Confirm the denial heuristic still fits.
- **Bridge lifecycle:** the host bridge + UDS temp dir must be torn down when the run ends (RAII, like the Phase-2 `ProxyGuard`).
