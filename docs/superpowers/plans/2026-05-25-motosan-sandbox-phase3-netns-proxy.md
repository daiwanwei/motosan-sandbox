# motosan-sandbox Phase 3 — Hard Linux egress (bwrap netns + transparent proxy) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make Linux `NetworkPolicy::Proxied` **hard** (was `Error::Unsupported`): run the command in a bubblewrap network namespace whose only route is a loopback bridge to the Phase-2 allowlist proxy, so even a tool that ignores `HTTP_PROXY` cannot reach the internet.

**Authoritative spec:** `docs/superpowers/specs/2026-05-25-motosan-sandbox-phase3-netns-proxy-design.md` — read it first; this plan implements it. Build in `/Users/daiwanwei/Projects/wade/motosan-sandbox`. Do NOT touch `motosan-agent-loop`.

**Approach (locked):** **B1** — bwrap-mounts isolate FS *only* on the `Proxied` path; Phase 1 Landlock+seccomp untouched for Blocked/Allowed. **System `bwrap` only** — absent → `Unsupported`. Codex-faithful two-stage re-exec; **no iptables**.

## ⚠️ Task 1 is a GATE

Task 1 determines whether bwrap netns can run *at all* in the iteration env. **If it can't (Docker-on-Mac nested userns often can't), STOP and reassess the execution strategy with the user before building anything else.** Do not write Tasks 2+ until Task 1 passes (in Docker with some flag combo, or you've switched to a bare Linux host / CI-only loop).

**Non-negotiables (spec):** the re-exec'd helper stays **synchronous (no tokio)** — fork+tokio is unsafe; the in-netns bridge is a **`fork()`ed child using blocking `std::net`** that survives `execvp`; **`--unshare-pid`** reaps it (target = pid 1); seccomp `ProxyRouted` denies `AF_UNIX` (target can't reach the host UDS, only the bridge can); fork happens **before** seccomp/execvp.

---

## File map

```
crates/motosan-sandbox/
├── Cargo.toml                      # (proxy feature already exists from Phase 2)
└── src/
    ├── reexec.rs                   # HelperPolicy gains `mode` + ProxyRouteSpec
    ├── transform.rs                # Linux Proxied arm: build ProxiedOuter re-exec (was Unsupported)
    ├── lib.rs                      # run()/maybe_start_proxy: Linux Proxied starts proxy+host-bridge if bwrap present
    ├── linux.rs                    # dispatch on mode; ProxiedOuter (build+exec bwrap); ProxiedInner (fork bridge+seccomp+execvp)
    ├── linux_bwrap.rs   (NEW,cfg)  # bwrap detection + argv builder (pure, unit-testable)
    ├── linux_bridge.rs  (NEW,cfg)  # in-netns: lo-up (ioctl), sync fork bridge, env rewrite
    └── proxy_bridge.rs  (NEW)      # host-side: ProxyRouteSpec + host UDS bridge (tokio, parent)
└── tests/
    ├── bwrap_viability_probe.rs (NEW, Task 1, cfg linux)
    └── linux_enforcement.rs        # +Phase 3 behavioral tests (Docker)
```

---

## Task 1: Viability spike — can bwrap netns run here? (GATE)

**Files:** `crates/motosan-sandbox/tests/bwrap_viability_probe.rs` (new, `#[cfg(target_os="linux")]`)

- [ ] **Step 1: Write the probe**

```rust
//! GATE (spec §9): can we run a bwrap network namespace in THIS env, and does it
//! produce a hard wall (ENETUNREACH for non-loopback)? If this can't pass in the
//! iteration env (Docker-on-Mac nested userns often can't), STOP — Phase 3's
//! whole approach depends on it.
#![cfg(target_os = "linux")]

use std::process::Command;

fn bwrap() -> Option<String> {
    let out = Command::new("sh").arg("-c").arg("command -v bwrap").output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else { None }
}

#[test]
fn bwrap_netns_is_usable_and_hard() {
    let Some(bwrap) = bwrap() else {
        eprintln!("SKIP: no bwrap on PATH — Phase 3 needs it");
        return;
    };

    // (a) a bwrap netns can run at all
    let basic = Command::new(&bwrap)
        .args(["--unshare-user", "--unshare-pid", "--unshare-net",
               "--ro-bind", "/", "/", "--dev", "/dev", "--", "/bin/true"])
        .status().expect("spawn bwrap");
    assert!(basic.success(),
        "bwrap --unshare-net failed in this env. Try the container with \
         --security-opt seccomp=unconfined --security-opt apparmor=unconfined, \
         then --privileged. If none work (common for Docker-on-Mac nested userns), \
         STOP and switch to a bare Linux runner — do NOT proceed to Task 2.");

    // (b) inside the netns, a connect to a NON-loopback address must be unreachable
    // (the hard wall). python3 is the most portable connector in the rust image.
    let script = "import socket,sys\n\
                  s=socket.socket();s.settimeout(2)\n\
                  try:\n  s.connect(('203.0.113.1',80))\n  print('REACHED');sys.exit(0)\n\
                  except OSError as e:\n  print('BLOCKED',e);sys.exit(7)\n";
    let hard = Command::new(&bwrap)
        .args(["--unshare-user","--unshare-pid","--unshare-net","--ro-bind","/","/",
               "--dev","/dev","--proc","/proc","--","python3","-c",script])
        .output().expect("spawn bwrap python");
    let stdout = String::from_utf8_lossy(&hard.stdout);
    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — never routable. In an empty netns
    // the connect must fail. Assert the SCRIPT ACTUALLY RAN AND REPORTED BLOCKED
    // (exit 7 / "BLOCKED") — NOT merely a nonzero exit, which would also happen if
    // python3 is missing (command-not-found), giving a false "blocked" pass.
    assert!(!stdout.contains("REACHED"),
        "direct connect to a non-loopback addr SUCCEEDED inside --unshare-net — netns NOT isolating");
    assert!(stdout.contains("BLOCKED") && hard.status.code() == Some(7),
        "the probe script did not run/report blocked (is python3 installed?). \
         exit={:?} stdout={stdout:?} stderr={:?}",
        hard.status.code(), String::from_utf8_lossy(&hard.stderr));
}
```

- [ ] **Step 2: Run in Docker — escalate flags as needed**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
# try in order; record which works:
for OPTS in "" "--security-opt seccomp=unconfined --security-opt apparmor=unconfined" "--privileged"; do
  echo "=== docker opts: [$OPTS] ==="
  docker run --rm $OPTS -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/tmp/ct -e CARGO_HOME=/tmp/ch \
    rust:1.95-bookworm bash -c "apt-get update -qq && apt-get install -y -qq bubblewrap python3 >/dev/null && \
      sysctl -w kernel.unprivileged_userns_clone=1 2>/dev/null; \
      cargo test --test bwrap_viability_probe -- --nocapture" && break
done
```
Expected: the probe PASSES under *some* flag set. **Record which flags were required** — Tasks 9–10 (test runner + CI) use them.
**If it passes under none:** STOP. Report to the user; the iteration loop must move to a bare Linux host or CI-only. Do not start Task 2.

- [ ] **Step 3: Commit (the probe is a permanent guard)**

```bash
git add crates/motosan-sandbox/tests/bwrap_viability_probe.rs
git commit -m "test(phase3): bwrap netns viability gate (must pass before building)"
```

---

## Task 2: bwrap detection + argv builder

**Files:** `crates/motosan-sandbox/src/linux_bwrap.rs` (new, `#[cfg(target_os="linux")]`), wire in `lib.rs`/`linux.rs`

- [ ] **Step 1: Write `linux_bwrap.rs` with detection + the pure argv builder + tests**

```rust
//! bwrap discovery + argv construction (pure; unit-testable without bwrap).
use std::path::{Path, PathBuf};

/// First `bwrap` on PATH, or None.
pub(crate) fn find_bwrap() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("bwrap"))
            .find(|p| p.is_file())
    })
}

/// FS + namespace flags. `inner_argv` is the command bwrap runs (our helper
/// re-invoked in ProxiedInner mode, then the real command).
///
/// Working directory: the outer helper is spawned with `current_dir = cmd.cwd`
/// (by `spawn_and_capture`), and bwrap inherits/preserves that cwd for the inner
/// command — so no `--chdir` is needed. If Task 9 shows the target's cwd isn't
/// `cmd.cwd`, add `--chdir <cwd>` here (the cwd is readable via `--ro-bind / /`).
pub(crate) fn build_bwrap_argv(
    writable_roots: &[PathBuf],
    read_only_subpaths: &[PathBuf],
    inner_argv: &[String],
) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    a.push("--new-session".into());
    a.push("--die-with-parent".into());
    // FS view: whole FS read-only, then re-enable writes, then re-protect subpaths.
    a.push("--ro-bind".into()); a.push("/".into()); a.push("/".into());
    a.push("--dev".into());     a.push("/dev".into());
    a.push("--proc".into());    a.push("/proc".into());
    // writable roots (shallow → deep so deeper rules layer on top)
    let mut roots = writable_roots.to_vec();
    roots.sort_by_key(|p| p.components().count());
    for r in &roots {
        let s = r.to_string_lossy().into_owned();
        a.push("--bind".into()); a.push(s.clone()); a.push(s);
    }
    // read-only carveouts inside writable roots (bwrap CAN express this)
    for ro in read_only_subpaths {
        let s = ro.to_string_lossy().into_owned();
        a.push("--ro-bind".into()); a.push(s.clone()); a.push(s);
    }
    // namespaces: user + pid (target=pid1, reaps the bridge) + net (the wall)
    a.push("--unshare-user".into());
    a.push("--unshare-pid".into());
    a.push("--unshare-net".into());
    a.push("--".into());
    a.extend(inner_argv.iter().cloned());
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn argv_has_ro_root_writable_bind_and_unshare_net() {
        let argv = build_bwrap_argv(
            &[PathBuf::from("/ws")],
            &[PathBuf::from("/ws/secret")],
            &["/inner".into(), "--mode=proxied-inner".into(), "--".into(), "/bin/true".into()],
        );
        let s = argv.join(" ");
        assert!(s.contains("--ro-bind / /"));
        assert!(s.contains("--bind /ws /ws"));
        assert!(s.contains("--ro-bind /ws/secret /ws/secret"));
        assert!(s.contains("--unshare-net"));
        assert!(s.contains("--unshare-pid"));
        // inner command after `--`
        let dd = argv.iter().position(|x| x == "--").unwrap();
        assert_eq!(argv[dd + 1], "/inner");
    }
    #[test]
    fn find_bwrap_returns_path_or_none() {
        // smoke: doesn't panic; result depends on env.
        let _ = find_bwrap();
    }
}
```

- [ ] **Step 2: wire `#[cfg(target_os="linux")] mod linux_bwrap;` in lib.rs; run tests; commit**

Run: `cargo test --features proxy --lib linux_bwrap` (on macOS the module is cfg'd out — run `cargo build` there; the pure tests run on Linux/Docker).
```bash
git add crates/motosan-sandbox/src/linux_bwrap.rs crates/motosan-sandbox/src/lib.rs
git commit -m "feat(phase3): bwrap detection + argv builder (cfg linux)"
```

---

## Task 3: `HelperPolicy` mode + `ProxyRouteSpec` IPC

**Files:** `crates/motosan-sandbox/src/reexec.rs`

- [ ] **Step 1: Extend `HelperPolicy` + add `ProxyRouteSpec`; tests**

```rust
/// Which enforcement path the re-exec'd helper takes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum HelperMode {
    /// Phase 1: Landlock + seccomp, single re-exec. (Blocked/Allowed)
    Landlock { network_blocked: bool },
    /// Phase 3 outer: build bwrap argv + execv bwrap. (Linux Proxied)
    ProxiedOuter { route_spec: ProxyRouteSpec },
    /// Phase 3 inner: fork bridge + seccomp ProxyRouted + execvp. (inside bwrap)
    ProxiedInner { route_spec: ProxyRouteSpec },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProxyRouteSpec { pub routes: Vec<ProxyRouteEntry> }
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProxyRouteEntry { pub env_key: String, pub uds_path: PathBuf }

// HelperPolicy gains `mode` + keeps `writable_roots` + `read_only_subpaths`
// (now carried for the bwrap path). `network_blocked` moves into HelperMode::Landlock.
```
`HelperPolicy::from_policy` now: `Blocked`/`Allowed` → `mode: Landlock{network_blocked}` (and still rejects `read_only_subpaths` on this path); `Proxied` → built later in `run()` (it needs the route_spec from the started proxy), so `from_policy` is only used for the Landlock path — `Proxied` construction moves to a `for_proxied(roots, ro_subpaths, route_spec)` constructor. Unit tests: Landlock mapping unchanged; `for_proxied` carries roots + ro_subpaths + route_spec; JSON round-trips for all `HelperMode` variants.

- [ ] **Step 2: run + commit** — `cargo test --features proxy --lib reexec`; commit `feat(phase3): HelperMode + ProxyRouteSpec IPC`.

---

## Task 4: Host-side bridge (parent, tokio) + lifecycle guard

**Files:** `crates/motosan-sandbox/src/proxy_bridge.rs` (new), wire in `lib.rs`

- [ ] **Step 1: `prepare_host_bridge` + RAII guard**

```rust
//! Host side of the netns proxy bridge (runs in the unsandboxed tokio parent).
use std::path::PathBuf;
use crate::reexec::{ProxyRouteSpec, ProxyRouteEntry};

/// For each proxy env var, create a UDS and a tokio task forwarding UDS↔proxy.
/// Returns the route spec (passed to the helper) + a guard that tears the
/// bridges + temp dir down on drop.
pub(crate) async fn prepare_host_bridge(
    proxy_addr: std::net::SocketAddr,
    env_keys: &[&str],
) -> std::io::Result<(ProxyRouteSpec, HostBridgeGuard)> {
    let dir = tempfile::tempdir()?;
    let mut routes = Vec::new();
    let mut tasks = Vec::new();
    for (i, key) in env_keys.iter().enumerate() {
        let uds_path = dir.path().join(format!("route-{i}.sock"));
        let listener = tokio::net::UnixListener::bind(&uds_path)?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    if let Ok(mut up) = tokio::net::TcpStream::connect(proxy_addr).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                    }
                });
            }
        });
        tasks.push(task);
        routes.push(ProxyRouteEntry { env_key: (*key).to_string(), uds_path });
    }
    Ok((ProxyRouteSpec { routes }, HostBridgeGuard { _dir: dir, tasks }))
}

pub(crate) struct HostBridgeGuard {
    _dir: tempfile::TempDir,         // removes the UDS temp dir on drop
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for HostBridgeGuard {
    fn drop(&mut self) { for t in &self.tasks { t.abort(); } }  // cleanup on every exit path
}
```

- [ ] **Step 2: test (tokio) + commit** — a test that binds a fake proxy listener, calls `prepare_host_bridge`, connects to the UDS, and asserts bytes reach the fake proxy. Commit `feat(phase3): host-side proxy bridge + RAII guard`.

---

## Task 5: seccomp `ProxyRouted` + lo-up + the in-netns bridge (sync)

**Files:** `crates/motosan-sandbox/src/linux_bridge.rs` (new, `#[cfg(target_os="linux")]`), seccomp in `linux.rs`

- [ ] **Step 1: seccomp `ProxyRouted` (add to `linux.rs`)**

```rust
/// Allow only AF_INET/AF_INET6 sockets; deny AF_UNIX + others. The empty netns
/// controls destination; this just stops the target reaching the host UDS.
#[cfg(target_os = "linux")]
fn install_proxy_routed_seccomp() -> Result<(), String> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen as Len,
        SeccompCmpOp::Ne, SeccompCondition as Cond, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;
    // deny socket(domain) when domain != AF_INET AND domain != AF_INET6
    let not_inet = || -> Result<SeccompRule, String> {
        SeccompRule::new(vec![
            Cond::new(0, Len::Dword, Ne, libc::AF_INET as u64).map_err(|e| e.to_string())?,
            Cond::new(0, Len::Dword, Ne, libc::AF_INET6 as u64).map_err(|e| e.to_string())?,
        ]).map_err(|e| e.to_string())
    };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket as i64, vec![not_inet()?]);
    rules.insert(libc::SYS_socketpair as i64, vec![not_inet()?]);
    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64, "aarch64" => TargetArch::aarch64,
        o => return Err(format!("unsupported arch: {o}")),
    };
    let f = SeccompFilter::new(rules, SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32), arch).map_err(|e| e.to_string())?;
    let p: BpfProgram = f.try_into().map_err(|e: seccompiler::BackendError| e.to_string())?;
    apply_filter(&p).map_err(|e| e.to_string())
}
```

- [ ] **Step 2: `linux_bridge.rs` — bring `lo` up + bind listeners (pre-fork) + the sync bridge child**

```rust
//! In-netns bridge: bring up loopback, bind a TCP listener per route (BEFORE
//! fork, so the parent knows the port), then fork ONE child that serves them
//! with blocking std I/O (NO tokio — we're post-fork in a sync helper).
use std::io::Result as IoResult;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use crate::reexec::ProxyRouteSpec;

/// Bind a loopback listener per route; returns (listener, uds_path, local_port).
/// A fresh `--unshare-net` netns has `lo` DOWN with no address, so we bring it
/// up UNCONDITIONALLY first (not as a fallback) — otherwise the bind always fails.
pub(crate) fn bind_route_listeners(spec: &ProxyRouteSpec)
    -> IoResult<Vec<(TcpListener, PathBuf, u16)>> {
    ensure_loopback_up()?;   // REQUIRED up front: lo is always down in a new netns
    let mut out = Vec::new();
    for r in &spec.routes {
        let l = TcpListener::bind(("127.0.0.1", 0))?;
        let port = l.local_addr()?.port();
        out.push((l, r.uds_path.clone(), port));
    }
    Ok(out)
}

/// Run the bridge forwarding loops FOREVER (called in the forked child). Each
/// listener gets a thread; each accepted conn gets two copy threads (cli↔uds).
pub(crate) fn serve_bridges_forever(listeners: Vec<(TcpListener, PathBuf, u16)>) -> ! {
    let mut handles = Vec::new();
    for (listener, uds_path, _) in listeners {
        handles.push(std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let uds_path = uds_path.clone();
                std::thread::spawn(move || {
                    if let Ok(uds) = UnixStream::connect(&uds_path) {
                        pump_bidirectional(client, uds);
                    }
                });
            }
        }));
    }
    for h in handles { let _ = h.join(); }
    std::process::exit(0); // unreachable in practice (pidns kill), but total
}

fn pump_bidirectional(a: std::net::TcpStream, b: UnixStream) {
    use std::io::{Read, Write};
    let (mut a_r, mut a_w) = (a.try_clone().unwrap(), a);
    let (mut b_r, mut b_w) = (b.try_clone().unwrap(), b);
    let t = std::thread::spawn(move || { let _ = std::io::copy(&mut a_r, &mut b_w); });
    let _ = std::io::copy(&mut b_r, &mut a_w);
    let _ = t.join();
}

/// Assign 127.0.0.1 to `lo` + bring it UP via raw ioctls (no netlink, no `ip`).
/// A fresh `--unshare-net` netns has `lo` down with no address — BOTH ops are
/// needed before `127.0.0.1` is bindable.
fn ensure_loopback_up() -> IoResult<()> {
    // SAFETY: SIOCSIFADDR + SIOCGIFFLAGS/SIOCSIFFLAGS on "lo" via an AF_INET DGRAM
    // socket. ifreq is zeroed; name is NUL-padded "lo".
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 { return Err(std::io::Error::last_os_error()); }
        let fail = |fd: i32| { let e = std::io::Error::last_os_error(); libc::close(fd); e };

        let set_name = |ifr: &mut libc::ifreq| {
            for (i, b) in b"lo".iter().enumerate() { ifr.ifr_name[i] = *b as libc::c_char; }
        };

        // 1) assign 127.0.0.1 (SIOCSIFADDR)
        let mut ifr: libc::ifreq = std::mem::zeroed();
        set_name(&mut ifr);
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
            sin_zero: [0; 8],
        };
        std::ptr::copy_nonoverlapping(
            &sin as *const _ as *const u8,
            &mut ifr.ifr_ifru as *mut _ as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
        if libc::ioctl(fd, libc::SIOCSIFADDR, &ifr) < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) { libc::close(fd); return Err(e); } // tolerate already-set
        }

        // 2) bring lo UP (read flags → OR IFF_UP → write back)
        let mut ifr2: libc::ifreq = std::mem::zeroed();
        set_name(&mut ifr2);
        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr2) < 0 { return Err(fail(fd)); }
        ifr2.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr2) < 0 { return Err(fail(fd)); }
        libc::close(fd);
    }
    Ok(())
}
```

> `libc::ifreq`'s union field names (`ifr_name`, `ifr_ifru.ifru_flags`) and the
> `sin_addr` byte order are version-sensitive — reconcile against the pinned
> `libc` and **validate in Task 9's `proxied_allowed_host_reachable` test** (which
> exercises the live lo-up + bridge). `s_addr` uses `from_ne_bytes` because
> `in_addr` is already network-order on Linux; if the bind rejects it, switch to
> `to_be()`. This is load-bearing — do NOT leave it stubbed.

- [ ] **Step 3: unit-test the seccomp builder compiles + a sync `pump_bidirectional` byte test; commit** `feat(phase3): ProxyRouted seccomp + sync in-netns bridge`.

---

## Task 6: The two-stage helper dispatch (`linux.rs` / `run_if_invoked`)

**Files:** `crates/motosan-sandbox/src/linux.rs`

**CRITICAL — detection must survive bwrap.** Phase 1 detects "I'm the helper" via `arg0 == HELPER_ARG0` (set by `Command::arg0` in spawn). **That does NOT survive bwrap**: bwrap sets the inner command's `argv[0]` to the program path, not our sentinel — so the inner stage would never engage on arg0 alone. Fix: add an **env stage-marker** `MOTOSAN_SANDBOX_STAGE` (bwrap inherits env reliably). `run_if_invoked` engages if **`arg0 == HELPER_ARG0` (Phase 1 / outer, direct parent→helper) OR `MOTOSAN_SANDBOX_STAGE == "inner"` (bwrap→inner)**. Do NOT rely on bwrap `--argv0` (version-dependent).

- [ ] **Step 1: dispatch on `HelperMode`**

`run_if_invoked` engages on the arg0 sentinel OR `MOTOSAN_SANDBOX_STAGE=inner`, then parses `HelperPolicy` (from `MOTOSAN_SANDBOX_POLICY` env) and matches `mode`:
- `Landlock{..}` → existing Phase-1 path (unchanged).
- `ProxiedOuter{route_spec}` → set up the inner invocation, all IPC via **env** (bwrap inherits it):
  1. `find_bwrap()` (absent → `die(HELPER_EXIT_NOT_ENFORCED, "bwrap not found")`).
  2. Reserialize the policy with `mode: ProxiedInner{route_spec}` → `set_var("MOTOSAN_SANDBOX_POLICY", json)`; `set_var("MOTOSAN_SANDBOX_STAGE", "inner")`.
  3. `inner_argv = [current_exe_path, real_program, real_args...]` (the inner helper reads its real command from `argv[1..]`, same convention as Phase 1; no `--stage` flag — the stage is the env marker).
  4. `argv = build_bwrap_argv(roots, ro_subpaths, inner_argv)`; `libc::execv(bwrap_path, argv)` — never returns; on failure `die(HELPER_EXIT_EXEC_FAILED, ...)`.
- `ProxiedInner{route_spec}` → the inner sequence:
  ```rust
  // 1. bind loopback listeners (knows ports) — BEFORE fork
  let listeners = linux_bridge::bind_route_listeners(&route_spec).unwrap_or_else(|e| die(...));
  let ports: Vec<(String,u16)> = route_spec.routes.iter().zip(&listeners)
      .map(|(r,(_,_,port))| (r.env_key.clone(), *port)).collect();
  // 2. fork the bridge child (sync std); child serves forever, parent continues
  match unsafe { libc::fork() } {
      -1 => die(HELPER_EXIT_NOT_ENFORCED, "fork bridge failed"),
      0  => linux_bridge::serve_bridges_forever(listeners),   // child: never returns
      _  => { /* parent (the target) continues below */ }
  }
  // `real` = the target command = inner argv[1..] (same convention as Phase 1).
  let real: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
  if real.is_empty() { die(HELPER_EXIT_BAD_POLICY, "no command"); }
  // 3. parent: rewrite proxy env to 127.0.0.1:<port>; scrub IPC env so the target
  //    inherits a clean environment (no MOTOSAN_SANDBOX_* leakage); then lock down.
  for (key, port) in ports { std::env::set_var(&key, format!("http://127.0.0.1:{port}")); }
  std::env::remove_var("MOTOSAN_SANDBOX_POLICY");
  std::env::remove_var("MOTOSAN_SANDBOX_STAGE");
  if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0) } != 0 { die(...); }
  install_proxy_routed_seccomp().unwrap_or_else(|e| die(HELPER_EXIT_NOT_ENFORCED, &e));
  // 4. execvp the real command (FS already isolated by bwrap's mount ns)
  let err = Command::new(&real[0]).args(&real[1..]).exec();
  die(HELPER_EXIT_EXEC_FAILED, &format!("exec failed: {err}"));
  ```
  > NOTES: `--unshare-pid` makes the target pid 1, so its exit kernel-kills the forked bridge — no reaping needed. The bridge child inherits the listener fds across fork; the parent should close its copies before exec so the target doesn't inherit listeners. Scrub `MOTOSAN_SANDBOX_POLICY`/`STAGE` before exec (done above) so the target sees a clean env. Keep this path **synchronous** — no tokio.

- [ ] **Step 2: build both platforms** (`cargo build` macOS = cfg'd out; Docker = compiles). Commit `feat(phase3): two-stage helper dispatch (ProxiedOuter/Inner)`.

---

## Task 7: `run()` / `transform()` integration

**Files:** `crates/motosan-sandbox/src/lib.rs`, `transform.rs`

- [ ] **Step 1: `maybe_start_proxy` — Linux Proxied now starts proxy + host bridge (if bwrap)**

In `maybe_start_proxy`, replace the Linux `Proxied → Err(Unsupported)` short-circuit:
```rust
if kind == SandboxKind::LinuxSeccomp {
    #[cfg(feature = "proxy")]
    {
        if crate::linux_bwrap::find_bwrap().is_none() {
            return Err(Error::Unsupported(SandboxKind::LinuxSeccomp)); // documented: needs bwrap
        }
        // start the Phase-2 proxy (same as macOS) ...
        let server = ProxyServer::start(...).await.map_err(Error::Spawn)?;
        // build the host bridge (UDS per env key) + route spec
        let (route_spec, bridge_guard) =
            crate::proxy_bridge::prepare_host_bridge(server.addr, &["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]).await.map_err(Error::Spawn)?;
        // thread route_spec into the helper policy (via TransformCtx or a field run() passes to transform)
        // hold (server, bridge_guard) in the run()-lifetime guard for RAII cleanup.
        ...
    }
    #[cfg(not(feature = "proxy"))]
    return Err(Error::Unsupported(SandboxKind::LinuxSeccomp));
}
```
`run()` keeps the proxy server + `HostBridgeGuard` alive for the whole run (extend `ProxyGuard` to also hold the bridge guard + route spec). The route spec must reach `transform()` — extend `TransformCtx` with `route_spec: Option<&ProxyRouteSpec>` (additive, like `proxy`).

- [ ] **Step 2: `transform()` Linux Proxied arm**

Replace the Linux `Proxied → Err(Unsupported)`: build the `ProxiedOuter` re-exec `SpawnRequest` via `HelperPolicy::for_proxied(writable_roots, read_only_subpaths, ctx.route_spec.cloned())` + arg0 sentinel + helper-exe. (`read_only_subpaths` is now allowed here — bwrap expresses it.) macOS Proxied unchanged (Seatbelt). Blocked/Allowed unchanged (Landlock).

- [ ] **Step 3: build both feature configs + platforms; commit** `feat(phase3): run()/transform Linux Proxied → bwrap netns (was Unsupported)`.

---

## Task 8: denial heuristic for netns-blocked egress

**Files:** `crates/motosan-sandbox/src/denial.rs`

- [ ] **Step 1: add network-unreachable markers + test**

A non-cooperative dial in the empty netns fails with "Network is unreachable" / "No route to host" — not in the Phase-0 marker set. Add them so `is_likely_sandbox_denied` flags netns-blocked egress on `LinuxSeccomp`:
```rust
const DENIAL_MARKERS: &[&str] = &[
    // ... existing ...
    "network is unreachable", "no route to host",
];
```
Test: `is_likely_sandbox_denied(exit≠0, stderr="connect: Network is unreachable", LinuxSeccomp)` → true. (Keep it scoped so a normal "connection refused" to an allowed-but-down host isn't over-claimed — document the tradeoff.)

- [ ] **Step 2: run + commit** `feat(phase3): treat netns network-unreachable as sandbox denial`.

---

## Task 9: Docker behavioral enforcement tests

**Files:** `crates/motosan-sandbox/tests/linux_enforcement.rs` (extend)

- [ ] **Step 1: add Phase-3 tests (cfg linux, run in Docker with the flags Task 1 found)**

A `proxied_*` group, each `if bwrap_unavailable() { skip }` EXCEPT the must-enforce one:
- `proxied_non_cooperative_egress_is_blocked` (**must-enforce, no skip**): a command that ignores `HTTP_PROXY` and dials a raw public IP (python3 socket to `203.0.113.1:80`) under a `Proxied` policy → exit≠0 (ENETUNREACH). Proves the netns wall. FAIL (not skip) if it connects.
- `proxied_allowed_host_reachable`: with the proxy + an allowed local upstream, a `curl`/python honoring `HTTP_PROXY` reaches it.
- `proxied_denied_host_refused`: the proxy 403s a non-allowlisted CONNECT (covered at the proxy-crate level too).
- `proxied_fs_write_outside_root_denied`: bwrap mounts block a write outside the writable root.
- `proxied_read_only_subpath_denied`: write to a `--ro-bind` carveout fails (the bwrap-path feature).
- `proxied_unsupported_without_bwrap`: PATH without bwrap → `Error::Unsupported`.

- [ ] **Step 2: run in Docker (flags from Task 1) + commit**

```bash
docker run --rm <FLAGS-FROM-TASK-1> -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/tmp/ct -e CARGO_HOME=/tmp/ch \
  rust:1.95-bookworm bash -c "apt-get update -qq && apt-get install -y -qq bubblewrap python3 curl >/dev/null && \
    sysctl -w kernel.unprivileged_userns_clone=1 2>/dev/null; \
    cargo test --features proxy --test linux_enforcement -- --test-threads=1"
```
Expected: `proxied_non_cooperative_egress_is_blocked` PASSES (not skipped). Commit `test(phase3): behavioral netns egress enforcement`.

---

## Task 10: CI + README + final gates

**Files:** `.github/workflows/ci.yml`, `.devcontainer/Dockerfile.linux-dev`, `crates/motosan-sandbox/README.md`

- [ ] **Step 1: CI Linux job provisions bwrap + userns**

Add to the Linux job (using the flags/sysctls Task 1 found needed):
```yaml
- run: sudo apt-get update -y && sudo apt-get install -y --no-install-recommends bubblewrap libcap-dev python3
- run: |
    sudo sysctl -w kernel.unprivileged_userns_clone=1 || true
    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
- run: cargo test --features proxy
```
Note in the workflow: Phase 3 (bwrap netns) needs this; Phase 0/1/2 don't.

- [ ] **Step 2: README — `## Linux egress allowlist (Phase 3)`**

`NetworkPolicy::Proxied` is now **hard on Linux** when `bwrap` is installed (bwrap netns + transparent loopback bridge to the allowlist proxy; even non-cooperative tools get `ENETUNREACH`). Requires system `bwrap`; absent → `Error::Unsupported`. Note: on the Proxied/bwrap path, `read_only_subpaths` IS enforced (unlike the Landlock path). Reword the Phase-2 "Linux Unsupported" note accordingly.

- [ ] **Step 3: full gates**

macOS: `cargo test`, `cargo test --features proxy`, `cargo clippy --all-features --all-targets -- -D warnings`, `cargo fmt --all -- --check` (Phase 0/1/2 + spike non-regression; Phase 3 code cfg'd out).
Docker (flags from Task 1): `cargo test --features proxy && cargo clippy --all-features --all-targets -- -D warnings`.
Commit `docs(phase3): README + CI bwrap provisioning`.

---

## Done criteria

- **Task 1 passed** (bwrap netns usable in the chosen env; the hard-wall probe green) — or the team explicitly moved to a bare-Linux/CI-only loop.
- Linux `Proxied` is **hard**: `proxied_non_cooperative_egress_is_blocked` passes (raw-IP dial → ENETUNREACH), allowed host reachable through the proxy, denied refused, FS write-outside-root denied, `read_only_subpath` denied.
- `bwrap` absent → `Proxied` returns `Error::Unsupported` (no silent weakening).
- Phase 0/1/2 + spike unregressed on macOS + Linux; clippy `-D warnings` + fmt clean (incl. `--features proxy`).
- The re-exec'd helper remains **synchronous (no tokio)**; the in-netns bridge is a `fork()`ed sync child reaped by `--unshare-pid`.

## Notes for the executor

- **Task 1 is a gate — do not build Tasks 2+ until it passes.** If Docker-on-Mac can't run bwrap netns under any flag set, STOP and report; switch to a bare Linux host or CI-only loop.
- Keep tokio OUT of the re-exec'd helper (`linux.rs`/`linux_bridge.rs`): fork+tokio is unsafe. Host bridge (parent) is tokio; in-netns bridge (forked child) is blocking `std`.
- Pin `bwrap` behavior to what Task 1 observed (flags, whether `--unshare-net` needs anything else in your env).
- `ensure_loopback_up` (Task 5) is **fully provided** but uses version-sensitive `libc::ifreq` union fields + `in_addr` byte order — reconcile against the pinned `libc` and **validate via Task 9's `proxied_allowed_host_reachable`** (the live lo-up + bind). No `unimplemented!` remains in the plan.
- **SAFETY docs:** the new `unsafe` blocks (`fork`, `ioctl`/`ifreq`, `prctl`) each need a `// SAFETY:` comment — if `clippy::undocumented_unsafe_blocks` is on, `-D warnings` will trip without them.
- Don't touch `motosan-agent-loop`; don't regress Phase 0/1/2; don't ship a cooperative Linux fallback (bwrap-or-Unsupported only).
