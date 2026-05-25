# motosan-sandbox

Run a command under a filesystem/network policy. Decoupled from any agent/LLM —
it only knows "run this command under this policy."

**Status:** Phase 1 — core API + macOS Seatbelt + Linux Landlock/seccomp.
Network is on/off; the allowlist proxy is Phase 2.

## Platform selection

Platform is chosen by the compile target (`cfg(target_os)`), **not** by Cargo
features. There is no `macos`/`linux` feature. Features are reserved for optional
*capabilities* (`cancellation`; `proxy` lands in Phase 2).

## Quick start

```rust
use motosan_sandbox::{Sandbox, SandboxCommand, SandboxPolicy, NetworkPolicy, WorkspaceWrite, RunOpts};
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<(), motosan_sandbox::Error> {
    // Call this at the very top of main() so the self-reexec hook is stable
    // across phases. No-op in Phase 0.
    motosan_sandbox::helper::run_if_invoked();

    let sb = Sandbox::new();
    // macOS resolves /var → /private/var; canonicalize roots before policy use.
    let workspace = std::path::PathBuf::from("/path/to/workspace")
        .canonicalize()
        .unwrap();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![workspace.clone()])
            .network(NetworkPolicy::Blocked),
    );

    // SECURITY: pass a curated env — never forward the whole parent environment.
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") { env.insert("PATH".into(), p); }

    let out = sb.run(
        SandboxCommand { program: "ls".into(), args: vec!["-la".into()],
                         cwd: workspace, env },
        &policy,
        RunOpts::default(),
    ).await?;

    println!("exit={:?}\n{}", out.exit_code, String::from_utf8_lossy(&out.stdout));
    Ok(())
}
```

## Security notes

- **Curate the environment.** `SandboxCommand::env` is passed verbatim; never set
  it to `std::env::vars_os()` — that leaks secrets into the command.
- **Don't mark `.git` read-only.** It breaks `git commit` inside the sandbox.
  `read_only_subpaths` denies *writes* to a subpath; it does **not** hide it
  from reads (Phase 0 grants whole-filesystem read). Use it to protect mutable
  state from being overwritten, not to gate access to secrets.
- **macOS paths are resolved.** Canonicalize writable roots (`/var` →
  `/private/var`) before building a policy.
- macOS `sandbox-exec` is deprecated by Apple but still functional; tracked risk.

## Linux (Phase 1)

`run()` enforces on Linux via **Landlock** (filesystem: read-everywhere, write
confined to `writable_roots`) + **seccomp** (network: denies `AF_INET`/`AF_INET6`
socket creation when blocked). No bubblewrap. Requires kernel ≥ 5.13; if Landlock
can't be enforced, `run()` returns `Error::NotEnforced` (never runs unsandboxed).

Consumers MUST call `motosan_sandbox::helper::run_if_invoked()` as the first line
of `main()` (self-reexec); otherwise Linux sandboxing silently won't engage.

Pass **canonical** `writable_roots` — Landlock matches the *resolved* path (e.g.
`/var` → `/private/var` on macOS; symlinked roots on Linux), so canonicalize
roots before building the policy or writes inside them may be denied. (Same
requirement as macOS.)

Limitations vs macOS: `read_only_subpaths` is **not supported** on the Linux
Landlock path (`NetworkPolicy::Blocked` / `Allowed`) — Landlock is allow-only,
so a Blocked/Allowed policy that sets it returns `Error::Unsupported`. The
Linux **Proxied** path (Phase 3 / `proxy` feature) uses bwrap mounts and
*does* enforce `read_only_subpaths` (see "Linux egress allowlist (Phase 3)"
below). Files remain readable on both paths (only writes are confined).

## Network allowlist (Phase 2 — `proxy` feature)

`NetworkPolicy::Proxied { allowlist }` routes egress through a local HTTP
`CONNECT`-only proxy and gates each connection by host against the allowlist.
Available behind the `proxy` Cargo feature:

```bash
cargo test --features proxy
```

```rust
use motosan_sandbox::{HostPattern, NetworkPolicy, SandboxPolicy, WorkspaceWrite};

let policy = SandboxPolicy::WorkspaceWrite(
    WorkspaceWrite::new(vec![workspace.clone()]).network(NetworkPolicy::Proxied {
        allowlist: vec![
            HostPattern::parse("crates.io"),       // exact host
            HostPattern::parse("*.rust-lang.org"), // subdomains only (excludes apex)
            HostPattern::parse("**.example.com"),  // apex + subdomains
            // HostPattern::parse("*"),            // any host
        ],
    }),
);
```

Allowlist syntax (block-by-default — empty list denies everything):

| Pattern | Matches | Excludes |
|---|---|---|
| `example.com` | exactly `example.com` | subdomains |
| `*.example.com` | `a.example.com`, `b.a.example.com` | the apex `example.com` |
| `**.example.com` | `example.com` + any subdomain | unrelated hosts |
| `*` | any host | — |

### Enforcement

- **macOS — hard.** Seatbelt restricts the child's egress to the local proxy
  port only. A tool that ignores `HTTP_PROXY` and opens a raw socket is blocked
  by the kernel (load-bearing test: `direct_connection_blocked_by_seatbelt`).
- **Linux — hard via Phase 3.** See "Linux egress allowlist (Phase 3)" below.
  Requires system `bwrap`; absent → `Error::Unsupported` (no cooperative
  bypassable fallback is shipped).

### Scope (Phase 2)

- `CONNECT` only — HTTPS works; plain-HTTP forward returns `405 Method Not
  Allowed`.
- No MITM, no SOCKS. The proxy decides allow/deny from the `CONNECT host:port`
  line; TLS bytes flow opaquely.
- The proxy starts per `run()` (loopback, ephemeral port). Reuse across runs is
  a future optimization.
- `Proxied` without the `proxy` feature → clear `Error` at `run()`.

## Linux egress allowlist (Phase 3 — `proxy` feature + `bwrap`)

On Linux, `NetworkPolicy::Proxied { allowlist }` is **hard** when system
`bwrap` is installed: the command runs in a bubblewrap network namespace
whose only route is a loopback bridge to the same allowlist proxy used on
macOS. A tool that ignores `HTTP_PROXY` and dials a raw IP gets
`ENETUNREACH` from the kernel — the netns has no other route.

```
target (in netns) → 127.0.0.1:<local_port> (lo)
                  → UnixStream (forked sync bridge)
                  → host UDS
                  → tokio host bridge (parent)
                  → 127.0.0.1:<proxy_port>
                  → allowlist proxy → upstream
```

Provisioning the runtime env (CI / Docker):

- `bwrap` on `PATH` (Debian/Ubuntu: `apt install bubblewrap`). Absent →
  `Sandbox::run` returns `Error::Unsupported(LinuxSeccomp)`.
- Unprivileged user namespaces enabled
  (`sysctl kernel.unprivileged_userns_clone=1`).
- On Ubuntu 24.04, the AppArmor userns restriction relaxed
  (`sysctl kernel.apparmor_restrict_unprivileged_userns=0`).
- On Docker-on-Mac (OrbStack/Docker Desktop), nested unprivileged userns
  often needs `--privileged` (verified by Task 1's
  `bwrap_viability_probe.rs`). Bare Linux CI runners (e.g. ubuntu-latest)
  do NOT need `--privileged`.

Filesystem semantics on the Phase 3 (`Proxied` / bwrap) path: whole FS
read-only via `--ro-bind / /`; `writable_roots` re-enable writes via
`--bind`; `read_only_subpaths` re-protect a path inside a writable root via
`--ro-bind <p> <p>`. Unlike the Landlock path, `read_only_subpaths` **is
enforced** here — bwrap can express it.

Helper internals (load-bearing for security):

- The re-exec'd helper is **synchronous** (no tokio) — the in-netns bridge
  is a `fork()`ed child using blocking `std::net`. Fork + tokio is unsafe;
  the host bridge (parent) is tokio.
- `--unshare-pid` makes the target pid 1 in the new pidns. When it exits,
  the kernel SIGKILLs the entire pidns — including the bridge child — so
  there is no reaping race.
- The inner-stage seccomp filter (`ProxyRouted`) allows `AF_INET`/`AF_INET6`
  only; `AF_UNIX` is denied for the target so it can't bypass the bridge by
  talking to the host UDS directly. The bridge child is forked **before**
  seccomp is installed, so it keeps `AF_UNIX` access.
- Inner-stage detection is via env (`MOTOSAN_SANDBOX_STAGE=inner`) because
  bwrap rewrites the inner program's `argv[0]` — our Phase-1 arg0 sentinel
  does not survive bwrap.

## Using with motosan-agent-loop (validated by the integration spike)

`motosan-sandbox` plugs into `motosan-agent-loop` with no loop-core changes:
expose execution as a `Tool` (`call()` → `Sandbox::run()`) and put approval in a
consumer `Extension`. See `tests/loop_integration.rs` for the proven pattern.

Three contract notes the spike surfaced:
- **Escalation is reissue, not Defer.** A denied command → inject a hint → the
  model re-calls with `escalated:true` → the same Tool runs `DangerFullAccess`.
  `ToolDecision::Defer` *skips* the tool, so reserve it for human-gating.
- **Encode the denial in the `ToolResult`.** An `Extension` only sees a
  `ToolResult`, not the `ExecOutput`, so the Tool must compute
  `is_likely_sandbox_denied` and stamp the verdict (the spike uses a sentinel).
- **`Defer` + background `ExtensionResume` needs `.ops(rx)` — and it's
  version-sensitive.** On published `motosan-agent-loop` 0.22.1 (what the spike
  built against), resolving a `Defer` via a background-task
  `AgentOp::ExtensionResume` without an external ops channel aborts with
  `Defer call '<id>' aborted: no ops channel`; pass
  `agent.run(...).ops(rx).result().await`. On 0.22.2+ this requirement may not
  apply (the loop's own resume test passes without `.ops()` there). **Pin to the
  loop version you ship against and re-verify.** Escalation via *reissue* (note 1)
  has no such version dependency — prefer it.
