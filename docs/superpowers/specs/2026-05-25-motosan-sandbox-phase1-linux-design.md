# motosan-sandbox Phase 1 — Linux backend (Landlock + seccomp) — Design

**Date:** 2026-05-25
**Status:** Draft for review
**Decision:** Linux enforcement = **Landlock (filesystem) + seccomp (network/syscalls), NO bubblewrap.** This **revises design §6.2** (which listed bwrap + seccomp + Landlock).

## 1. Decision & rationale

Phase 1 makes `run()` actually enforce on Linux (today it returns
`Error::Unsupported`). Mechanism: **Landlock for the filesystem, seccomp for the
network**, with the re-exec helper machinery whose no-op stub shipped in Phase 0
(`helper::run_if_invoked`). **No bubblewrap.**

Why (settled after brainstorming + studying how Codex tests its sandbox):

1. **Semantic parity with Phase 0 macOS.** Phase 0 is read-everywhere /
   write-scoped / network-on-off. Landlock (read `/`, write the roots) + seccomp
   (deny egress syscalls) expresses exactly that. bwrap would make Linux
   *stronger* than macOS (path hiding, network namespace) — a cross-platform
   asymmetry for the same `SandboxPolicy`.
2. **No external runtime dependency.** Landlock + seccomp are pure-Rust crates
   (`landlock`, `seccompiler`, `libc`). bwrap is a binary that must exist at
   runtime (or be vendored/built — Codex compiles bubblewrap via `build.rs`).
3. **CI/deployment portability.** Codex's bwrap tests require `apt install
   bubblewrap`, `sysctl kernel.unprivileged_userns_clone=1`, relaxing the
   AppArmor userns restriction, and a runtime skip-probe. Landlock + seccomp
   needs none of that — only a recent-kernel runner (GitHub `ubuntu-latest` =
   kernel 6.x).
4. **bwrap's unique value (network namespace) isn't needed until Phase 3.**
   Phase 2's proxy is cooperative (env-var); the transparent proxy (Phase 3)
   needs netns. So bwrap arrives *with* Phase 3 as an additive layer.

**Accepted cost (consistent with Phase 0, not a new gap):** a sandboxed command
can **read** any file (Landlock grants read on `/`); only *writes* are confined.
macOS Phase 0 already behaves this way.

**Honest caveat:** the Landlock-only path is the one Codex deprioritized (its
legacy mode, untested upstream). So *we* own the "is Landlock actually enforced?"
guard and our own behavioral tests — both cheap and specified below.

## 2. What changes from Phase 0

- `motosan-sandbox` gains Linux-only deps: `landlock`, `seccompiler`, `libc`
  (+ `serde`/`serde_json` for helper IPC), all under
  `[target.'cfg(target_os = "linux")'.dependencies]`. macOS/other builds are
  unaffected (the design's no-`macos`/`linux`-feature rule still holds).
- **No separate helper *crate* for Phase 1.** Without bwrap there is no heavy C
  build, so the enforcement lives in a `#[cfg(target_os = "linux")]` module
  inside `motosan-sandbox`, linked into the consumer's binary and reached via
  self-reexec. (This simplifies design §3.1's 3-crate plan.) **One tiny `[[bin]]`
  target IS added** — a few-line program whose `main` is just
  `run_if_invoked()` — because integration tests need a spawnable re-exec target
  (they can't control the test harness's `main`). The same bin doubles as the
  "external-helper mode" entry. See §7.
- `transform()`'s `LinuxSeccomp` arm stops returning `Unsupported` and builds the
  re-exec argv.
- `helper::run_if_invoked()` gets its real Linux implementation.
- New `Error` variants: `NotEnforced` (Landlock didn't take) and
  `Unsupported`-for-`read_only_subpaths` (see §4).

## 3. Execution flow (single re-exec — simpler than Codex's two-stage)

Because there is no bwrap, there is **one** re-exec, not two:

**Helper-exe resolution.** `transform()` needs the path to the binary that hosts
`run_if_invoked()`. `Sandbox` carries it: `Sandbox::new()` defaults to
`std::env::current_exe()` (self-reexec — the consumer's own binary), and
`Sandbox::with_helper_exe(path)` overrides it ("external-helper mode" — what the
§7 tests use, pointing at the tiny test `[[bin]]`). This mirrors Codex's
`codex_linux_sandbox_exe`. Resolving `current_exe()` is the one impurity the
Linux arm introduces; the macOS arm and passthrough stay pure.

```
run(cmd, WorkspaceWrite{roots, network}, opts)         [consumer process]
  └─ transform() (Linux arm) builds a SpawnRequest:
       program = <helper-exe>            (current_exe() by default; override for tests)
       arg0    = "__motosan_sandbox_helper"            (sentinel)
       args    = [<real program>, <real args>...]
       env     = curated env + MOTOSAN_SANDBOX_POLICY=<json> + network marker
  └─ spawn (tokio): Command::new(current_exe).arg0(sentinel).current_dir(cwd)
                    .env_clear().envs(env) ...
       │
       ▼  re-exec'd process starts main() → helper::run_if_invoked()
          sees arg0 == sentinel → enters helper, NEVER returns:
            1. prctl(PR_SET_NO_NEW_PRIVS, 1)
            2. install seccomp filter (deny AF_INET/AF_INET6 socket creation
               if network Blocked — see §5)
            3. install Landlock ruleset (read "/", write roots + /dev/null);
               if RulesetStatus::NotEnforced → exit HELPER_EXIT_NOT_ENFORCED
            4. execvp(<real program>, <real args>)     [enforced from here on]
               if execvp fails → exit HELPER_EXIT_EXEC_FAILED
```

`SpawnRequest` gains an `arg0: Option<OsString>` field (additive). `spawn.rs`
applies it via `Command::arg0` on unix. Exit-status fidelity unchanged (Phase 0
already decodes `code`/`signal`); a seccomp denial surfaces as `SIGSYS`
(signal 31), which `is_likely_sandbox_denied` already treats as a denial on
`LinuxSeccomp`.

**Helper → parent error channel.** The helper signals setup failures (before the
target ever runs) via **reserved exit codes** chosen to avoid colliding with
common command codes (`0`/`1`/`2`/`126`/`127`) and shell signal codes
(`128+n`): `HELPER_EXIT_NOT_ENFORCED = 121`, `HELPER_EXIT_BAD_POLICY = 122`,
`HELPER_EXIT_EXEC_FAILED = 123`. The helper also writes a one-line sentinel to
stderr (e.g. `motosan-sandbox: landlock not enforced`) so the cause is visible.
`run()` inspects the child's exit code **after** spawn: a reserved code maps to
the matching `Error` (`NotEnforced` / `Transform` / `Spawn`); any other code is
a genuine command result and flows through as a normal `ExecOutput`. The
residual collision risk (a target legitimately exiting 121–123) is accepted and
noted; the stderr sentinel disambiguates in practice.

## 4. Filesystem (Landlock) — and the allow-only limitation

Landlock is **allow-only**: you grant access to path hierarchies; there is no
"deny" within a granted hierarchy. Consequences:

- **ReadOnly:** grant `AccessFs::from_read` on `/`. No write grants (so all
  writes fail) — `/dev/null` write granted for ergonomics.
- **WorkspaceWrite:** grant read on `/`, grant read+write on each `writable_root`
  and `/dev/null`.
- **`read_only_subpaths` is NOT expressible** (you cannot carve a read-only hole
  inside a writable root with an allow-only model). Phase 1 therefore **rejects**
  a policy with non-empty `read_only_subpaths` on Linux:
  `Err(Error::Unsupported(..))` with a clear message. (macOS supports it via
  Seatbelt `deny` rules; this is a documented cross-platform asymmetry. Phase 0's
  own README already steers users away from the feature.)

`ABI::V5`, `CompatLevel::BestEffort` (degrade gracefully on older-but-≥5.13
kernels), `set_no_new_privs(true)`, `restrict_self()`. If
`status.ruleset == RulesetStatus::NotEnforced` → fail loud (`Error::NotEnforced`),
never run unsandboxed.

## 5. Network (seccomp) — filter `socket` by domain, not `connect`

**Block at socket *creation*, keyed on the address family.** `connect`/`bind`
take a `sockaddr` *pointer* (arg1) and **seccomp cannot dereference pointers**, so
a `connect`-blocklist is forced to deny *all* connects — including `AF_UNIX`,
which silently breaks legitimate local IPC (nscd name resolution, journald
logging, dbus). The correct lever (also Codex's) is `socket`/`socketpair`, whose
**`domain` is arg0 — a scalar seccomp *can* inspect.**

- **Blocked:** install a `seccompiler` filter (default `Allow`, match
  `Errno(EPERM)`) that denies `socket` and `socketpair` when **arg0 (domain) is
  `AF_INET` (2) or `AF_INET6` (10)**. A process that cannot create an internet
  socket cannot do any TCP/UDP egress or inbound, while `AF_UNIX` (1) sockets
  (local IPC) and all file I/O keep working. Set
  `MOTOSAN_SANDBOX_NETWORK_DISABLED=1` in the child env (cooperative signal from
  Phase 0). Target arch from `std::env::consts::ARCH` (x86_64, aarch64). A
  `connect`/`sendto` blocklist is **not** used (wrong lever, breaks `AF_UNIX`);
  it may be added later only as redundant defense, never as the primary control.
- **Allowed:** install no network filter.
- (Always, cheap defense — optional for MVP, include if trivial: deny `ptrace`,
  `process_vm_readv`/`writev`.)

No `--unshare-net` (that's bwrap); seccomp egress-deny is the whole network
mechanism in Phase 1. Phase 3 adds netns when the transparent proxy needs it.

## 6. Helper IPC (parent → re-exec'd self)

Policy crosses the re-exec boundary as JSON in `MOTOSAN_SANDBOX_POLICY`. To keep
the public policy types serde-free, an internal `#[derive(Serialize,
Deserialize)] struct HelperPolicy { writable_roots, network_blocked }` is mapped
from `SandboxPolicy` on the way out and parsed in `run_if_invoked`. Detection of
re-exec is the sentinel `arg0`; the real command is `argv[1..]`.

## 7. Testing (mirrors Codex's proven behavioral approach)

Behavioral, through the real re-exec path — exactly how Phase 0 macOS, the spike,
and Codex itself test (Codex asserts on exit codes; "exit 0 == breach"):

- **Re-exec target for tests:** integration tests don't control a `main()`, so
  they can't host `run_if_invoked()` themselves. Phase 1 adds a tiny `[[bin]]`
  (its `main` is just `run_if_invoked()`); tests locate it via
  `CARGO_BIN_EXE_<name>` (the exact mechanism Codex uses) and spawn *it* as the
  re-exec target. So the test drives `transform()` to produce a `SpawnRequest`
  whose `program` is that bin, then spawns and asserts on the child's behavior.
- `#![cfg(target_os = "linux")]` on the suite. Assert: write inside root
  succeeds; write outside root fails (nonzero exit); read outside root succeeds;
  network blocked (`curl`/`nc`/`/dev/tcp` exits nonzero — mechanism-agnostic, safe
  even if the binary is absent); `read_only_subpaths` policy → `Error::Unsupported`.
- **Availability guard:** if Landlock reports `NotEnforced` at runtime (kernel
  too old / disabled), tests that require enforcement `eprintln!` a skip and
  return, rather than failing — same spirit as Codex's bwrap skip-probe. CI uses
  `ubuntu-latest` (Landlock-capable), so they actually run there.
- Pure unit tests for the policy→`HelperPolicy` mapping and the seccomp syscall
  set (no BPF execution needed — Codex doesn't either).

## 8. Out of scope (later phases)

bubblewrap, mount isolation, path hiding, network namespace, `read_only_subpaths`
on Linux, the cooperative proxy (Phase 2), transparent netns proxy (Phase 3),
Windows. The standalone helper `[[bin]]` for "external-helper mode" is only added
to the extent §7 needs a spawnable target for tests.

## 9. Risks

- **Kernel < 5.13 / Landlock disabled:** handled by fail-loud (`NotEnforced`).
  Document the minimum kernel.
- **Landlock `BestEffort` silently under-enforcing on partial-support kernels:**
  we treat only `NotEnforced` as fatal; `PartiallyEnforced` is accepted but
  should be logged. Revisit if a deployment needs a hard ABI floor.
- **Re-exec footgun:** if the consumer forgets `run_if_invoked()` at the top of
  `main()`, the re-exec'd process falls through into the app instead of enforcing.
  Detection is the **arg0 sentinel only** (consistent with §3); the parent cannot
  reliably tell that the child failed to engage, so Phase 1 does **not** ship the
  `HelperHookMissing` guard floated in Phase 0 §6.2 (it would be unreliable).
  Instead this is a **documented hard requirement**: call
  `motosan_sandbox::helper::run_if_invoked()` as the first line of `main()`, or
  Linux sandboxing silently won't engage. The crate-root docs and the
  `with_helper_exe` docs state this prominently. (A reliable guard can be revisited
  later if it earns its keep.)
