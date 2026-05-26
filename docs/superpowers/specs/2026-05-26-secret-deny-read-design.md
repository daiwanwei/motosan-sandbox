# Secret deny-read (glob-based) — Design

**Status:** approved design, pre-implementation.
**Date:** 2026-05-26.

## Problem

motosan grants whole-filesystem **read** on every non-`DangerFullAccess` policy
(Seatbelt `(allow file-read*)`; Linux Landlock `AccessFs::from_read` over `/`;
bwrap `--ro-bind / /`). `read_only_subpaths` only blocks **writes**. So untrusted
code under the sandbox can read secrets (`~/.aws/credentials`, `~/.ssh`, `*.pem`,
`.env`) and exfiltrate them through whatever egress the network policy permits —
even a tight `Proxied` exchange allowlist. For running untrusted financial
strategy code, read-confinement of secrets is the missing control.

## Goal

Add a deny-read mechanism specified as **glob patterns**, mirroring Codex's
`codex-rs/sandboxing` model byte-for-byte where practical. Enforced on macOS
Seatbelt and the Linux bwrap (`Proxied`) path; `Error::Unsupported` on the Linux
Landlock path (allow-only, cannot carve a read exception — identical to the
existing `read_only_subpaths` limitation).

## Non-goals

- No read/write **allow** via glob — globs are **deny-read only** (Codex's
  invariant: "glob file system permissions only support deny-read entries").
- No Landlock support (fundamental: allow-only model).
- No requested-vs-granted permission intersection (`ReadDenyMatcher` and friends
  in Codex) — motosan has no permission-negotiation layer; render globs directly.
- No change to network or write enforcement.

## Reference (how Codex does it)

- **Model** (`sandboxing/src/policy_transforms.rs`): filesystem entries are
  `(path, access)` with `access ∈ {Read, Write, Deny}` and
  `path ∈ {Path, GlobPattern, Special}`; globs are deny-read only.
- **Seatbelt** (`sandboxing/src/seatbelt.rs`,
  `build_seatbelt_unreadable_glob_policy`): each glob → anchored regex; emits
  `(deny file-read* (regex #"…"))` + `(deny file-write-unlink (regex #"…"))`,
  plus a second regex for the canonicalized static prefix. No FS walk.
- **bwrap** (`linux-sandbox/src/bwrap.rs`): expands globs by scanning the FS
  (Codex uses ripgrep), bounded by `glob_scan_max_depth` and
  `MAX_UNREADABLE_GLOB_MATCHES = 8192`, then masks each concrete match.
- **Landlock** (`sandboxing/src/landlock.rs`): no deny-read handling at all.

## API surface

Deny-read attaches to both read-granting policies. `WorkspaceWrite` already uses
a `#[non_exhaustive]` builder, so a new field is non-breaking. `ReadOnly` is a
struct **variant** today (`ReadOnly { network }`); adding a field there is
breaking, so it is **restructured into a builder struct** to match
`WorkspaceWrite`. motosan is `0.1.0` / pre-release, so the break is acceptable
and yields a consistent API.

```rust
// BEFORE
pub enum SandboxPolicy {
    DangerFullAccess,
    ReadOnly { network: NetworkPolicy },
    WorkspaceWrite(WorkspaceWrite),
}

// AFTER
pub enum SandboxPolicy {
    DangerFullAccess,
    ReadOnly(ReadOnly),            // ← now wraps a builder struct
    WorkspaceWrite(WorkspaceWrite),
}

#[non_exhaustive]
pub struct ReadOnly {
    pub network: NetworkPolicy,
    pub deny_read_globs: Vec<String>,
}
impl ReadOnly {
    pub fn new(network: NetworkPolicy) -> Self;          // deny_read_globs = []
    pub fn deny_read(self, glob: impl Into<String>) -> Self;
}

// WorkspaceWrite: one new field + builder method (non-breaking)
pub struct WorkspaceWrite {
    pub writable_roots: Vec<PathBuf>,
    pub read_only_subpaths: Vec<PathBuf>,
    pub exclude_tmp: bool,
    pub network: NetworkPolicy,
    pub deny_read_globs: Vec<String>,   // NEW
}
impl WorkspaceWrite {
    pub fn deny_read(self, glob: impl Into<String>) -> Self;  // NEW
}
```

Usage:
```rust
let policy = SandboxPolicy::WorkspaceWrite(
    WorkspaceWrite::new(vec![workspace])
        .network(NetworkPolicy::Proxied { allowlist })
        .deny_read("**/.env")
        .deny_read("**/*.pem"),
);
// read-only analysis tool:
let policy = SandboxPolicy::ReadOnly(
    ReadOnly::new(NetworkPolicy::Proxied { allowlist }).deny_read("**/.aws/**"),
);
```

- `deny_read_globs` is **orthogonal** to `read_only_subpaths` (writes vs reads);
  both may be set on `WorkspaceWrite`.
- A new accessor `SandboxPolicy::deny_read_globs(&self) -> &[String]` returns the
  effective list (`&[]` for `DangerFullAccess`), so backends read it uniformly —
  parallel to the existing `SandboxPolicy::network()`.
- Restructuring `ReadOnly` is a breaking change touching **~18 `ReadOnly { … }`
  sites across 6 files** — both constructions and `match`/destructure arms in
  `src/policy.rs`, `src/transform.rs`, `src/seatbelt.rs`, `src/reexec.rs`, plus
  `tests/seatbelt_enforcement.rs` and `tests/transform_common.rs`. (`loop_integration.rs`
  does **not** use `ReadOnly`.) All become `ReadOnly(ReadOnly::new(network))` /
  `ReadOnly(ro)` + `ro.network`. Mechanical but budget for it in the plan.
- Relative globs resolve against `SandboxCommand::cwd`; absolute globs are used
  as-is. This cwd is threaded into the transform (already available there).

## Backend enforcement

| Backend | Rendering |
|---|---|
| **macOS Seatbelt** | per glob → anchored regex; append `(deny file-read* (regex #"…"))` (verified on-machine: a deny appended after the base `(allow file-read*)` overrides it — SBPL last-match-wins). We emit the read deny only; we do **not** mirror Codex's extra `(deny file-write-unlink …)` — writes/unlinks outside writable roots are already denied, so it adds nothing for a read-deny feature. The glob's **static prefix is canonicalized** (`/tmp`→`/private/tmp`) so the regex matches the resolved path the kernel checks. |
| **Linux bwrap (`Proxied`)** | expand each glob by walking from its **static (non-wildcard) prefix** with `globset` + `walkdir`; mask each match — files via `--ro-bind /dev/null <p>`, directories via `--tmpfs <p>`. **Ordering: mask mounts are emitted LAST in the bwrap argv** — after `--ro-bind / /` and after the writable `--bind` roots — because bwrap applies mounts in argv order; otherwise a writable `--bind` would re-expose a secret living under a writable root. |
| **Linux Landlock (`Blocked`/`Allowed`)** | `Error::Unsupported(LinuxSeccomp)` when `deny_read_globs` is non-empty. Identical to `read_only_subpaths` handling in `reexec.rs` (`policy.is_full_access()` exempt). |

`DangerFullAccess` ignores `deny_read_globs` (no sandbox).

## Glob handling, caps, dependencies

- **Matching/expansion** (Linux only): add `globset` and `walkdir` under
  `[target.'cfg(target_os = "linux")'.dependencies]`. The Seatbelt glob→regex
  transform needs no dependency.
- **Bounding the walk:** scope each walk to the glob's **static prefix** (e.g.
  `/home/u/.aws/**` walks only `/home/u/.aws`, not `/`), so prefixed globs are
  cheap. `MAX_DENY_READ_GLOB_MATCHES: usize = 8192` is a hard cap on total
  matches; exceeding it is an error (refuse rather than partially mask). No
  configurable depth field in v1 — broad root-anchored globs (`**/x`) are
  documented as expensive; a `glob_scan_max_depth` knob is a noted follow-up.
- **Glob syntax:** `globset` default (`**`, `*`, `?`, `[…]`), absolute or
  cwd-relative. Documented in the crate README.

## Error handling — fail-closed

1. Non-empty `deny_read_globs` on the Linux Landlock path →
   `Error::Unsupported(SandboxKind::LinuxSeccomp)`.
2. bwrap glob expansion exceeding `MAX_DENY_READ_GLOB_MATCHES` →
   `Error::Transform("deny-read glob matched too many paths…")`.
3. Invalid glob syntax → `Error::Transform` at policy-build time (when the
   backend first compiles the pattern).
4. Never silently run a command without the requested deny-read protection.

## Testing strategy

**Unit**
- glob→regex transform: a table of cases mirroring Codex's
  `seatbelt_tests` (anchoring, `**`/`*`, special chars escaped, static-prefix
  regex). Security-critical — a wrong regex under-denies.
- builder defaults + `deny_read` chaining on both `ReadOnly` and `WorkspaceWrite`.
- Landlock rejection: `deny_read_globs` non-empty on the Landlock helper-policy
  mapping → `Error::Unsupported` (parallel to
  `read_only_subpaths_rejected_on_landlock_path`).
- bwrap argv: globs expand to mask mounts; match-cap exceeded → error.

**Behavioral — macOS** (`tests/seatbelt_enforcement.rs`)
- Write a secret file under a readable dir; run a sandboxed `cat secret` with
  `deny_read("**/secret*")` → non-zero exit + denial; `cat sibling` → succeeds
  (no over-deny). Assert the file is genuinely unreadable, not merely absent.

**Behavioral — Linux** (`tests/linux_enforcement.rs`, `Proxied`/bwrap)
- Same shape: secret masked (read fails), sibling/parent dir still readable.
- **Ordering test:** a deny-read secret living *inside a writable root* is still
  masked (proves mask mounts are emitted after the writable `--bind`).

**Verification gate**
`cargo test --all-features`, lib tests, `clippy --all-features --all-targets
-D warnings`, `fmt --check`, and (Linux code) `cargo check`/`clippy --target
x86_64-unknown-linux-gnu --features proxy` since the bwrap path can't run on the
macOS dev box (CI runs the real netns tests).

## Out of scope / follow-ups

- `ReadDenyMatcher` / permission intersection (not needed without negotiation).
- Glob deny-read on Landlock (would require inverting to an allow-list of
  readable roots minus denied — large, separate effort).
- Parallel/gitignore-aware walking (Codex's ripgrep); `walkdir` is sufficient.
