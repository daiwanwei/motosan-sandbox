# ExecPolicy — command allowlist gate — Design

**Status:** approved design, pre-implementation.
**Date:** 2026-05-26.

## Problem

motosan's OS sandbox confines what a command can *do* (network/filesystem), but
it runs whatever command it is handed. When the command itself comes from an
untrusted source — an LLM/agent proposing a shell command — there is no gate
that says "this program is not allowed to run at all." A coarse pre-check
("allow `python3`/`pip`, deny `curl`/`ssh`") is a useful second line of defense
before the OS sandbox engages.

## Goal

A small, standalone `ExecPolicy` that vets the **entry command** by program
**basename** OR **exact path** (consumer's choice per entry), default-deny,
returning `Allow` / `Deny{reason}`. The consumer evaluates
it *before* `Sandbox::run`. Decoupled from `run()` (mirrors Codex's two-gate
architecture and motosan's "this crate only runs a command under a policy"
philosophy).

## Non-goals (deliberate, see "Why minimal")

- **No argument inspection.** No `git status` vs `git push` rules. Arg-prefix
  gating is a security half-measure (`python3 -c "<anything>"` defeats it; args
  have many bypass forms) and the real containment is the OS sandbox. Program-
  name granularity is what this gate can honestly enforce.
- **No Starlark / policy files / CLI.** Codex needs those because its policies
  are user-authored text; motosan consumers build rules in Rust.
- **No `Prompt`/ask decision.** A consumer wanting human-gating treats any
  `Deny` as "ask." A third variant is not needed to express that.
- **No `$PATH` lookup / symlink resolution.** Exact-path entries match the
  program string **as given**; they do not search `$PATH` or canonicalize
  symlinks. (Single-path pinning IS supported via slash entries — see Matching;
  the `host_executable`-style multi-path pinning is a noted follow-up.)
- **No wiring into `Sandbox::run`.** It stays a standalone gate the consumer
  composes.

## Why minimal (the program-name decision)

`ExecPolicy` is a *coarse second gate*; the load-bearing containment is the OS
sandbox (network allowlist, write confinement, deny-read). Program-level
granularity (basename or exact path) matches exactly what this gate can enforce
honestly — arg-level rules would overpromise (a permitted `python3` can run
arbitrary code regardless of its args). Keeping it to a program allowlist makes
it ~one tiny, fully unit-testable module with almost no logic to get wrong. If a
real need for arg rules appears, the `allow(...)` API extends to prefix-token
rules without a breaking change.

## API

New module `crates/motosan-sandbox/src/execpolicy.rs` (pure logic, no deps, not
feature-gated):

```rust
use std::collections::BTreeSet;
use crate::types::SandboxCommand;

/// Allowlist of program entries permitted to run. Each entry is either a
/// **basename** (no `/`; matches the program's `Path::file_name`) or an
/// **exact path** (contains `/`; matches the program string verbatim).
/// Default-deny: a command not matched by any entry is denied.
#[derive(Debug, Default, Clone)]
pub struct ExecPolicy {
    allowed: BTreeSet<String>,
}

impl ExecPolicy {
    /// An empty policy that denies every command.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit a program. Chainable. An entry **containing `/`** is matched as an
    /// **exact full path** (e.g. `allow("/usr/bin/python3")` permits only that
    /// path); an entry **without `/`** is matched by **basename** (e.g.
    /// `allow("python3")` permits `/usr/bin/python3`, `./python3`, or bare
    /// `python3`). Use a path entry to stop an untrusted command from running a
    /// look-alike binary at an attacker-chosen path.
    pub fn allow(mut self, program: impl Into<String>) -> Self {
        self.allowed.insert(program.into());
        self
    }

    /// Vet a command. `Allow` iff the program satisfies some allowlist entry
    /// (exact-path entry == full program; basename entry == program basename).
    pub fn check(&self, cmd: &SandboxCommand) -> ExecDecision {
        let full = cmd.program.to_string_lossy();
        if full.is_empty() {
            return ExecDecision::Deny {
                program: String::new(),
                reason: "command has no usable program name".to_string(),
            };
        }
        let base = program_basename(&cmd.program);
        let matched = self.allowed.iter().any(|entry| {
            if entry.contains('/') {
                *entry == *full // exact full-path match
            } else {
                base.as_deref() == Some(entry.as_str()) // basename match
            }
        });
        if matched {
            ExecDecision::Allow
        } else {
            let program = base.unwrap_or_else(|| full.into_owned());
            ExecDecision::Deny {
                reason: format!("program '{program}' is not in the exec allowlist"),
                program,
            }
        }
    }
}

/// Verdict from [`ExecPolicy::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecDecision {
    Allow,
    Deny { program: String, reason: String },
}

impl ExecDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ExecDecision::Allow)
    }
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}
```

`program_basename` is a private helper: `Path::new(program).file_name()` →
`to_str()` → owned `String`; returns `None` for empty / pure-separator inputs
(`""`, `"/"`). Trailing slashes are stripped by `Path::file_name`, so `"foo/"`
yields `"foo"`.

Re-exported from `lib.rs`:
```rust
pub use execpolicy::{ExecDecision, ExecPolicy};
```

## Usage (the two-gate pattern)

```rust
let gate = ExecPolicy::new().allow("python3").allow("pip");

match gate.check(&cmd) {
    ExecDecision::Deny { reason, .. } => {
        // reject — the command never reaches the OS sandbox
        return Err(MyError::Disallowed(reason));
    }
    ExecDecision::Allow => {
        let out = sandbox.run(cmd, &policy, opts).await?;
        // ...
    }
}
```

## Matching semantics

- Empty program string → `Deny` "no usable program name".
- Otherwise the command matches if ANY allowlist entry matches:
  - entry **contains `/`** → matches when it **equals the full program string**
    (exact path, e.g. `/usr/bin/python3`);
  - entry **without `/`** → matches when it **equals the program's basename**
    (`Path::file_name`), so `python3`, `/usr/bin/python3`, and `./python3` all
    satisfy `allow("python3")`.
- No match (incl. empty allowlist) → `Deny{program, reason}`; the reason names
  the basename, or the full string when there is no basename (e.g. `"/"`).
- No argument inspection; no `$PATH` / symlink resolution. (Note: `"foo/"`
  resolves to basename `"foo"`; `Path::file_name` strips a trailing slash.)

## Honest caveat (must be documented)

`ExecPolicy` vets only the **entry command** passed to `run()`. It does **not**:
- police what the sandboxed process subsequently `exec`s (the OS sandbox
  currently allows `process-exec` broadly), nor
- constrain what an allowed interpreter does (`python3 -c "…"` can do anything
  the OS sandbox permits).

Also note **basename entries are path-agnostic**: `allow("python3")` permits a
binary named `python3` at *any* path, including an attacker-chosen one. When the
command is untrusted and you care *which* binary runs, use an **exact-path
entry** (`allow("/usr/bin/python3")`); basename entries are for convenience.

It is a coarse second gate; the OS sandbox (network/fs) is the real containment.
Most valuable when the command itself is untrusted input (LLM/agent-proposed).

## Files

- `crates/motosan-sandbox/src/execpolicy.rs` — **create**: module + exhaustive
  unit tests.
- `crates/motosan-sandbox/src/lib.rs` — **modify**: `mod execpolicy;` + re-export.
- `crates/motosan-sandbox/README.md` — **modify**: "Command allowlist
  (ExecPolicy)" section with the two-gate snippet + the caveat, including that
  basename entries are path-agnostic (use an exact path to pin) and that a venv
  interpreter's basename is `python`, not `python3`.

## Testing (all unit, no OS / no integration)

The gate is pure logic, so every test is a plain `#[test]` runnable on all
platforms:

- basename entry: `allow("python3")` allows bare `python3`, `/usr/bin/python3`,
  and `./python3` (path-agnostic).
- `.venv/bin/pip` → basename `pip` → allowed by `allow("pip")` (the case the
  financial example needs).
- non-listed program (`curl`) → `Deny`, reason names the basename.
- empty policy (`ExecPolicy::new()`) denies everything.
- empty program string `""` → `Deny` "no usable program name".
- pure-slash program `"/"` → `Deny` (reason names `/`; it is not empty, so not
  the "no usable program name" path).
- **exact-path entry:** `allow("/usr/bin/python3")` allows exactly
  `/usr/bin/python3` but **denies** `/tmp/evil/python3` (same basename, different
  path) and bare `python3`.
- `is_allowed`/`is_denied` helpers agree with the variant.
- builder chaining accumulates the allowlist.

## Out of scope / follow-ups

- Prefix-token / argument rules (extend `allow` to ordered token patterns).
- `Prompt`/ask decision variant.
- `host_executable`-style pinning: allow a *basename* but only for a SET of
  absolute paths. The slash→exact rule already lets a consumer pin a single
  path; this is the multi-path generalization.
- Optional convenience integration in `Sandbox::run` behind a separate method.
