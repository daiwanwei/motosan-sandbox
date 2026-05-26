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

A small, standalone `ExecPolicy` that vets the **entry command** by **program
name**, default-deny, returning `Allow` / `Deny{reason}`. The consumer evaluates
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
- **No path resolution / `host_executable` pinning.** Matching is by basename
  only (documented limitation). Path-pinning is a noted future refinement.
- **No wiring into `Sandbox::run`.** It stays a standalone gate the consumer
  composes.

## Why minimal (the program-name decision)

`ExecPolicy` is a *coarse second gate*; the load-bearing containment is the OS
sandbox (network allowlist, write confinement, deny-read). Program-name
granularity matches exactly what this gate can enforce honestly — arg-level
rules would overpromise (a permitted `python3` can run arbitrary code regardless
of its args). Keeping it to a name allowlist makes it ~one tiny, fully
unit-testable module with almost no logic to get wrong. If a real need for arg
rules appears, the `allow(name)` API extends to prefix-token rules without a
breaking change.

## API

New module `crates/motosan-sandbox/src/execpolicy.rs` (pure logic, no deps, not
feature-gated):

```rust
use std::collections::BTreeSet;
use crate::types::SandboxCommand;

/// Allowlist of program basenames permitted to run. Default-deny: a command
/// whose program basename is not in the set is denied.
#[derive(Debug, Default, Clone)]
pub struct ExecPolicy {
    allowed: BTreeSet<String>,
}

impl ExecPolicy {
    /// An empty policy that denies every command.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit a program by basename (e.g. `"python3"`, `"pip"`). Chainable.
    /// Matches the program's file name, so `/usr/bin/python3` and `python3`
    /// both satisfy `allow("python3")`.
    pub fn allow(mut self, program: impl Into<String>) -> Self {
        self.allowed.insert(program.into());
        self
    }

    /// Vet a command. Returns `Allow` iff its program basename is allow-listed.
    pub fn check(&self, cmd: &SandboxCommand) -> ExecDecision {
        match program_basename(&cmd.program) {
            Some(base) if self.allowed.contains(&base) => ExecDecision::Allow,
            Some(base) => ExecDecision::Deny {
                reason: format!("program '{base}' is not in the exec allowlist"),
                program: base,
            },
            None => ExecDecision::Deny {
                program: cmd.program.to_string_lossy().into_owned(),
                reason: "command has no usable program name".to_string(),
            },
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
`to_str()` → owned `String`; returns `None` for empty / trailing-slash inputs.

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

- Take `cmd.program`'s basename (`Path::file_name`).
- In `allowed` → `Allow`. Not in `allowed` (incl. empty allowlist) →
  `Deny{program, reason}`.
- No basename — empty string or a pure-separator program (`"/"`) → `Deny` with a
  "no usable program name" reason. (Note: `"foo/"` resolves to basename `"foo"`;
  `Path::file_name` strips a trailing slash.)
- No argument inspection; no `$PATH` / symlink resolution. Basename only.

## Honest caveat (must be documented)

`ExecPolicy` vets only the **entry command** passed to `run()`. It does **not**:
- police what the sandboxed process subsequently `exec`s (the OS sandbox
  currently allows `process-exec` broadly), nor
- constrain what an allowed interpreter does (`python3 -c "…"` can do anything
  the OS sandbox permits).

It is a coarse second gate; the OS sandbox (network/fs) is the real containment.
Most valuable when the command itself is untrusted input (LLM/agent-proposed).

## Files

- `crates/motosan-sandbox/src/execpolicy.rs` — **create**: module + exhaustive
  unit tests.
- `crates/motosan-sandbox/src/lib.rs` — **modify**: `mod execpolicy;` + re-export.
- `crates/motosan-sandbox/README.md` — **modify**: "Command allowlist
  (ExecPolicy)" section with the two-gate snippet + the caveat.

## Testing (all unit, no OS / no integration)

The gate is pure logic, so every test is a plain `#[test]` runnable on all
platforms:

- allow-listed program passes — bare (`python3`) and absolute (`/usr/bin/python3`).
- non-listed program → `Deny`, reason names the basename.
- empty policy (`ExecPolicy::new()`) denies everything.
- empty program string / pure-slash program (`"/"`) → `Deny` "no usable program name".
- relative program (`./python3`) → basename `python3` → matches `allow("python3")`
  (documented: basename match; path is not vetted — caveat covers the risk).
- `is_allowed`/`is_denied` helpers agree with the variant.
- builder chaining accumulates the allowlist.

## Out of scope / follow-ups

- Prefix-token / argument rules (extend `allow` to ordered token patterns).
- `Prompt`/ask decision variant.
- `host_executable`-style absolute-path pinning for basename rules (closes the
  `./python3` basename-match risk).
- Optional convenience integration in `Sandbox::run` behind a separate method.
