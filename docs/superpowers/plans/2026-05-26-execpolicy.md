# ExecPolicy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a standalone, default-deny `ExecPolicy` command-allowlist gate consumers can evaluate before `Sandbox::run`, with slash→exact-path / no-slash→basename matching.

**Architecture:** One small pure-logic module (`src/execpolicy.rs`) with `ExecPolicy` (builder around a `BTreeSet<String>` of entries) and `ExecDecision` (`Allow` / `Deny{program, reason}`). Re-exported from `lib.rs`. Not wired into `Sandbox::run` — the consumer composes the two gates. No deps, not feature-gated, fully unit-tested with no OS interaction.

**Tech Stack:** Rust stdlib only (`std::collections::BTreeSet`, `std::path::Path`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-26-execpolicy-design.md`.

---

## File Structure

- `crates/motosan-sandbox/src/execpolicy.rs` — **create**: the module + exhaustive unit tests.
- `crates/motosan-sandbox/src/lib.rs` — **modify**: `mod execpolicy;` + `pub use execpolicy::{ExecDecision, ExecPolicy};`.
- `crates/motosan-sandbox/README.md` — **modify**: "Command allowlist (ExecPolicy)" section.

One small module, one small library re-export, one README section. The module is pure logic (no `cfg`-gated cross-sections), so the recurring "verify all 3 feature cells × both targets" trap doesn't bite here — but the verification gate runs them anyway.

---

### Task 1: `ExecPolicy` module + tests (TDD red → green)

**Files:**
- Create: `crates/motosan-sandbox/src/execpolicy.rs`
- Modify: `crates/motosan-sandbox/src/lib.rs`

- [ ] **Step 1: Create the module with API stubs + the full test suite**

Create `crates/motosan-sandbox/src/execpolicy.rs` (stubs that COMPILE but fail at runtime — every `check` returns `Deny`, so the `Allow`-case tests will fail; this is the deliberate RED phase):

```rust
//! Standalone command-allowlist gate. See
//! `docs/superpowers/specs/2026-05-26-execpolicy-design.md`.
//!
//! `ExecPolicy` is a *coarse second gate* evaluated by the consumer BEFORE
//! `Sandbox::run`; the OS sandbox (network/fs) remains the real containment.

use std::collections::BTreeSet;
use std::path::Path;

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

    /// Permit a program. Chainable. An entry **containing `/`** is matched as
    /// an **exact full path** (e.g. `allow("/usr/bin/python3")` permits only
    /// that path); an entry **without `/`** is matched by **basename** (e.g.
    /// `allow("python3")` permits `/usr/bin/python3`, `./python3`, or bare
    /// `python3`). Use a path entry to stop an untrusted command from running a
    /// look-alike binary at an attacker-chosen path.
    pub fn allow(mut self, _program: impl Into<String>) -> Self {
        // STUB — Step 3 implements this.
        self
    }

    /// Vet a command. `Allow` iff the program satisfies some allowlist entry.
    pub fn check(&self, _cmd: &SandboxCommand) -> ExecDecision {
        // STUB — Step 3 implements this.
        ExecDecision::Deny {
            program: String::new(),
            reason: "unimplemented".to_string(),
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

/// Basename helper: empty / pure-separator inputs (`""`, `"/"`) yield `None`.
/// Trailing slashes are stripped by `Path::file_name` (so `"foo/"` → `"foo"`).
fn program_basename(program: &std::ffi::OsStr) -> Option<String> {
    Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn cmd(program: &str) -> SandboxCommand {
        SandboxCommand {
            program: program.into(),
            args: Vec::new(),
            cwd: PathBuf::from("/"),
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn basename_entry_allows_bare_absolute_and_relative() {
        let p = ExecPolicy::new().allow("python3");
        assert!(p.check(&cmd("python3")).is_allowed());
        assert!(p.check(&cmd("/usr/bin/python3")).is_allowed());
        assert!(p.check(&cmd("./python3")).is_allowed());
    }

    #[test]
    fn venv_pip_basename_matches_pip_entry() {
        let p = ExecPolicy::new().allow("pip");
        // The financial example calls `.venv/bin/pip install …`; basename is `pip`.
        assert!(p.check(&cmd(".venv/bin/pip")).is_allowed());
    }

    #[test]
    fn non_listed_program_denied_with_basename_in_reason() {
        let p = ExecPolicy::new().allow("python3");
        let d = p.check(&cmd("/usr/bin/curl"));
        assert!(d.is_denied());
        if let ExecDecision::Deny { program, reason } = d {
            assert_eq!(program, "curl");
            assert!(reason.contains("'curl'"), "reason was: {reason}");
        } else {
            panic!("expected Deny");
        }
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = ExecPolicy::new();
        assert!(p.check(&cmd("python3")).is_denied());
        assert!(p.check(&cmd("/bin/sh")).is_denied());
    }

    #[test]
    fn empty_program_string_denies_with_no_usable_name_reason() {
        let p = ExecPolicy::new().allow("python3");
        let d = p.check(&cmd(""));
        if let ExecDecision::Deny { program, reason } = d {
            assert_eq!(program, "");
            assert!(
                reason.contains("no usable program name"),
                "reason was: {reason}"
            );
        } else {
            panic!("expected Deny for empty program");
        }
    }

    #[test]
    fn pure_slash_program_denies_with_allowlist_reason() {
        let p = ExecPolicy::new().allow("python3");
        let d = p.check(&cmd("/"));
        // "/" is NOT empty and has no usable basename → falls into the
        // ordinary "not in allowlist" path, with the full program in the reason.
        if let ExecDecision::Deny { program, reason } = d {
            assert_eq!(program, "/");
            assert!(
                reason.contains("'/'") && reason.contains("not in the exec allowlist"),
                "reason was: {reason}"
            );
        } else {
            panic!("expected Deny for '/'");
        }
    }

    #[test]
    fn exact_path_entry_pins_one_path_and_denies_lookalikes() {
        let p = ExecPolicy::new().allow("/usr/bin/python3");
        assert!(p.check(&cmd("/usr/bin/python3")).is_allowed());
        // Same basename, different (attacker-chosen) path → DENIED.
        assert!(p.check(&cmd("/tmp/evil/python3")).is_denied());
        // Bare basename → DENIED (the entry is a path, not a basename rule).
        assert!(p.check(&cmd("python3")).is_denied());
    }

    #[test]
    fn is_allowed_and_is_denied_agree_with_variant() {
        assert!(ExecDecision::Allow.is_allowed());
        assert!(!ExecDecision::Allow.is_denied());
        let d = ExecDecision::Deny {
            program: "x".into(),
            reason: "y".into(),
        };
        assert!(d.is_denied());
        assert!(!d.is_allowed());
    }

    #[test]
    fn builder_chaining_accumulates_the_allowlist() {
        let p = ExecPolicy::new()
            .allow("python3")
            .allow("pip")
            .allow("/usr/bin/jq");
        assert!(p.check(&cmd("python3")).is_allowed());
        assert!(p.check(&cmd("/anywhere/pip")).is_allowed());
        assert!(p.check(&cmd("/usr/bin/jq")).is_allowed());
        assert!(p.check(&cmd("jq")).is_denied()); // path entry doesn't basename-match
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`, run tests RED**

In `crates/motosan-sandbox/src/lib.rs`:
1. Add `mod execpolicy;` next to the other `mod` declarations (alongside `mod denial;`, `mod error;`, etc.).
2. Add `pub use execpolicy::{ExecDecision, ExecPolicy};` next to the other `pub use` lines.

Then run: `cargo test -p motosan-sandbox --lib execpolicy::`
Expected: tests COMPILE but most FAIL (only `empty_policy_denies_everything` and `is_allowed_and_is_denied_agree_with_variant` will pass — every `check` returns `Deny` from the stub, so `Allow`-case tests fail; the deny-reason assertions also fail because the stub returns "unimplemented"). Specifically expect failures on `basename_entry_allows_*`, `venv_pip_basename_*`, `non_listed_program_denied_*`, `empty_program_string_denies_*`, `pure_slash_program_*`, `exact_path_entry_*`, `builder_chaining_*`.

- [ ] **Step 3: Implement `allow` and `check` for real (green)**

In `crates/motosan-sandbox/src/execpolicy.rs`, replace the two stub bodies. The `allow` body:
```rust
    pub fn allow(mut self, program: impl Into<String>) -> Self {
        self.allowed.insert(program.into());
        self
    }
```
The `check` body:
```rust
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
```

- [ ] **Step 4: Run tests GREEN**

Run: `cargo test -p motosan-sandbox --lib execpolicy::`
Expected: all 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/motosan-sandbox/src/execpolicy.rs crates/motosan-sandbox/src/lib.rs
git commit -m "feat(execpolicy): standalone command-allowlist gate (basename + exact-path)"
```

---

### Task 2: README section

**Files:**
- Modify: `crates/motosan-sandbox/README.md`

- [ ] **Step 1: Add the "Command allowlist (ExecPolicy)" section**

In `crates/motosan-sandbox/README.md`, add a top-level section (near the other usage docs):

```markdown
## Command allowlist (`ExecPolicy`)

`ExecPolicy` is a small, standalone gate evaluated **before** `Sandbox::run` —
useful when the command itself comes from an untrusted source (an LLM/agent
proposing a shell command). Default-deny, no deps, pure logic.

```rust
use motosan_sandbox::{ExecPolicy, ExecDecision};

let gate = ExecPolicy::new().allow("python3").allow("pip");
match gate.check(&cmd) {
    ExecDecision::Deny { reason, .. } => return Err(reason.into()), // never reaches the sandbox
    ExecDecision::Allow => sandbox.run(cmd, &policy, opts).await?,
};
```

**Matching:** an entry **with `/`** is an **exact full-path** rule
(`allow("/usr/bin/python3")` permits only that path — use this when the command
is untrusted and you care *which* binary runs); an entry **without `/`** is a
**basename** rule (`allow("python3")` permits any program whose `file_name` is
`python3`, including `./python3` at an attacker-chosen path).

**Caveats** (this gate is coarse on purpose; the OS sandbox is the real wall):
- It vets the entry command only — not what the sandboxed process then `exec`s,
  and not what `python3 -c "…"` does inside an allowed interpreter.
- A venv interpreter's basename is `python`, not `python3` — `.venv/bin/python`
  needs `allow("python")` (or an exact path), not `allow("python3")`.
- No `$PATH` lookup, no symlink resolution.
```

- [ ] **Step 2: Commit**

```bash
git add crates/motosan-sandbox/README.md
git commit -m "docs(readme): document ExecPolicy command-allowlist gate"
```

---

### Task 3: Full verification (all feature cells × both targets)

The recurring lesson from PR #3 and PR #4: `--all-features` alone is not enough; CI runs `clippy (default features)`, `clippy (no default features)`, and `clippy (all features)` on each OS, and a `cfg`/feature cross-section can fail there even when `--all-features` is green. Run all three cells × both targets locally.

- [ ] **Step 1: fmt + macOS clippy across both feature cells**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings                  # macOS default
cargo clippy --all-features --all-targets -- -D warnings   # macOS all
```
Expected: each line ends with `Finished`, no errors.

- [ ] **Step 2: Linux-target clippy across all three feature cells**

Run each separately (do NOT use a shell variable for the args — zsh doesn't word-split unquoted vars, which masks failures):
```bash
cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
cargo clippy --target x86_64-unknown-linux-gnu --no-default-features --all-targets -- -D warnings
cargo clippy --target x86_64-unknown-linux-gnu --all-features --all-targets -- -D warnings
```
Expected: each ends with `Finished`, no errors.

- [ ] **Step 3: Full test suite (no regressions)**

Run: `cargo test --all-features 2>&1 | tail -5`
Expected: every suite passes; the lib test count goes up by 9 (the new execpolicy tests).

- [ ] **Step 4: Push the branch**

Run: `git push -u origin feat/execpolicy`
Expected: branch pushed. (Open the PR separately and watch CI to confirm all three feature cells × both runners go green.)

---

## Self-Review

- **Spec coverage:** API (`ExecPolicy`, `ExecDecision`, `is_allowed`/`is_denied`, builder `allow`, `check`) → Task 1; matching semantics (basename vs exact-path; `""` no-usable-name vs `"/"` not-in-allowlist) → Task 1 tests + Step 3 impl; re-export → Task 1 Step 2; README with two-gate snippet + caveats (incl. venv-`python` note, basename-path-agnostic warning, no-`$PATH` note) → Task 2; tests list — all 9 spec bullets have a `#[test]` → Task 1 Step 1 (basename allows / venv pip / non-listed / empty policy / empty program / pure-slash / exact-path / is_allowed-is_denied / builder chaining). Out-of-scope items (prefix-token args, `Prompt`, multi-path pinning, `Sandbox::run` integration) are not in any task — intentional.
- **Placeholder scan:** no TBDs; full code in every step; tests are concrete `#[test]` functions with real assertions; no "similar to Task N."
- **Type consistency:** `ExecPolicy::{new, allow, check}`, `ExecDecision::{Allow, Deny{program, reason}}`, `is_allowed`/`is_denied`, `program_basename(&OsStr) -> Option<String>` defined in Task 1 Step 1 and used identically in tests and the Step 3 impl. The `Deny` field names (`program`, `reason`) match across stub, impl, tests, and README snippet. The `SandboxCommand` shape (`program: OsString`, `args`, `cwd`, `env`) matches the real type in `src/types.rs`.
