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
    pub fn allow(mut self, program: impl Into<String>) -> Self {
        self.allowed.insert(program.into());
        self
    }

    /// Vet a command. `Allow` iff the program satisfies some allowlist entry.
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
