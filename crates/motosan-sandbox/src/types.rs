//! Core value types. Filled out in Task 4; this stub exists so `error.rs`
//! (which references `SandboxKind`) compiles.

/// Which enforcement backend is active for the current target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    /// No enforcement — command runs unwrapped.
    None,
    /// macOS Apple Seatbelt via `sandbox-exec`.
    MacosSeatbelt,
    /// Linux seccomp/Landlock/bwrap helper (Phase 1).
    LinuxSeccomp,
}
