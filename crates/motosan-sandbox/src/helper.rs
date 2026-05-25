//! Self-reexec hook. In Phase 1 (Linux) this inspects arg0 and, if invoked as
//! the sandbox helper, applies kernel restrictions and never returns. In Phase 0
//! it is a no-op on every platform — but consumers should call it at the top of
//! `main()` NOW so the call site is stable across phases.

/// Runs the sandbox helper if this process was re-exec'd as one; otherwise
/// returns immediately. Phase 0: always returns (no-op).
pub fn run_if_invoked() {
    // Phase 1 (Linux) will:
    //   1. read the re-exec marker env var,
    //   2. if present, parse the policy + apply seccomp/bwrap, then execvp,
    //   3. never return.
    // Phase 0 has no helper, so this is intentionally empty.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_if_invoked_is_noop_in_phase0() {
        // Must return without side effects when not re-exec'd.
        run_if_invoked();
    }
}
