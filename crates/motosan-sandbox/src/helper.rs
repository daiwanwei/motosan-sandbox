//! Self-reexec hook. On Linux this inspects arg0 and, if invoked as the sandbox
//! helper, applies kernel restrictions and never returns. It is a no-op on other
//! platforms — but consumers should call it at the top of `main()` so the call
//! site is stable across platforms.

/// Runs the sandbox helper if this process was re-exec'd as one; otherwise
/// returns immediately. Call this as the FIRST line of `main()`. On non-Linux
/// targets it is a no-op (Phase 0 behavior).
pub fn run_if_invoked() {
    #[cfg(target_os = "linux")]
    crate::linux::run_if_invoked();
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
