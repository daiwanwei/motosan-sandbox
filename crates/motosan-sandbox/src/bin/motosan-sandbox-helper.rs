//! Re-exec / test target for the Linux sandbox helper.
//!
//! When this binary is spawned with the sentinel arg0 + a policy in the env,
//! `run_if_invoked()` applies the sandbox and `execvp`s the real command (never
//! returning). When run directly (no sentinel), it is a no-op that exits 0.
fn main() {
    motosan_sandbox::helper::run_if_invoked();
    // Not invoked as a sandbox helper — nothing to do.
}
