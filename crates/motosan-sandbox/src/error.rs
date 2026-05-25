//! The single crate-level error. Shared by `transform()` and `run()` so that an
//! unsupported platform or a policy error is not awkwardly wrapped in `io::Error`.

use crate::types::SandboxKind;

/// Errors returned by [`crate::Sandbox`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive] // additive: HelperHookMissing (Phase 1), Proxy (Phase 2) land later
pub enum Error {
    /// The current platform has no sandbox backend wired up yet.
    #[error("sandboxing is not supported on this platform/backend: {0:?}")]
    Unsupported(SandboxKind),

    /// The Linux sandbox helper could not enforce restrictions (e.g. Landlock
    /// reported NotEnforced — kernel too old or disabled). The command was NOT
    /// run unsandboxed.
    #[error("sandbox could not be enforced: {0}")]
    NotEnforced(String),

    /// The policy could not be turned into a runnable command.
    #[error("failed to build sandbox command: {0}")]
    Transform(String),

    /// Spawning or waiting on the child process failed.
    #[error("failed to spawn sandboxed command: {0}")]
    Spawn(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_displays_kind() {
        let e = Error::Unsupported(SandboxKind::LinuxSeccomp);
        assert!(e.to_string().contains("LinuxSeccomp"));
    }

    #[test]
    fn spawn_wraps_io_error() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e = Error::Spawn(io);
        assert!(e.to_string().contains("failed to spawn"));
    }
}
