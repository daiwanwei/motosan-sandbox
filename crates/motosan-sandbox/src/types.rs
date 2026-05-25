//! Core value types: the command to run, the captured output, run options, and
//! the internal `SpawnRequest` produced by `transform()`. See design §5.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

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

/// A command to run inside the sandbox.
///
/// SECURITY: `env` is whatever the caller supplies — the sandbox does NOT
/// inherit the parent environment. Callers MUST pass a curated/allowlisted env;
/// forwarding `std::env::vars_os()` would leak secrets into the command.
#[derive(Debug, Clone)]
pub struct SandboxCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// Absolute working directory.
    pub cwd: PathBuf,
    pub env: BTreeMap<OsString, OsString>,
}

/// Result of a sandboxed run.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// `Some(code)` if the process exited normally.
    pub exit_code: Option<i32>,
    /// `Some(sig)` if the process was killed by a signal (unix).
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// True if the process was killed because it exceeded `RunOpts::timeout`.
    pub timed_out: bool,
}

/// Options controlling a single `run()`.
#[derive(Debug, Default)]
pub struct RunOpts {
    /// Kill the command after this duration. `None` = no timeout.
    pub timeout: Option<Duration>,
    /// Cap captured stdout/stderr at this many bytes each (0 = unlimited).
    pub max_output_bytes: usize,
    #[cfg(feature = "cancellation")]
    /// Cancel the run cooperatively; killing the child.
    pub cancel: Option<tokio_util::sync::CancellationToken>,
}

/// Lightweight handle to a running network proxy. Carried by `TransformCtx` from
/// Phase 0 so the API is stable, but unused until `NetworkPolicy::Proxied`
/// (Phase 2). It holds only an address — no server logic lives here.
#[derive(Debug, Clone)]
pub struct ProxyHandle {
    pub addr: std::net::SocketAddr,
}

/// Side inputs to `transform()` that are not part of the policy. Keeps
/// `transform()` pure: a proxy address (Phase 2) is INJECTED here, never
/// discovered inside transform.
#[derive(Debug, Default)]
pub struct TransformCtx<'a> {
    pub proxy: Option<&'a ProxyHandle>,
}

/// The concrete, ready-to-spawn command that `transform()` produces. `spawn()`
/// consumes it mechanically — all policy decisions (wrapper program, env vars)
/// are already baked in here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: BTreeMap<OsString, OsString>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_opts_default_is_empty() {
        let o = RunOpts::default();
        assert!(o.timeout.is_none());
        assert_eq!(o.max_output_bytes, 0);
    }

    #[test]
    fn transform_ctx_default_has_no_proxy() {
        let ctx = TransformCtx::default();
        assert!(ctx.proxy.is_none());
    }
}
