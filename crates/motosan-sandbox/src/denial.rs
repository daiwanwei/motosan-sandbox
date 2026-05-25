//! Heuristic: did this output look like a sandbox denial? Used by consumers to
//! decide whether to prompt for escalation. See design §5/§9.2.

use crate::types::{ExecOutput, SandboxKind};

const DENIAL_MARKERS: &[&str] = &[
    "operation not permitted",
    "permission denied",
    "read-only file system",
    "seccomp",
    "sandbox",
    "landlock",
    // Phase 3 (Linux Proxied / bwrap netns): a non-cooperative tool that
    // dials a raw IP in the empty netns fails by routing, not by seccomp.
    // The connect surfaces as ENETUNREACH/EHOSTUNREACH (libc), so we add
    // both substrings. Scope: a normal "connection refused" to an
    // allowed-but-down host is NOT in this set on purpose — that's a
    // legitimate upstream failure, not a sandbox denial.
    "network is unreachable",
    "no route to host",
];

/// Non-sandbox exit codes we must NOT misread as denials.
/// 2 = misuse, 126 = not executable, 127 = not found.
const NON_SANDBOX_CODES: &[i32] = &[2, 126, 127];

/// Best-effort: returns true if `out` looks like the command was blocked by the
/// sandbox. Always false for `SandboxKind::None` or a clean exit.
pub fn is_likely_sandbox_denied(out: &ExecOutput, kind: SandboxKind) -> bool {
    if kind == SandboxKind::None {
        return false;
    }
    if out.exit_code == Some(0) {
        return false;
    }
    if let Some(code) = out.exit_code {
        if NON_SANDBOX_CODES.contains(&code) {
            return false;
        }
    }

    // Linux seccomp denials kill with SIGSYS (signal 31).
    if kind == SandboxKind::LinuxSeccomp && out.signal == Some(31) {
        return true;
    }

    let haystack = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_lowercase();

    DENIAL_MARKERS.iter().any(|m| haystack.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(code: Option<i32>, signal: Option<i32>, stderr: &str) -> ExecOutput {
        ExecOutput {
            exit_code: code,
            signal,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
            timed_out: false,
        }
    }

    #[test]
    fn none_backend_never_denied() {
        let o = out(Some(1), None, "permission denied");
        assert!(!is_likely_sandbox_denied(&o, SandboxKind::None));
    }

    #[test]
    fn clean_exit_not_denied() {
        let o = out(Some(0), None, "permission denied");
        assert!(!is_likely_sandbox_denied(&o, SandboxKind::MacosSeatbelt));
    }

    #[test]
    fn permission_denied_marker_is_denial() {
        let o = out(Some(1), None, "mkdir: Permission denied");
        assert!(is_likely_sandbox_denied(&o, SandboxKind::MacosSeatbelt));
    }

    #[test]
    fn not_found_code_excluded() {
        let o = out(Some(127), None, "command not found");
        assert!(!is_likely_sandbox_denied(&o, SandboxKind::MacosSeatbelt));
    }

    #[test]
    fn sigsys_on_linux_is_denial() {
        let o = out(None, Some(31), "");
        assert!(is_likely_sandbox_denied(&o, SandboxKind::LinuxSeccomp));
    }

    /// Phase 3: a non-cooperative tool dialing a raw IP in the bwrap netns
    /// fails by routing — `ENETUNREACH` → "Network is unreachable". The
    /// classifier must surface this as a sandbox denial so consumers know
    /// to offer escalation.
    #[test]
    fn netns_network_unreachable_is_denial() {
        let o = out(Some(1), None, "connect: Network is unreachable");
        assert!(is_likely_sandbox_denied(&o, SandboxKind::LinuxSeccomp));
    }

    #[test]
    fn netns_no_route_to_host_is_denial() {
        let o = out(Some(1), None, "curl: (7) No route to host");
        assert!(is_likely_sandbox_denied(&o, SandboxKind::LinuxSeccomp));
    }

    /// Negative: a plain "connection refused" (allowed-but-down upstream)
    /// must NOT be classified as a sandbox denial.
    #[test]
    fn connection_refused_is_not_a_sandbox_denial() {
        let o = out(Some(1), None, "connect: Connection refused");
        assert!(!is_likely_sandbox_denied(&o, SandboxKind::LinuxSeccomp));
    }
}
