//! Cross-platform pieces of the Linux re-exec helper protocol: the sentinel,
//! env keys, reserved exit codes, the policy IPC struct, the re-exec request
//! builder, and the exit-code classifier. The actual enforcement (Landlock +
//! seccomp) lives in `linux.rs` (`#[cfg(target_os = "linux")]`).

use crate::error::Error;

/// `argv[0]` the parent sets so the re-exec'd process knows it is the helper.
pub(crate) const HELPER_ARG0: &str = "__motosan_sandbox_helper";
/// Env var carrying the JSON policy across the re-exec boundary.
#[allow(dead_code)]
pub(crate) const POLICY_ENV: &str = "MOTOSAN_SANDBOX_POLICY";

// Reserved exit codes the helper uses to signal setup failure before the target
// runs. Chosen to avoid 0/1/2/126/127 and the 128+signal range.
pub(crate) const HELPER_EXIT_NOT_ENFORCED: i32 = 121;
pub(crate) const HELPER_EXIT_BAD_POLICY: i32 = 122;
pub(crate) const HELPER_EXIT_EXEC_FAILED: i32 = 123;

/// Map a child exit code to a helper-setup `Error`, or `None` if the code is a
/// genuine command result.
pub(crate) fn classify_helper_exit(code: Option<i32>) -> Option<Error> {
    match code {
        Some(HELPER_EXIT_NOT_ENFORCED) => Some(Error::NotEnforced(
            "landlock/seccomp could not be enforced (see child stderr)".into(),
        )),
        Some(HELPER_EXIT_BAD_POLICY) => Some(Error::Transform(
            "sandbox helper rejected the policy (see child stderr)".into(),
        )),
        Some(HELPER_EXIT_EXEC_FAILED) => Some(Error::Transform(
            "sandbox helper failed to exec the target (see child stderr)".into(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_reserved_codes() {
        assert!(matches!(
            classify_helper_exit(Some(121)),
            Some(Error::NotEnforced(_))
        ));
        assert!(matches!(
            classify_helper_exit(Some(122)),
            Some(Error::Transform(_))
        ));
        assert!(matches!(
            classify_helper_exit(Some(123)),
            Some(Error::Transform(_))
        ));
    }

    #[test]
    fn passes_through_normal_codes() {
        assert!(classify_helper_exit(Some(0)).is_none());
        assert!(classify_helper_exit(Some(1)).is_none());
        assert!(classify_helper_exit(Some(127)).is_none());
        assert!(classify_helper_exit(None).is_none()); // killed by signal
    }
}
