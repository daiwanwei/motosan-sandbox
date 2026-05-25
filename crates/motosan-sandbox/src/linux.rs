//! Linux enforcement: apply seccomp (network) + Landlock (filesystem) to the
//! current process, then exec the target. Reached only via the re-exec helper
//! (`helper::run_if_invoked`). All failures exit with a reserved code + a stderr
//! sentinel so the parent's `classify_helper_exit` can surface them.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use crate::reexec::{
    HelperPolicy, HELPER_ARG0, HELPER_EXIT_BAD_POLICY, HELPER_EXIT_EXEC_FAILED,
    HELPER_EXIT_NOT_ENFORCED, POLICY_ENV,
};

/// Called by `helper::run_if_invoked()`. Returns immediately if this process is
/// NOT a sandbox re-exec; otherwise applies enforcement and `exec`s the target
/// (never returns), or exits with a reserved code on failure.
pub(crate) fn run_if_invoked() {
    // Detection: argv[0] == sentinel.
    let mut argv = std::env::args_os();
    let arg0 = argv.next();
    if arg0.as_deref() != Some(std::ffi::OsStr::new(HELPER_ARG0)) {
        return; // not a helper invocation
    }

    // Remaining argv is [<real program>, <real args>...].
    let parts: Vec<OsString> = argv.collect();
    if parts.is_empty() {
        die(HELPER_EXIT_BAD_POLICY, "no command to run");
    }

    let helper = match std::env::var(POLICY_ENV) {
        Ok(json) => match serde_json::from_str::<HelperPolicy>(&json) {
            Ok(h) => h,
            Err(e) => die(HELPER_EXIT_BAD_POLICY, &format!("bad policy json: {e}")),
        },
        Err(e) => die(HELPER_EXIT_BAD_POLICY, &format!("missing {POLICY_ENV}: {e}")),
    };

    // 1. no_new_privs (required for seccomp without CAP_SYS_ADMIN).
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die(
            HELPER_EXIT_NOT_ENFORCED,
            "prctl(PR_SET_NO_NEW_PRIVS) failed",
        );
    }
    // 2. seccomp (network).
    if helper.network_blocked {
        if let Err(e) = install_network_seccomp() {
            die(
                HELPER_EXIT_NOT_ENFORCED,
                &format!("seccomp install failed: {e}"),
            );
        }
    }
    // 3. Landlock (filesystem). Fail loud if not enforced.
    if let Err(e) = install_landlock(&helper.writable_roots) {
        die(
            HELPER_EXIT_NOT_ENFORCED,
            &format!("landlock failed: {e}"),
        );
    }

    // Don't leak the IPC var into the target.
    std::env::remove_var(POLICY_ENV);

    // 4. exec the target (argv[0] defaults to the program path — correct arg0).
    let program = &parts[0];
    let err = Command::new(program).args(&parts[1..]).exec(); // only returns on failure
    die(
        HELPER_EXIT_EXEC_FAILED,
        &format!("exec {program:?} failed: {err}"),
    );
}

fn die(code: i32, msg: &str) -> ! {
    eprintln!("motosan-sandbox: {msg}");
    std::process::exit(code);
}

fn install_network_seccomp() -> Result<(), String> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
        SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
    };

    let map = |fam: u64| -> Result<SeccompRule, String> {
        SeccompRule::new(vec![
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, fam)
                .map_err(|e| e.to_string())?,
        ])
        .map_err(|e| e.to_string())
    };
    let af_inet = libc::AF_INET as u64;
    let af_inet6 = libc::AF_INET6 as u64;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(
        libc::SYS_socket as i64,
        vec![map(af_inet)?, map(af_inet6)?],
    );
    rules.insert(
        libc::SYS_socketpair as i64,
        vec![map(af_inet)?, map(af_inet6)?],
    );

    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        other => return Err(format!("unsupported arch: {other}")),
    };
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| e.to_string())?;
    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| e.to_string())?;
    apply_filter(&prog).map_err(|e| e.to_string())
}

fn install_landlock(writable_roots: &[PathBuf]) -> Result<(), String> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };
    let abi = ABI::V5;
    let ro = AccessFs::from_read(abi);
    let rw = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(rw)
        .map_err(|e| e.to_string())?
        .create()
        .map_err(|e| e.to_string())?
        .add_rules(path_beneath_rules(["/"], ro))
        .map_err(|e| e.to_string())?
        .add_rules(path_beneath_rules(["/dev/null"], rw))
        .map_err(|e| e.to_string())?
        .no_new_privs(true);

    if !writable_roots.is_empty() {
        ruleset = ruleset
            .add_rules(path_beneath_rules(writable_roots, rw))
            .map_err(|e| e.to_string())?;
    }

    let status = ruleset.restrict_self().map_err(|e| e.to_string())?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err("Landlock ruleset NotEnforced (kernel too old or disabled)".to_string());
    }
    Ok(())
}
