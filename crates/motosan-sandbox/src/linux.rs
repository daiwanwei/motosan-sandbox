//! Linux enforcement: apply seccomp (network) + Landlock (filesystem) to the
//! current process, then exec the target. Reached only via the re-exec helper
//! (`helper::run_if_invoked`). All failures exit with a reserved code + a stderr
//! sentinel so the parent's `classify_helper_exit` can surface them.
//!
//! Phase 3: this file also dispatches the two-stage `Proxied` flow:
//! - `ProxiedOuter`: build the bwrap argv (mount + user + pid + net
//!   namespaces) and `execv(bwrap, …)`. The inner command is THIS helper
//!   binary re-invoked in `ProxiedInner` mode, then the target.
//! - `ProxiedInner` (inside bwrap): bring `lo` up, bind a loopback listener
//!   per route, `fork()` a sync bridge child that survives `execvp`,
//!   install `no_new_privs` + `ProxyRouted` seccomp, rewrite proxy env vars,
//!   then `execvp` the target.
//!
//! Detection: the parent → outer stage uses the Phase-1 `arg0 == HELPER_ARG0`
//! sentinel (set by `tokio::process::Command::arg0` in `spawn_and_capture`).
//! The bwrap → inner stage uses the env marker `MOTOSAN_SANDBOX_STAGE=inner`
//! because bwrap rewrites `argv[0]` to the inner program path — so the
//! sentinel does NOT survive bwrap.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use crate::linux_bridge::{bind_route_listeners, serve_bridges_forever};
use crate::linux_bwrap::{build_bwrap_argv, find_bwrap};
use crate::reexec::{
    HelperMode, HelperPolicy, ProxyRouteSpec, HELPER_ARG0, HELPER_EXIT_BAD_POLICY,
    HELPER_EXIT_EXEC_FAILED, HELPER_EXIT_NOT_ENFORCED, POLICY_ENV, STAGE_ENV, STAGE_INNER,
};

/// Called by `helper::run_if_invoked()`. Returns immediately if this process
/// is NOT a sandbox re-exec; otherwise dispatches on the (arg0, stage-env,
/// HelperMode) tuple and never returns under normal operation.
pub(crate) fn run_if_invoked() {
    // Detection: either the arg0 sentinel (parent → Landlock / ProxiedOuter)
    // or the inner stage marker (bwrap → ProxiedInner). bwrap rewrites
    // `argv[0]`, so the sentinel doesn't survive — we MUST check the env.
    let mut argv = std::env::args_os();
    let arg0 = argv.next();
    let is_helper_arg0 = arg0.as_deref() == Some(std::ffi::OsStr::new(HELPER_ARG0));
    let is_inner_stage = std::env::var(STAGE_ENV).ok().as_deref() == Some(STAGE_INNER);
    if !is_helper_arg0 && !is_inner_stage {
        return;
    }

    // On the inner-stage branch bwrap has rewritten `argv[0]`, so the rest
    // of argv is already `[real_program, real_args...]`. On the
    // outer/Landlock branch the same shape holds — the sentinel we just
    // consumed was the override.
    let parts: Vec<OsString> = argv.collect();

    let helper = match std::env::var(POLICY_ENV) {
        Ok(json) => match serde_json::from_str::<HelperPolicy>(&json) {
            Ok(h) => h,
            Err(e) => die(HELPER_EXIT_BAD_POLICY, &format!("bad policy json: {e}")),
        },
        Err(e) => die(
            HELPER_EXIT_BAD_POLICY,
            &format!("missing {POLICY_ENV}: {e}"),
        ),
    };

    match helper.mode {
        HelperMode::Landlock { network_blocked } => run_landlock(parts, &helper, network_blocked),
        HelperMode::ProxiedOuter { ref route_spec } => {
            run_proxied_outer(parts, &helper, route_spec.clone())
        }
        HelperMode::ProxiedInner { ref route_spec } => {
            run_proxied_inner(parts, route_spec.clone())
        }
    }
}

/// Phase 1: Landlock + (optional) seccomp, then `execvp(target)`. Unchanged
/// from the pre-Phase-3 implementation.
fn run_landlock(parts: Vec<OsString>, helper: &HelperPolicy, network_blocked: bool) -> ! {
    if parts.is_empty() {
        die(HELPER_EXIT_BAD_POLICY, "no command to run");
    }

    // 1. no_new_privs (required for seccomp without CAP_SYS_ADMIN).
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is documented to take
    // four unused args after the option; we pass zeros as required. No
    // memory is dereferenced. Caller is single-threaded.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die(
            HELPER_EXIT_NOT_ENFORCED,
            "prctl(PR_SET_NO_NEW_PRIVS) failed",
        );
    }
    // 2. seccomp (network).
    if network_blocked {
        if let Err(e) = install_network_seccomp() {
            die(
                HELPER_EXIT_NOT_ENFORCED,
                &format!("seccomp install failed: {e}"),
            );
        }
    }
    // 3. Landlock (filesystem). Fail loud if not enforced.
    if let Err(e) = install_landlock(&helper.writable_roots) {
        die(HELPER_EXIT_NOT_ENFORCED, &format!("landlock failed: {e}"));
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

/// Phase 3 outer stage: rewrite the helper policy as `ProxiedInner`, build
/// the bwrap argv, and `execv(bwrap, …)`. Never returns.
///
/// All IPC to the inner stage goes through env vars (`POLICY_ENV` +
/// `STAGE_ENV`) because bwrap inherits the env reliably, but rewrites
/// `argv[0]`. We do NOT rely on bwrap `--argv0` (version-dependent).
fn run_proxied_outer(parts: Vec<OsString>, helper: &HelperPolicy, _route_spec: ProxyRouteSpec) -> ! {
    if parts.is_empty() {
        die(HELPER_EXIT_BAD_POLICY, "no command to run");
    }

    let bwrap = match find_bwrap() {
        Some(p) => p,
        None => die(HELPER_EXIT_NOT_ENFORCED, "bwrap not found on PATH"),
    };

    // Reserialize as ProxiedInner so the bwrap'd helper takes the inner
    // branch. `into_proxied_inner` only rewrites the mode tag.
    let inner_policy = helper.clone().into_proxied_inner();
    let inner_json = match serde_json::to_string(&inner_policy) {
        Ok(s) => s,
        Err(e) => die(HELPER_EXIT_BAD_POLICY, &format!("reserialize policy: {e}")),
    };
    std::env::set_var(POLICY_ENV, &inner_json);
    std::env::set_var(STAGE_ENV, STAGE_INNER);

    // The inner argv: helper-exe (this binary), then the real program +
    // args. The inner stage detects via STAGE_ENV, not arg0 — bwrap
    // rewrites arg0 anyway.
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => die(
            HELPER_EXIT_NOT_ENFORCED,
            &format!("current_exe: {e}"),
        ),
    };
    let mut inner_argv: Vec<String> = Vec::with_capacity(1 + parts.len());
    inner_argv.push(current_exe.to_string_lossy().into_owned());
    for p in &parts {
        inner_argv.push(p.to_string_lossy().into_owned());
    }

    let argv = build_bwrap_argv(
        &helper.writable_roots,
        &helper.read_only_subpaths,
        &inner_argv,
    );

    // execv(bwrap, [bwrap, argv...]). On failure we exit with EXEC_FAILED.
    let err = Command::new(&bwrap).args(&argv).exec();
    die(
        HELPER_EXIT_EXEC_FAILED,
        &format!("execv bwrap {bwrap:?} failed: {err}"),
    );
}

/// Phase 3 inner stage (inside bwrap): bind loopback listeners, fork the
/// sync bridge child, then `no_new_privs` + `ProxyRouted` seccomp + rewrite
/// proxy env + `execvp(target)`. Never returns.
fn run_proxied_inner(parts: Vec<OsString>, route_spec: ProxyRouteSpec) -> ! {
    if parts.is_empty() {
        die(HELPER_EXIT_BAD_POLICY, "no command to run");
    }

    // 1. Bind loopback listeners BEFORE fork so we know the ports to
    //    advertise via env. (`bind_route_listeners` brings `lo` up first.)
    let bound = match bind_route_listeners(&route_spec) {
        Ok(b) => b,
        Err(e) => die(
            HELPER_EXIT_NOT_ENFORCED,
            &format!("bind loopback listeners: {e}"),
        ),
    };

    // Record the (env_key, port) pairs the parent (= target process) will
    // use to rewrite proxy env vars. Cloning here so we can hand `bound`
    // to the bridge child.
    let env_rewrites: Vec<(String, u16)> = route_spec
        .routes
        .iter()
        .zip(bound.iter())
        .map(|(r, b)| (r.env_key.clone(), b.local_port))
        .collect();

    // 2. Fork. The CHILD becomes the bridge (sync std I/O, AF_UNIX
    //    allowed); the PARENT becomes the target after seccomp + execvp.
    //    `--unshare-pid` (bwrap) makes the parent pid 1; when it exits,
    //    the kernel SIGKILLs the entire pidns, reaping the bridge — no
    //    explicit wait needed (spec §7).
    //
    // SAFETY: fork() in a synchronous, single-threaded helper is well
    // defined. The child inherits all open fds (including the listener
    // sockets in `bound`), then runs ONLY async-signal-safe code paths
    // until it starts threads inside `serve_bridges_forever` (legal
    // because at that point there's no shared state with the parent).
    // The parent never touches `bound` again; it closes its copies of
    // the listener fds implicitly by dropping `bound` below before
    // calling `execvp`. Tokio is NOT present in this binary.
    match unsafe { libc::fork() } {
        -1 => {
            let e = std::io::Error::last_os_error();
            die(HELPER_EXIT_NOT_ENFORCED, &format!("fork bridge: {e}"));
        }
        0 => {
            // Child: serve forever; never returns.
            serve_bridges_forever(bound);
        }
        _ => {
            // Parent: close our copies of the listener fds (dropping
            // `bound` does this) so the target doesn't inherit them.
            drop(bound);
        }
    }

    // 3. Rewrite proxy env to the in-netns loopback bridge.
    for (key, port) in &env_rewrites {
        std::env::set_var(key, format!("http://127.0.0.1:{port}"));
    }
    // Scrub IPC env so the target sees a clean environment (no
    // MOTOSAN_SANDBOX_* leakage).
    std::env::remove_var(POLICY_ENV);
    std::env::remove_var(STAGE_ENV);

    // 4. no_new_privs + ProxyRouted seccomp on the TARGET (the parent of
    //    the fork). The bridge child is unaffected — it already exists.
    // SAFETY: same as the Landlock path — prctl with documented args, no
    // memory dereferenced, single-threaded process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die(
            HELPER_EXIT_NOT_ENFORCED,
            "prctl(PR_SET_NO_NEW_PRIVS) failed",
        );
    }
    if let Err(e) = install_proxy_routed_seccomp() {
        die(
            HELPER_EXIT_NOT_ENFORCED,
            &format!("ProxyRouted seccomp: {e}"),
        );
    }

    // 5. execvp the target. FS is already isolated by bwrap's mount ns.
    let program = &parts[0];
    let err = Command::new(program).args(&parts[1..]).exec();
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
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule, TargetArch,
    };

    let map = |fam: u64| -> Result<SeccompRule, String> {
        SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            fam,
        )
        .map_err(|e| e.to_string())?])
        .map_err(|e| e.to_string())
    };
    let af_inet = libc::AF_INET as u64;
    let af_inet6 = libc::AF_INET6 as u64;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket, vec![map(af_inet)?, map(af_inet6)?]);
    rules.insert(libc::SYS_socketpair, vec![map(af_inet)?, map(af_inet6)?]);

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

/// `ProxyRouted` seccomp filter (Phase 3, spec §6). Distinct from the Phase-1
/// `Blocked` filter: allow `socket`/`socketpair` only for `AF_INET` /
/// `AF_INET6`; deny everything else (notably `AF_UNIX`, so the target can't
/// bypass the bridge by talking to the host UDS directly). Destination
/// filtering is the netns's job — this just controls socket families.
///
/// Applied in the inner stage AFTER the bridge has been forked (the child
/// keeps full socket access, the parent / target inherits this filter), AFTER
/// `no_new_privs`, BEFORE `execvp(target)`.
fn install_proxy_routed_seccomp() -> Result<(), String> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule, TargetArch,
    };

    // socket(domain, ...) is rule[0]; deny when domain != AF_INET AND domain != AF_INET6.
    let not_inet = || -> Result<SeccompRule, String> {
        SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::AF_INET as u64,
            )
            .map_err(|e| e.to_string())?,
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::AF_INET6 as u64,
            )
            .map_err(|e| e.to_string())?,
        ])
        .map_err(|e| e.to_string())
    };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket, vec![not_inet()?]);
    rules.insert(libc::SYS_socketpair, vec![not_inet()?]);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// `install_proxy_routed_seccomp` must at least successfully BUILD the
    /// BPF program (compilation = `try_into`). We can't actually apply it
    /// in this test thread without breaking the rest of the test run, but
    /// build-failure (wrong syscall id, bad rule shape) would surface here.
    #[test]
    fn proxy_routed_seccomp_filter_builds() {
        // Replicate the body up to but not including `apply_filter`.
        use seccompiler::{
            BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
            SeccompFilter, SeccompRule, TargetArch,
        };

        let not_inet = || -> Result<SeccompRule, String> {
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ne,
                    libc::AF_INET as u64,
                )
                .map_err(|e| e.to_string())?,
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ne,
                    libc::AF_INET6 as u64,
                )
                .map_err(|e| e.to_string())?,
            ])
            .map_err(|e| e.to_string())
        };
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(libc::SYS_socket, vec![not_inet().unwrap()]);
        rules.insert(libc::SYS_socketpair, vec![not_inet().unwrap()]);

        let arch = match std::env::consts::ARCH {
            "x86_64" => TargetArch::x86_64,
            "aarch64" => TargetArch::aarch64,
            other => panic!("unsupported test arch: {other}"),
        };
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            arch,
        )
        .expect("filter compose");
        let _prog: BpfProgram = filter.try_into().expect("compile to BPF");
    }
}
