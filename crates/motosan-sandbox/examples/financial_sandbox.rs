//! Financial-style sandbox: run untrusted strategy code under a network
//! allowlist + write confinement + secret deny-read, in two phases.
//!
//! Run: `cargo run --example financial_sandbox --features proxy`
//!
//! Exits 0 when every deterministic control held (or when python3/bwrap are
//! absent and it self-skips); exits non-zero if a control leaked open.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use motosan_sandbox::{
    Error, ExecOutput, HostPattern, NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy,
    WorkspaceWrite,
};

const STRATEGY_PY: &str = include_str!("strategy.py");

fn find_python3() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|c| c.is_file())
}

/// Curated env: PATH only — never forward the parent environment (would leak
/// secrets into the untrusted strategy).
fn base_env() -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    env
}

async fn run(
    sb: &Sandbox,
    program: &OsString,
    args: &[&str],
    cwd: &Path,
    env: BTreeMap<OsString, OsString>,
    policy: &SandboxPolicy,
) -> Result<ExecOutput, Error> {
    // `..Default::default()` is load-bearing WITH the `cancellation` feature
    // (fills the cfg-gated `cancel` field) but reads as `needless_update`
    // WITHOUT it (all remaining fields specified). Allow the lint rather than
    // drop the update (which would be a missing-field error under cancellation)
    // or reassign-after-default (which trips `field_reassign_with_default`).
    #[allow(clippy::needless_update)]
    let opts = RunOpts {
        timeout: Some(Duration::from_secs(30)),
        max_output_bytes: 1 << 20,
        ..Default::default()
    };
    sb.run(
        SandboxCommand {
            program: program.clone(),
            args: args.iter().map(|s| OsString::from(*s)).collect(),
            cwd: cwd.to_path_buf(),
            env,
        },
        policy,
        opts,
    )
    .await
}

#[tokio::main]
async fn main() {
    // Linux self-reexec hook (no-op on macOS). MUST be first.
    motosan_sandbox::helper::run_if_invoked();

    let Some(py) = find_python3() else {
        println!("skip: python3 not found on PATH");
        return; // exit 0
    };
    let py: OsString = py.into_os_string();

    // Workspace + planted files.
    let tmp = tempfile::tempdir().expect("tempdir");
    let ws = tmp.path().canonicalize().expect("canonicalize workspace");
    std::fs::write(ws.join("input.csv"), b"ts,price\n1,100\n").unwrap();
    std::fs::write(ws.join(".env"), b"BINANCE_SECRET=do-not-read\n").unwrap();
    std::fs::write(ws.join("strategy.py"), STRATEGY_PY).unwrap();
    // Redirected dirs must exist before pip writes to them.
    std::fs::create_dir_all(ws.join("tmp")).unwrap();
    std::fs::create_dir_all(ws.join(".cache/pip")).unwrap();

    let sb = Sandbox::new();

    // ---- Phase A: provision (PyPI allowlist) ----
    println!("== Phase A: provision (network allowlist: pypi.org) ==");
    let provision = SandboxPolicy::WorkspaceWrite(WorkspaceWrite::new(vec![ws.clone()]).network(
        NetworkPolicy::Proxied {
            allowlist: vec![
                HostPattern::parse("pypi.org"),
                HostPattern::parse("files.pythonhosted.org"),
            ],
        },
    ));
    let mut penv = base_env();
    penv.insert("HOME".into(), ws.clone().into_os_string());
    penv.insert(
        "PIP_CACHE_DIR".into(),
        ws.join(".cache/pip").into_os_string(),
    );
    penv.insert("TMPDIR".into(), ws.join("tmp").into_os_string());

    match run(
        &sb,
        &py,
        &["-m", "venv", ".venv"],
        &ws,
        penv.clone(),
        &provision,
    )
    .await
    {
        Ok(out) => println!("  venv create exit={:?}", out.exit_code),
        Err(e) => {
            println!("skip: provision unsupported here ({e}). On Linux, `Proxied` needs bwrap — see README.");
            return; // exit 0
        }
    }
    let pip = ws.join(".venv/bin/pip");
    if pip.is_file() {
        let pip_os = pip.into_os_string();
        match run(
            &sb,
            &pip_os,
            &["install", "--no-input", "--quiet", "packaging"],
            &ws,
            penv,
            &provision,
        )
        .await
        {
            Ok(out) => println!("  pip install exit={:?} (best-effort)", out.exit_code),
            Err(e) => println!("  pip install skipped ({e}, best-effort)"),
        }
    }

    // ---- Phase B: run untrusted strategy (exchange allowlist + deny_read) ----
    println!("== Phase B: run strategy (allowlist: api.binance.com, deny_read: .env) ==");
    let run_policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()])
            .network(NetworkPolicy::Proxied {
                allowlist: vec![HostPattern::parse("api.binance.com")],
            })
            .deny_read(ws.join(".env").to_string_lossy().into_owned()),
    );
    let venv_py = ws.join(".venv/bin/python");
    let prog: OsString = if venv_py.is_file() {
        venv_py.into_os_string()
    } else {
        py.clone()
    };

    let out = match run(&sb, &prog, &["strategy.py"], &ws, base_env(), &run_policy).await {
        Ok(out) => out,
        Err(e) => {
            println!("skip: run unsupported here ({e}).");
            return; // exit 0
        }
    };
    print!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
    }
    let code = out.exit_code.unwrap_or(1);
    println!("strategy exit={code} (0 = all deterministic controls held)");
    // `process::exit` skips destructors — drop the TempDir first so repeated
    // runs don't litter $TMPDIR (ws is an independent PathBuf, safe to outlive).
    drop(tmp);
    // Propagate so a leaked control fails the CI smoke step.
    std::process::exit(code);
}
