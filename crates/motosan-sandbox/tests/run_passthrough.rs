#![cfg(unix)]

use motosan_sandbox::{RunOpts, Sandbox, SandboxCommand, SandboxPolicy};
use std::collections::BTreeMap;

fn cmd(program: &str, args: &[&str]) -> SandboxCommand {
    SandboxCommand {
        program: program.into(),
        args: args.iter().map(|s| (*s).into()).collect(),
        cwd: std::env::temp_dir(),
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn run_full_access_executes_command() {
    let sb = Sandbox::new();
    let out = sb
        .run(cmd("/bin/echo", &["from-run"]), &SandboxPolicy::DangerFullAccess, RunOpts::default())
        .await
        .expect("run succeeds");
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "from-run");
}
