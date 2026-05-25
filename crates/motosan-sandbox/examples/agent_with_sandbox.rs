//! Runnable demo of motosan-sandbox inside a motosan-agent-loop agent (macOS).
//! `cargo run --example agent_with_sandbox --features testing` is not needed —
//! it uses the dev-dependency MockLlm, so run with `cargo run --example
//! agent_with_sandbox` from the workspace (macOS only).
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("This example demonstrates Seatbelt enforcement and only runs on macOS.");
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    // Reuse the glue proven in tests/loop_integration.rs. For an example we
    // inline a tiny version: run one allowed command through the sandbox.
    use motosan_sandbox::{
        NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy, WorkspaceWrite,
    };
    use std::collections::BTreeMap;

    let ws = std::env::temp_dir().canonicalize().unwrap();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Blocked),
    );
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    let out = Sandbox::new()
        .run(
            SandboxCommand {
                program: "/bin/echo".into(),
                args: vec!["sandboxed!".into()],
                cwd: ws,
                env,
            },
            &policy,
            RunOpts::default(),
        )
        .await
        .unwrap();
    println!(
        "exit={:?} stdout={}",
        out.exit_code,
        String::from_utf8_lossy(&out.stdout)
    );
}
