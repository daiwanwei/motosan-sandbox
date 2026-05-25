//! Integration spike: prove motosan-sandbox plugs into motosan-agent-loop via
//! Tool + Extension with zero loop-core changes. macOS only (Phase 0 enforces
//! via Seatbelt; Linux returns Unsupported).
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use motosan_agent_tool::{Tool, ToolContext, ToolDef, ToolResult};
use serde_json::{json, Value};

use motosan_sandbox::{
    is_likely_sandbox_denied, ExecOutput, NetworkPolicy, RunOpts, Sandbox, SandboxCommand,
    SandboxPolicy, WorkspaceWrite,
};

/// Sentinel the tool stamps into a denied result so an Extension (which only
/// sees a `ToolResult`, never the `ExecOutput`) can recognize a sandbox denial.
/// See design §4.1 — a finding, not a final mechanism.
const DENIED_SENTINEL: &str = "[motosan-sandbox: DENIED]";

/// Allowlisted env — never forward the parent environment into the sandbox.
fn curated_env() -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    env
}

/// Map a sandbox `ExecOutput` to a loop `ToolResult` (free fn: orphan rule
/// forbids `impl From` here, both types are foreign to this test crate).
fn to_tool_result(out: ExecOutput, kind: motosan_sandbox::SandboxKind) -> ToolResult {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let body = format!(
        "exit={:?} timed_out={}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.exit_code, out.timed_out
    );
    if is_likely_sandbox_denied(&out, kind) {
        ToolResult::error(format!("{DENIED_SENTINEL}\n{body}"))
    } else if out.exit_code == Some(0) {
        ToolResult::text(body)
    } else {
        ToolResult::error(body)
    }
}

/// Build the `SandboxCommand` + policy for a `{command, escalated}` arg object.
// `&Path` (not `&PathBuf`) — clippy::ptr_arg would reject `&PathBuf` under
// `-D warnings`, and `.to_path_buf()` is the correct owned-clone (`.clone()` on
// a `&Path` would clone the reference, not the path).
fn command_and_policy(args: &Value, workspace: &Path) -> Option<(SandboxCommand, SandboxPolicy)> {
    let command: Vec<String> = serde_json::from_value(args.get("command")?.clone()).ok()?;
    if command.is_empty() {
        return None;
    }
    let escalated = args
        .get("escalated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let policy = if escalated {
        SandboxPolicy::DangerFullAccess
    } else {
        SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec![workspace.to_path_buf()]).network(NetworkPolicy::Blocked),
        )
    };
    let cmd = SandboxCommand {
        program: command[0].clone().into(),
        args: command[1..].iter().map(Into::into).collect(),
        cwd: workspace.to_path_buf(),
        env: curated_env(),
    };
    Some((cmd, policy))
}

/// The execution tool: runs a `shell` command under the sandbox.
struct SandboxedExecTool {
    sandbox: Sandbox,
    workspace: PathBuf,
}

impl Tool for SandboxedExecTool {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: "shell".into(),
            description: "Run a shell command in the sandboxed workspace.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "command": { "type": "array", "items": { "type": "string" } },
                    "escalated": { "type": "boolean" }
                },
                "required": ["command"]
            }),
        }
    }

    fn call(
        &self,
        args: Value,
        _ctx: &ToolContext,
    ) -> Pin<Box<dyn Future<Output = ToolResult> + Send + '_>> {
        Box::pin(async move {
            let Some((cmd, policy)) = command_and_policy(&args, &self.workspace) else {
                return ToolResult::error("missing/invalid `command`");
            };
            match self.sandbox.run(cmd, &policy, RunOpts::default()).await {
                Ok(out) => to_tool_result(out, Sandbox::detect()),
                Err(e) => ToolResult::error(format!("sandbox run failed: {e}")),
            }
        })
    }
}

/// A canonicalized temp workspace (macOS /var → /private/var).
fn workspace() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

#[tokio::test]
async fn tool_runs_command_under_sandbox_directly() {
    // No engine yet — just prove the Tool wrapper executes via the sandbox.
    let (_guard, ws) = workspace();
    let tool = SandboxedExecTool {
        sandbox: Sandbox::new(),
        workspace: ws.clone(),
    };
    let res = tool
        .call(
            json!({ "command": ["/bin/sh", "-c", "echo hi > inside.txt"] }),
            &ToolContext::new("t", "spike"),
        )
        .await;
    assert!(!res.is_error, "got: {:?}", res.as_text());
    assert!(ws.join("inside.txt").exists());
}
