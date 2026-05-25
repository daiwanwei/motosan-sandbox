//! Integration spike: prove motosan-sandbox plugs into motosan-agent-loop via
//! Tool + Extension with zero loop-core changes. macOS only (Phase 0 enforces
//! via Seatbelt; Linux returns Unsupported).
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use motosan_agent_tool::{Tool, ToolContext, ToolDef, ToolResult};
use serde_json::{json, Value};

use motosan_agent_loop::testing::MockLlmClient;
use motosan_agent_loop::{
    Engine, ExtError, Extension, FlowDecision, HookCtx, LlmClient, LlmResponse, Message,
    ToolCallItem, ToolDecision,
};

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

#[tokio::test]
async fn engine_dispatches_tool_and_runs_inside_workspace() {
    let (_guard, ws) = workspace();
    let tool = SandboxedExecTool {
        sandbox: Sandbox::new(),
        workspace: ws.clone(),
    };

    let llm = Arc::new(MockLlmClient::new(vec![
        LlmResponse::single_tool_call(
            "c1".into(),
            "shell".into(),
            json!({ "command": ["/bin/sh", "-c", "echo hi > inside.txt"] }),
        ),
        LlmResponse::Message("done".into()),
    ]));

    let agent = Arc::new(
        Engine::builder()
            .tool(Arc::new(tool))
            .max_iterations(4)
            .build(),
    );

    let result = agent
        .run(llm as Arc<dyn LlmClient>, vec![Message::user("write a file")])
        .result()
        .await
        .unwrap();

    assert_eq!(result.answer, "done");
    assert!(
        ws.join("inside.txt").exists(),
        "tool should have written inside the workspace"
    );
}

#[tokio::test]
async fn engine_tool_denied_writing_outside_workspace() {
    let (_guard, ws) = workspace();
    let (_other_guard, other) = workspace(); // outside the writable root
    let escape = other.join("escape.txt");
    let tool = SandboxedExecTool {
        sandbox: Sandbox::new(),
        workspace: ws.clone(),
    };

    let llm = Arc::new(MockLlmClient::new(vec![
        LlmResponse::single_tool_call(
            "c1".into(),
            "shell".into(),
            json!({ "command": ["/bin/sh", "-c", format!("echo x > {}", escape.display())] }),
        ),
        LlmResponse::Message("acknowledged".into()),
    ]));

    let agent = Arc::new(
        Engine::builder()
            .tool(Arc::new(tool))
            .max_iterations(4)
            .build(),
    );

    let result = agent
        .run(
            llm as Arc<dyn LlmClient>,
            vec![Message::user("write outside")],
        )
        .result()
        .await
        .unwrap();

    // The run completes (the model gets the denied result back and says its line)…
    assert_eq!(result.answer, "acknowledged");
    // …but the sandbox actually blocked the write. This is the load-bearing
    // assertion: real Seatbelt denied an out-of-root write end-to-end.
    assert!(
        !escape.exists(),
        "write outside the workspace must be denied"
    );
}

/// Consumer-side approval: when a result carries the sandbox-denied sentinel,
/// inject a hint so the model can re-request with `escalated:true` (reissue —
/// NOT Defer; see design §4).
#[derive(Default)]
struct SandboxApprovalExtension {
    injections: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Extension for SandboxApprovalExtension {
    fn name(&self) -> &'static str {
        "sandbox-approval"
    }

    async fn after_tool_result(
        &mut self,
        result: &ToolResult,
        _ctx: &mut HookCtx<'_>,
    ) -> Result<FlowDecision, ExtError> {
        let denied =
            result.is_error && result.as_text().is_some_and(|t| t.contains(DENIED_SENTINEL));
        if denied {
            self.injections.fetch_add(1, Ordering::SeqCst);
            Ok(FlowDecision::Inject(Message::user(
                "That command was blocked by the sandbox. If it genuinely needs \
                 to escape the workspace, call `shell` again with \"escalated\": true.",
            )))
        } else {
            Ok(FlowDecision::Continue)
        }
    }
}

#[tokio::test]
async fn denied_then_reissued_escalated_succeeds() {
    let (_guard, ws) = workspace();
    let (_other_guard, other) = workspace();
    let escape = other.join("escape.txt");
    let escape_cmd = format!("echo x > {}", escape.display());

    let injections = Arc::new(AtomicUsize::new(0));
    let ext = SandboxApprovalExtension {
        injections: Arc::clone(&injections),
    };
    let tool = SandboxedExecTool {
        sandbox: Sandbox::new(),
        workspace: ws.clone(),
    };

    let llm = Arc::new(MockLlmClient::new(vec![
        // turn 1: sandboxed write outside → denied
        LlmResponse::single_tool_call(
            "c1".into(),
            "shell".into(),
            json!({ "command": ["/bin/sh", "-c", escape_cmd.clone()] }),
        ),
        // turn 2: after the injected hint, retry escalated → DangerFullAccess
        LlmResponse::single_tool_call(
            "c2".into(),
            "shell".into(),
            json!({ "command": ["/bin/sh", "-c", escape_cmd], "escalated": true }),
        ),
        // turn 3: done
        LlmResponse::Message("done".into()),
    ]));

    let agent = Arc::new(
        Engine::builder()
            .tool(Arc::new(tool))
            .extension(Box::new(ext))
            .max_iterations(6)
            .build(),
    );

    let result = agent
        .run(
            llm as Arc<dyn LlmClient>,
            vec![Message::user("write outside, escalate if needed")],
        )
        .result()
        .await
        .unwrap();

    assert_eq!(result.answer, "done");
    assert_eq!(
        injections.load(Ordering::SeqCst),
        1,
        "denial should inject exactly one hint"
    );
    assert!(
        escape.exists(),
        "escalated (DangerFullAccess) retry should have written the file"
    );
}

// keep references alive for unused imports check until Task 5 adds users
#[allow(dead_code)]
fn _phantom_uses(_a: ToolCallItem, _b: ToolDecision) {}
