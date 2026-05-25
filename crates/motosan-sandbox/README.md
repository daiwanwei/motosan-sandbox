# motosan-sandbox

Run a command under a filesystem/network policy. Decoupled from any agent/LLM —
it only knows "run this command under this policy."

**Status:** Phase 1 — core API + macOS Seatbelt + Linux Landlock/seccomp.
Network is on/off; the allowlist proxy is Phase 2.

## Platform selection

Platform is chosen by the compile target (`cfg(target_os)`), **not** by Cargo
features. There is no `macos`/`linux` feature. Features are reserved for optional
*capabilities* (`cancellation`; `proxy` lands in Phase 2).

## Quick start

```rust
use motosan_sandbox::{Sandbox, SandboxCommand, SandboxPolicy, NetworkPolicy, WorkspaceWrite, RunOpts};
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<(), motosan_sandbox::Error> {
    // Call this at the very top of main() so the self-reexec hook is stable
    // across phases. No-op in Phase 0.
    motosan_sandbox::helper::run_if_invoked();

    let sb = Sandbox::new();
    // macOS resolves /var → /private/var; canonicalize roots before policy use.
    let workspace = std::path::PathBuf::from("/path/to/workspace")
        .canonicalize()
        .unwrap();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![workspace.clone()])
            .network(NetworkPolicy::Blocked),
    );

    // SECURITY: pass a curated env — never forward the whole parent environment.
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") { env.insert("PATH".into(), p); }

    let out = sb.run(
        SandboxCommand { program: "ls".into(), args: vec!["-la".into()],
                         cwd: workspace, env },
        &policy,
        RunOpts::default(),
    ).await?;

    println!("exit={:?}\n{}", out.exit_code, String::from_utf8_lossy(&out.stdout));
    Ok(())
}
```

## Security notes

- **Curate the environment.** `SandboxCommand::env` is passed verbatim; never set
  it to `std::env::vars_os()` — that leaks secrets into the command.
- **Don't mark `.git` read-only.** It breaks `git commit` inside the sandbox.
  `read_only_subpaths` is for secret material.
- **macOS paths are resolved.** Canonicalize writable roots (`/var` →
  `/private/var`) before building a policy.
- macOS `sandbox-exec` is deprecated by Apple but still functional; tracked risk.

## Linux (Phase 1)

`run()` enforces on Linux via **Landlock** (filesystem: read-everywhere, write
confined to `writable_roots`) + **seccomp** (network: denies `AF_INET`/`AF_INET6`
socket creation when blocked). No bubblewrap. Requires kernel ≥ 5.13; if Landlock
can't be enforced, `run()` returns `Error::NotEnforced` (never runs unsandboxed).

Consumers MUST call `motosan_sandbox::helper::run_if_invoked()` as the first line
of `main()` (self-reexec); otherwise Linux sandboxing silently won't engage.

Pass **canonical** `writable_roots` — Landlock matches the *resolved* path (e.g.
`/var` → `/private/var` on macOS; symlinked roots on Linux), so canonicalize
roots before building the policy or writes inside them may be denied. (Same
requirement as macOS.)

Limitations vs macOS: `read_only_subpaths` is **not supported** on Linux
(Landlock is allow-only) — a policy that sets it returns `Error::Unsupported`.
Files remain readable (only writes are confined), same as macOS Phase 0.

## Using with motosan-agent-loop (validated by the integration spike)

`motosan-sandbox` plugs into `motosan-agent-loop` with no loop-core changes:
expose execution as a `Tool` (`call()` → `Sandbox::run()`) and put approval in a
consumer `Extension`. See `tests/loop_integration.rs` for the proven pattern.

Three contract notes the spike surfaced:
- **Escalation is reissue, not Defer.** A denied command → inject a hint → the
  model re-calls with `escalated:true` → the same Tool runs `DangerFullAccess`.
  `ToolDecision::Defer` *skips* the tool, so reserve it for human-gating.
- **Encode the denial in the `ToolResult`.** An `Extension` only sees a
  `ToolResult`, not the `ExecOutput`, so the Tool must compute
  `is_likely_sandbox_denied` and stamp the verdict (the spike uses a sentinel).
- **`Defer` + background `ExtensionResume` needs `.ops(rx)` — and it's
  version-sensitive.** On published `motosan-agent-loop` 0.22.1 (what the spike
  built against), resolving a `Defer` via a background-task
  `AgentOp::ExtensionResume` without an external ops channel aborts with
  `Defer call '<id>' aborted: no ops channel`; pass
  `agent.run(...).ops(rx).result().await`. On 0.22.2+ this requirement may not
  apply (the loop's own resume test passes without `.ops()` there). **Pin to the
  loop version you ship against and re-verify.** Escalation via *reissue* (note 1)
  has no such version dependency — prefer it.
