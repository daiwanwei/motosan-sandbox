# Financial Sandbox Example Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runnable `cargo run --example financial_sandbox --features proxy` showing the two-phase (provision → run) pattern and the full enforcement matrix (write-confine, deny-read, network allowlist deny + egress wall) against a real untrusted Python strategy.

**Architecture:** An in-repo cargo example (`examples/financial_sandbox.rs`) plus a stdlib-only `examples/strategy.py` embedded via `include_str!` and written into a temp workspace at runtime. Phase A provisions a venv under a PyPI allowlist; Phase B runs the strategy under a tight exchange-allowlist + `deny_read` policy with a `PATH`-only env. The harness propagates the strategy's exit code so a leaked control fails CI; it self-skips (exit 0) when `python3`/`bwrap` are absent.

**Tech Stack:** Rust (tokio, tempfile — existing dev-deps), `motosan-sandbox` (local crate, `proxy` feature), Python 3 stdlib (`urllib`, `socket`, `os`, `json`).

**Spec:** `docs/superpowers/specs/2026-05-26-financial-sandbox-example-design.md`.

---

## File Structure

- `crates/motosan-sandbox/examples/strategy.py` — **create**: the untrusted strategy, stdlib-only, prints `PASS`/`FAIL` per control and exits non-zero on a leak.
- `crates/motosan-sandbox/examples/financial_sandbox.rs` — **create**: the harness (workspace setup, Phase A/B, exit propagation, graceful skips).
- `.github/workflows/ci.yml` — **modify**: add a smoke step running the example on both OSes.
- `crates/motosan-sandbox/README.md` — **modify**: "Financial sandbox example" section + external git-dep stanza + bwrap-less-Linux caveat.

This example demonstrates the library; it adds no library code. "TDD" here = the example self-asserts (the strategy exits non-zero on a control leak) and the CI smoke step runs it — so running the example IS the test.

---

### Task 1: The untrusted strategy (`strategy.py`)

**Files:**
- Create: `crates/motosan-sandbox/examples/strategy.py`

- [ ] **Step 1: Write the strategy**

Create `crates/motosan-sandbox/examples/strategy.py`:

```python
"""Untrusted 'strategy' run inside the motosan sandbox. Stdlib only.

Prints PASS/FAIL for each enforced control and exits non-zero if any
DETERMINISTIC control failed open (a leak). Check 7 (reach the allowlisted
host) is best-effort and never affects the exit code.
"""
import json
import os
import socket
import sys
import urllib.request

results = []  # (ok: bool, name: str)


def check(name, action, expect_block):
    """expect_block=True → the action SHOULD be denied (PASS if it raises)."""
    try:
        action()
        ok = not expect_block
        detail = "succeeded"
    except Exception as exc:  # noqa: BLE001 - any denial counts
        ok = expect_block
        detail = type(exc).__name__
    results.append((ok, name))
    print(f"{'PASS' if ok else 'FAIL'} {name} ({detail})", flush=True)


# 1. workspace write — allowed
check("workspace-write",
      lambda: open("result.json", "w").write(json.dumps({"ok": 1})),
      expect_block=False)

# 2. write outside the workspace — denied
check("write-confinement",
      lambda: open("/tmp/motosan_escape", "w").write("x"),
      expect_block=True)

# 3. read a normal input file — allowed
check("read-input", lambda: open("input.csv").read(), expect_block=False)

# 4. read the secret — denied by deny_read
check("secret-deny-read", lambda: open(".env").read(), expect_block=True)

# 5. reach a NON-allowlisted host THROUGH the proxy — denied (proxy refuses
#    CONNECT locally; deterministic, no internet needed).
check("net-allowlist-deny",
      lambda: urllib.request.urlopen("https://example.com", timeout=3),
      expect_block=True)

# 6. raw socket to a non-loopback address (bypasses the proxy) — the egress
#    wall blocks it (Seatbelt kernel deny / netns ENETUNREACH). 203.0.113.0/24
#    is TEST-NET-3 (RFC 5737), never routable.
check("direct-egress-wall",
      lambda: socket.create_connection(("203.0.113.1", 80), 2).close(),
      expect_block=True)

# 7. reach the ALLOWLISTED host — best-effort (needs internet), never fatal.
try:
    urllib.request.urlopen("https://api.binance.com/api/v3/ping", timeout=3)
    print("INFO net-allow reached api.binance.com (online)", flush=True)
except Exception as exc:  # noqa: BLE001
    print(f"INFO net-allow best-effort: {type(exc).__name__} "
          "(offline or proxy-gated)", flush=True)

leaked = [name for ok, name in results if not ok]
print(f"--- {len(results) - len(leaked)}/{len(results)} controls held ---",
      flush=True)
sys.exit(1 if leaked else 0)
```

- [ ] **Step 2: Sanity-check the strategy parses**

Run: `python3 -m py_compile crates/motosan-sandbox/examples/strategy.py && echo OK`
Expected: `OK` (no syntax error).

- [ ] **Step 3: Commit**

```bash
git add crates/motosan-sandbox/examples/strategy.py
git commit -m "example(strategy): stdlib untrusted strategy asserting the control matrix"
```

---

### Task 2: The harness (`financial_sandbox.rs`)

**Files:**
- Create: `crates/motosan-sandbox/examples/financial_sandbox.rs`

- [ ] **Step 1: Write the harness**

Create `crates/motosan-sandbox/examples/financial_sandbox.rs`:

```rust
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
    sb.run(
        SandboxCommand {
            program: program.clone(),
            args: args.iter().map(|s| OsString::from(*s)).collect(),
            cwd: cwd.to_path_buf(),
            env,
        },
        policy,
        RunOpts {
            timeout: Some(Duration::from_secs(30)),
            max_output_bytes: 1 << 20,
            ..Default::default()
        },
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
    let provision = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).network(NetworkPolicy::Proxied {
            allowlist: vec![
                HostPattern::parse("pypi.org"),
                HostPattern::parse("files.pythonhosted.org"),
            ],
        }),
    );
    let mut penv = base_env();
    penv.insert("HOME".into(), ws.clone().into_os_string());
    penv.insert("PIP_CACHE_DIR".into(), ws.join(".cache/pip").into_os_string());
    penv.insert("TMPDIR".into(), ws.join("tmp").into_os_string());

    match run(&sb, &py, &["-m", "venv", ".venv"], &ws, penv.clone(), &provision).await {
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
```

- [ ] **Step 2: Verify it compiles (with and without the proxy feature)**

Run:
```bash
cargo build -p motosan-sandbox --example financial_sandbox --features proxy
cargo build -p motosan-sandbox --example financial_sandbox
```
Expected: both compile (the example references only always-present API; `proxy` is needed at *runtime*, not to compile).

- [ ] **Step 3: Run it for real (macOS dev box)**

Run: `cargo run -p motosan-sandbox --example financial_sandbox --features proxy`
Expected: prints Phase A (venv exit=Some(0)), Phase B matrix with **`PASS`** on all of `workspace-write`, `write-confinement`, `read-input`, `secret-deny-read`, `net-allowlist-deny`, `direct-egress-wall`; an `INFO net-allow …` line; `--- 6/6 controls held ---`; process exit 0.

- [ ] **Step 4: Commit**

```bash
git add crates/motosan-sandbox/examples/financial_sandbox.rs
git commit -m "example(financial_sandbox): two-phase provision+run harness"
```

---

### Task 3: README + CI smoke step

**Files:**
- Modify: `crates/motosan-sandbox/README.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the README section**

In `crates/motosan-sandbox/README.md`, add a top-level section:

```markdown
## Example: financial sandbox

A runnable end-to-end demo of running untrusted strategy code safely:

```bash
cargo run --example financial_sandbox --features proxy
```

It shows the **two-phase** pattern — a permissive *provision* policy (venv +
best-effort `pip`, allowlisted to `pypi.org`) then a tight *run* policy
(allowlisted to `api.binance.com`, with `.env` hidden via `deny_read`, and a
`PATH`-only env) — and a stdlib Python strategy that asserts every control:
workspace-write OK, write-outside denied, secret read denied, non-allowlisted
host denied (through the proxy), and direct egress walled. The strategy exits
non-zero if any control leaks, so the example doubles as a regression check.

Consuming `motosan-sandbox` from your own project:

```toml
[dependencies]
motosan-sandbox = { git = "https://github.com/motosan-dev/motosan-sandbox", features = ["proxy"] }
```

> **Linux note:** the example self-skips on a box without `bwrap`, because both
> features it showcases (`Proxied` egress and `deny_read`) are bwrap-only on
> Linux (`deny_read` is `Unsupported` on the Landlock path by design). It runs
> fully on macOS and on bwrap-equipped Linux.
```

- [ ] **Step 2: Add the CI smoke step**

In `.github/workflows/ci.yml`, after the `cargo test (proxy feature)` step, add:

```yaml
      # Smoke-test the example end-to-end. It exits non-zero only if a
      # deterministic control leaks (real regression guard), and self-skips
      # (exit 0) when python3/bwrap are absent. Both runners have python3;
      # ubuntu provisions bwrap above, so the strategy runs for real there.
      - name: cargo run example (financial_sandbox smoke)
        run: cargo run --example financial_sandbox --features proxy
```

- [ ] **Step 3: Commit**

```bash
git add crates/motosan-sandbox/README.md .github/workflows/ci.yml
git commit -m "docs(readme)+ci: document and smoke-test the financial_sandbox example"
```

---

### Task 4: Full verification

- [ ] **Step 1: Lint + fmt**

Run:
```bash
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```
Expected: clean (examples are included in `--all-targets`).

- [ ] **Step 2: Cross-target Linux compile (example builds on the CI target)**

Run: `cargo clippy --target x86_64-unknown-linux-gnu --all-features --all-targets -- -D warnings`
Expected: clean (the example compiles for Linux; it actually runs on CI-ubuntu).

- [ ] **Step 3: Re-run the example to confirm exit 0**

Run: `cargo run -p motosan-sandbox --example financial_sandbox --features proxy; echo "exit=$?"`
Expected: matrix all `PASS`, `exit=0`.

- [ ] **Step 4: Existing suites still pass**

Run: `cargo test --all-features 2>&1 | tail -5`
Expected: PASS (no regressions; the example is not run by `cargo test`).

Push the branch and let CI run the smoke step on both runners.

---

## Self-Review

- **Spec coverage:** strategy with the 7-row matrix (incl. allowlist-deny-via-proxy + egress-wall split) → Task 1; two-phase harness with PyPI-vs-exchange allowlist contrast, redirected cache dirs, curated env, exit-code propagation, and `python3`/`bwrap` skips → Task 2; README (external git-dep stanza + bwrap-less-Linux caveat) + CI smoke step → Task 3; verification incl. cross-target Linux compile → Task 4. The "propagate strategy exit" decision (spec §Architecture step 6) is `std::process::exit(code)` in Task 2.
- **Placeholder scan:** no TBDs; full strategy + harness code; the `pip install packaging` and `api.binance.com` allow-path are intentionally best-effort, not placeholders.
- **Type consistency:** `find_python3`/`base_env`/`run` helpers defined once in Task 2 and used consistently; `run()` returns `Result<ExecOutput, Error>` and every caller matches on `Ok/Err`; policy built via `WorkspaceWrite::new(...).network(...).deny_read(...)` exactly as the (now-merged) API exposes; `HostPattern::parse`, `NetworkPolicy::Proxied { allowlist }`, `RunOpts { timeout, max_output_bytes, ..Default::default() }` all match the public surface. `strategy.py` filename matches the `include_str!` and the planted file the harness runs.
