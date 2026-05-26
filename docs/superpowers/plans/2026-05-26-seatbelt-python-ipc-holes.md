# macOS Seatbelt POSIX-IPC Holes (Python Compatibility) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Python `multiprocessing` (Lock/Queue) and OpenMP/MKL native libs run under the macOS Seatbelt backend by granting POSIX semaphores unconditionally and POSIX shared memory **narrowly** (only the OpenMP lib name), mirroring Codex.

**Architecture:** The Seatbelt base policy (`seatbelt_base_policy.sbpl`) is `(deny default)` plus a minimal allow-list. POSIX semaphores (`ipc-posix-sem`) are not granted, so `sem_open()` fails with `EPERM` and any `multiprocessing` primitive dies. We grant `ipc-posix-sem` unconditionally, and grant shared memory **only for the Intel-OpenMP registered-lib name** (`(ipc-posix-name-regex #"^/__KMP_REGISTERED_LIB_[0-9]+$")`) — a byte-for-byte copy of Codex's `codex-rs/sandboxing/src/seatbelt_base_policy.sbpl`. This is the smallest shm surface that still lets OpenMP/MKL-threaded native libs run, and it deliberately does **not** open general `multiprocessing.shared_memory` (arbitrary `/psm_*` names stay denied — a Task 3 negative test pins this). Enforcement is proven with TDD against real `python3`.

**Tech Stack:** Rust, `tokio::test`, macOS `sandbox-exec` (SBPL), `python3` (stdlib `multiprocessing`).

---

## Validated finding (why this plan exists)

All rows below were reproduced on macOS with motosan's exact generated policy and verified against the final narrow grant:

| Workload | Needs | Under this plan's grant |
|---|---|---|
| `multiprocessing.Lock()` / `Semaphore()` / `Queue` | `ipc-posix-sem` (unconditional) | ✅ allowed |
| In-process threaded NumPy / pandas (OpenBLAS) | nothing (pthreads, no POSIX IPC) | ✅ already worked, untouched |
| Intel-OpenMP / MKL native libs | shm for `/__KMP_REGISTERED_LIB_*` | ✅ allowed (narrow name) |
| `multiprocessing.shared_memory` (arbitrary `/psm_*`) | unconditional shm create/write/unlink | ❌ **deliberately denied** (Task 3 negative test) |

Decision: we mirror Codex exactly. The unconditional semaphore grant is the load-bearing fix (without it *all* `multiprocessing` fails). Shared memory is opened only for the fixed OpenMP lib name — the smallest useful surface. General `shared_memory` support was rejected in favor of a tighter covert-channel surface; if a real workload needs it, widening the regex is a one-line follow-up.

## Scope

**In scope:** macOS Seatbelt base policy only (the validated gap). The `ipc-posix-sem` + narrow `ipc-posix-shm` grants + enforcement tests (one positive, one negative) + docs.

**Out of scope (documented as follow-ups in Task 4, not implemented here):**
- **General `multiprocessing.shared_memory`** (arbitrary `/psm_*` names) is intentionally **not** supported — it would need an unconditional shm grant (wider covert-channel surface). Task 3 pins it as denied. Widen the name regex later only if a real workload needs it.
- **`multiprocessing.Pool().map()` hangs** even after the semaphore grant — the macOS default `spawn` start method re-execs the interpreter and sets up IPC queues; this needs separate investigation (likely additional Mach/bootstrap surface). The semaphore grant is necessary but not sufficient for full `Pool`.
- **`pseudo-tty`** — Codex's base policy also allows PTY access for interactive tools. Batch financial scripts don't need it; not validated here.
- **Linux parity** — on the Landlock/bwrap path, POSIX semaphores create files under `/dev/shm`, which Landlock governs as filesystem. A parallel gap likely exists but uses a different mechanism and is untested. Track separately.

## File Structure

- `crates/motosan-sandbox/src/seatbelt_base_policy.sbpl` — **modify**: add `ipc-posix-sem` (unconditional) + the narrow `ipc-posix-shm` block.
- `crates/motosan-sandbox/src/seatbelt.rs` — **modify (tests only)**: assert `build_policy` emits the new directives.
- `crates/motosan-sandbox/tests/seatbelt_enforcement.rs` — **modify**: add a positive test (semaphore allowed) and a negative test (general `shared_memory` still denied), both driving real `python3`.
- `crates/motosan-sandbox/README.md` — **modify**: document the IPC allowances + the follow-ups above.

---

### Task 1: Behavioral test — POSIX semaphore must be allowed (TDD red)

**Files:**
- Test: `crates/motosan-sandbox/tests/seatbelt_enforcement.rs` (append)

- [ ] **Step 1: Add a `python3` locator helper + the failing test**

Append to `crates/motosan-sandbox/tests/seatbelt_enforcement.rs`:

```rust
/// Resolve `python3` from PATH, or `None` so the test can skip cleanly on
/// runners without it. (The Seatbelt enforcement suite is macOS-only; CI
/// macOS runners have system python3.)
fn python3() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|c| c.is_file())
}

/// Curated env carrying only PATH — never forward the parent environment.
fn path_env() -> BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    env
}

#[tokio::test]
async fn python_posix_semaphore_is_allowed() {
    let Some(py) = python3() else {
        eprintln!("skip: python3 not on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    let sb = Sandbox::new();
    // ReadOnly is enough: a POSIX semaphore is IPC, not a filesystem write.
    let policy = SandboxPolicy::ReadOnly {
        network: NetworkPolicy::Blocked,
    };
    let out = sb
        .run(
            SandboxCommand {
                program: py.into(),
                args: vec![
                    "-c".into(),
                    "import multiprocessing as mp; mp.Lock(); print('ok')".into(),
                ],
                cwd,
                env: path_env(),
            },
            &policy,
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        out.exit_code,
        Some(0),
        "POSIX semaphore must be allowed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ok"));
}
```

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `cargo test -p motosan-sandbox --test seatbelt_enforcement python_posix_semaphore_is_allowed -- --nocapture`
Expected: FAIL — assertion on `exit_code` fires; stderr contains `PermissionError: [Errno 1] Operation not permitted`.

- [ ] **Step 3: Commit the red test**

```bash
git add crates/motosan-sandbox/tests/seatbelt_enforcement.rs
git commit -m "test(seatbelt): POSIX semaphore denied by base policy (red)"
```

---

### Task 2: Grant POSIX semaphore + shared memory in the base policy (green)

**Files:**
- Modify: `crates/motosan-sandbox/src/seatbelt_base_policy.sbpl`
- Test: `crates/motosan-sandbox/src/seatbelt.rs` (unit test in the `tests` module)

- [ ] **Step 1: Add the IPC allow rules to the base policy**

In `crates/motosan-sandbox/src/seatbelt_base_policy.sbpl`, after the
`(allow mach-lookup)` line and before the filesystem comment block, insert:

```
; --- POSIX IPC. Semaphores (UNCONDITIONAL): required by ALL `multiprocessing`
;     (Lock/Queue) — without this `sem_open()` returns EPERM and any mp dies.
;     Shared memory (NARROW): opened only for the Intel-OpenMP registered-lib
;     name so MKL/libomp-threaded native libs work. General shm (arbitrary
;     /psm_* names, i.e. `multiprocessing.shared_memory`) stays DENIED. NOT
;     needed for in-process threaded NumPy/pandas/OpenBLAS (pthreads, no IPC).
;     Byte-for-byte copy of Codex's seatbelt base policy
;     (codex-rs/sandboxing/src/seatbelt_base_policy.sbpl). ---
(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data
  ipc-posix-shm-write-create
  ipc-posix-shm-write-unlink
  (ipc-posix-name-regex #"^/__KMP_REGISTERED_LIB_[0-9]+$"))
```

The file should then read, in full:

```
(version 1)
(deny default)

; --- process & IPC basics needed to exec almost anything ---
(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow mach-lookup)

; --- POSIX IPC. Semaphores (UNCONDITIONAL): required by ALL `multiprocessing`
;     (Lock/Queue) — without this `sem_open()` returns EPERM and any mp dies.
;     Shared memory (NARROW): opened only for the Intel-OpenMP registered-lib
;     name so MKL/libomp-threaded native libs work. General shm (arbitrary
;     /psm_* names, i.e. `multiprocessing.shared_memory`) stays DENIED. NOT
;     needed for in-process threaded NumPy/pandas/OpenBLAS (pthreads, no IPC).
;     Byte-for-byte copy of Codex's seatbelt base policy
;     (codex-rs/sandboxing/src/seatbelt_base_policy.sbpl). ---
(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data
  ipc-posix-shm-write-create
  ipc-posix-shm-write-unlink
  (ipc-posix-name-regex #"^/__KMP_REGISTERED_LIB_[0-9]+$"))

; --- whole filesystem is READABLE; writes are governed by appended rules ---
(allow file-read*)

; --- always allow writing to the bit bucket ---
(allow file-write-data (literal "/dev/null"))
```

- [ ] **Step 2: Verify the behavioral test from Task 1 now PASSES**

Run: `cargo test -p motosan-sandbox --test seatbelt_enforcement python_posix_semaphore_is_allowed -- --nocapture`
Expected: PASS — stdout contains `ok`.

- [ ] **Step 3: Add a unit test pinning the directives in the generated policy**

In `crates/motosan-sandbox/src/seatbelt.rs`, inside `mod tests`, add:

```rust
#[test]
fn base_policy_grants_posix_ipc() {
    let (text, _) = build_policy(
        &SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Blocked,
        },
        None,
    )
    .unwrap();
    assert!(
        text.contains("(allow ipc-posix-sem)"),
        "base policy must grant POSIX semaphores for Python multiprocessing"
    );
    // Shared memory is granted, but NARROWLY — only for the OpenMP lib name.
    assert!(
        text.contains("ipc-posix-shm-write-create"),
        "base policy must grant shm create for OpenMP/MKL native libs"
    );
    assert!(
        text.contains("__KMP_REGISTERED_LIB_"),
        "shm grant must stay restricted to the OpenMP lib name (not general /psm_*)"
    );
}
```

- [ ] **Step 4: Run the unit test to verify it PASSES**

Run: `cargo test -p motosan-sandbox --lib seatbelt::tests::base_policy_grants_posix_ipc`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/motosan-sandbox/src/seatbelt_base_policy.sbpl crates/motosan-sandbox/src/seatbelt.rs
git commit -m "feat(seatbelt): grant POSIX sem + shm IPC in base policy for Python compat"
```

---

### Task 3: Negative test — general `shared_memory` must STAY denied

The shm grant is narrow (OpenMP lib name only). Python's general
`multiprocessing.shared_memory` uses random `/psm_*` names, which the narrow
grant does NOT cover, so it must still be denied. This test pins that
deliberate scope decision so a future "let's just allow all shm" change can't
silently widen the surface. Because it asserts *current* behavior, it passes
immediately after Task 2 — there is no red phase.

**Files:**
- Test: `crates/motosan-sandbox/tests/seatbelt_enforcement.rs` (append)

- [ ] **Step 1: Add the negative enforcement test**

Append to `crates/motosan-sandbox/tests/seatbelt_enforcement.rs` (reuses the
`python3()` and `path_env()` helpers from Task 1):

```rust
/// The narrow shm grant covers only the OpenMP lib name. General
/// `multiprocessing.shared_memory` (random `/psm_*` names) must STAY denied —
/// this pins the deliberate scope decision (see plan §Scope). NOTE: Apple's
/// `python3` shim prints a harmless `xcrun ... Operation not permitted` banner
/// on stderr even on success, so we assert on the distinctive `/psm_*` name +
/// a non-zero exit, NOT on the generic "Operation not permitted" string.
#[tokio::test]
async fn python_general_shared_memory_stays_denied() {
    let Some(py) = python3() else {
        eprintln!("skip: python3 not on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    let sb = Sandbox::new();
    let policy = SandboxPolicy::ReadOnly {
        network: NetworkPolicy::Blocked,
    };
    // SharedMemory(create=True) calls shm_open(O_CREAT) on a /psm_* name,
    // which the narrow OpenMP-only grant does not cover.
    let script = "import multiprocessing.shared_memory as sm; \
                  sm.SharedMemory(create=True, size=64); print('UNEXPECTED ok')";
    let out = sb
        .run(
            SandboxCommand {
                program: py.into(),
                args: vec!["-c".into(), script.into()],
                cwd,
                env: path_env(),
            },
            &policy,
            RunOpts::default(),
        )
        .await
        .unwrap();
    assert_ne!(
        out.exit_code,
        Some(0),
        "general shared_memory must stay denied; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("psm_"),
        "expected the POSIX shared-memory (/psm_*) denial; stderr: {stderr}"
    );
}
```

- [ ] **Step 2: Run the test to verify it PASSES**

Run: `cargo test -p motosan-sandbox --test seatbelt_enforcement python_general_shared_memory_stays_denied -- --nocapture`
Expected: PASS — the child exits non-zero and stderr carries
`PermissionError: [Errno 1] Operation not permitted: '/psm_…'`. (Ignore the
separate `xcrun ... couldn't create cache file` banner — it is harmless and
present on passing runs too; that is exactly why the assertion keys on `psm_`.)

- [ ] **Step 3: Commit**

```bash
git add crates/motosan-sandbox/tests/seatbelt_enforcement.rs
git commit -m "test(seatbelt): general shared_memory stays denied under narrow shm grant"
```

---

### Task 4: Document the IPC allowances and the known follow-ups

**Files:**
- Modify: `crates/motosan-sandbox/README.md`

- [ ] **Step 1: Add a "macOS IPC allowances" subsection under "Security notes"**

In `crates/motosan-sandbox/README.md`, under the `## Security notes` section,
append this bullet and note block:

```markdown
- **macOS grants POSIX semaphores, and shared memory narrowly.** The Seatbelt
  base policy allows `ipc-posix-sem` **unconditionally** — required by all
  `multiprocessing` (Lock/Queue); without it `sem_open()` returns `EPERM` and
  any `multiprocessing` use dies. Shared memory is granted **only** for the
  Intel-OpenMP registered-lib name (`^/__KMP_REGISTERED_LIB_[0-9]+$`), so
  MKL/libomp-threaded native libs work. (In-process threaded NumPy / pandas /
  OpenBLAS needs neither — it uses pthreads, no POSIX IPC.) This is a
  byte-for-byte copy of Codex's base policy. The semaphore grant is a local IPC
  channel, but opens no network egress and no filesystem-escape path — an
  exfiltration vector only if a colluding process already runs on the host,
  outside the untrusted-script threat model.

> **Known macOS limitations (tracked, not yet fixed):**
> - **General `multiprocessing.shared_memory` is denied by design.** It uses
>   arbitrary `/psm_*` names not covered by the narrow OpenMP-only shm grant.
>   Supporting it needs an unconditional shm grant (wider covert-channel
>   surface); widen the name regex only if a real workload requires it.
> - `multiprocessing.Pool()` still hangs: macOS uses the `spawn` start method,
>   which re-execs the interpreter and sets up IPC queues needing further
>   Seatbelt surface. Semaphore-only primitives (Lock/Queue) work.
> - PTY (`pseudo-tty`) is not granted; interactive TTY tools may misbehave.
> - Linux parity for POSIX IPC (`/dev/shm` under Landlock) is not yet addressed.
```

- [ ] **Step 2: Commit**

```bash
git add crates/motosan-sandbox/README.md
git commit -m "docs(seatbelt): document POSIX IPC allowances and known follow-ups"
```

---

### Task 5: Full verification

- [ ] **Step 1: Run the whole macOS enforcement suite**

Run: `cargo test -p motosan-sandbox --test seatbelt_enforcement`
Expected: all tests PASS (the two new Python tests skip cleanly only if `python3` is absent).

- [ ] **Step 2: Run lib unit tests + clippy + fmt**

Run:
```bash
cargo test -p motosan-sandbox --lib
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```
Expected: all green, no warnings, no fmt diff.

- [ ] **Step 3: Confirm no other backend regressed**

Run: `cargo test --all-features`
Expected: PASS (Linux-only tests are `#[cfg]`-skipped on macOS and vice versa).

---

## Self-Review

- **Spec coverage:** the validated gap (POSIX semaphore denial) → Tasks 1–2; the related shm grant → Task 3; documentation + honest scoping of the three follow-ups → Task 4; verification → Task 5. The Pool-hang, pseudo-tty, and Linux parity are explicitly out of scope and recorded, not silently dropped.
- **Type consistency:** `python3()` and `path_env()` are defined once in Task 1 and reused in Task 3; `build_policy` signature matches `crates/motosan-sandbox/src/seatbelt.rs:28`; `SandboxPolicy::ReadOnly { network }`, `NetworkPolicy::Blocked`, `SandboxCommand`, `RunOpts::default()` match the public API in `lib.rs`.
- **No placeholders:** every code and command step is concrete.
