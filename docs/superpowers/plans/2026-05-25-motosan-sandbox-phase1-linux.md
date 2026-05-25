# motosan-sandbox Phase 1 — Linux backend (Landlock + seccomp) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `Sandbox::run()` actually enforce on Linux (today it returns `Error::Unsupported`) via **Landlock (filesystem) + seccomp (network), no bubblewrap**, behind the re-exec helper machinery whose no-op stub shipped in Phase 0.

**Architecture:** Single re-exec. `transform()`'s Linux arm builds a `SpawnRequest` that runs the helper-exe with a sentinel `arg0`; `helper::run_if_invoked()` detects the sentinel, applies `no_new_privs` + seccomp (deny `AF_INET`/`AF_INET6` socket creation) + Landlock (read `/`, write the roots), then `execvp`s the target. Enforcement lives in a `#[cfg(target_os = "linux")]` module inside `motosan-sandbox`; a tiny `[[bin]]` is the re-exec/test target.

**Authoritative spec:** `docs/superpowers/specs/2026-05-25-motosan-sandbox-phase1-linux-design.md` (this repo, branch `design/motosan-sandbox`, commit `a765eb7`). Read it before starting. This plan implements it.

**Repo:** build in `/Users/daiwanwei/Projects/wade/motosan-sandbox` (Phase 0 + spike already shipped there). Do NOT modify `motosan-agent-loop`.

**Environment / how to run tests:**
- The Linux enforcement tests are `#![cfg(target_os = "linux")]` — they do not run on the macOS dev machine.
- **Iteration loop = Docker**, native `linux/arm64`, run with **`--security-opt seccomp=unconfined --security-opt apparmor=unconfined`** (Docker's default seccomp profile blocks the `landlock_*` syscalls → Landlock would report `NotEnforced` → the skip-guard would fire and every enforcement test would *silently skip*, looking green while testing nothing). One test (`landlock_actually_enforces`) asserts enforcement happened and must FAIL (not skip) if `NotEnforced`, so a fully-skipped suite can't masquerade as success.
- **Source of truth = GitHub Actions `ubuntu-latest`** (bare runner, Landlock-capable kernel, no container seccomp profile to mask Landlock — needs NO bwrap/userns/AppArmor provisioning).
- **macOS** only runs the Phase 0 + spike suites (non-regression) + `clippy` + `fmt`. Do NOT attempt a macOS `--target ...-musl` build (no cross-linker).

**Key API references (these two crates are fiddly — get them right):**

`landlock` (matches Codex's usage):
```rust
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI, path_beneath_rules,
};
let abi = ABI::V5;
let ro = AccessFs::from_read(abi);
let rw = AccessFs::from_all(abi);
let mut ruleset = Ruleset::default()
    .set_compatibility(CompatLevel::BestEffort)
    .handle_access(rw)?
    .create()?
    .add_rules(path_beneath_rules(["/"], ro))?
    .add_rules(path_beneath_rules(["/dev/null"], rw))?
    .set_no_new_privs(true);
if !writable_roots.is_empty() {
    ruleset = ruleset.add_rules(path_beneath_rules(&writable_roots, rw))?;
}
let status = ruleset.restrict_self()?;
// status.ruleset == RulesetStatus::NotEnforced  => fail loud
```

`seccompiler` — **watch the action argument order** (`new(rules, mismatch, match, arch)`):
```rust
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;
let af_inet = libc::AF_INET as u64;    // 2
let af_inet6 = libc::AF_INET6 as u64;  // 10
let domain_is_inet = |fam: u64| -> Result<SeccompRule, _> {
    SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, fam)?])
};
let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
rules.insert(libc::SYS_socket as i64,     vec![domain_is_inet(af_inet)?, domain_is_inet(af_inet6)?]);
rules.insert(libc::SYS_socketpair as i64, vec![domain_is_inet(af_inet)?, domain_is_inet(af_inet6)?]);
let arch = match std::env::consts::ARCH {
    "x86_64" => seccompiler::TargetArch::x86_64,
    "aarch64" => seccompiler::TargetArch::aarch64,
    other => /* exit BAD_POLICY: unsupported arch */,
};
let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch)?;
let prog: BpfProgram = filter.try_into()?;
apply_filter(&prog)?;
```
Rationale (do not deviate): `socket`'s domain is **arg0, a scalar seccomp can inspect**; `connect`/`bind` carry a `sockaddr` *pointer* seccomp cannot deref, so a connect-blocklist would be forced to also block `AF_UNIX` and break local IPC. Deny internet socket *creation* instead.

---

## File map

```
crates/motosan-sandbox/
├── Cargo.toml                    # +[[bin]], +linux-target deps, +serde
├── src/
│   ├── lib.rs                    # Sandbox gains helper_exe + with_helper_exe
│   ├── error.rs                  # +Error::NotEnforced
│   ├── types.rs                  # SpawnRequest gains arg0
│   ├── spawn.rs                  # apply arg0 (unix); classify reserved exit codes
│   ├── transform.rs              # Linux arm builds re-exec request (was Unsupported)
│   ├── reexec.rs   (NEW)         # cross-platform: HelperPolicy IPC, sentinel/env consts,
│   │                             #   build_reexec_request(), classify_helper_exit()
│   ├── linux.rs    (NEW, cfg)    # #[cfg(linux)] enforcement: landlock + seccomp + run_helper
│   ├── helper.rs                 # run_if_invoked(): real Linux impl; no-op elsewhere
│   └── bin/
│       └── motosan-sandbox-helper.rs  (NEW)  # main = run_if_invoked()
└── tests/
    └── linux_enforcement.rs (NEW, cfg linux)  # behavioral suite + must-enforce test
```

**Dependency split (refines spec §2):** `serde` + `serde_json` are **non-gated**
(so the `HelperPolicy` mapping is unit-testable on macOS, which §7 wants);
`landlock` + `seccompiler` + `libc` are Linux-gated (they don't build on macOS).

---

## Task 1: Cargo deps + the helper `[[bin]]` + Error::NotEnforced

**Files:** `crates/motosan-sandbox/Cargo.toml`, `src/bin/motosan-sandbox-helper.rs`, `src/error.rs`

- [ ] **Step 1: Extend Cargo.toml**

Edit `crates/motosan-sandbox/Cargo.toml`. Add the bin target, serde, and the Linux-only deps:

```toml
[[bin]]
name = "motosan-sandbox-helper"
path = "src/bin/motosan-sandbox-helper.rs"

[dependencies]
# ... existing (thiserror, tracing, tokio, tokio-util optional) ...
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4"        # version indicative — pin at implementation
seccompiler = "0.4"     # version indicative — pin at implementation
libc = "0.2"
```

- [ ] **Step 2: Create the helper bin**

Create `crates/motosan-sandbox/src/bin/motosan-sandbox-helper.rs`:

```rust
//! Re-exec / test target for the Linux sandbox helper.
//!
//! When this binary is spawned with the sentinel arg0 + a policy in the env,
//! `run_if_invoked()` applies the sandbox and `execvp`s the real command (never
//! returning). When run directly (no sentinel), it is a no-op that exits 0.
fn main() {
    motosan_sandbox::helper::run_if_invoked();
    // Not invoked as a sandbox helper — nothing to do.
}
```

- [ ] **Step 3: Add `Error::NotEnforced`**

Edit `crates/motosan-sandbox/src/error.rs`, add a variant to the `#[non_exhaustive] enum Error`:

```rust
    /// The Linux sandbox helper could not enforce restrictions (e.g. Landlock
    /// reported NotEnforced — kernel too old or disabled). The command was NOT
    /// run unsandboxed.
    #[error("sandbox could not be enforced: {0}")]
    NotEnforced(String),
```

- [ ] **Step 4: Verify it builds (macOS) and the bin exists**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo build && cargo build --bin motosan-sandbox-helper`
Expected: both compile. (The bin's `main` compiles because `helper::run_if_invoked` already exists from Phase 0.)

- [ ] **Step 5: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/Cargo.toml crates/motosan-sandbox/src/bin/motosan-sandbox-helper.rs crates/motosan-sandbox/src/error.rs
git commit -m "feat(linux): scaffold Phase 1 — helper bin, linux deps, Error::NotEnforced"
```

---

## Task 2: `SpawnRequest.arg0` + spawn applies it + reserved-exit-code classifier

**Files:** `src/types.rs`, `src/spawn.rs`, `src/reexec.rs` (new), `src/lib.rs`

- [ ] **Step 1: Add `arg0` to `SpawnRequest`**

Edit `crates/motosan-sandbox/src/types.rs` — add a field to `SpawnRequest`:

```rust
pub struct SpawnRequest {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: BTreeMap<OsString, OsString>,
    /// Override the child's `argv[0]`. Used by the Linux re-exec helper to set
    /// the sentinel; `None` means default (the program path).
    pub arg0: Option<OsString>,
}
```

Every existing `SpawnRequest { .. }` literal (in `transform.rs`, `seatbelt.rs`,
and tests) must now set `arg0: None`. Update them — search the crate for
`SpawnRequest {` and add `arg0: None,`.

- [ ] **Step 2: Write the failing classifier test**

Create `crates/motosan-sandbox/src/reexec.rs` (cross-platform module — the IPC
and helpers live here so they're unit-testable on macOS):

```rust
//! Cross-platform pieces of the Linux re-exec helper protocol: the sentinel,
//! env keys, reserved exit codes, the policy IPC struct, the re-exec request
//! builder, and the exit-code classifier. The actual enforcement (Landlock +
//! seccomp) lives in `linux.rs` (`#[cfg(target_os = "linux")]`).

use crate::error::Error;

/// `argv[0]` the parent sets so the re-exec'd process knows it is the helper.
pub(crate) const HELPER_ARG0: &str = "__motosan_sandbox_helper";
/// Env var carrying the JSON policy across the re-exec boundary.
pub(crate) const POLICY_ENV: &str = "MOTOSAN_SANDBOX_POLICY";

// Reserved exit codes the helper uses to signal setup failure before the target
// runs. Chosen to avoid 0/1/2/126/127 and the 128+signal range.
pub(crate) const HELPER_EXIT_NOT_ENFORCED: i32 = 121;
pub(crate) const HELPER_EXIT_BAD_POLICY: i32 = 122;
pub(crate) const HELPER_EXIT_EXEC_FAILED: i32 = 123;

/// Map a child exit code to a helper-setup `Error`, or `None` if the code is a
/// genuine command result.
pub(crate) fn classify_helper_exit(code: Option<i32>) -> Option<Error> {
    match code {
        Some(HELPER_EXIT_NOT_ENFORCED) => Some(Error::NotEnforced(
            "landlock/seccomp could not be enforced (see child stderr)".into(),
        )),
        Some(HELPER_EXIT_BAD_POLICY) => Some(Error::Transform(
            "sandbox helper rejected the policy (see child stderr)".into(),
        )),
        Some(HELPER_EXIT_EXEC_FAILED) => Some(Error::Transform(
            "sandbox helper failed to exec the target (see child stderr)".into(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_reserved_codes() {
        assert!(matches!(classify_helper_exit(Some(121)), Some(Error::NotEnforced(_))));
        assert!(matches!(classify_helper_exit(Some(122)), Some(Error::Transform(_))));
        assert!(matches!(classify_helper_exit(Some(123)), Some(Error::Transform(_))));
    }

    #[test]
    fn passes_through_normal_codes() {
        assert!(classify_helper_exit(Some(0)).is_none());
        assert!(classify_helper_exit(Some(1)).is_none());
        assert!(classify_helper_exit(Some(127)).is_none());
        assert!(classify_helper_exit(None).is_none()); // killed by signal
    }
}
```

Add to `crates/motosan-sandbox/src/lib.rs`: `mod reexec;`

- [ ] **Step 3: Apply `arg0` in spawn + classify the exit code**

Edit `crates/motosan-sandbox/src/spawn.rs`. After building `command` and before
`spawn()`, apply the arg0 override on unix:

```rust
    #[cfg(unix)]
    if let Some(arg0) = &req.arg0 {
        use std::os::unix::process::CommandExt;
        command.arg0(arg0);
    }
```

Then, where `ExecOutput` is returned, classify reserved helper exit codes into an
error — but ONLY when this spawn was a Linux helper re-exec (arg0 == sentinel).
Otherwise a passthrough / Seatbelt command that legitimately exits 121–123 would
be misreported. Add `use std::ffi::OsStr;` at the top of `spawn.rs`, then:

```rust
    // Reserved exit codes only mean "helper setup failed" for a Linux helper
    // re-exec (arg0 == sentinel). For any other spawn, 121–123 is a genuine
    // command result and must pass through unchanged.
    if req.arg0.as_deref() == Some(OsStr::new(crate::reexec::HELPER_ARG0)) {
        if let Some(err) = crate::reexec::classify_helper_exit(exit_code) {
            return Err(err);
        }
    }

    Ok(ExecOutput { exit_code, signal, stdout: ..., stderr: ..., timed_out })
```

> The arg0 gate scopes the reserved-code semantics to the helper. A *target*
> command run UNDER the helper that itself exits 121–123 is still ambiguous
> (accepted; spec §3); the child's stderr sentinel disambiguates, and these
> codes are otherwise unused.

- [ ] **Step 4: Run the unit + spawn tests**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --lib reexec && cargo test --lib spawn`
Expected: PASS (classifier tests + existing spawn tests still green; the existing
`output_is_byte_capped` etc. exit with 0/3/4 → not reserved → pass through).

- [ ] **Step 5: clippy + commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
cargo clippy --all-features --all-targets -- -D warnings
git add -A && git commit -m "feat(linux): SpawnRequest.arg0 + reserved-exit-code classifier"
```

---

## Task 3: `HelperPolicy` IPC + mapping (rejects `read_only_subpaths` on Linux)

**Files:** `src/reexec.rs` (extend)

- [ ] **Step 1: Write the failing tests + the mapping**

Append to `crates/motosan-sandbox/src/reexec.rs`:

```rust
use crate::policy::SandboxPolicy;
use std::path::PathBuf;

/// The policy as the re-exec'd helper needs it: which roots are writable and
/// whether network is blocked. Read-everywhere is implicit (Phase 0 semantics).
/// Serialized to JSON in `POLICY_ENV`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HelperPolicy {
    pub writable_roots: Vec<PathBuf>,
    pub network_blocked: bool,
}

impl HelperPolicy {
    /// Build from a `SandboxPolicy`. Errors if the policy uses a feature the
    /// Linux backend cannot express.
    pub(crate) fn from_policy(policy: &SandboxPolicy) -> Result<Self, Error> {
        use crate::policy::NetworkPolicy;
        let network_blocked = policy.network() == NetworkPolicy::Blocked;
        let writable_roots = match policy {
            // DangerFullAccess never reaches the helper (transform passes through).
            SandboxPolicy::DangerFullAccess => Vec::new(),
            SandboxPolicy::ReadOnly { .. } => Vec::new(),
            SandboxPolicy::WorkspaceWrite(w) => {
                if !w.read_only_subpaths.is_empty() {
                    // Landlock is allow-only: you cannot carve a read-only hole
                    // inside a writable root. macOS Seatbelt supports this; Linux
                    // does not. Fail loud rather than silently under-enforce.
                    return Err(Error::Unsupported(crate::SandboxKind::LinuxSeccomp));
                }
                w.writable_roots.clone()
            }
        };
        Ok(Self { writable_roots, network_blocked })
    }
}

#[cfg(test)]
mod ipc_tests {
    use super::*;
    use crate::policy::{NetworkPolicy, WorkspaceWrite};

    #[test]
    fn workspace_write_maps_roots_and_network() {
        let p = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).network(NetworkPolicy::Blocked),
        );
        let h = HelperPolicy::from_policy(&p).unwrap();
        assert_eq!(h.writable_roots, vec![PathBuf::from("/ws")]);
        assert!(h.network_blocked);
    }

    #[test]
    fn read_only_maps_to_no_roots() {
        let h = HelperPolicy::from_policy(&SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Allowed,
        })
        .unwrap();
        assert!(h.writable_roots.is_empty());
        assert!(!h.network_blocked);
    }

    #[test]
    fn read_only_subpaths_rejected() {
        let p = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).read_only("/ws/secret"),
        );
        assert!(matches!(HelperPolicy::from_policy(&p), Err(Error::Unsupported(_))));
    }

    #[test]
    fn json_round_trips() {
        let h = HelperPolicy { writable_roots: vec!["/a".into(), "/b".into()], network_blocked: true };
        let s = serde_json::to_string(&h).unwrap();
        let back: HelperPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(h, back);
    }
}
```

- [ ] **Step 2: Run the tests (macOS — pure, no privileges)**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --lib reexec`
Expected: PASS (4 new tests).

- [ ] **Step 3: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/src/reexec.rs
git commit -m "feat(linux): HelperPolicy IPC + mapping (rejects read_only_subpaths)"
```

---

## Task 4: `Sandbox::with_helper_exe` + `transform()` Linux arm builds the re-exec request

**Files:** `src/lib.rs`, `src/reexec.rs` (extend), `src/transform.rs`

- [ ] **Step 1: Add the re-exec request builder + test**

Append to `crates/motosan-sandbox/src/reexec.rs`:

```rust
use crate::types::{SandboxCommand, SpawnRequest};
use std::ffi::OsString;
use std::path::Path;

/// Build the `SpawnRequest` that re-execs `helper_exe` to enforce + run `cmd`.
/// Pure given `helper_exe`; cross-platform so it is unit-testable on macOS.
pub(crate) fn build_reexec_request(
    cmd: &SandboxCommand,
    helper: &HelperPolicy,
    helper_exe: &Path,
) -> Result<SpawnRequest, Error> {
    let policy_json = serde_json::to_string(helper)
        .map_err(|e| Error::Transform(format!("serialize policy: {e}")))?;

    let mut env = cmd.env.clone();
    env.insert(POLICY_ENV.into(), policy_json.into());
    if helper.network_blocked {
        env.insert(crate::NETWORK_DISABLED_ENV.into(), "1".into());
    }

    // argv layout the helper expects: [<real program>, <real args>...]; arg0 is
    // overridden to the sentinel so run_if_invoked() recognizes the re-exec.
    let mut args: Vec<OsString> = Vec::with_capacity(1 + cmd.args.len());
    args.push(cmd.program.clone());
    args.extend(cmd.args.iter().cloned());

    Ok(SpawnRequest {
        program: helper_exe.as_os_str().to_os_string(),
        args,
        cwd: cmd.cwd.clone(),
        env,
        arg0: Some(HELPER_ARG0.into()),
    })
}

#[cfg(test)]
mod build_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cmd() -> SandboxCommand {
        SandboxCommand {
            program: "/bin/echo".into(),
            args: vec!["hi".into()],
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn builds_reexec_argv_and_env() {
        let helper = HelperPolicy { writable_roots: vec!["/ws".into()], network_blocked: true };
        let req = build_reexec_request(&cmd(), &helper, Path::new("/usr/bin/myhelper")).unwrap();

        assert_eq!(req.program, OsString::from("/usr/bin/myhelper"));
        assert_eq!(req.arg0, Some(OsString::from(HELPER_ARG0)));
        assert_eq!(req.args[0], OsString::from("/bin/echo"));
        assert_eq!(req.args[1], OsString::from("hi"));
        assert!(req.env.contains_key(std::ffi::OsStr::new(POLICY_ENV)));
        assert!(req.env.contains_key(std::ffi::OsStr::new(crate::NETWORK_DISABLED_ENV)));
        // policy JSON round-trips
        let json = req.env.get(std::ffi::OsStr::new(POLICY_ENV)).unwrap().to_string_lossy();
        let parsed: HelperPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, helper);
    }
}
```

- [ ] **Step 2: Add `helper_exe` to `Sandbox` + `with_helper_exe`**

Edit `crates/motosan-sandbox/src/lib.rs`. Replace the `Sandbox` struct + add the
builder (keep `new()`/`Default` infallible — `current_exe()` is resolved lazily
in `transform`, not here):

```rust
#[derive(Debug, Default)]
pub struct Sandbox {
    /// Path to the binary hosting `helper::run_if_invoked()`. `None` → resolve
    /// `std::env::current_exe()` lazily in `transform()` (self-reexec). `Some` →
    /// "external-helper mode" (tests point this at the `motosan-sandbox-helper`
    /// bin).
    helper_exe: Option<std::path::PathBuf>,
}

impl Sandbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use an explicit helper binary instead of `current_exe()`.
    pub fn with_helper_exe(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.helper_exe = Some(path.into());
        self
    }

    // detect() unchanged from Phase 0.
}
```

(`helper_exe` is a private field; `Default` gives `None`. Existing
`Sandbox::new()` / `Sandbox::default()` callers are unaffected — additive.)

- [ ] **Step 3: Wire the Linux arm of `transform()`**

Edit `crates/motosan-sandbox/src/transform.rs`. Replace the `LinuxSeccomp` arm
(currently `Err(Error::Unsupported(..))`) so it builds the re-exec request:

```rust
            SandboxKind::LinuxSeccomp => {
                use crate::reexec::{build_reexec_request, HelperPolicy};
                let helper = HelperPolicy::from_policy(policy)?; // rejects read_only_subpaths
                let helper_exe = match &self.helper_exe {
                    Some(p) => p.clone(),
                    None => std::env::current_exe()
                        .map_err(|e| Error::Transform(format!("resolve current_exe: {e}")))?,
                };
                build_reexec_request(cmd, &helper, &helper_exe)
            }
```

`transform` needs access to `self.helper_exe` — it already takes `&self`. (The
`#[cfg(not(target_os = "macos"))] MacosSeatbelt` arm and the macOS arm are
unchanged from the Phase 0 review fix.)

- [ ] **Step 4: Run tests (macOS — builder + mapping are pure)**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --lib reexec`
Expected: PASS (builder test + earlier mapping/classifier tests).
Also: `cargo test` — Phase 0 + spike suites unaffected (macOS still uses the
Seatbelt arm; transform signature unchanged).

- [ ] **Step 5: clippy + commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
cargo clippy --all-features --all-targets -- -D warnings
git add -A && git commit -m "feat(linux): with_helper_exe + transform() Linux arm builds re-exec request"
```

---

## Task 5: Linux enforcement module (`linux.rs`) — Landlock + seccomp + run_helper

**Files:** `src/linux.rs` (new, `#[cfg(target_os = "linux")]`), `src/lib.rs`

All code here is Linux-only; it compiles in Docker/CI and is `cfg`'d out on macOS.

- [ ] **Step 1: Write `linux.rs`**

Create `crates/motosan-sandbox/src/linux.rs`:

```rust
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
        die(HELPER_EXIT_NOT_ENFORCED, "prctl(PR_SET_NO_NEW_PRIVS) failed");
    }
    // 2. seccomp (network).
    if helper.network_blocked {
        if let Err(e) = install_network_seccomp() {
            die(HELPER_EXIT_NOT_ENFORCED, &format!("seccomp install failed: {e}"));
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
    die(HELPER_EXIT_EXEC_FAILED, &format!("exec {program:?} failed: {err}"));
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
        SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, fam)
            .map_err(|e| e.to_string())?])
        .map_err(|e| e.to_string())
    };
    let af_inet = libc::AF_INET as u64;
    let af_inet6 = libc::AF_INET6 as u64;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket as i64, vec![map(af_inet)?, map(af_inet6)?]);
    rules.insert(libc::SYS_socketpair as i64, vec![map(af_inet)?, map(af_inet6)?]);

    let arch: TargetArch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        other => return Err(format!("unsupported arch: {other}")),
    };
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // mismatch (default): allow everything else
        SeccompAction::Errno(libc::EPERM as u32), // match: deny AF_INET/AF_INET6 socket()
        arch,
    )
    .map_err(|e| e.to_string())?;
    let prog: BpfProgram = filter.try_into().map_err(|e: seccompiler::Error| e.to_string())?;
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
        .set_no_new_privs(true);

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
```

> Notes for the implementer:
> - `path_beneath_rules` may error on a path that doesn't exist; `writable_roots`
>   should exist (the caller's workspace). If a root is missing, `add_rules`
>   returns an error → `die(NOT_ENFORCED)`. Acceptable for MVP.
> - Pin exact `landlock`/`seccompiler` versions and adjust the imports if the API
>   differs slightly (trait names, `TargetArch` casing). The shapes above match
>   the versions Codex uses; verify against the pinned versions in Docker.
>   **clippy runs with `-D warnings`, so TRIM imports too, not just add** — if the
>   pinned `landlock` doesn't need a trait (e.g. `Access`) in scope, an unused
>   `use` will fail the lint. Reconcile the import set to exactly what's used.
> - `set_no_new_privs(true)` on the ruleset is redundant with the `prctl` above —
>   harmless; keep both for clarity.

- [ ] **Step 2: Wire the module (Linux-only)**

Edit `crates/motosan-sandbox/src/lib.rs`, add:

```rust
#[cfg(target_os = "linux")]
mod linux;
```

- [ ] **Step 3: Compile-check**

macOS: `cargo build` (the `linux` module is cfg'd out — confirm nothing else
broke). Linux (Docker): `cargo build` must compile `linux.rs` with the pinned
crate versions. (No runnable assertion yet — Task 7 exercises it.)

- [ ] **Step 4: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/src/linux.rs crates/motosan-sandbox/src/lib.rs
git commit -m "feat(linux): Landlock + seccomp enforcement + run_helper (cfg linux)"
```

---

## Task 6: Real `helper::run_if_invoked()` on Linux

**Files:** `src/helper.rs`

- [ ] **Step 1: Replace the Phase 0 stub body**

Edit `crates/motosan-sandbox/src/helper.rs` so the Linux build delegates to
`linux::run_if_invoked()` while other platforms keep the no-op:

```rust
/// Runs the sandbox helper if this process was re-exec'd as one; otherwise
/// returns immediately. Call this as the FIRST line of `main()`. On non-Linux
/// targets it is a no-op (Phase 0 behavior).
pub fn run_if_invoked() {
    #[cfg(target_os = "linux")]
    crate::linux::run_if_invoked();
}
```

Keep the existing `#[cfg(test)] fn run_if_invoked_is_noop_in_phase0` test, but
note it only proves the no-op on non-Linux; on Linux it still returns when arg0
isn't the sentinel (the test process's arg0 is the test binary, not the
sentinel), so the test stays valid on both.

- [ ] **Step 2: Build both platforms**

macOS: `cargo build` (no-op path). Docker: `cargo build` (delegates to linux).

- [ ] **Step 3: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/src/helper.rs
git commit -m "feat(linux): run_if_invoked() applies enforcement on Linux"
```

---

## Task 7: Linux behavioral integration tests (run in Docker / CI)

**Files:** `tests/linux_enforcement.rs` (new)

- [ ] **Step 1: Write the suite**

Create `crates/motosan-sandbox/tests/linux_enforcement.rs`:

```rust
//! Behavioral Linux enforcement tests. Run in Docker
//! (`--security-opt seccomp=unconfined`) and on CI ubuntu-latest. Exit-code based:
//! "exit 0 where it should fail == sandbox breach".
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use motosan_sandbox::{
    Error, NetworkPolicy, RunOpts, Sandbox, SandboxCommand, SandboxPolicy, WorkspaceWrite,
};

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_motosan-sandbox-helper"))
}

fn sandbox() -> Sandbox {
    Sandbox::new().with_helper_exe(helper_exe())
}

fn workspace() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

fn sh(script: &str, cwd: &std::path::Path) -> SandboxCommand {
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") {
        env.insert("PATH".into(), p);
    }
    SandboxCommand {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: cwd.to_path_buf(),
        env,
    }
}

fn ws_policy(root: &std::path::Path, network: NetworkPolicy) -> SandboxPolicy {
    SandboxPolicy::WorkspaceWrite(WorkspaceWrite::new(vec![root.to_path_buf()]).network(network))
}

/// True if Landlock isn't enforced here (e.g. Docker default seccomp profile
/// blocking landlock_* syscalls, or kernel < 5.13). Used to SKIP — but NOT by
/// `landlock_actually_enforces`, which must fail instead.
async fn landlock_unavailable(sb: &Sandbox, ws: &std::path::Path) -> bool {
    let (_o, other) = workspace();
    let target = other.join("probe.txt");
    let script = format!("echo x > {}", target.display());
    match sb.run(sh(&script, ws), &ws_policy(ws, NetworkPolicy::Blocked), RunOpts::default()).await {
        Err(Error::NotEnforced(_)) => true,
        _ => target.exists(), // if the out-of-root write SUCCEEDED, enforcement isn't happening
    }
}

#[tokio::test]
async fn landlock_actually_enforces() {
    // Guard against a silently-skipped suite: this test MUST prove enforcement,
    // never skip. (In Docker, run with --security-opt seccomp=unconfined.)
    let (_g, ws) = workspace();
    let sb = sandbox();
    assert!(
        !landlock_unavailable(&sb, &ws).await,
        "Landlock not enforced here — run the container with --security-opt seccomp=unconfined; \
         a skipped suite must not be mistaken for success"
    );
}

#[tokio::test]
async fn write_inside_workspace_succeeds() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await { eprintln!("skip: landlock unavailable"); return; }
    let out = sb.run(sh("echo hi > inside.txt", &ws), &ws_policy(&ws, NetworkPolicy::Blocked), RunOpts::default()).await.unwrap();
    assert_eq!(out.exit_code, Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(ws.join("inside.txt").exists());
}

#[tokio::test]
async fn write_outside_workspace_denied() {
    let (_g, ws) = workspace();
    let (_o, other) = workspace();
    let escape = other.join("escape.txt");
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await { eprintln!("skip: landlock unavailable"); return; }
    let out = sb.run(sh(&format!("echo x > {}", escape.display()), &ws), &ws_policy(&ws, NetworkPolicy::Blocked), RunOpts::default()).await.unwrap();
    assert_ne!(out.exit_code, Some(0));
    assert!(!escape.exists());
}

#[tokio::test]
async fn read_outside_workspace_allowed() {
    let (_g, ws) = workspace();
    let (_s, src) = workspace();
    std::fs::write(src.join("data.txt"), b"payload").unwrap();
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await { eprintln!("skip: landlock unavailable"); return; }
    let out = sb.run(sh(&format!("cat {}", src.join("data.txt").display()), &ws), &ws_policy(&ws, NetworkPolicy::Blocked), RunOpts::default()).await.unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "payload");
}

#[tokio::test]
async fn network_blocked() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    if landlock_unavailable(&sb, &ws).await { eprintln!("skip: landlock unavailable"); return; }
    // Use BASH explicitly: `/dev/tcp` is a bash builtin that calls
    // socket(AF_INET)+connect → our seccomp denies socket(AF_INET) → EPERM →
    // nonzero. `/bin/sh` on Debian is dash, which has NO /dev/tcp, so it would
    // exit nonzero for the wrong reason (feature absent, not network blocked).
    // bash is present in the debian rust image and on ubuntu-latest.
    let mut env = BTreeMap::new();
    if let Some(p) = std::env::var_os("PATH") { env.insert("PATH".into(), p); }
    let cmd = SandboxCommand {
        program: "/bin/bash".into(),
        args: vec!["-c".into(), "exec 3<>/dev/tcp/127.0.0.1/9".into()],
        cwd: ws.clone(),
        env,
    };
    let out = sb.run(cmd, &ws_policy(&ws, NetworkPolicy::Blocked), RunOpts::default()).await.unwrap();
    assert_ne!(out.exit_code, Some(0), "network egress should be blocked (socket(AF_INET) denied)");
}

#[tokio::test]
async fn read_only_subpaths_rejected() {
    let (_g, ws) = workspace();
    let sb = sandbox();
    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![ws.clone()]).read_only(ws.join("secret")),
    );
    let err = sb.run(sh("true", &ws), &policy, RunOpts::default()).await.unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)));
}

#[tokio::test]
async fn danger_full_access_runs_unsandboxed() {
    let (_g, ws) = workspace();
    let (_o, other) = workspace();
    let escape = other.join("danger.txt");
    let sb = sandbox();
    // DangerFullAccess is passthrough — even an out-of-root write succeeds.
    let out = sb.run(sh(&format!("echo x > {}", escape.display()), &ws), &SandboxPolicy::DangerFullAccess, RunOpts::default()).await.unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert!(escape.exists());
}
```

- [ ] **Step 2: Run in Docker**

```bash
# from the repo root; Dockerfile/base with rust + recent kernel.
docker run --rm -it \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  -v "$PWD":/src -w /src rust:latest \
  bash -c "cargo test --test linux_enforcement -- --test-threads=1"
```
Expected: all PASS. `landlock_actually_enforces` must PASS (not skip) — if it
fails, the container is masking Landlock; confirm the `seccomp=unconfined` flag.

- [ ] **Step 3: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/tests/linux_enforcement.rs
git commit -m "test(linux): behavioral enforcement suite (fs isolation, network block, fail-loud)"
```

---

## Task 8: CI Linux job + README + final gates

**Files:** `.github/workflows/ci.yml`, `crates/motosan-sandbox/README.md`

- [ ] **Step 1: Confirm/extend CI**

The Phase 0 CI matrix already includes `ubuntu-latest`. Ensure the Linux job runs
`cargo test` (which now includes `linux_enforcement`) **without** any bwrap /
userns / AppArmor provisioning — that's the payoff of choosing Landlock+seccomp.
Add a comment in the workflow:

```yaml
      # Linux sandbox tests use Landlock + seccomp only — NO bubblewrap, NO
      # unprivileged-userns / AppArmor sysctls needed (unlike bwrap-based sandboxes).
      # ubuntu-latest's kernel is Landlock-capable, so enforcement runs for real.
```

No other CI change is required (the matrix already runs `cargo test` +
`--features cancellation` + clippy + fmt + doc on both OSes).

- [ ] **Step 2: README Linux section**

Append to `crates/motosan-sandbox/README.md`:

```markdown
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
```

- [ ] **Step 3: Full gates**

macOS:
```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
cargo test                  # Phase 0 + spike non-regression
cargo test --features cancellation
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```
Docker (Linux truth):
```bash
docker run --rm --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  -v "$PWD":/src -w /src rust:latest \
  bash -c "cargo test && cargo clippy --all-features --all-targets -- -D warnings"
```
Expected: all green on both; `landlock_actually_enforces` passes in Docker.

- [ ] **Step 4: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add -A && git commit -m "docs(linux): README Phase 1 section + CI note"
```

---

## Done criteria

- macOS: Phase 0 + spike suites green; clippy/fmt clean. No regression.
- Docker (`seccomp=unconfined`) + CI ubuntu-latest: `linux_enforcement` green,
  including `landlock_actually_enforces` **passing (not skipping)** — write-inside
  succeeds, write-outside denied, read-outside allowed, network blocked,
  `read_only_subpaths` → `Error::Unsupported`, `DangerFullAccess` passthrough.
- `NotEnforced` is returned (never silent unsandboxed run) when Landlock can't
  enforce.
- No bubblewrap dependency; no `macos`/`linux` Cargo features; network is the
  seccomp socket-domain filter (not a connect-blocklist).
- `cargo clippy --all-features --all-targets -D warnings` + `cargo fmt --check`
  clean on both platforms.

## Notes for the executor

- TDD: pure modules (`reexec.rs`) are red-green on macOS; the `linux.rs`
  enforcement is validated behaviorally in Docker (Task 7) — write those tests
  first and watch them fail (skip-guard will let them "pass" only if Landlock is
  truly unavailable, which is why `landlock_actually_enforces` exists).
- If a test forces a change to `motosan-agent-loop`, that's out of scope — Phase 1
  is sandbox-repo only.
- Pin `landlock`/`seccompiler` to real published versions and reconcile the import
  paths / `TargetArch` casing against those versions in the first Docker build.
- Run Linux tests single-threaded (`--test-threads=1`) if temp-dir/cwd races
  appear; each test uses its own tempdir so it should be fine, but the re-exec +
  enforcement is process-global per child, so keep tests hermetic.
