# Secret deny-read (glob-based) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add glob-based deny-read so untrusted code under the sandbox cannot read secrets (`~/.aws`, `.env`, `*.pem`), enforced on macOS Seatbelt and the Linux bwrap (`Proxied`) path; `Error::Unsupported` on the Linux Landlock path.

**Architecture:** A `deny_read_globs: Vec<String>` list on both read-granting policies (`ReadOnly` restructured into a builder struct; `WorkspaceWrite` gains a builder field), surfaced via a `SandboxPolicy::deny_read_globs()` accessor. Seatbelt renders each glob to an anchored `(deny file-read* (regex …))` (last-match-wins over the base `(allow file-read*)`). The bwrap path expands each glob from its static prefix with `globset`+`walkdir` and masks matches (`--ro-bind /dev/null` for files, `--tmpfs` for dirs) emitted LAST in the argv. Landlock rejects (allow-only).

**Tech Stack:** Rust, `globset` + `walkdir` (linux-only deps), macOS `sandbox-exec` (SBPL regex), Linux bwrap, `#[non_exhaustive]` builder structs.

**Spec:** `docs/superpowers/specs/2026-05-26-secret-deny-read-design.md`.

---

## File Structure

- `crates/motosan-sandbox/src/policy.rs` — **modify**: restructure `ReadOnly` into a builder struct; add `deny_read_globs` to `ReadOnly` + `WorkspaceWrite`; add `SandboxPolicy::deny_read_globs()`.
- `crates/motosan-sandbox/src/lib.rs` — **modify**: export the new `ReadOnly` type.
- `crates/motosan-sandbox/src/seatbelt.rs` — **modify**: glob→regex helper + append deny-read rules in `build_policy` (thread `cwd`).
- `crates/motosan-sandbox/src/reexec.rs` — **modify**: `HelperPolicy.deny_read_globs`; reject on Landlock in `from_policy`; accept in `for_proxied`.
- `crates/motosan-sandbox/src/transform.rs` — **modify**: pass `deny_read_globs` into `HelperPolicy::for_proxied`; pass `cwd` to seatbelt.
- `crates/motosan-sandbox/src/linux_bwrap.rs` — **modify**: glob expansion + mask args appended last in `build_bwrap_argv`.
- `crates/motosan-sandbox/src/linux.rs` — **modify**: pass `deny_read_globs` from `HelperPolicy` into `build_bwrap_argv`.
- `crates/motosan-sandbox/Cargo.toml` — **modify**: add `globset`, `walkdir` under `[target.'cfg(target_os = "linux")'.dependencies]`.
- `crates/motosan-sandbox/tests/seatbelt_enforcement.rs` — **modify**: behavioral macOS deny-read tests.
- `crates/motosan-sandbox/tests/linux_enforcement.rs` — **modify**: behavioral Linux deny-read tests (incl. ordering).
- `crates/motosan-sandbox/README.md` — **modify**: document deny-read.

---

### Task 1: API — restructure `ReadOnly` + add `deny_read_globs`

**Files:**
- Modify: `crates/motosan-sandbox/src/policy.rs`
- Modify: `crates/motosan-sandbox/src/lib.rs`

- [ ] **Step 1: Write failing builder tests**

In `crates/motosan-sandbox/src/policy.rs`, add to `mod tests`:

```rust
#[test]
fn readonly_builder_defaults_and_chains() {
    let ro = ReadOnly::new(NetworkPolicy::Blocked);
    assert_eq!(ro.network, NetworkPolicy::Blocked);
    assert!(ro.deny_read_globs.is_empty());

    let ro = ReadOnly::new(NetworkPolicy::Allowed)
        .deny_read("**/.env")
        .deny_read("**/*.pem");
    assert_eq!(ro.deny_read_globs, vec!["**/.env", "**/*.pem"]);
}

#[test]
fn workspace_write_deny_read_chains() {
    let w = WorkspaceWrite::new(vec!["/ws".into()]).deny_read("**/.env");
    assert_eq!(w.deny_read_globs, vec!["**/.env".to_string()]);
}

#[test]
fn deny_read_globs_accessor_covers_each_variant() {
    assert!(SandboxPolicy::DangerFullAccess.deny_read_globs().is_empty());
    assert_eq!(
        SandboxPolicy::ReadOnly(ReadOnly::new(NetworkPolicy::Blocked).deny_read("a"))
            .deny_read_globs(),
        &["a".to_string()]
    );
    assert_eq!(
        SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).deny_read("b")
        )
        .deny_read_globs(),
        &["b".to_string()]
    );
}
```

- [ ] **Step 2: Run to verify it fails to COMPILE**

Run: `cargo test -p motosan-sandbox --lib policy:: 2>&1 | head -20`
Expected: compile error — `ReadOnly::new` / `deny_read` / `deny_read_globs` not found.

- [ ] **Step 3: Restructure `ReadOnly` into a builder struct**

In `crates/motosan-sandbox/src/policy.rs`, add the new struct (place it just above `pub enum SandboxPolicy`):

```rust
/// Read-only filesystem policy: whole FS readable except `deny_read_globs`;
/// network per `NetworkPolicy`. Builder struct (mirrors [`WorkspaceWrite`]) so
/// new fields stay non-breaking.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadOnly {
    pub network: NetworkPolicy,
    /// Glob patterns whose matches are made UNREADABLE. Enforced on macOS
    /// Seatbelt + Linux bwrap (`Proxied`); `Error::Unsupported` on the Linux
    /// Landlock path (allow-only). Relative globs resolve against the command cwd.
    pub deny_read_globs: Vec<String>,
}

impl ReadOnly {
    pub fn new(network: NetworkPolicy) -> Self {
        Self {
            network,
            deny_read_globs: Vec::new(),
        }
    }

    /// Add a deny-read glob pattern (e.g. `"**/.env"`, `"**/*.pem"`).
    pub fn deny_read(mut self, glob: impl Into<String>) -> Self {
        self.deny_read_globs.push(glob.into());
        self
    }
}
```

- [ ] **Step 4: Change the `ReadOnly` variant + add the accessor**

In `crates/motosan-sandbox/src/policy.rs`, change the enum variant:

```rust
    /// Read-only filesystem; see [`ReadOnly`].
    ReadOnly(ReadOnly),
```
(was `ReadOnly { network: NetworkPolicy }`)

Update `SandboxPolicy::network()` arm:
```rust
            SandboxPolicy::ReadOnly(r) => r.network.clone(),
```

Add the accessor inside `impl SandboxPolicy` (next to `network`):
```rust
    /// Effective deny-read glob list. `&[]` for `DangerFullAccess`.
    pub fn deny_read_globs(&self) -> &[String] {
        match self {
            SandboxPolicy::DangerFullAccess => &[],
            SandboxPolicy::ReadOnly(r) => &r.deny_read_globs,
            SandboxPolicy::WorkspaceWrite(w) => &w.deny_read_globs,
        }
    }
```

- [ ] **Step 5: Add `deny_read_globs` to `WorkspaceWrite`**

In `crates/motosan-sandbox/src/policy.rs`, add the field to the struct:
```rust
    pub deny_read_globs: Vec<String>,
```
Initialize it in `WorkspaceWrite::new` (`deny_read_globs: Vec::new(),`) and add the builder:
```rust
    /// Add a deny-read glob pattern (e.g. `"**/.env"`). Orthogonal to
    /// `read_only_subpaths` (which denies WRITES, not reads).
    pub fn deny_read(mut self, glob: impl Into<String>) -> Self {
        self.deny_read_globs.push(glob.into());
        self
    }
```

- [ ] **Step 6: Export `ReadOnly`**

In `crates/motosan-sandbox/src/lib.rs`, add `ReadOnly` to the policy re-export:
```rust
pub use policy::{HostPattern, NetworkPolicy, ReadOnly, SandboxPolicy, WorkspaceWrite};
```

- [ ] **Step 7: Fix every `ReadOnly { … }` call site (the breaking change)**

Run `cargo build -p motosan-sandbox --all-features 2>&1 | grep -A2 'ReadOnly'` to list sites. Apply mechanically across `src/policy.rs`, `src/transform.rs`, `src/seatbelt.rs`, `src/reexec.rs`, `tests/seatbelt_enforcement.rs`, `tests/transform_common.rs` (~18 sites):
- Construction `SandboxPolicy::ReadOnly { network: X }` → `SandboxPolicy::ReadOnly(ReadOnly::new(X))`.
- Match/destructure `SandboxPolicy::ReadOnly { network }` → `SandboxPolicy::ReadOnly(r)` then use `r.network`; `SandboxPolicy::ReadOnly { .. }` → `SandboxPolicy::ReadOnly(_)`.
Add `use crate::policy::ReadOnly;` (or `super::ReadOnly`) where needed in test modules.

- [ ] **Step 8: Run the full lib test suite**

Run: `cargo test -p motosan-sandbox --lib`
Expected: PASS (all builder tests green, no remaining compile errors).

- [ ] **Step 9: Commit**

```bash
git add crates/motosan-sandbox/src/policy.rs crates/motosan-sandbox/src/lib.rs crates/motosan-sandbox/src/transform.rs crates/motosan-sandbox/src/seatbelt.rs crates/motosan-sandbox/src/reexec.rs crates/motosan-sandbox/tests/seatbelt_enforcement.rs crates/motosan-sandbox/tests/transform_common.rs
git commit -m "feat(policy): ReadOnly builder + deny_read_globs on read policies"
```

---

### Task 2: macOS Seatbelt — render deny-read globs to regex deny rules

**Files:**
- Modify: `crates/motosan-sandbox/src/seatbelt.rs`
- Modify: `crates/motosan-sandbox/src/transform.rs`
- Test: `crates/motosan-sandbox/tests/seatbelt_enforcement.rs`

- [ ] **Step 1: Write failing unit tests for the glob→regex helper**

In `crates/motosan-sandbox/src/seatbelt.rs` `mod tests`, add:

```rust
#[test]
fn glob_to_deny_regexes_translates_and_anchors() {
    // Absolute glob: emits the pattern regex + the static-prefix dir regex.
    let rs = deny_read_regexes("/Users/x/.aws/**", std::path::Path::new("/tmp"));
    assert!(rs.iter().any(|r| r == r"^/Users/x/\.aws/.*$"));
    assert!(rs.iter().any(|r| r == r"^/Users/x/\.aws$"));
}

#[test]
fn glob_to_deny_regexes_single_star_is_segment_scoped() {
    let rs = deny_read_regexes("/ws/*.pem", std::path::Path::new("/tmp"));
    assert!(rs.iter().any(|r| r == r"^/ws/[^/]*\.pem$"));
}

#[test]
fn glob_to_deny_regexes_resolves_relative_against_cwd() {
    let rs = deny_read_regexes(".env", std::path::Path::new("/work/s"));
    assert!(rs.iter().any(|r| r == r"^/work/s/\.env$"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p motosan-sandbox --lib seatbelt:: 2>&1 | head -15`
Expected: compile error — `deny_read_regexes` not found.

- [ ] **Step 3: Implement the glob→regex helper**

In `crates/motosan-sandbox/src/seatbelt.rs`, add:

```rust
use std::path::Path;

/// Translate one deny-read glob into anchored Seatbelt regex(es). Mirrors
/// Codex's `seatbelt_regex_for_unreadable_glob`: a regex for the glob itself
/// plus, when the glob has a `/**` tail, a regex for the static-prefix
/// directory so the directory node is also denied. Relative globs resolve
/// against `cwd`. `**` → `.*`, `*` → `[^/]*`, `?` → `[^/]`; all other regex
/// metachars are escaped.
pub(crate) fn deny_read_regexes(glob: &str, cwd: &Path) -> Vec<String> {
    // Resolve to absolute against cwd.
    let abs = if glob.starts_with('/') {
        glob.to_string()
    } else {
        format!("{}/{}", cwd.to_string_lossy().trim_end_matches('/'), glob)
    };

    let mut out = vec![format!("^{}$", glob_body_to_regex(&abs))];

    // Static prefix directory (everything before the first wildcard segment),
    // so `/a/b/**` also denies reading `/a/b` itself.
    if let Some(idx) = abs.find(['*', '?']) {
        let prefix = &abs[..idx];
        if let Some(dir) = prefix.rsplit_once('/').map(|(d, _)| d) {
            if !dir.is_empty() {
                out.push(format!("^{}$", regex_escape(dir)));
            }
        }
    }
    out
}

/// Translate glob metachars to regex; escape everything else.
fn glob_body_to_regex(glob: &str) -> String {
    let mut re = String::with_capacity(glob.len() * 2);
    let bytes = glob.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'*' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    re.push_str(".*");
                    i += 2;
                    // swallow a following '/' so `**/` matches zero dirs too
                    if i < bytes.len() && bytes[i] == b'/' {
                        i += 1;
                    }
                    continue;
                } else {
                    re.push_str("[^/]*");
                }
            }
            b'?' => re.push_str("[^/]"),
            c => re.push_str(&regex_escape(&(c as char).to_string())),
        }
        i += 1;
    }
    re
}

/// Escape regex metacharacters in a literal string.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if r".+*?()|[]{}^$\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
```

- [ ] **Step 4: Append deny-read rules in `build_policy` (thread cwd)**

In `crates/motosan-sandbox/src/seatbelt.rs`, change `build_policy`'s signature to accept the cwd and emit the rules. Update the signature:
```rust
pub(crate) fn build_policy(
    policy: &SandboxPolicy,
    proxy: Option<SocketAddr>,
    cwd: &Path,
) -> Result<(String, Vec<Param>), Error> {
```
After the existing network match block (just before `Ok((sections.join("\n"), params))`), add:
```rust
    // Deny-read globs → regex deny rules. Appended AFTER `(allow file-read*)`
    // so they override it (SBPL last-match-wins). No -D param needed: the
    // regex is inline. Static-prefix is taken as-is here; canonicalization of
    // the prefix is the caller's responsibility (writable roots are already
    // canonicalized by convention).
    for glob in policy.deny_read_globs() {
        for re in deny_read_regexes(glob, cwd) {
            let re = re.replace('"', "\\\"");
            sections.push(format!("(deny file-read* (regex #\"{re}\"))"));
        }
    }
```
Update the caller `transform_seatbelt` to pass cwd:
```rust
    let (policy_text, params) = build_policy(policy, proxy, &cmd.cwd)?;
```
Fix the `build_policy(...)` calls in `seatbelt.rs` `mod tests` to pass a cwd, e.g. `std::path::Path::new("/tmp")`.

- [ ] **Step 5: Run unit tests to verify they pass**

Run: `cargo test -p motosan-sandbox --lib seatbelt::`
Expected: PASS.

- [ ] **Step 6: Write the behavioral macOS enforcement test**

In `crates/motosan-sandbox/tests/seatbelt_enforcement.rs`, append:

```rust
#[tokio::test]
async fn deny_read_glob_hides_secret_but_not_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join(".env"), b"SECRET=1").unwrap();
    std::fs::write(root.join("data.txt"), b"public").unwrap();

    let sb = Sandbox::new();
    let policy = SandboxPolicy::ReadOnly(
        motosan_sandbox::ReadOnly::new(NetworkPolicy::Blocked)
            .deny_read(format!("{}/.env", root.display())),
    );

    // secret: denied
    let out = sb
        .run(sh("cat .env", &root), &policy, RunOpts::default())
        .await
        .unwrap();
    assert_ne!(out.exit_code, Some(0), "secret read must be denied");

    // sibling: allowed (no over-deny)
    let out = sb
        .run(sh("cat data.txt", &root), &policy, RunOpts::default())
        .await
        .unwrap();
    assert_eq!(
        out.exit_code,
        Some(0),
        "sibling read must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("public"));
}
```
(`sh(...)` and the imports already exist at the top of this file; add `NetworkPolicy` to the `use` if not present.)

- [ ] **Step 7: Run the behavioral test**

Run: `cargo test -p motosan-sandbox --test seatbelt_enforcement deny_read_glob_hides_secret_but_not_sibling -- --nocapture`
Expected: PASS (secret `cat` non-zero/denied; `data.txt` prints `public`).

- [ ] **Step 8: Commit**

```bash
git add crates/motosan-sandbox/src/seatbelt.rs crates/motosan-sandbox/src/transform.rs crates/motosan-sandbox/tests/seatbelt_enforcement.rs
git commit -m "feat(seatbelt): enforce deny_read_globs via regex deny rules"
```

---

### Task 3: Linux Landlock — reject deny-read (fail-closed)

**Files:**
- Modify: `crates/motosan-sandbox/src/reexec.rs`
- Modify: `crates/motosan-sandbox/src/transform.rs`

- [ ] **Step 1: Write the failing rejection test**

In `crates/motosan-sandbox/src/reexec.rs` `mod ipc_tests`, add:

```rust
#[test]
fn deny_read_globs_rejected_on_landlock_path() {
    let policy = SandboxPolicy::ReadOnly(
        crate::policy::ReadOnly::new(NetworkPolicy::Blocked).deny_read("**/.env"),
    );
    assert!(matches!(
        HelperPolicy::from_policy(&policy),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn for_proxied_carries_deny_read_globs() {
    let h = HelperPolicy::for_proxied(
        vec!["/ws".into()],
        vec![],
        vec!["**/.env".to_string()],
        ProxyRouteSpec { routes: vec![] },
    );
    assert_eq!(h.deny_read_globs, vec!["**/.env".to_string()]);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --target x86_64-unknown-linux-gnu -p motosan-sandbox --features proxy --lib reexec:: 2>&1 | head -20`
(Add the target once: `rustup target add x86_64-unknown-linux-gnu`. On a Linux box, drop `--target`.)
Expected: compile error — `deny_read_globs` field / 4-arg `for_proxied` not found.

- [ ] **Step 3: Add the field + reject on Landlock + accept on Proxied**

In `crates/motosan-sandbox/src/reexec.rs`, add the field to `HelperPolicy`:
```rust
    pub deny_read_globs: Vec<String>,
```
In `from_policy`, after the existing network/`read_only_subpaths` checks and before building `Ok(Self{…})`, add:
```rust
        // Landlock is allow-only: cannot carve a read-deny. Fail-closed,
        // exactly like read_only_subpaths above.
        if !policy.deny_read_globs().is_empty() {
            return Err(Error::Unsupported(crate::SandboxKind::LinuxSeccomp));
        }
```
Set `deny_read_globs: Vec::new(),` in that `Ok(Self{…})`. Change `for_proxied` to accept and store the globs:
```rust
    pub(crate) fn for_proxied(
        writable_roots: Vec<PathBuf>,
        read_only_subpaths: Vec<PathBuf>,
        deny_read_globs: Vec<String>,
        route_spec: ProxyRouteSpec,
    ) -> Self {
        Self {
            writable_roots,
            read_only_subpaths,
            deny_read_globs,
            mode: HelperMode::ProxiedOuter { route_spec },
        }
    }
```

- [ ] **Step 4: Update the `for_proxied` caller in transform.rs**

In `crates/motosan-sandbox/src/transform.rs`, in the Linux Proxied arm, extract and pass the globs:
```rust
                        let (writable_roots, read_only_subpaths) = match policy {
                            SandboxPolicy::WorkspaceWrite(w) => {
                                (w.writable_roots.clone(), w.read_only_subpaths.clone())
                            }
                            _ => (Vec::new(), Vec::new()),
                        };
                        let helper = HelperPolicy::for_proxied(
                            writable_roots,
                            read_only_subpaths,
                            policy.deny_read_globs().to_vec(),
                            route_spec,
                        );
```
(Only the added `policy.deny_read_globs().to_vec()` arg is new.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --target x86_64-unknown-linux-gnu -p motosan-sandbox --features proxy --lib reexec::`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/motosan-sandbox/src/reexec.rs crates/motosan-sandbox/src/transform.rs
git commit -m "feat(linux): carry deny_read_globs to bwrap; reject on Landlock"
```

---

### Task 4: Linux bwrap — expand globs and mask matches (LAST in argv)

**Files:**
- Modify: `crates/motosan-sandbox/Cargo.toml`
- Modify: `crates/motosan-sandbox/src/linux_bwrap.rs`
- Modify: `crates/motosan-sandbox/src/linux.rs`
- Test: `crates/motosan-sandbox/tests/linux_enforcement.rs`

- [ ] **Step 1: Add linux-only deps**

In `crates/motosan-sandbox/Cargo.toml`, under `[target.'cfg(target_os = "linux")'.dependencies]`, add:
```toml
globset = "0.4"
walkdir = "2"
```

- [ ] **Step 2: Write failing unit tests for expansion + argv**

In `crates/motosan-sandbox/src/linux_bwrap.rs` `mod tests`, add:

```rust
#[test]
fn expand_deny_read_masks_files_and_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/.env"), b"x").unwrap();
    std::fs::create_dir(root.join("secretdir")).unwrap();

    let globs = vec![
        format!("{}/**/.env", root.display()),
        format!("{}/secretdir", root.display()),
    ];
    let masks = expand_deny_read_masks(&globs).unwrap();
    let file = root.join("sub/.env").to_string_lossy().into_owned();
    let dir = root.join("secretdir").to_string_lossy().into_owned();
    // file → ro-bind /dev/null; dir → tmpfs
    assert!(masks.windows(3).any(|w| w == ["--ro-bind", "/dev/null", &file]));
    assert!(masks.windows(2).any(|w| w == ["--tmpfs", &dir]));
}

#[test]
fn build_bwrap_argv_emits_masks_after_writable_binds() {
    let argv = build_bwrap_argv(
        &[std::path::PathBuf::from("/ws")],
        &[],
        &["/ws/secret".to_string()],   // a concrete pre-expanded mask path
        &["/inner".to_string()],
    );
    let s = argv.join(" ");
    let writable_idx = s.find("--bind /ws /ws").unwrap();
    let mask_idx = s.find("/ws/secret").unwrap();
    assert!(mask_idx > writable_idx, "masks must come after writable binds");
}
```
(Note: Step 4 changes `build_bwrap_argv`'s 4th param to pre-expanded **mask paths**, not raw globs — see below.)

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test --target x86_64-unknown-linux-gnu -p motosan-sandbox --features proxy --lib linux_bwrap:: 2>&1 | head -20`
Expected: compile error — `expand_deny_read_masks` not found / arity mismatch.

- [ ] **Step 4: Implement expansion + thread masks into argv**

In `crates/motosan-sandbox/src/linux_bwrap.rs`, add the expansion helper:
```rust
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

/// Hard cap on total deny-read matches (mirrors Codex's 8192).
const MAX_DENY_READ_GLOB_MATCHES: usize = 8192;

/// Expand deny-read globs against the host FS (the outer helper stage runs on
/// the host before entering bwrap) and return bwrap mask args: files get
/// `--ro-bind /dev/null <p>`, directories get `--tmpfs <p>`. Walks from each
/// glob's static prefix. Errors if matches exceed the cap (refuse, don't
/// partially mask).
pub(crate) fn expand_deny_read_masks(globs: &[String]) -> std::io::Result<Vec<String>> {
    use globset::Glob;
    use walkdir::WalkDir;

    let mut args = Vec::new();
    let mut count = 0usize;
    for g in globs {
        let matcher = Glob::new(g)
            .map_err(|e| IoError::new(ErrorKind::InvalidInput, format!("bad glob {g:?}: {e}")))?
            .compile_matcher();
        let root = static_prefix_dir(g);
        for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
            let p = entry.path();
            if !matcher.is_match(p) {
                continue;
            }
            count += 1;
            if count > MAX_DENY_READ_GLOB_MATCHES {
                return Err(IoError::new(
                    ErrorKind::Other,
                    format!("deny-read glob {g:?} matched >{MAX_DENY_READ_GLOB_MATCHES} paths"),
                ));
            }
            let s = p.to_string_lossy().into_owned();
            if entry.file_type().is_dir() {
                args.push("--tmpfs".into());
                args.push(s);
            } else {
                args.push("--ro-bind".into());
                args.push("/dev/null".into());
                args.push(s);
            }
        }
    }
    Ok(args)
}

/// The non-wildcard leading directory of a glob, e.g. `/a/b/**` → `/a/b`,
/// `/a/*.pem` → `/a`. Falls back to `/` if there is no static prefix.
fn static_prefix_dir(glob: &str) -> PathBuf {
    let cut = glob.find(['*', '?']).unwrap_or(glob.len());
    let prefix = &glob[..cut];
    match prefix.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from("/"),
    }
}
```
Change `build_bwrap_argv` to take a 4th param of **already-expanded mask args** and append them LAST:
```rust
pub(crate) fn build_bwrap_argv(
    writable_roots: &[PathBuf],
    read_only_subpaths: &[PathBuf],
    deny_read_masks: &[String],
    inner_argv: &[String],
) -> Vec<String> {
```
Immediately before the `--unshare-user` block (i.e. after the `read_only_subpaths` loop, before namespaces), append the masks LAST among filesystem rules:
```rust
    // Deny-read masks LAST so they override the whole-FS ro-bind AND any
    // writable --bind above (bwrap applies mounts in argv order).
    a.extend(deny_read_masks.iter().cloned());
```
Update the existing `build_bwrap_argv` test(s) in this file to pass a `&[]` for the new param.

- [ ] **Step 5: Pass masks from `linux.rs`**

In `crates/motosan-sandbox/src/linux.rs`, where `build_bwrap_argv` is called (around line 161), expand first and pass:
```rust
    let deny_read_masks = crate::linux_bwrap::expand_deny_read_masks(&helper.deny_read_globs)
        .unwrap_or_else(|e| die(HELPER_EXIT_NOT_ENFORCED, &format!("deny-read expand: {e}")));
    let argv = build_bwrap_argv(
        &helper.writable_roots,
        &helper.read_only_subpaths,
        &deny_read_masks,
        &inner_argv,
    );
```
(`die`, `HELPER_EXIT_NOT_ENFORCED` already exist in `linux.rs`.)

- [ ] **Step 6: Run unit tests**

Run: `cargo test --target x86_64-unknown-linux-gnu -p motosan-sandbox --features proxy --lib linux_bwrap::`
Expected: PASS.

- [ ] **Step 7: Write the behavioral Linux enforcement tests**

In `crates/motosan-sandbox/tests/linux_enforcement.rs`, append (follow the file's existing proxied-test helpers/imports; secret lives inside a writable root to also prove ordering):

```rust
#[tokio::test]
async fn deny_read_masks_secret_inside_writable_root() {
    let Some(_) = system_bwrap() else { eprintln!("skip: no bwrap"); return; };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join(".env"), b"SECRET=1").unwrap();
    std::fs::write(root.join("data.txt"), b"public").unwrap();

    let policy = SandboxPolicy::WorkspaceWrite(
        WorkspaceWrite::new(vec![root.clone()])
            .network(NetworkPolicy::Proxied { allowlist: vec![] })
            .deny_read(format!("{}/.env", root.display())),
    );
    let sb = sandbox_with_helper();

    let out = sb.run(sh("cat .env", &root), &policy, RunOpts::default()).await.unwrap();
    assert_ne!(out.exit_code, Some(0), "secret inside writable root must stay masked");

    let out = sb.run(sh("cat data.txt", &root), &policy, RunOpts::default()).await.unwrap();
    assert_eq!(out.exit_code, Some(0), "sibling readable; stderr: {}",
        String::from_utf8_lossy(&out.stderr));
}
```
(Use whatever bwrap-presence guard + `Sandbox` constructor the existing proxied tests in this file use — match their `system_bwrap()`/`sandbox_with_helper()`/`sh()` names; rename to the real helpers if they differ.)

- [ ] **Step 8: Verify it compiles for Linux (runs on CI)**

Run: `cargo clippy --target x86_64-unknown-linux-gnu --all-features --all-targets -- -D warnings`
Expected: clean. (The test actually executes only on the Linux CI runner; locally we confirm it compiles + lints.)

- [ ] **Step 9: Commit**

```bash
git add crates/motosan-sandbox/Cargo.toml crates/motosan-sandbox/src/linux_bwrap.rs crates/motosan-sandbox/src/linux.rs crates/motosan-sandbox/tests/linux_enforcement.rs
git commit -m "feat(linux): expand deny_read_globs to bwrap masks (emitted last)"
```

---

### Task 5: Docs + full verification

**Files:**
- Modify: `crates/motosan-sandbox/README.md`

- [ ] **Step 1: Document deny-read in the README**

In `crates/motosan-sandbox/README.md`, under "Security notes", add:
```markdown
- **Hide secrets with `deny_read`.** `ReadOnly`/`WorkspaceWrite` accept
  `deny_read("<glob>")` patterns (e.g. `**/.env`, `**/*.pem`) that make matches
  UNREADABLE — the control that stops untrusted code from exfiltrating API keys
  through an allowed egress. Enforced on macOS Seatbelt (regex deny) and the
  Linux bwrap `Proxied` path (mask mounts). On the Linux Landlock path
  (`Blocked`/`Allowed` network) a non-empty deny-read list returns
  `Error::Unsupported` — Landlock is allow-only and cannot carve a read
  exception (same limitation as `read_only_subpaths`). Relative globs resolve
  against the command cwd; masks are applied after writable binds, so a secret
  inside a writable root is still hidden. Broad root-anchored globs (`**/x`)
  walk much of the tree on Linux — prefer prefixed globs.
```

- [ ] **Step 2: Commit docs**

```bash
git add crates/motosan-sandbox/README.md
git commit -m "docs(readme): document deny_read glob secret-hiding"
```

- [ ] **Step 3: Full verification gate**

Run each; all must pass:
```bash
cargo test -p motosan-sandbox --lib
cargo test -p motosan-sandbox --test seatbelt_enforcement
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
# Linux code (can't run netns locally; CI runs the behavioral Linux tests):
cargo clippy --target x86_64-unknown-linux-gnu --all-features --all-targets -- -D warnings
```
Expected: all green. Push the branch and let CI run the Linux behavioral deny-read test on the real runner.

---

## Self-Review

- **Spec coverage:** API restructure + `deny_read_globs` accessor → Task 1; Seatbelt regex (incl. relative-cwd resolution, static-prefix) → Task 2; Landlock `Unsupported` fail-closed → Task 3; bwrap expansion + mask-last ordering + match cap + linux deps → Task 4; README + verification → Task 5. The dropped `file-write-unlink` rule (spec §Backend) is honored by emitting read-deny only in Task 2. The ordering correctness clause and writable-root masking test (spec §Testing) are in Task 4.
- **Placeholder scan:** no TBDs; all code/commands concrete. The ~18 call-site edits (Task 1 Step 7) are compiler-driven with the exact mechanical rule + file list — not a placeholder.
- **Type consistency:** `ReadOnly::new`/`deny_read`/`deny_read_globs()` defined in Task 1 are used identically in Tasks 2–4; `HelperPolicy.deny_read_globs` (Task 3) feeds `expand_deny_read_masks` (Task 4); `build_bwrap_argv`'s new 4th param is pre-expanded mask args in both its definition (Task 4 Step 4) and its callers (Task 4 Step 5, and the Task 4 Step 2 argv test). `for_proxied`'s new 3rd arg (`deny_read_globs`) matches between definition (Task 3) and caller (Task 3 Step 4).

> **Known follow-up (out of scope):** a configurable `glob_scan_max_depth`; deny-read on the Landlock path; canonicalizing the Seatbelt static prefix through symlinks (today writable roots are canonicalized by convention — document that deny-read globs should likewise use resolved paths on macOS).
