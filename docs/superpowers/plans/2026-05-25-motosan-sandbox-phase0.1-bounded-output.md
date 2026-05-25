# motosan-sandbox Phase 0.1 — Bounded Output Capture

> **For agentic workers:** Single-task follow-up. Use superpowers:test-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `max_output_bytes` bound the memory used while capturing a sandboxed command's output, not just the bytes returned.

**Why:** Today `spawn.rs` drains each pipe with `read_to_end` (unbounded) and only truncates afterwards with `cap()`. A sandboxed command emitting huge output (`head -c 1G /dev/zero`, or worse `cat /dev/zero` bounded only by the timeout) buffers it all in host memory first — a memory-DoS. This is the one Phase-0 review finding worth fixing before pointing untrusted agent commands at the crate. (Found in code review 2026-05-25; see `project_motosan_sandbox` memory and the design doc §8.)

**Approach (matches Codex):** read at most `max_output_bytes` into the buffer, then **drain-and-discard** the remainder to EOF so the child never blocks on a full pipe and still terminates naturally. Memory is bounded to ~`max` per stream; runaway *time* remains bounded by `RunOpts::timeout` (unchanged). `max_output_bytes == 0` keeps the current unlimited behavior.

**Repo:** `/Users/daiwanwei/Projects/wade/motosan-sandbox`. File: `crates/motosan-sandbox/src/spawn.rs`.

---

## Task: Cap output during read, not after

**Files:**
- Modify: `crates/motosan-sandbox/src/spawn.rs`

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `crates/motosan-sandbox/src/spawn.rs`:

```rust
    #[tokio::test]
    #[cfg(unix)]
    async fn large_output_is_capped_and_process_completes() {
        // 1 MB of output, capped to 128 bytes. Must return exactly 128 bytes
        // AND let the process finish (exit 0) — proving we drained the rest
        // instead of buffering 1 MB or deadlocking on a full pipe.
        let opts = RunOpts {
            max_output_bytes: 128,
            ..Default::default()
        };
        // NOTE: `spawn_and_capture` takes a 3rd `helper_reexec` arg (added in
        // Phase 1) — pass `false` (this is a plain spawn, not a Linux re-exec).
        let out = spawn_and_capture(
            req("/bin/sh", &["-c", "head -c 1000000 /dev/zero"]),
            &opts,
            false,
        )
        .await
        .unwrap();
        assert_eq!(out.stdout.len(), 128);
        assert_eq!(out.exit_code, Some(0)); // proves we DRAINED (head could finish) — 1 MB >> pipe buf
        assert!(!out.timed_out);
    }
```

- [ ] **Step 2: Run it (this is a guard, NOT a red test)**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --lib spawn::tests::large_output_is_capped_and_process_completes`
Expected: **PASS even on the current code** — `read_to_end` also drains the pipe, so `head` finishes (exit 0) and `cap()` truncates to 128. This test can't go red because the *observable* behavior (128 bytes, exit 0) is identical before and after; the fix is about **memory**, which a unit test can't see without instrumentation.

So treat this as a **regression + drain-correctness guard**, not red-green: it WILL catch a broken `read_capped` that forgets to drain (the 1 MB output ≫ the ~64 KB pipe buffer, so a no-drain reader would block `head` → the child never exits → the test hangs). If you want a strict red first, stub `read_capped` to `unimplemented!()`, watch it panic, then implement.

> The real proof of the fix is reading the result: **no `read_to_end` on an *unbounded* stream remains** — only inside `read_capped` (the `max == 0` branch, and the bounded `take(max)` reader). Verify with the grep in Step 5.

- [ ] **Step 3: Implement `read_capped` and rewire the drain tasks**

In `crates/motosan-sandbox/src/spawn.rs`:

1. Update the imports at the top:

```rust
use std::process::Stdio;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::error::Error;
use crate::types::{ExecOutput, RunOpts, SpawnRequest};
```

2. **Delete** the `cap` function entirely:

```rust
// DELETE THIS:
// fn cap(mut v: Vec<u8>, max: usize) -> Vec<u8> {
//     if max != 0 && v.len() > max {
//         v.truncate(max);
//     }
//     v
// }
```

3. **Add** the capped reader (place it where `cap` was):

```rust
/// Read up to `max` bytes (0 = unlimited) from `reader`, then drain and discard
/// the remainder to EOF so the child never blocks on a full pipe. Bounds the
/// captured buffer to ~`max` bytes; runaway *duration* is still bounded by the
/// caller's `RunOpts::timeout`.
async fn read_capped<R: AsyncRead + Unpin>(mut reader: R, max: usize) -> Vec<u8> {
    if max == 0 {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf).await;
        return buf;
    }

    // Read at most `max` bytes. `Take` reports EOF once the limit is hit, so
    // `read_to_end` stops there without over-allocating.
    let mut buf = Vec::with_capacity(max.min(64 * 1024));
    {
        let mut limited = (&mut reader).take(max as u64);
        let _ = limited.read_to_end(&mut buf).await;
    }

    // Drain whatever is left into a fixed scratch buffer so the writer side
    // doesn't block; we never grow `buf` past `max`.
    let mut scratch = [0u8; 8 * 1024];
    loop {
        match reader.read(&mut scratch).await {
            Ok(0) | Err(_) => break, // EOF or error → done draining
            Ok(_) => {}
        }
    }

    buf
}
```

4. Rewire the two drain tasks to use it (replace the `out_task`/`err_task` blocks):

```rust
    let max = opts.max_output_bytes;
    let out_task = tokio::spawn(read_capped(stdout_pipe, max));
    let err_task = tokio::spawn(read_capped(stderr_pipe, max));
```

5. Remove the now-redundant `cap(...)` calls in the returned `ExecOutput` (capping already happened during read):

```rust
    Ok(ExecOutput {
        exit_code,
        signal,
        stdout: out_task.await.unwrap_or_default(),
        stderr: err_task.await.unwrap_or_default(),
        timed_out,
    })
```

(Delete the earlier `let stdout = out_task.await.unwrap_or_default();` / `let stderr = ...` lines if you inline them here, or keep them and drop the `cap()` wrappers — either way, no `cap(` call remains.)

- [ ] **Step 4: Run the full spawn suite — expect PASS**

Run: `cd /Users/daiwanwei/Projects/wade/motosan-sandbox && cargo test --lib spawn`
Expected: PASS, including the existing `output_is_byte_capped` (echo "abcdefgh", max 4 → 4 bytes) and the new `large_output_is_capped_and_process_completes`, and `timeout_kills_and_flags` / `captures_stdout_and_exit_code` unchanged.

- [ ] **Step 5: Full gates**

Run:
```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
cargo test
cargo test --features cancellation
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```
Expected: all PASS, no warnings. (Confirm no `read_to_end` on an uncapped stream remains — `grep -n read_to_end src/spawn.rs` should show it only inside `read_capped`'s `max == 0` branch.)

- [ ] **Step 6: Commit**

```bash
cd /Users/daiwanwei/Projects/wade/motosan-sandbox
git add crates/motosan-sandbox/src/spawn.rs
git commit -m "fix(spawn): bound capture memory to max_output_bytes (drain-and-discard rest)"
```

---

## Done criteria

- `spawn.rs` contains no `read_to_end` call on an unbounded stream except inside `read_capped`'s `max == 0` path.
- `max_output_bytes = N` returns at most `N` bytes per stream and the child still completes (or is killed by timeout) — verified by `output_is_byte_capped` + `large_output_is_capped_and_process_completes`.
- All gates green.

## Notes
- This does **not** make infinite producers (`cat /dev/zero`) terminate on their own — that still relies on `RunOpts::timeout`. The fix bounds *memory*, which is the DoS vector. Document timeout as the time bound.
- Optional README follow-up (review finding #2, separate tiny commit): reword the `read_only_subpaths` note — it denies *writes* to a subpath, it does NOT hide it from *reads* (Phase 0 allows whole-filesystem read; deny-read carve-outs are a later phase).
