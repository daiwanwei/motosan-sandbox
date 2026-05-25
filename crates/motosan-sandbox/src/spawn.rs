//! Spawn a `SpawnRequest` with tokio and capture its output. Mechanical — all
//! policy decisions were already made by `transform()`. See design §8.

use std::process::Stdio;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::error::Error;
use crate::types::{ExecOutput, RunOpts, SpawnRequest};

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

/// Why we stopped waiting early.
enum StopReason {
    Timeout,
    #[cfg_attr(not(feature = "cancellation"), allow(dead_code))]
    Cancel,
}

/// A future that resolves after `d`, or never if `None`.
async fn sleep_for(d: Option<std::time::Duration>) {
    match d {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// Spawn and wait, honoring timeout / byte cap / (optional) cancellation.
pub(crate) async fn spawn_and_capture(
    req: SpawnRequest,
    opts: &RunOpts,
    helper_reexec: bool,
) -> Result<ExecOutput, Error> {
    let mut command = Command::new(&req.program);
    command
        .args(&req.args)
        .current_dir(&req.cwd)
        .env_clear()
        .envs(&req.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(unix)]
    if helper_reexec {
        command.arg0(crate::reexec::HELPER_ARG0);
    }

    let mut child = command.spawn().map_err(Error::Spawn)?;

    // Drain each pipe in its own task so a full pipe buffer can't deadlock the
    // wait. The tasks own the pipes (Send + 'static) and return the bytes read.
    let stdout_pipe = child.stdout.take().expect("stdout piped");
    let stderr_pipe = child.stderr.take().expect("stderr piped");
    let max = opts.max_output_bytes;
    let out_task = tokio::spawn(read_capped(stdout_pipe, max));
    let err_task = tokio::spawn(read_capped(stderr_pipe, max));

    let mut timed_out = false;

    // `early` does NOT borrow `child`; `child.wait()` is passed to select! BY
    // VALUE, so when `early` wins, select drops the wait future (releasing the
    // &mut borrow) before the handler runs — letting us kill + reap the child.
    let early = async {
        #[cfg(feature = "cancellation")]
        {
            if let Some(token) = &opts.cancel {
                return tokio::select! {
                    _ = sleep_for(opts.timeout) => StopReason::Timeout,
                    _ = token.cancelled() => StopReason::Cancel,
                };
            }
        }
        sleep_for(opts.timeout).await;
        StopReason::Timeout
    };

    let status: std::io::Result<std::process::ExitStatus> = tokio::select! {
        s = child.wait() => s,
        reason = early => {
            timed_out = matches!(reason, StopReason::Timeout);
            let _ = child.start_kill();
            child.wait().await
        }
    };

    let status = status.map_err(Error::Spawn)?;
    let (exit_code, signal) = decode_status(status);

    // Pipes hit EOF once the child is gone, so the drain tasks complete.
    let stdout = out_task.await.unwrap_or_default();
    let stderr = err_task.await.unwrap_or_default();

    // Reserved exit codes only mean "helper setup failed" for a Linux helper
    // re-exec. For any other spawn, 121–123 is a genuine command result and
    // must pass through unchanged.
    if helper_reexec {
        if let Some(err) = crate::reexec::classify_helper_exit(exit_code, &stderr) {
            return Err(err);
        }
    }

    Ok(ExecOutput {
        exit_code,
        signal,
        stdout,
        stderr,
        timed_out,
    })
}

#[cfg(unix)]
fn decode_status(s: std::process::ExitStatus) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    (s.code(), s.signal())
}

#[cfg(not(unix))]
fn decode_status(s: std::process::ExitStatus) -> (Option<i32>, Option<i32>) {
    (s.code(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn req(program: &str, args: &[&str]) -> SpawnRequest {
        SpawnRequest {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn captures_stdout_and_exit_code() {
        let out = spawn_and_capture(req("/bin/echo", &["hello"]), &RunOpts::default(), false)
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
        assert!(!out.timed_out);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn nonzero_exit_is_captured() {
        let out = spawn_and_capture(
            req("/bin/sh", &["-c", "exit 3"]),
            &RunOpts::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(out.exit_code, Some(3));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn timeout_kills_and_flags() {
        let opts = RunOpts {
            timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        };
        let out = spawn_and_capture(req("/bin/sleep", &["5"]), &opts, false)
            .await
            .unwrap();
        assert!(out.timed_out);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn output_is_byte_capped() {
        let opts = RunOpts {
            max_output_bytes: 4,
            ..Default::default()
        };
        let out = spawn_and_capture(req("/bin/echo", &["abcdefgh"]), &opts, false)
            .await
            .unwrap();
        assert_eq!(out.stdout.len(), 4);
    }

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

    #[tokio::test]
    async fn missing_program_is_spawn_error() {
        let err = spawn_and_capture(req("/no/such/binary", &[]), &RunOpts::default(), false)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Spawn(_)));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn helper_env_alone_does_not_enable_helper_mode() {
        let mut request = req("/bin/sh", &["-c", "exit 121"]);
        request.env.insert(
            crate::reexec::POLICY_ENV.into(),
            "caller-controlled value".into(),
        );
        let out = spawn_and_capture(request, &RunOpts::default(), false)
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(121));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn helper_mode_classifies_reserved_code_with_stderr() {
        let err = spawn_and_capture(
            req("/bin/sh", &["-c", "echo helper boom >&2; exit 121"]),
            &RunOpts::default(),
            true,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::NotEnforced(msg) if msg.contains("helper boom")));
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "cancellation"))]
    async fn cancelled_token_kills_run() {
        use tokio_util::sync::CancellationToken;
        let token = CancellationToken::new();
        token.cancel(); // pre-cancelled: the cancel leg wins deterministically
        let opts = RunOpts {
            cancel: Some(token),
            timeout: None,
            ..Default::default()
        };
        // Without cancellation this sleep would hang for 5s; cancel must kill it
        // promptly and the run must not be flagged as a timeout.
        let out = spawn_and_capture(req("/bin/sleep", &["5"]), &opts, false)
            .await
            .unwrap();
        assert!(!out.timed_out);
    }
}
