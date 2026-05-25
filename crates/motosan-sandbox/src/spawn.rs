//! Spawn a `SpawnRequest` with tokio and capture its output. Mechanical — all
//! policy decisions were already made by `transform()`. See design §8.

use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::error::Error;
use crate::types::{ExecOutput, RunOpts, SpawnRequest};

/// Truncate to `max` bytes (0 = unlimited).
fn cap(mut v: Vec<u8>, max: usize) -> Vec<u8> {
    if max != 0 && v.len() > max {
        v.truncate(max);
    }
    v
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

    let mut child = command.spawn().map_err(Error::Spawn)?;

    // Drain each pipe in its own task so a full pipe buffer can't deadlock the
    // wait. The tasks own the pipes (Send + 'static) and return the bytes read.
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let out_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf).await;
        buf
    });
    let err_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf).await;
        buf
    });

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

    Ok(ExecOutput {
        exit_code,
        signal,
        stdout: cap(stdout, opts.max_output_bytes),
        stderr: cap(stderr, opts.max_output_bytes),
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
        let out = spawn_and_capture(req("/bin/echo", &["hello"]), &RunOpts::default())
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
        assert!(!out.timed_out);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn nonzero_exit_is_captured() {
        let out = spawn_and_capture(req("/bin/sh", &["-c", "exit 3"]), &RunOpts::default())
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(3));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn timeout_kills_and_flags() {
        let opts = RunOpts { timeout: Some(Duration::from_millis(200)), ..Default::default() };
        let out = spawn_and_capture(req("/bin/sleep", &["5"]), &opts).await.unwrap();
        assert!(out.timed_out);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn output_is_byte_capped() {
        let opts = RunOpts { max_output_bytes: 4, ..Default::default() };
        let out = spawn_and_capture(req("/bin/echo", &["abcdefgh"]), &opts).await.unwrap();
        assert_eq!(out.stdout.len(), 4);
    }

    #[tokio::test]
    async fn missing_program_is_spawn_error() {
        let err = spawn_and_capture(req("/no/such/binary", &[]), &RunOpts::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Spawn(_)));
    }
}
