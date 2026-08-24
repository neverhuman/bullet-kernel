//! Bounded process execution: wall-clock timeout with process-group kill.
//! Partial output survives a timeout because lines are collected into shared
//! buffers as they arrive.

use crate::argv::PreparedInvocation;
use crate::error::HarnessError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

/// Shared slot exposing the live child pid for interrupt/terminate.
pub type PidSlot = Arc<Mutex<Option<u32>>>;

/// Outcome of one bounded invocation.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Stdout lines in arrival order (partial on timeout).
    pub stdout_lines: Vec<String>,
    /// Collected stderr (partial on timeout).
    pub stderr: String,
    /// Exit code when the process finished.
    pub exit_code: Option<i32>,
    /// True when the wall clock bound fired.
    pub timed_out: bool,
    /// Observed wall time.
    pub wall: Duration,
}

/// SIGKILL the process group led by `pid`, then the pid itself as fallback.
pub fn kill_process_group(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .status();
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

fn lock_push(lines: &Mutex<Vec<String>>, line: String) {
    if let Ok(mut guard) = lines.lock() {
        guard.push(line);
    }
}

fn take_lines(lines: &Mutex<Vec<String>>) -> Vec<String> {
    lines
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_default()
}

/// Run to completion under the invocation's wall-clock bound. The child runs
/// in its own process group; on timeout the whole group is killed.
///
/// # Errors
///
/// `SPAWN_FAILED` when the process cannot start; `IO_FAILED` when the child
/// exposes no stdio pipes.
pub async fn run_to_completion(
    prep: &PreparedInvocation,
    pid_slot: Option<PidSlot>,
) -> Result<RunOutcome, HarnessError> {
    let started = Instant::now();
    let mut child = prep.command().spawn().map_err(|err| HarnessError::Spawn {
        program: prep.program.clone(),
        reason: err.to_string(),
    })?;
    let pid = child.id();
    if let (Some(slot), Some(pid)) = (&pid_slot, pid) {
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(pid);
        }
    }
    let stdout = child.stdout.take().ok_or_else(|| HarnessError::Io {
        context: "child stdout".to_string(),
        reason: "pipe missing".to_string(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| HarnessError::Io {
        context: "child stderr".to_string(),
        reason: "pipe missing".to_string(),
    })?;

    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let err_buf: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let lines_task = Arc::clone(&lines);
    let err_task = Arc::clone(&err_buf);

    let fut = async move {
        let out_read = async {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                lock_push(&lines_task, line);
            }
        };
        let err_read = async {
            let mut text = String::new();
            let _ = BufReader::new(stderr).read_to_string(&mut text).await;
            lock_push(&err_task, text);
        };
        let ((), ()) = tokio::join!(out_read, err_read);
        child.wait().await
    };

    match tokio::time::timeout(prep.timeout, fut).await {
        Ok(status) => {
            if let Some(slot) = &pid_slot {
                if let Ok(mut guard) = slot.lock() {
                    *guard = None;
                }
            }
            let exit_code = status
                .map_err(|err| HarnessError::Io {
                    context: "child wait".to_string(),
                    reason: err.to_string(),
                })?
                .code();
            Ok(RunOutcome {
                stdout_lines: take_lines(&lines),
                stderr: take_lines(&err_buf).join(""),
                exit_code,
                timed_out: false,
                wall: started.elapsed(),
            })
        }
        Err(_) => {
            if let Some(pid) = pid {
                kill_process_group(pid);
            }
            if let Some(slot) = &pid_slot {
                if let Ok(mut guard) = slot.lock() {
                    *guard = None;
                }
            }
            Ok(RunOutcome {
                stdout_lines: take_lines(&lines),
                stderr: take_lines(&err_buf).join(""),
                exit_code: None,
                timed_out: true,
                wall: started.elapsed(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argv::ArgvBuilder;

    #[tokio::test]
    async fn captures_stdout_and_exit_code() {
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", "echo one; echo two; exit 3"])
            .build()
            .unwrap();
        let outcome = run_to_completion(&prep, None).await.unwrap();
        assert_eq!(outcome.stdout_lines, ["one", "two"]);
        assert_eq!(outcome.exit_code, Some(3));
        assert!(!outcome.timed_out);
    }

    #[tokio::test]
    async fn timeout_kills_the_process_group_and_keeps_partial_output() {
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", "echo early; sleep 30; echo late"])
            .timeout(Duration::from_millis(400))
            .build()
            .unwrap();
        let started = Instant::now();
        let outcome = run_to_completion(&prep, None).await.unwrap();
        assert!(outcome.timed_out);
        assert!(started.elapsed() < Duration::from_secs(5), "bounded kill");
        assert_eq!(outcome.stdout_lines, ["early"]);
        assert_eq!(outcome.exit_code, None);
    }

    #[tokio::test]
    async fn pid_slot_is_set_and_cleared() {
        let slot: PidSlot = Arc::new(Mutex::new(None));
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", "true"])
            .build()
            .unwrap();
        let outcome = run_to_completion(&prep, Some(Arc::clone(&slot)))
            .await
            .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(slot.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_binary_is_a_typed_spawn_failure() {
        let prep = ArgvBuilder::new("definitely-not-a-binary-9f3c", "/tmp")
            .build()
            .unwrap();
        let err = run_to_completion(&prep, None).await.unwrap_err();
        assert_eq!(err.reason_code(), "SPAWN_FAILED");
    }
}
