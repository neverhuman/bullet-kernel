//! Bounded process execution: wall-clock timeout with process-group kill.
//! Partial output survives a timeout because lines are collected into shared
//! buffers as they arrive.

use crate::argv::PreparedInvocation;
use crate::error::HarnessError;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::Notify;

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

/// Why supervised execution stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunStop {
    /// The process exited on its own, including non-zero crashes.
    Exited,
    /// An explicit cancellation was requested.
    Canceled,
    /// The authority heartbeat failed.
    HeartbeatFailed,
    /// The wall-clock deadline expired.
    TimedOut,
}

/// Outcome that preserves explicit cancellation and heartbeat semantics.
#[derive(Debug, Clone)]
pub struct SupervisedOutcome {
    /// Backward-compatible process and output facts.
    pub outcome: RunOutcome,
    /// Exact reason supervision ended.
    pub stop: RunStop,
}

/// Race-safe one-shot stop signal shared with cancellation/heartbeat owners.
#[derive(Clone, Debug, Default)]
pub struct SupervisionSignal {
    state: Arc<AtomicU8>,
    notify: Arc<Notify>,
}

impl SupervisionSignal {
    /// Request operator/controller cancellation.
    pub fn cancel(&self) {
        self.trigger(1);
    }

    /// Record loss of the durable authority heartbeat.
    pub fn heartbeat_failed(&self) {
        self.trigger(2);
    }

    fn trigger(&self, state: u8) {
        if self
            .state
            .compare_exchange(0, state, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.notify.notify_waiters();
        }
    }

    async fn wait(&self) -> RunStop {
        loop {
            let notified = self.notify.notified();
            match self.state.load(Ordering::SeqCst) {
                1 => return RunStop::Canceled,
                2 => return RunStop::HeartbeatFailed,
                _ => notified.await,
            }
        }
    }
}

/// SIGKILL the process group led by `pid`, then the pid itself as fallback.
pub fn kill_process_group(pid: u32) {
    kill_process_group_members(pid);
    let _ = std::process::Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// SIGKILL any descendants that still occupy the child's process group after
/// the group leader has already been reaped. This deliberately omits the
/// direct-pid fallback because that pid is no longer an owned live child.
pub(crate) fn kill_process_group_members(pid: u32) {
    let _ = std::process::Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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
    Ok(run_supervised(prep, pid_slot, None).await?.outcome)
}

/// Run with explicit cancellation and heartbeat-loss supervision. Every stop
/// path kills the process group before reaping pipes; a provider crash also
/// gets a final group kill so descendants cannot outlive their parent.
///
/// # Errors
///
/// `SPAWN_FAILED` when the process cannot start; `IO_FAILED` when required
/// stdio pipes are unavailable or the child cannot be waited.
pub async fn run_supervised(
    prep: &PreparedInvocation,
    pid_slot: Option<PidSlot>,
    signal: Option<SupervisionSignal>,
) -> Result<SupervisedOutcome, HarnessError> {
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
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child, pid).await;
        clear_pid_slot(&pid_slot);
        return Err(pipe_missing("child stdout"));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child, pid).await;
        clear_pid_slot(&pid_slot);
        return Err(pipe_missing("child stderr"));
    };

    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let err_buf: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let lines_task = Arc::clone(&lines);
    let err_task = Arc::clone(&err_buf);

    let mut out_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            lock_push(&lines_task, line);
        }
    });
    let mut err_handle = tokio::spawn(async move {
        let mut text = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut text).await;
        lock_push(&err_task, text);
    });

    let timeout = tokio::time::sleep(prep.timeout);
    tokio::pin!(timeout);
    let stop_wait = async {
        match signal {
            Some(signal) => signal.wait().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(stop_wait);
    let (stop, wait_result) = tokio::select! {
        status = child.wait() => (RunStop::Exited, Some(status)),
        () = &mut timeout => (RunStop::TimedOut, None),
        stop = &mut stop_wait => (stop, None),
    };
    if let Some(pid) = pid {
        kill_process_group(pid);
    }
    if stop != RunStop::Exited {
        terminate_child(&mut child, None).await;
    }
    clear_pid_slot(&pid_slot);
    if tokio::time::timeout(Duration::from_secs(2), async {
        let _ = tokio::join!(&mut out_handle, &mut err_handle);
    })
    .await
    .is_err()
    {
        out_handle.abort();
        err_handle.abort();
    }
    let exit_code = match wait_result {
        Some(status) => status
            .map_err(|err| HarnessError::Io {
                context: "child wait".to_string(),
                reason: err.to_string(),
            })?
            .code(),
        None => None,
    };
    Ok(SupervisedOutcome {
        outcome: RunOutcome {
            stdout_lines: take_lines(&lines),
            stderr: take_lines(&err_buf).join(""),
            exit_code,
            timed_out: stop == RunStop::TimedOut,
            wall: started.elapsed(),
        },
        stop,
    })
}

async fn terminate_child(child: &mut tokio::process::Child, pid: Option<u32>) {
    if let Some(pid) = pid {
        kill_process_group(pid);
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

fn clear_pid_slot(pid_slot: &Option<PidSlot>) {
    if let Some(slot) = pid_slot {
        if let Ok(mut guard) = slot.lock() {
            *guard = None;
        }
    }
}

fn pipe_missing(context: &str) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: "pipe missing".to_string(),
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
    async fn provider_crash_is_nonzero_and_descendants_are_killed() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("descendant.pid");
        let script = background_script(&pid_file, "exit 7");
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", &script])
            .build()
            .unwrap();
        let result = run_supervised(&prep, None, None).await.unwrap();
        assert_eq!(result.stop, RunStop::Exited);
        assert_eq!(result.outcome.exit_code, Some(7));
        assert_descendant_dead(&pid_file).await;
    }

    #[tokio::test]
    async fn timeout_kills_the_process_group_and_keeps_partial_output() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("descendant.pid");
        let script = background_script(&pid_file, "wait");
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", &script])
            .timeout(Duration::from_millis(400))
            .build()
            .unwrap();
        let started = Instant::now();
        let outcome = run_to_completion(&prep, None).await.unwrap();
        assert!(outcome.timed_out);
        assert!(started.elapsed() < Duration::from_secs(5), "bounded kill");
        assert_eq!(outcome.stdout_lines, ["early"]);
        assert_eq!(outcome.exit_code, None);
        assert_descendant_dead(&pid_file).await;

        // The bidirectional JSONL transport must enforce the same deadline
        // while a provider holds stdout open without ever completing a frame.
        let interactive = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", "printf unterminated; sleep 30"])
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let factory = |program: &str, args: &[&str], env: &[(&str, &str)]| {
            use std::os::unix::process::CommandExt;
            let mut command = std::process::Command::new(program);
            command.args(args).env_clear().process_group(0);
            for (key, value) in env {
                command.env(key, value);
            }
            command
        };
        let canaries =
            crate::admission::CanarySecrets::new(vec!["interactive-deadline-canary".to_string()])
                .unwrap();
        let mut handler = |_line: &str| {
            Ok(crate::live::InteractiveReaction {
                send: Vec::new(),
                done: false,
            })
        };
        let started = Instant::now();
        let capture = crate::live::run_interactive(
            &factory,
            &interactive,
            &canaries,
            Vec::new(),
            &mut handler,
        )
        .unwrap();
        assert!(capture.timed_out);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bounded JSONL read"
        );

        let oversized = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", "head -c 1048577 /dev/zero | tr '\\0' x"])
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let error = crate::live::capture_turn(&factory, &oversized, &canaries).unwrap_err();
        assert_eq!(error.reason_code(), "IO_FAILED");
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

    #[tokio::test]
    async fn explicit_cancel_kills_the_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("descendant.pid");
        let signal = SupervisionSignal::default();
        let trigger = signal.clone();
        let script = background_script(&pid_file, "wait");
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", &script])
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            trigger.cancel();
        });
        let result = run_supervised(&prep, None, Some(signal)).await.unwrap();
        assert_eq!(result.stop, RunStop::Canceled);
        assert!(!result.outcome.timed_out);
        assert_eq!(result.outcome.stdout_lines, ["early"]);
        assert_descendant_dead(&pid_file).await;
    }

    #[tokio::test]
    async fn heartbeat_failure_kills_the_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("descendant.pid");
        let signal = SupervisionSignal::default();
        let trigger = signal.clone();
        let script = background_script(&pid_file, "wait");
        let prep = ArgvBuilder::new("sh", "/tmp")
            .args(["-c", &script])
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            trigger.heartbeat_failed();
        });
        let result = run_supervised(&prep, None, Some(signal)).await.unwrap();
        assert_eq!(result.stop, RunStop::HeartbeatFailed);
        assert!(result.outcome.wall < Duration::from_secs(5));
        assert_descendant_dead(&pid_file).await;
    }

    fn background_script(pid_file: &std::path::Path, terminal: &str) -> String {
        format!(
            "sleep 30 & child=$!; echo $child > {}; echo early; {terminal}",
            pid_file.display()
        )
    }

    async fn assert_descendant_dead(pid_file: &std::path::Path) {
        let pid = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        for _ in 0..40 {
            if !process_running(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("descendant {pid} survived process-group termination");
    }

    fn process_running(pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        stat.rsplit_once(") ")
            .and_then(|(_, suffix)| suffix.chars().next())
            .is_some_and(|state| state != 'Z')
    }
}
