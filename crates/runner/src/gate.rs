//! Deterministic gate execution: a bounded shell command inside the private
//! clone. Only a typed zero exit is a pass; a timeout or refusal never is.

use crate::error::RunnerError;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

const CAPTURE_LIMIT: usize = 4096;

/// Typed result of one gate run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateReport {
    /// The command line that ran.
    pub command: String,
    /// Process exit code when it finished.
    pub exit_code: Option<i32>,
    /// True when the wall-clock bound killed the gate.
    pub timed_out: bool,
    /// Captured stdout (truncated).
    pub stdout: String,
    /// Captured stderr (truncated).
    pub stderr: String,
}

impl GateReport {
    /// Only a clean zero exit passes.
    #[must_use]
    pub fn passed(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

fn truncate(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= CAPTURE_LIMIT {
        return text.into_owned();
    }
    format!("{}… [truncated]", &text[..CAPTURE_LIMIT])
}

/// Run one gate command via `sh -c` in `workdir`, bounded by `timeout`.
///
/// # Errors
///
/// Returns `GATE_FAILED` only when the command cannot be spawned at all; a
/// failing or timed-out gate is a normal `GateReport`.
pub async fn run_gate(
    workdir: &Path,
    command: &str,
    timeout: Duration,
) -> Result<GateReport, RunnerError> {
    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| RunnerError::Gate {
            command: command.to_string(),
            reason: err.to_string(),
        })?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(GateReport {
            command: command.to_string(),
            exit_code: output.status.code(),
            timed_out: false,
            stdout: truncate(&output.stdout),
            stderr: truncate(&output.stderr),
        }),
        Ok(Err(err)) => Err(RunnerError::Gate {
            command: command.to_string(),
            reason: err.to_string(),
        }),
        Err(_) => Ok(GateReport {
            command: command.to_string(),
            exit_code: None,
            timed_out: true,
            stdout: String::new(),
            stderr: String::new(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pass_fail_and_timeout_are_typed() {
        let dir = std::env::temp_dir();
        let pass = run_gate(&dir, "true", Duration::from_secs(5))
            .await
            .unwrap();
        assert!(pass.passed());
        let fail = run_gate(
            &dir,
            "echo out; echo err >&2; exit 3",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(!fail.passed());
        assert_eq!(fail.exit_code, Some(3));
        assert!(fail.stdout.contains("out"));
        assert!(fail.stderr.contains("err"));
        let slow = run_gate(&dir, "sleep 10", Duration::from_millis(100))
            .await
            .unwrap();
        assert!(slow.timed_out);
        assert!(!slow.passed());
    }
}
