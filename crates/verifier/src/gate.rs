//! Gate execution inside the clean clone: bounded, typed, and honest about
//! gates that executed zero tests.

use bullet_domain::{GateOutcome, REASON_ZERO_TESTS};
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

/// Reason code when the gate ran out of budget.
pub const REASON_GATE_TIMEOUT: &str = "GATE_TIMEOUT";
/// Reason code when the gate exited nonzero.
pub const REASON_GATE_NONZERO_EXIT: &str = "GATE_NONZERO_EXIT";
/// Reason code when the shell could not find the gate command.
pub const REASON_GATE_COMMAND_NOT_FOUND: &str = "GATE_COMMAND_NOT_FOUND";
/// Reason code when the gate process could not be spawned.
pub const REASON_GATE_SPAWN_FAILED: &str = "GATE_SPAWN_FAILED";
/// Reason code when the gate died on a signal.
pub const REASON_GATE_SIGNALED: &str = "GATE_SIGNALED";

/// Typed result of one gate run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateRun {
    /// Typed outcome.
    pub outcome: GateOutcome,
    /// Stable reason code refining the outcome.
    pub reason: Option<String>,
    /// Detail for operators; never parsed.
    pub detail: Option<String>,
    /// Exit code when the gate produced one.
    pub exit_code: Option<i32>,
}

/// Whether the gate command is `cargo test`-shaped (including nextest), so
/// a zero-test run must read `NOT_RUN`, never `PASS`.
#[must_use]
pub fn cargo_test_shaped(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let has_cargo = tokens
        .iter()
        .any(|token| token.rsplit('/').next() == Some("cargo"));
    let has_test = tokens
        .iter()
        .any(|token| *token == "test" || *token == "nextest");
    has_cargo && has_test
}

/// Total tests executed according to `test result:` summary lines. `None`
/// when the output carries no summary at all.
#[must_use]
pub fn executed_test_count(stdout: &str) -> Option<u64> {
    let mut total: Option<u64> = None;
    for line in stdout.lines() {
        let Some(rest) = line.trim_start().strip_prefix("test result:") else {
            continue;
        };
        let mut line_total = 0u64;
        for suffix in [" passed", " failed"] {
            for chunk in rest.split(';') {
                if let Some(number) = chunk.strip_suffix(suffix) {
                    if let Ok(value) = number
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .parse::<u64>()
                    {
                        line_total += value;
                    }
                }
            }
        }
        total = Some(total.unwrap_or(0) + line_total);
    }
    total
}

fn command_for(clone_dir: &Path, gate_command: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg(gate_command).current_dir(clone_dir);
    // Credential and repository-redirection variables never reach the gate.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_string();
        if name.starts_with("GIT_")
            || name == "GH_TOKEN"
            || name == "GITHUB_TOKEN"
            || name == "SSH_AUTH_SOCK"
        {
            cmd.env_remove(&name);
        }
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn classify(status: std::process::ExitStatus, gate_command: &str, stdout: &str) -> GateRun {
    let Some(code) = status.code() else {
        return GateRun {
            outcome: GateOutcome::InfraError,
            reason: Some(REASON_GATE_SIGNALED.into()),
            detail: Some(format!("gate terminated by signal: {status}")),
            exit_code: None,
        };
    };
    if code == 127 {
        return GateRun {
            outcome: GateOutcome::InfraError,
            reason: Some(REASON_GATE_COMMAND_NOT_FOUND.into()),
            detail: Some("shell reported exit 127 (command not found)".into()),
            exit_code: Some(code),
        };
    }
    if code != 0 {
        return GateRun {
            outcome: GateOutcome::Fail,
            reason: Some(REASON_GATE_NONZERO_EXIT.into()),
            detail: None,
            exit_code: Some(code),
        };
    }
    if cargo_test_shaped(gate_command) && executed_test_count(stdout) == Some(0) {
        return GateRun {
            outcome: GateOutcome::NotRun,
            reason: Some(REASON_ZERO_TESTS.into()),
            detail: Some("gate exited 0 but executed zero tests".into()),
            exit_code: Some(code),
        };
    }
    GateRun {
        outcome: GateOutcome::Pass,
        reason: None,
        detail: None,
        exit_code: Some(code),
    }
}

/// Run the gate with a hard budget. Timeout is `TIMED_OUT`, spawn failure
/// is `INFRA_ERROR`; both are outcomes, never fabricated `PASS`.
pub async fn run_gate(clone_dir: &Path, gate_command: &str, timeout_secs: u64) -> GateRun {
    let mut child = match command_for(clone_dir, gate_command).spawn() {
        Ok(child) => child,
        Err(err) => {
            return GateRun {
                outcome: GateOutcome::InfraError,
                reason: Some(REASON_GATE_SPAWN_FAILED.into()),
                detail: Some(err.to_string()),
                exit_code: None,
            }
        }
    };
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let reader = tokio::spawn(async move {
        let mut out = String::new();
        let mut err = String::new();
        if let Some(pipe) = stdout_pipe.as_mut() {
            let _ = pipe.read_to_string(&mut out).await;
        }
        if let Some(pipe) = stderr_pipe.as_mut() {
            let _ = pipe.read_to_string(&mut err).await;
        }
        (out, err)
    });
    match timeout(Duration::from_secs(timeout_secs), child.wait()).await {
        Err(_elapsed) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            reader.abort();
            GateRun {
                outcome: GateOutcome::TimedOut,
                reason: Some(REASON_GATE_TIMEOUT.into()),
                detail: Some(format!("gate exceeded {timeout_secs}s budget")),
                exit_code: None,
            }
        }
        Ok(Err(err)) => GateRun {
            outcome: GateOutcome::InfraError,
            reason: Some(REASON_GATE_SPAWN_FAILED.into()),
            detail: Some(err.to_string()),
            exit_code: None,
        },
        Ok(Ok(status)) => {
            let (stdout, _stderr) = reader.await.unwrap_or_default();
            classify(status, gate_command, &stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_shapes_are_detected() {
        assert!(cargo_test_shaped("cargo test"));
        assert!(cargo_test_shaped("/home/x/.cargo/bin/cargo test --lib"));
        assert!(cargo_test_shaped("cargo nextest run"));
        assert!(!cargo_test_shaped("cargo build"));
        assert!(!cargo_test_shaped("pytest test"));
    }

    #[test]
    fn summary_lines_are_summed() {
        let out = "running 0 tests\n\
                   test result: ok. 0 passed; 0 failed; 0 ignored\n\
                   test result: ok. 0 passed; 0 failed; 0 ignored\n";
        assert_eq!(executed_test_count(out), Some(0));
        let some = "test result: ok. 3 passed; 1 failed; 0 ignored\n";
        assert_eq!(executed_test_count(some), Some(4));
        assert_eq!(executed_test_count("no summary here"), None);
    }
}
