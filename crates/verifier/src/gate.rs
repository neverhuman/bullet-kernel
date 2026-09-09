//! Gate execution inside the clean clone through immutable catalog argv.

use bullet_domain::{GateDefinition, GateOutcome};
use std::path::Path;
use std::process::Stdio;
use tokio::time::{timeout, Duration};

/// Reason code when the gate ran out of budget.
pub const REASON_GATE_TIMEOUT: &str = "GATE_TIMEOUT";
/// Reason code when the gate exited nonzero.
pub const REASON_GATE_NONZERO_EXIT: &str = "GATE_NONZERO_EXIT";
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

fn command_for(clone_dir: &Path, gate: GateDefinition) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(gate.program());
    cmd.args(gate.args())
        .current_dir(clone_dir)
        .env_clear()
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .kill_on_drop(true);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn classify(status: std::process::ExitStatus) -> GateRun {
    let Some(code) = status.code() else {
        return GateRun {
            outcome: GateOutcome::InfraError,
            reason: Some(REASON_GATE_SIGNALED.into()),
            detail: Some(format!("gate terminated by signal: {status}")),
            exit_code: None,
        };
    };
    if code != 0 {
        return GateRun {
            outcome: GateOutcome::Fail,
            reason: Some(REASON_GATE_NONZERO_EXIT.into()),
            detail: None,
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
pub async fn run_gate(clone_dir: &Path, gate: GateDefinition) -> GateRun {
    let child = match command_for(clone_dir, gate).spawn() {
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
    let timeout_secs = gate.timeout_secs();
    match timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await {
        Err(_elapsed) => GateRun {
            outcome: GateOutcome::TimedOut,
            reason: Some(REASON_GATE_TIMEOUT.into()),
            detail: Some(format!("gate exceeded {timeout_secs}s budget")),
            exit_code: None,
        },
        Ok(Err(err)) => GateRun {
            outcome: GateOutcome::InfraError,
            reason: Some(REASON_GATE_SPAWN_FAILED.into()),
            detail: Some(err.to_string()),
            exit_code: None,
        },
        Ok(Ok(output)) => classify(output.status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> GateDefinition {
        let gate_id = bullet_domain::GateId::parse(bullet_domain::REPOSITORY_GATE_ID).unwrap();
        bullet_domain::gate_definition(&gate_id).unwrap()
    }

    #[tokio::test]
    async fn direct_fixed_gate_pass_fail_and_policy_timeout_are_typed() {
        let directory = tempfile::tempdir().unwrap();
        let subject = directory.path().join("PONG.txt");
        std::fs::write(&subject, "PONG\n").unwrap();
        assert_eq!(
            run_gate(directory.path(), definition()).await.outcome,
            GateOutcome::Pass
        );

        std::fs::write(&subject, "NOT PONG\n").unwrap();
        let failed = run_gate(directory.path(), definition()).await;
        assert_eq!(failed.outcome, GateOutcome::Fail);
        assert_eq!(failed.exit_code, Some(1));

        std::fs::remove_file(&subject).unwrap();
        assert!(std::process::Command::new("/usr/bin/mkfifo")
            .arg(&subject)
            .status()
            .unwrap()
            .success());
        let timed_out = run_gate(directory.path(), definition()).await;
        assert_eq!(timed_out.outcome, GateOutcome::TimedOut);
        assert_eq!(timed_out.reason.as_deref(), Some(REASON_GATE_TIMEOUT));
    }
}
