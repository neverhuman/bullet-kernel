//! Deterministic gate execution through a sealed fixed-argv registry.
//! Provider text and caller strings are never programs, arguments, or shell.

use crate::error::RunnerError;
use bullet_harness_core::proposal::validate_gate_ids;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

const CAPTURE_LIMIT: usize = 4096;

/// Fixed gate used by the credential-free repository fixture.
pub const REPOSITORY_GATE_ID: &str = "repo.gate.v1";

#[derive(Clone, Copy)]
struct GateDefinition {
    id: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

const GATES: &[GateDefinition] = &[GateDefinition {
    id: REPOSITORY_GATE_ID,
    program: "/usr/bin/grep",
    args: &["-qx", "PONG", "PONG.txt"],
}];

/// Sealed V1 registry. There is intentionally no dynamic registration API.
#[derive(Clone, Copy, Debug, Default)]
pub struct GateRegistry;

impl GateRegistry {
    /// Frozen registry used by production Runner paths.
    #[must_use]
    pub const fn v1() -> Self {
        Self
    }

    fn definition(self, gate_id: &str) -> Result<GateDefinition, RunnerError> {
        GATES
            .iter()
            .find(|gate| gate.id == gate_id)
            .copied()
            .ok_or_else(|| RunnerError::GateSelection {
                reason: format!("unknown gate_id {gate_id:?}"),
            })
    }

    /// Validate a complete ordered selection against lexical and registry
    /// authority.
    ///
    /// # Errors
    ///
    /// `GATE_SELECTION_REFUSED` for malformed, duplicate, empty, oversized,
    /// or unknown identifiers.
    pub fn validate_selection(self, gate_ids: &[String]) -> Result<(), RunnerError> {
        validate_gate_ids(gate_ids).map_err(|error| RunnerError::GateSelection {
            reason: error.to_string(),
        })?;
        for gate_id in gate_ids {
            self.definition(gate_id)?;
        }
        Ok(())
    }

    /// Require the provider to echo the exact ordered policy selection.
    /// Execution still uses `admitted`, never provider data.
    ///
    /// # Errors
    ///
    /// `GATE_SELECTION_REFUSED` when either list is invalid or differs.
    pub fn require_exact(
        self,
        admitted: &[String],
        proposed: &[String],
    ) -> Result<(), RunnerError> {
        self.validate_selection(admitted)?;
        self.validate_selection(proposed)?;
        if admitted != proposed {
            return Err(RunnerError::GateSelection {
                reason: format!(
                    "proposal gate_ids {proposed:?} do not equal admitted gate_ids {admitted:?}"
                ),
            });
        }
        Ok(())
    }

    /// Return the registry-owned argv for audit display.
    ///
    /// # Errors
    ///
    /// `GATE_SELECTION_REFUSED` for an unknown identifier.
    pub fn argv(self, gate_id: &str) -> Result<Vec<String>, RunnerError> {
        let gate = self.definition(gate_id)?;
        Ok(std::iter::once(gate.program)
            .chain(gate.args.iter().copied())
            .map(str::to_string)
            .collect())
    }

    async fn run(
        self,
        workdir: &Path,
        gate_id: &str,
        timeout: Duration,
    ) -> Result<GateReport, RunnerError> {
        let gate = self.definition(gate_id)?;
        let argv = self.argv(gate_id)?;
        let child = tokio::process::Command::new(gate.program)
            .args(gate.args)
            .current_dir(workdir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| RunnerError::Gate {
                command: gate_id.to_string(),
                reason: error.to_string(),
            })?;
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Ok(GateReport {
                gate_id: gate_id.to_string(),
                argv,
                exit_code: output.status.code(),
                timed_out: false,
                stdout: truncate(&output.stdout),
                stderr: truncate(&output.stderr),
            }),
            Ok(Err(error)) => Err(RunnerError::Gate {
                command: gate_id.to_string(),
                reason: error.to_string(),
            }),
            Err(_) => Ok(GateReport {
                gate_id: gate_id.to_string(),
                argv,
                exit_code: None,
                timed_out: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        }
    }
}

/// One fixed-argv gate result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateReport {
    /// Registry-owned gate identifier.
    pub gate_id: String,
    /// Exact fixed argv selected by the registry.
    pub argv: Vec<String>,
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

/// Run one admitted gate using only registry-owned argv.
///
/// # Errors
///
/// Returns `GATE_SELECTION_REFUSED` for unknown IDs and `GATE_FAILED` only
/// when the fixed process cannot be executed.
pub async fn run_gate(
    workdir: &Path,
    gate_id: &str,
    timeout: Duration,
) -> Result<GateReport, RunnerError> {
    GateRegistry::v1().run(workdir, gate_id, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fixed_argv_pass_fail_and_timeout_are_typed() {
        let directory = tempfile::tempdir().unwrap();
        let subject = directory.path().join("PONG.txt");
        std::fs::write(&subject, "PONG\n").unwrap();
        let pass = run_gate(directory.path(), REPOSITORY_GATE_ID, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(pass.passed());
        assert_eq!(pass.argv, ["/usr/bin/grep", "-qx", "PONG", "PONG.txt"]);

        std::fs::write(&subject, "NOT PONG\n").unwrap();
        let fail = run_gate(directory.path(), REPOSITORY_GATE_ID, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(!fail.passed());
        assert_eq!(fail.exit_code, Some(1));

        std::fs::remove_file(&subject).unwrap();
        let fifo = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&subject)
            .status()
            .unwrap();
        assert!(fifo.success());
        let slow = run_gate(
            directory.path(),
            REPOSITORY_GATE_ID,
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert!(slow.timed_out);
        assert!(!slow.passed());
    }

    #[tokio::test]
    async fn unknown_or_command_shaped_ids_never_execute() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("PWNED");
        let malicious = format!("repo.gate.v1;/usr/bin/touch{}", marker.to_string_lossy());
        let error = run_gate(directory.path(), &malicious, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), "GATE_SELECTION_REFUSED");
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn repository_shell_text_is_never_a_gate_program() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("PWNED");
        std::fs::write(directory.path().join("PONG.txt"), "PONG\n").unwrap();
        std::fs::write(
            directory.path().join("gate.sh"),
            format!("#!/bin/sh\ntouch {}\n", marker.display()),
        )
        .unwrap();

        let report = run_gate(directory.path(), REPOSITORY_GATE_ID, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(report.passed());
        assert!(!marker.exists());
    }

    #[test]
    fn selection_is_bounded_unique_known_and_exact() {
        let registry = GateRegistry::v1();
        let admitted = vec![REPOSITORY_GATE_ID.to_string()];
        assert!(registry.validate_selection(&admitted).is_ok());
        assert!(registry.require_exact(&admitted, &admitted).is_ok());
        for invalid in [
            vec![],
            vec![REPOSITORY_GATE_ID.into(), REPOSITORY_GATE_ID.into()],
            vec!["unknown.gate.v1".into()],
        ] {
            assert!(registry.validate_selection(&invalid).is_err());
        }
    }
}
