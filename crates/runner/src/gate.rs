//! Deterministic gate execution through a sealed fixed-argv registry.
//! Provider text and caller strings are never programs, arguments, or shell.

mod process;
mod workdir;
pub(crate) use workdir::GateWorkdir;

use crate::error::RunnerError;
pub use bullet_domain::REPOSITORY_GATE_ID;
use bullet_domain::{gate_definition, parse_gate_ids, GateDefinition, GateId};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

const CAPTURE_LIMIT: usize = 4096;

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
        let gate_id = GateId::parse(gate_id).map_err(|error| RunnerError::GateSelection {
            reason: error.to_string(),
        })?;
        gate_definition(&gate_id).ok_or_else(|| RunnerError::GateSelection {
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
        let gate_ids = parse_gate_ids(gate_ids).map_err(|error| RunnerError::GateSelection {
            reason: error.to_string(),
        })?;
        for gate_id in gate_ids {
            if gate_definition(&gate_id).is_none() {
                return Err(RunnerError::GateSelection {
                    reason: format!("unknown gate_id {gate_id:?}"),
                });
            }
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
        Ok(gate.argv())
    }

    async fn run(self, workdir: &Path, gate_id: &str) -> Result<GateReport, RunnerError> {
        let workdir = GateWorkdir::open(workdir)?;
        self.run_bound(&workdir, gate_id).await
    }

    async fn run_bound(
        self,
        workdir: &GateWorkdir,
        gate_id: &str,
    ) -> Result<GateReport, RunnerError> {
        let gate = self.definition(gate_id)?;
        let argv = gate.argv();
        let scratch =
            process::create_scratch(workdir.spawn_path()).map_err(|reason| RunnerError::Gate {
                command: gate_id.to_string(),
                reason,
            })?;
        let mut command = tokio::process::Command::new(gate.program());
        command
            .args(gate.args())
            .current_dir(workdir.spawn_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        configure_gate_environment(&mut command, &scratch.path());
        let policy_timeout = Duration::from_secs(gate.timeout_secs());
        let output = process::run(&mut command, policy_timeout, CAPTURE_LIMIT)
            .await
            .map_err(|reason| RunnerError::Gate {
                command: gate_id.to_string(),
                reason,
            })?;
        Ok(GateReport {
            gate_id: gate_id.to_string(),
            argv,
            exit_code: output.exit_code,
            timed_out: output.timed_out,
            stdout: truncate(&output.stdout),
            stderr: truncate(&output.stderr),
        })
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

fn truncate(captured: &process::Captured) -> String {
    let text = String::from_utf8_lossy(&captured.bytes);
    if !captured.overflow && text.len() <= CAPTURE_LIMIT {
        return text.into_owned();
    }
    let mut end = CAPTURE_LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated]", &text[..end])
}

fn configure_gate_environment(command: &mut tokio::process::Command, scratch: &Path) {
    let cargo_target = scratch.join("cargo-target");
    command
        .env_clear()
        .env("CARGO_HOME", "/nonexistent")
        .env("CARGO_TARGET_DIR", cargo_target)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", "/nonexistent")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("RUSTUP_HOME", "/nonexistent")
        .env("TMPDIR", scratch);
}

/// Run one admitted gate using only registry-owned argv.
///
/// # Errors
///
/// Returns `GATE_SELECTION_REFUSED` for unknown IDs and `GATE_FAILED` only
/// when the fixed process cannot be executed.
pub async fn run_gate(workdir: &Path, gate_id: &str) -> Result<GateReport, RunnerError> {
    GateRegistry::v1().run(workdir, gate_id).await
}

/// Run one admitted gate from an already-opened workspace directory identity.
pub(crate) async fn run_gate_bound(
    workdir: &GateWorkdir,
    gate_id: &str,
) -> Result<GateReport, RunnerError> {
    GateRegistry::v1().run_bound(workdir, gate_id).await
}

/// Complete one gate and rebind the exact worktree before its result can
/// influence repair, another provider turn, or another apply.
pub(crate) async fn run_gate_bound_verified(
    workdir: &GateWorkdir,
    gate_id: &str,
    expected_git_tree: &str,
) -> Result<GateReport, RunnerError> {
    verify_gate_completion(workdir, expected_git_tree, run_gate_bound(workdir, gate_id)).await
}

async fn verify_gate_completion<F>(
    workdir: &GateWorkdir,
    expected_git_tree: &str,
    completion: F,
) -> Result<GateReport, RunnerError>
where
    F: Future<Output = Result<GateReport, RunnerError>>,
{
    let report = completion.await;
    workdir.verify_git_tree(expected_git_tree).await?;
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn captured_output_truncates_only_at_utf8_boundaries() {
        let mut output = "a".repeat(CAPTURE_LIMIT - 1);
        output.push('é');
        output.push_str("tail");
        let truncated = truncate(&process::Captured {
            bytes: output.into_bytes(),
            overflow: true,
        });
        assert!(truncated.starts_with(&"a".repeat(CAPTURE_LIMIT - 1)));
        assert!(truncated.ends_with("… [truncated]"));
        assert!(!truncated.contains('é'));
    }

    #[tokio::test]
    async fn gate_environment_is_closed_and_build_output_is_external() {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = process::create_scratch(workspace.path()).unwrap();
        let mut command = tokio::process::Command::new("/usr/bin/env");
        configure_gate_environment(&mut command, &scratch.path());
        let output = command.output().await.unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let environment = stdout
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect::<BTreeMap<_, _>>();
        let target = scratch.path().join("cargo-target");
        assert_eq!(environment.get("CARGO_HOME"), Some(&"/nonexistent"));
        assert_eq!(
            environment.get("CARGO_TARGET_DIR"),
            Some(&target.to_str().unwrap())
        );
        assert_eq!(environment.get("HOME"), Some(&"/nonexistent"));
        assert_eq!(environment.get("LC_ALL"), Some(&"C"));
        assert_eq!(environment.get("PATH"), Some(&"/usr/bin:/bin"));
        assert_eq!(
            environment.get("TMPDIR"),
            Some(&scratch.path().to_str().unwrap())
        );
        assert_eq!(environment.len(), 12);
        assert!(!target.starts_with(workspace.path()));

        let mut access = tokio::process::Command::new("/usr/bin/test");
        access.arg("-d").arg(scratch.path());
        configure_gate_environment(&mut access, &scratch.path());
        assert!(access.status().await.unwrap().success());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ignored_untracked_inputs_remain_refused() {
        let directory = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("/usr/bin/git")
                .args(args)
                .current_dir(directory.path())
                .env_clear()
                .env("HOME", "/nonexistent")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };
        git(&["init", "-q", "-b", "main"]);
        std::fs::write(directory.path().join(".gitignore"), "target/\n").unwrap();
        std::fs::write(directory.path().join("PONG.txt"), "PONG\n").unwrap();
        git(&["add", ".gitignore", "PONG.txt"]);
        let expected = format!("sha1:{}", git(&["write-tree"]));
        std::fs::create_dir(directory.path().join("target")).unwrap();
        std::fs::write(
            directory.path().join("target/influences-build"),
            "hostile\n",
        )
        .unwrap();

        let workdir = GateWorkdir::open(directory.path()).unwrap();
        let error = workdir.verify_git_tree(&expected).await.unwrap_err();
        assert_eq!(error.reason_code(), "GATE_FAILED");
    }

    #[tokio::test]
    async fn fixed_argv_pass_fail_and_timeout_are_typed() {
        let directory = tempfile::tempdir().unwrap();
        let subject = directory.path().join("PONG.txt");
        std::fs::write(&subject, "PONG\n").unwrap();
        let pass = run_gate(directory.path(), REPOSITORY_GATE_ID)
            .await
            .unwrap();
        assert!(pass.passed());
        assert_eq!(pass.argv, ["/usr/bin/grep", "-qx", "PONG", "PONG.txt"]);

        std::fs::write(&subject, "NOT PONG\n").unwrap();
        let fail = run_gate(directory.path(), REPOSITORY_GATE_ID)
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
        let slow = run_gate(directory.path(), REPOSITORY_GATE_ID)
            .await
            .unwrap();
        assert!(slow.timed_out);
        assert!(!slow.passed());
    }

    #[tokio::test]
    async fn unknown_or_command_shaped_ids_never_execute() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("PWNED");
        let malicious = format!(
            "{REPOSITORY_GATE_ID};/usr/bin/touch{}",
            marker.to_string_lossy()
        );
        let error = run_gate(directory.path(), &malicious).await.unwrap_err();
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

        let report = run_gate(directory.path(), REPOSITORY_GATE_ID)
            .await
            .unwrap();
        assert!(report.passed());
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn opened_workdir_survives_a_post_validation_symlink_swap() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let admitted = root.path().join("admitted");
        let retained = root.path().join("retained");
        let outside = root.path().join("outside");
        std::fs::create_dir(&admitted).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(admitted.join("PONG.txt"), "PONG\n").unwrap();
        std::fs::write(outside.join("PONG.txt"), "NOT PONG\n").unwrap();
        let bound = GateWorkdir::open(&admitted).unwrap();
        std::fs::rename(&admitted, &retained).unwrap();
        symlink(&outside, &admitted).unwrap();

        let report = GateRegistry::v1()
            .run_bound(&bound, REPOSITORY_GATE_ID)
            .await
            .unwrap();
        assert!(report.passed());
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_gate_mutation_refuses_before_the_next_action() {
        let directory = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("/usr/bin/git")
                .args(args)
                .current_dir(directory.path())
                .env_clear()
                .env("HOME", "/nonexistent")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };
        git(&["init", "-q", "-b", "main"]);
        std::fs::write(directory.path().join("README.md"), "exact\n").unwrap();
        std::fs::write(directory.path().join("PONG.txt"), "NOT PONG\n").unwrap();
        git(&["add", "README.md", "PONG.txt"]);
        let expected = format!("sha1:{}", git(&["write-tree"]));
        let workdir = GateWorkdir::open(directory.path()).unwrap();
        let next_actions = AtomicUsize::new(0);

        let result = async {
            let report = verify_gate_completion(&workdir, &expected, async {
                std::fs::write(directory.path().join("README.md"), "mutated\n").unwrap();
                Ok(GateReport {
                    gate_id: REPOSITORY_GATE_ID.to_owned(),
                    argv: vec!["/usr/bin/grep".to_owned()],
                    exit_code: Some(1),
                    timed_out: false,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
            .await?;
            assert!(!report.passed());
            next_actions.fetch_add(1, Ordering::SeqCst);
            Ok::<(), RunnerError>(())
        }
        .await;

        assert_eq!(result.unwrap_err().reason_code(), "GATE_FAILED");
        assert_eq!(next_actions.load(Ordering::SeqCst), 0);
    }
}
