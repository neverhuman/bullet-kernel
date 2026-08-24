//! Test-only workspace simulation for Runner loop mechanics.
//!
//! This module is compiled only with `cfg(test)`. Its receipts are explicitly
//! non-authoritative and cannot be selected by the production entrypoint.

mod harness;
mod orchestration;

use super::*;
use crate::{DirectLeaseClient, MemoryJournal, MonotonicClock, REPOSITORY_GATE_ID};
use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::{Digest, RunnerId, TaskClass, WorkPackageId};
use bullet_harness_core::{ChangeOp, FileChange};
use harness::ScriptedSim;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

struct SimWorkspace {
    attempt_id: AttemptId,
    repo_dir: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    base_sha: String,
}

impl SimWorkspace {
    fn new(attempt_id: AttemptId) -> Self {
        Self {
            attempt_id,
            repo_dir: None,
            runtime_dir: None,
            base_sha: String::new(),
        }
    }

    fn repo(&self) -> Result<&Path, RunnerError> {
        self.repo_dir
            .as_deref()
            .ok_or_else(|| RunnerError::Protocol("test simulator has no clone".into()))
    }

    fn git(&self, args: &[&str]) -> Result<Vec<u8>, RunnerError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.repo()?)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .map_err(|error| RunnerError::Io {
                context: "test simulator git".into(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(RunnerError::Io {
                context: format!("test simulator git {args:?}"),
                reason: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(output.stdout)
    }

    async fn clone_workspace(
        &mut self,
        source_repo: &Path,
        base_sha: &str,
        root: &Path,
        _allowed_prefixes: &[String],
    ) -> Result<WorkspaceInfo, RunnerError> {
        let workspace = root.join("work").join(self.attempt_id.as_str());
        let repo = workspace.join("repo");
        let runtime = root.join("runtime").join(self.attempt_id.as_str());
        std::fs::create_dir_all(&workspace).map_err(|error| RunnerError::Io {
            context: "test simulator workspace".into(),
            reason: error.to_string(),
        })?;
        std::fs::create_dir_all(&runtime).map_err(|error| RunnerError::Io {
            context: "test simulator runtime".into(),
            reason: error.to_string(),
        })?;
        let output = Command::new("git")
            .args(["clone", "-q", "--no-hardlinks"])
            .arg(source_repo)
            .arg(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .map_err(|error| RunnerError::Io {
                context: "test simulator clone".into(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(RunnerError::Io {
                context: "test simulator clone".into(),
                reason: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        self.repo_dir = Some(repo.clone());
        self.runtime_dir = Some(runtime.clone());
        self.base_sha = base_sha.to_string();
        self.git(&["checkout", "-q", "--detach", base_sha])?;
        Ok(WorkspaceInfo {
            repo_dir: repo,
            runtime_dir: runtime,
            branch: "test-only/simulator".into(),
            base_sha: base_sha.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl WorkspaceSession for SimWorkspace {
    async fn apply_change(&mut self, changes: &[FileChange]) -> Result<u64, RunnerError> {
        let repo = self.repo()?.to_path_buf();
        for change in changes {
            let path = repo.join(&change.path);
            if change.op == ChangeOp::Delete {
                if !path.is_file() {
                    return Err(RunnerError::Gitd {
                        method: "apply_change".into(),
                        code: "PATH_ABSENT".into(),
                        message: format!("no regular file to delete at: {}", change.path),
                    });
                }
                std::fs::remove_file(&path).map_err(|error| RunnerError::Io {
                    context: "test simulator delete".into(),
                    reason: error.to_string(),
                })?;
                continue;
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| RunnerError::Io {
                    context: "test simulator parent".into(),
                    reason: error.to_string(),
                })?;
            }
            std::fs::write(&path, change.contents.as_deref().unwrap_or_default()).map_err(
                |error| RunnerError::Io {
                    context: "test simulator write".into(),
                    reason: error.to_string(),
                },
            )?;
        }
        u64::try_from(changes.len()).map_err(|error| RunnerError::Protocol(error.to_string()))
    }

    async fn checkpoint(&mut self) -> Result<Value, RunnerError> {
        let receipt = serde_json::json!({
            "classification": "TEST_ONLY_SIMULATOR",
            "attempt_id": self.attempt_id.as_str(),
        });
        let runtime = self
            .runtime_dir
            .as_ref()
            .ok_or_else(|| RunnerError::Protocol("test simulator has no runtime".into()))?;
        std::fs::write(runtime.join("checkpoint.json"), receipt.to_string()).map_err(|error| {
            RunnerError::Io {
                context: "test simulator checkpoint".into(),
                reason: error.to_string(),
            }
        })?;
        Ok(receipt)
    }

    async fn prepare_candidate(
        &mut self,
        change_seed: &str,
        _mission: &str,
    ) -> Result<CandidateReceipt, RunnerError> {
        self.git(&["add", "-A"])?;
        self.git(&[
            "-c",
            "user.name=Bullet Test Simulator",
            "-c",
            "user.email=simulator@invalid",
            "commit",
            "-q",
            "-m",
            "test-only candidate",
        ])?;
        let head = String::from_utf8_lossy(&self.git(&["rev-parse", "HEAD"])?)
            .trim()
            .to_string();
        let tree = String::from_utf8_lossy(&self.git(&["rev-parse", "HEAD^{tree}"])?)
            .trim()
            .to_string();
        let patch = self.git(&["diff", "--binary", &format!("{}..HEAD", self.base_sha)])?;
        let paths = String::from_utf8_lossy(&self.git(&[
            "diff",
            "--name-only",
            &format!("{}..HEAD", self.base_sha),
        ])?)
        .lines()
        .map(str::to_string)
        .collect();
        let digest = Digest::of(&patch).to_hex();
        Ok(CandidateReceipt {
            id: format!("can_{}", Digest::of(change_seed.as_bytes()).to_hex()),
            base_commit: self.base_sha.clone(),
            head_commit: head,
            tree_hash: tree,
            patch_hash: digest,
            actual_scope: paths,
            prepared_at: "TEST_ONLY_SIMULATOR".into(),
        })
    }
}

fn proposal(changes: Value) -> Value {
    proposal_with_gates(changes, serde_json::json!([REPOSITORY_GATE_ID]))
}

fn proposal_with_gates(changes: Value, gate_ids: Value) -> Value {
    serde_json::json!({
        "intent_summary": "test-only runner simulation",
        "changes": changes,
        "gate_ids": gate_ids,
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

#[tokio::test]
async fn unadmitted_provider_gate_is_refused_before_apply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal_with_gates(
            serde_json::json!([
                { "path": "PWNED", "op": "create", "contents": "wrong gate applied\n" }
            ]),
            serde_json::json!(["attacker.gate.v1"]),
        ),
    );
    adapter.override_proposal(
        1,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    let (outcome, journal, repo) = run_simulated(
        dir.path(),
        "gate-selection-repair",
        adapter.clone(),
        vec!["PONG.txt".into(), "PWNED".into()],
        vec![REPOSITORY_GATE_ID.into()],
    )
    .await;

    assert_eq!(outcome.repair_rounds, 1);
    assert!(!repo.join("PWNED").exists());
    assert!(repo.join("PONG.txt").is_file());
    assert!(adapter.prompts()[1].contains("GATE_SELECTION_REFUSED"));
    assert!(journal
        .stages()
        .contains(&"gate_selection_refused".to_string()));
}

fn seeded_ledger(seed: &str) -> (Arc<Mutex<MemoryLedger>>, WorkPackageId) {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "test-only runner simulation".into(),
            objective: "create PONG.txt".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("materialize simulation");
    (Arc::new(Mutex::new(ledger)), graph.packages[0].id.clone())
}

fn build_origin(root: &Path) -> (PathBuf, String) {
    let repo = root.join("origin");
    std::fs::create_dir(&repo).expect("origin");
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", root)
            .output()
            .expect("fixture git");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.name", "Bullet Test"]);
    git(&["config", "user.email", "test@invalid"]);
    std::fs::write(repo.join("README.md"), "origin\n").expect("seed");
    git(&["add", "README.md"]);
    git(&["commit", "-q", "-m", "base"]);
    let base = git(&["rev-parse", "HEAD"]);
    (repo, base)
}

async fn run_simulated(
    root: &Path,
    seed: &str,
    adapter: Arc<ScriptedSim>,
    scope: Vec<String>,
    gate_ids: Vec<String>,
) -> (AttemptOutcome, Arc<MemoryJournal>, PathBuf) {
    let (origin, base) = build_origin(root);
    let (ledger, package) = seeded_ledger(seed);
    let client: Arc<dyn LeaseClient> = Arc::new(DirectLeaseClient::new(ledger));
    let journal = Arc::new(MemoryJournal::new());
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed(seed),
        runner_epoch: 1,
        idempotency_key: format!("{seed}-1"),
        ttl_seconds: 15,
    };
    let config = AttemptConfig::new(
        origin,
        base,
        root.join("farm"),
        "test-only objective".into(),
        scope,
        gate_ids,
    );
    let grant = client.acquire(&request).await.expect("test lease");
    journal.record("lease_acquired", "TEST_ONLY_SIMULATOR");
    let mut workspace = SimWorkspace::new(grant.attempt.id.clone());
    let info = workspace
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
        .expect("test-only clone");
    journal.record("workspace_cloned", "TEST_ONLY_SIMULATOR");
    let outcome = run_cloned_attempt(
        client,
        adapter,
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &grant,
        &config,
        &mut workspace,
        &info,
    )
    .await
    .expect("test-only loop");
    (outcome, journal, info.repo_dir)
}

#[tokio::test]
async fn scope_refusal_repairs_only_in_test_simulator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "secrets/key.txt", "op": "create", "contents": "nope\n" }
        ])),
    );
    adapter.override_proposal(
        1,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    let (outcome, journal, repo) = run_simulated(
        dir.path(),
        "scope-repair",
        adapter.clone(),
        vec!["PONG.txt".into()],
        vec![REPOSITORY_GATE_ID.into()],
    )
    .await;
    assert_eq!(outcome.repair_rounds, 1);
    assert_eq!(outcome.candidate.prepared_at, "TEST_ONLY_SIMULATOR");
    assert!(!repo.join("secrets").exists());
    assert!(repo.join("PONG.txt").is_file());
    assert!(adapter.prompts()[1].contains("SCOPE_DENIED"));
    assert!(journal.stages().contains(&"scope_denied".to_string()));
}

#[tokio::test]
async fn missing_delete_repairs_only_in_test_simulator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "MISSING.txt", "op": "delete", "contents": null }
        ])),
    );
    adapter.override_proposal(
        1,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
        ])),
    );
    let (outcome, journal, repo) = run_simulated(
        dir.path(),
        "path-repair",
        adapter.clone(),
        vec!["PONG.txt".into(), "MISSING.txt".into()],
        vec![REPOSITORY_GATE_ID.into()],
    )
    .await;
    assert_eq!(outcome.repair_rounds, 1);
    assert!(repo.join("PONG.txt").is_file());
    assert!(adapter.prompts()[1].contains("PATH_ABSENT"));
    assert!(journal.stages().contains(&"path_absent".to_string()));
}

#[tokio::test]
async fn gate_delete_repairs_only_in_test_simulator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = Arc::new(ScriptedSim::new());
    adapter.override_proposal(
        0,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "create", "contents": "WRONG\n" },
            { "path": "OLD.txt", "op": "create", "contents": "old\n" }
        ])),
    );
    adapter.override_proposal(
        1,
        proposal(serde_json::json!([
            { "path": "PONG.txt", "op": "modify", "contents": "PONG\n" },
            { "path": "OLD.txt", "op": "delete", "contents": null }
        ])),
    );
    let (outcome, _journal, repo) = run_simulated(
        dir.path(),
        "delete-repair",
        adapter,
        vec!["PONG.txt".into(), "OLD.txt".into()],
        vec![REPOSITORY_GATE_ID.into()],
    )
    .await;
    assert_eq!(outcome.repair_rounds, 1);
    assert_eq!(outcome.candidate.actual_scope, vec!["PONG.txt"]);
    assert!(repo.join("PONG.txt").is_file());
    assert!(!repo.join("OLD.txt").exists());
}
