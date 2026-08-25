//! Test-only workspace simulation for Runner loop mechanics.
//!
//! This module is compiled only with `cfg(test)`. Its receipts are explicitly
//! non-authoritative and cannot be selected by the production entrypoint.

mod harness;
mod orchestration;

use super::*;
use crate::gitd::{ApplyProposalReceipt, CheckpointBinding};
use crate::{DirectLeaseClient, MemoryJournal, MonotonicClock, REPOSITORY_GATE_ID};
use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::{Digest, RunnerId, TaskClass, WorkPackageId};
use bullet_harness_core::{PatchMutation, PatchProposal, Preimage};
use harness::ScriptedSim;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

struct SimWorkspace {
    attempt_id: AttemptId,
    repo_dir: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    base_sha: String,
    checkpoint_id: String,
    checkpoint_digest: String,
    generation: u64,
}

impl SimWorkspace {
    fn new(attempt_id: AttemptId) -> Self {
        Self {
            attempt_id,
            repo_dir: None,
            runtime_dir: None,
            base_sha: String::new(),
            checkpoint_id: String::new(),
            checkpoint_digest: String::new(),
            generation: 0,
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
        self.checkpoint_digest = Digest::of(format!("TEST_ONLY:{base_sha}:0").as_bytes()).to_hex();
        self.checkpoint_id = format!("ckp_{}", self.checkpoint_digest);
        self.git(&["checkout", "-q", "--detach", base_sha])?;
        Ok(WorkspaceInfo {
            repo_dir: repo,
            runtime_dir: runtime,
            branch: "test-only/simulator".into(),
            base_sha: base_sha.to_string(),
            base_checkpoint_id: self.checkpoint_id.clone(),
            base_checkpoint_digest: self.checkpoint_digest.clone(),
        })
    }
}

#[async_trait::async_trait]
impl WorkspaceSession for SimWorkspace {
    async fn apply_proposal(
        &mut self,
        proposal: &PatchProposal,
    ) -> Result<ApplyProposalReceipt, RunnerError> {
        if proposal.producing_attempt_id != self.attempt_id.as_str()
            || proposal.base_checkpoint_id != self.checkpoint_id
            || proposal.base_checkpoint_digest != self.checkpoint_digest
        {
            return Err(RunnerError::Gitd {
                method: "apply_proposal".into(),
                code: "STALE_CHECKPOINT".into(),
                message: "TEST_ONLY simulator binding mismatch".into(),
            });
        }
        let repo = self.repo()?.to_path_buf();
        for operation in &proposal.operations {
            let path = repo.join(&operation.path);
            match &operation.preimage {
                Preimage::Absent if path.exists() => {
                    return Err(RunnerError::Gitd {
                        method: "apply_proposal".into(),
                        code: "PREIMAGE_MISMATCH".into(),
                        message: format!("expected absent path: {}", operation.path),
                    });
                }
                Preimage::Digest { digest } => {
                    if !path.is_file() {
                        return Err(RunnerError::Gitd {
                            method: "apply_proposal".into(),
                            code: "PATH_ABSENT".into(),
                            message: format!("no regular file at: {}", operation.path),
                        });
                    }
                    let bytes = std::fs::read(&path).map_err(|error| RunnerError::Io {
                        context: "test simulator preimage".into(),
                        reason: error.to_string(),
                    })?;
                    if Digest::of(&bytes).to_hex() != *digest {
                        return Err(RunnerError::Gitd {
                            method: "apply_proposal".into(),
                            code: "PREIMAGE_MISMATCH".into(),
                            message: format!("stale preimage: {}", operation.path),
                        });
                    }
                }
                Preimage::Absent => {}
            }
        }
        for operation in &proposal.operations {
            let path = repo.join(&operation.path);
            if matches!(operation.mutation, PatchMutation::Delete) {
                if !path.is_file() {
                    return Err(RunnerError::Gitd {
                        method: "apply_proposal".into(),
                        code: "PATH_ABSENT".into(),
                        message: format!("no regular file to delete at: {}", operation.path),
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
            let PatchMutation::Write { content_utf8 } = &operation.mutation else {
                unreachable!("delete handled above")
            };
            std::fs::write(&path, content_utf8).map_err(|error| RunnerError::Io {
                context: "test simulator write".into(),
                reason: error.to_string(),
            })?;
        }
        self.generation += 1;
        self.checkpoint_digest = Digest::of(
            format!(
                "TEST_ONLY:{}:{}:{}",
                self.base_sha, self.generation, proposal.proposal_id
            )
            .as_bytes(),
        )
        .to_hex();
        self.checkpoint_id = format!("ckp_{}", self.checkpoint_digest);
        Ok(ApplyProposalReceipt {
            proposal_id: proposal.proposal_id.clone(),
            applied: u64::try_from(proposal.operations.len())
                .map_err(|error| RunnerError::Protocol(error.to_string()))?,
            checkpoint: CheckpointBinding {
                id: self.checkpoint_id.clone(),
                digest: self.checkpoint_digest.clone(),
            },
        })
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
    let operations = changes
        .as_array()
        .expect("test changes")
        .iter()
        .map(|change| {
            let path = change["path"].as_str().expect("test path");
            let op = change["op"].as_str().expect("test op");
            let preimage = match (op, path) {
                ("create", _) => serde_json::json!({ "kind": "absent" }),
                ("modify", "PONG.txt") => serde_json::json!({
                    "kind": "digest", "digest": Digest::of(b"WRONG\n").to_hex()
                }),
                ("delete", "OLD.txt") => serde_json::json!({
                    "kind": "digest", "digest": Digest::of(b"old\n").to_hex()
                }),
                _ => serde_json::json!({ "kind": "digest", "digest": "0".repeat(64) }),
            };
            let mutation = if op == "delete" {
                serde_json::json!({ "kind": "delete" })
            } else {
                serde_json::json!({
                    "kind": "write",
                    "content_utf8": change["contents"].as_str().expect("test contents")
                })
            };
            serde_json::json!({ "path": path, "preimage": preimage, "mutation": mutation })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "test-only runner simulation",
        "operations": operations,
        "gate_ids": gate_ids,
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

fn prompt_subject(prompt: &str, label: &str) -> String {
    prompt
        .lines()
        .find_map(|line| line.trim().strip_prefix(label).map(str::to_owned))
        .unwrap_or_else(|| panic!("missing {label} in prompt"))
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
            serde_json::json!([format!("gat_{}", "7".repeat(64))]),
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

    assert_eq!(outcome.repair_rounds, 1, "{:?}", journal.stages());
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
    assert_eq!(outcome.repair_rounds, 1, "{:?}", journal.stages());
    assert_eq!(outcome.candidate.prepared_at, "TEST_ONLY_SIMULATOR");
    assert!(!repo.join("secrets").exists());
    assert!(repo.join("PONG.txt").is_file());
    assert!(adapter.prompts()[1].contains("SCOPE_DENIED"));
    let prompts = adapter.prompts();
    assert_eq!(
        prompt_subject(&prompts[0], "Base checkpoint ID: "),
        prompt_subject(&prompts[1], "Base checkpoint ID: "),
        "a pre-apply refusal must retain the current checkpoint"
    );
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
    assert_eq!(outcome.repair_rounds, 1, "{:?}", journal.stages());
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
        adapter.clone(),
        vec!["PONG.txt".into(), "OLD.txt".into()],
        vec![REPOSITORY_GATE_ID.into()],
    )
    .await;
    assert_eq!(outcome.repair_rounds, 1);
    assert_eq!(outcome.candidate.actual_scope, vec!["PONG.txt"]);
    assert!(repo.join("PONG.txt").is_file());
    assert!(!repo.join("OLD.txt").exists());
    let prompts = adapter.prompts();
    assert_ne!(
        prompt_subject(&prompts[0], "Base checkpoint ID: "),
        prompt_subject(&prompts[1], "Base checkpoint ID: "),
        "an applied proposal must chain the daemon-issued next checkpoint"
    );
}
