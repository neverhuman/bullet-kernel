//! Test-only workspace simulation for Runner loop mechanics.
//!
//! This module is compiled only with `cfg(test)`. Its receipts are explicitly
//! non-authoritative and cannot be selected by the production entrypoint.

mod candidate;
mod harness;
mod orchestration;
mod workspace;

use super::*;
use crate::{MemoryJournal, MonotonicClock, REPOSITORY_GATE_ID};
use bullet_application::{materialize_plan, MemoryLedger, PlanInput};
use bullet_domain::{Digest, RunnerId, TaskClass, WorkPackageId};
use harness::ScriptedSim;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use workspace::SimWorkspace;

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

fn git_value(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("retained fixture git");
    assert!(output.status.success(), "{:?}", output.status);
    String::from_utf8(output.stdout)
        .expect("retained Git output")
        .trim()
        .to_owned()
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
    let client = Arc::new(candidate::TestCandidateClient::new(ledger));
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
    )
    .with_preservation_destination(root.join(format!("success-preserve-{seed}")));
    let config = client.admit_config(config);
    let grant = client.acquire(&request).await.expect("test lease");
    journal.record("lease_acquired", "TEST_ONLY_SIMULATOR");
    let mut workspace = SimWorkspace::new(grant.authority_token.clone());
    let mut info = workspace
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
        &mut info,
    )
    .await
    .expect("test-only loop");
    assert!(
        !info.repo_dir.exists(),
        "successful preservation must precede cleanup of the live workspace"
    );
    let retained = outcome
        .preservation
        .receipt
        .destination
        .join("generation/repo");
    assert_eq!(
        git_value(&retained, &["rev-parse", "HEAD"]),
        outcome.candidate.head_commit
    );
    assert_eq!(
        git_value(&retained, &["rev-parse", "HEAD^{tree}"]),
        outcome.candidate.tree_hash
    );
    (outcome, journal, retained)
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
    outcome
        .preservation
        .validate_against(&outcome.candidate, &outcome.attempt_id, outcome.fence)
        .expect("Candidate preservation binding");
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
