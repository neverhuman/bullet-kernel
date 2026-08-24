//! Full loop against the real bullet-gitd and the harness simulator: an
//! out-of-scope proposal is refused with typed SCOPE_DENIED and fed back to
//! the model, then a valid proposal is applied, the deterministic gate
//! passes, and an exact candidate with real SHAs is prepared. Delete rounds
//! remove files from the candidate tree; a delete of a nonexistent path is
//! fed back as PATH_ABSENT and repaired in a later round.

mod support;

use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptState, RunnerId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, DirectLeaseClient, HeartbeatConfig,
    MemoryJournal, MonotonicClock,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn assert_exact_candidate(outcome: &AttemptOutcome, base_sha: &str) {
    assert_eq!(outcome.fence, 1);
    assert_eq!(outcome.repair_rounds, 1);
    assert_eq!(outcome.candidate.base_commit, base_sha);
    assert_ne!(outcome.candidate.head_commit, base_sha);
    assert_eq!(outcome.candidate.head_commit.len(), 40);
    assert!(outcome
        .candidate
        .head_commit
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
    assert_eq!(outcome.candidate.patch_hash.len(), 64);
    assert_eq!(outcome.candidate.actual_scope, vec!["PONG.txt".to_string()]);
    assert!(outcome.gate.passed());
}

fn assert_refusal_fed_back(prompts: &[String], base_sha: &str) {
    assert_eq!(prompts.len(), 2, "initial turn plus one repair round");
    assert!(prompts[0].contains(base_sha));
    assert!(prompts[0].contains("PatchProposal"));
    assert!(prompts[1].contains("SCOPE_DENIED"));
    assert!(prompts[1].contains("secrets/key.txt"));
}

fn assert_journal_order(stages: &[String]) {
    let position = |stage: &str| {
        stages
            .iter()
            .position(|s| s == stage)
            .unwrap_or_else(|| panic!("{stage} missing from {stages:?}"))
    };
    assert!(position("scope_denied") < position("patch_applied"));
    assert!(position("patch_applied") < position("candidate_prepared"));
    assert_eq!(
        stages.iter().filter(|s| *s == "patch_applied").count(),
        1,
        "exactly one apply: {stages:?}"
    );
}

fn assert_ledger_truth(ledger: &Arc<Mutex<MemoryLedger>>, outcome: &AttemptOutcome) {
    let ledger = ledger.lock().expect("ledger");
    let attempt = ledger
        .get_attempt(&outcome.attempt_id)
        .expect("read")
        .expect("attempt row");
    assert_eq!(attempt.state, AttemptState::Succeeded);
    assert!(ledger
        .get_lease(&attempt.variant_id)
        .expect("lease")
        .is_none());
    assert!(ledger.ready_rows().expect("ready").is_empty());
}

#[tokio::test]
async fn scope_denied_feedback_then_exact_candidate() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let (origin, base_sha) = support::build_origin(dir.path());
    let (ledger, package) = support::seeded_ledger("loop-sim");
    let client = Arc::new(DirectLeaseClient::new(ledger.clone()));
    let adapter = Arc::new(support::ScriptedSim::new());
    adapter.override_proposal(0, support::out_of_scope_proposal());
    let journal = Arc::new(MemoryJournal::new());
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed("loop-sim"),
        runner_epoch: 1,
        idempotency_key: "loop-sim-1".into(),
        ttl_seconds: 60,
    };
    let mut config = AttemptConfig::new(
        origin,
        base_sha.clone(),
        dir.path().join("farm"),
        "create PONG.txt containing PONG".into(),
        vec!["PONG.txt".into()],
        "test -f PONG.txt".into(),
    );
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(100),
        ttl_seconds: 60,
    };
    let outcome = run_attempt(
        client,
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect("attempt succeeds after one repair round");

    assert_exact_candidate(&outcome, &base_sha);
    assert_refusal_fed_back(&adapter.prompts(), &base_sha);
    let repo_dir = dir
        .path()
        .join("farm/work")
        .join(outcome.attempt_id.as_str())
        .join("repo");
    assert!(repo_dir.join("PONG.txt").is_file());
    assert!(!repo_dir.join("secrets").exists(), "denial applied nothing");
    assert_journal_order(&journal.stages());
    assert_ledger_truth(&ledger, &outcome);
}

async fn run_scripted_attempt(
    adapter: Arc<support::ScriptedSim>,
    dir: &Path,
    seed: &str,
    scope_prefixes: Vec<String>,
    gate_command: &str,
) -> (AttemptOutcome, Arc<MemoryJournal>, PathBuf) {
    let (origin, base_sha) = support::build_origin(dir);
    let (ledger, package) = support::seeded_ledger(seed);
    let client = Arc::new(DirectLeaseClient::new(ledger));
    let journal = Arc::new(MemoryJournal::new());
    let request = AcquireRequest {
        work_package_id: package,
        runner_id: RunnerId::from_seed(seed),
        runner_epoch: 1,
        idempotency_key: format!("{seed}-1"),
        ttl_seconds: 60,
    };
    let mut config = AttemptConfig::new(
        origin,
        base_sha,
        dir.join("farm"),
        "drive the scripted proposals".into(),
        scope_prefixes,
        gate_command.into(),
    );
    config.heartbeat = HeartbeatConfig {
        interval: Duration::from_millis(100),
        ttl_seconds: 60,
    };
    let outcome = run_attempt(
        client,
        adapter,
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect("attempt succeeds after one repair round");
    let repo_dir = dir
        .join("farm/work")
        .join(outcome.attempt_id.as_str())
        .join("repo");
    (outcome, journal, repo_dir)
}

/// Exact paths committed into the candidate's tree, via `git ls-tree`.
fn candidate_tree_paths(repo_dir: &Path, tree_hash: &str) -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(["ls-tree", "-r", "--name-only", tree_hash])
        .current_dir(repo_dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git ls-tree runs");
    assert!(
        out.status.success(),
        "git ls-tree: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn delete_round_removes_created_file_from_candidate_tree() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = Arc::new(support::ScriptedSim::new());
    adapter.override_proposal(
        0,
        support::proposal_with_changes(
            "create PONG.txt plus a scratch file the gate forbids",
            serde_json::json!([
                { "path": "PONG.txt", "op": "create", "contents": "PONG\n" },
                { "path": "OLD.txt", "op": "create", "contents": "obsolete\n" }
            ]),
        ),
    );
    adapter.override_proposal(
        1,
        support::proposal_with_changes(
            "delete the scratch file",
            serde_json::json!([
                { "path": "OLD.txt", "op": "delete", "contents": null }
            ]),
        ),
    );
    let (outcome, journal, repo_dir) = run_scripted_attempt(
        adapter.clone(),
        dir.path(),
        "loop-delete",
        vec!["PONG.txt".into(), "OLD.txt".into()],
        "test -f PONG.txt && test ! -f OLD.txt",
    )
    .await;

    assert_eq!(outcome.repair_rounds, 1);
    assert!(outcome.gate.passed());
    let prompts = adapter.prompts();
    assert_eq!(prompts.len(), 2, "initial turn plus one gate repair round");
    assert!(prompts[1].contains("GATE_RESULT"));
    assert!(repo_dir.join("PONG.txt").is_file());
    assert!(!repo_dir.join("OLD.txt").exists(), "delete left the tree");
    let tree = candidate_tree_paths(&repo_dir, &outcome.candidate.tree_hash);
    assert!(tree.contains(&"PONG.txt".to_string()), "{tree:?}");
    assert!(
        !tree.contains(&"OLD.txt".to_string()),
        "candidate tree must lack the deleted file: {tree:?}"
    );
    let stages = journal.stages();
    assert_eq!(
        stages.iter().filter(|s| *s == "patch_applied").count(),
        2,
        "both rounds applied: {stages:?}"
    );
}

#[tokio::test]
async fn path_absent_feedback_then_successful_repair() {
    support::require_gitd();
    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = Arc::new(support::ScriptedSim::new());
    adapter.override_proposal(
        0,
        support::proposal_with_changes(
            "create PONG.txt and delete a file that never existed",
            serde_json::json!([
                { "path": "PONG.txt", "op": "create", "contents": "PONG\n" },
                { "path": "GHOST.txt", "op": "delete", "contents": null }
            ]),
        ),
    );
    adapter.override_proposal(
        1,
        support::proposal_with_changes(
            "create PONG.txt without the bad delete",
            serde_json::json!([
                { "path": "PONG.txt", "op": "create", "contents": "PONG\n" }
            ]),
        ),
    );
    let (outcome, journal, repo_dir) = run_scripted_attempt(
        adapter.clone(),
        dir.path(),
        "loop-absent",
        vec!["PONG.txt".into(), "GHOST.txt".into()],
        "test -f PONG.txt",
    )
    .await;

    assert_eq!(outcome.repair_rounds, 1);
    assert!(outcome.gate.passed());
    let prompts = adapter.prompts();
    assert_eq!(prompts.len(), 2, "initial turn plus one PATH_ABSENT round");
    assert!(prompts[1].contains("PATH_ABSENT"));
    assert!(prompts[1].contains("GHOST.txt"));
    let stages = journal.stages();
    let absent = stages
        .iter()
        .position(|s| s == "path_absent")
        .unwrap_or_else(|| panic!("path_absent missing from {stages:?}"));
    let applied = stages
        .iter()
        .position(|s| s == "patch_applied")
        .unwrap_or_else(|| panic!("patch_applied missing from {stages:?}"));
    assert!(
        absent < applied,
        "refusal precedes the only apply: {stages:?}"
    );
    assert_eq!(
        stages.iter().filter(|s| *s == "patch_applied").count(),
        1,
        "all-or-nothing: the refused batch applied nothing: {stages:?}"
    );
    assert!(repo_dir.join("PONG.txt").is_file());
    assert!(!repo_dir.join("GHOST.txt").exists());
    assert_eq!(outcome.candidate.actual_scope, vec!["PONG.txt".to_string()]);
}
