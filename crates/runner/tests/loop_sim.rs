//! Full loop against the real bullet-gitd and the harness simulator: an
//! out-of-scope proposal is refused with typed SCOPE_DENIED and fed back to
//! the model, then a valid proposal is applied, the deterministic gate
//! passes, and an exact candidate with real SHAs is prepared.

mod support;

use bullet_application::{Ledger, MemoryLedger};
use bullet_domain::{AttemptState, RunnerId};
use bullet_runner_core::{
    run_attempt, AcquireRequest, AttemptConfig, AttemptOutcome, DirectLeaseClient, HeartbeatConfig,
    MemoryJournal, MonotonicClock,
};
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
    if !support::gitd_ready() {
        eprintln!("{}", support::SKIP_REASON);
        return;
    }
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
