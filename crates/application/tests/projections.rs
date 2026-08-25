//! Memory ledger projection reads: empty sets are empty, orders are the
//! SQLite orders, and the clock is the simulation clock.

use bullet_application::store::ProjectionReader;
use bullet_application::{
    materialize_plan, run_demo, EffectIntentRecord, EffectReceiptRecord, EffectState, LeaseService,
    Ledger, MemoryLedger, PlanInput, ReceiptVerdict, ZERO_OID,
};
use bullet_domain::{
    AttemptId, AttemptState, Candidate, CandidateId, Digest, EffectId, EffectReceiptId, TaskClass,
};
use chrono::DateTime;

fn plan(packages: usize) -> PlanInput {
    PlanInput {
        title: "projection".into(),
        objective: "read-only projection order".into(),
        packages: (0..packages)
            .map(|index| (format!("pkg-{index}"), TaskClass::BoundedBugFix))
            .collect(),
    }
}

fn intent(seed: &str, created_at: &str) -> EffectIntentRecord {
    EffectIntentRecord {
        id: EffectId::from_seed(seed),
        logical_effect_key: format!("push:{seed}"),
        provider: "local-bare".into(),
        target_identity: format!("refs/heads/bullet/candidate/{seed}"),
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: AttemptId::from_seed("proj-attempt"),
        fence: 1,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: None,
        state: EffectState::Proposed,
        unknown_retries: 0,
        created_at: created_at.into(),
    }
}

fn receipt(seed: &str, intent: &EffectId, recorded_at: &str) -> EffectReceiptRecord {
    EffectReceiptRecord {
        id: EffectReceiptId::from_seed(seed),
        effect_intent_id: intent.clone(),
        observed_remote_identity: "refs/heads/x".into(),
        observed_state_hash: Some("b".repeat(40)),
        verification_method: "read-back".into(),
        verification_result: ReceiptVerdict::Match,
        adopted_after_unknown: false,
        recorded_at: recorded_at.into(),
    }
}

#[test]
fn empty_ledger_projects_empty_sets_and_a_canonical_clock() {
    let ledger = MemoryLedger::new();
    assert!(ledger.list_leases().expect("leases").is_empty());
    assert!(ledger.list_all_attempts().expect("attempts").is_empty());
    assert!(ledger.list_candidates().expect("candidates").is_empty());
    assert!(ledger.list_evidence().expect("evidence").is_empty());
    assert!(ledger.list_effects().expect("effects").is_empty());
    assert!(ledger.list_effect_intents().expect("intents").is_empty());
    assert!(ledger.list_effect_receipts().expect("receipts").is_empty());
    let clock = ledger.authority_time().expect("clock");
    assert_eq!(clock, ledger.simulation_time());
    DateTime::parse_from_rfc3339(&clock).expect("canonical clock");
}

#[test]
fn attempts_order_by_variant_then_fence_and_leases_by_variant() {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(
        &mut ledger,
        "proj-order",
        &plan(2),
        "2026-08-25T00:00:00.000Z",
    )
    .expect("materialize");
    let (_, _, first) = LeaseService::acquire(&mut ledger, &graph, 0, "order-a", 15).expect("a");
    LeaseService::release(&mut ledger, &first, AttemptState::Cancelled, true).expect("release");
    LeaseService::acquire(&mut ledger, &graph, 0, "order-b", 15).expect("b");
    LeaseService::acquire(&mut ledger, &graph, 1, "order-c", 15).expect("c");

    let attempts = ledger.list_all_attempts().expect("attempts");
    assert_eq!(attempts.len(), 3);
    let keys: Vec<(String, u64)> = attempts
        .iter()
        .map(|attempt| (attempt.variant_id.to_string(), attempt.fence))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys, sorted,
        "attempts are ordered by variant id then fence"
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|a| a.state == AttemptState::Cancelled)
            .count(),
        1
    );

    let leases = ledger.list_leases().expect("leases");
    assert_eq!(leases.len(), 2);
    assert!(leases[0].variant_id.as_str() < leases[1].variant_id.as_str());
    assert!(leases.iter().all(|lease| lease.ttl_seconds == 15));
}

#[test]
fn json_rows_order_by_id_and_component_demo_invents_no_authority_rows() {
    let mut ledger = MemoryLedger::new();
    for seed in ["z-3", "a-1", "m-2"] {
        let candidate = Candidate {
            id: CandidateId::from_seed(seed),
            attempt_id: AttemptId::from_seed("proj-attempt"),
            base_sha: "a".repeat(40),
            head_sha: "b".repeat(40),
            tree_sha: "c".repeat(40),
            patch_digest: Digest::of(seed.as_bytes()),
        };
        assert!(ledger.put_candidate(&candidate).expect("insert"));
    }
    let ids: Vec<String> = ledger
        .list_candidates()
        .expect("candidates")
        .iter()
        .map(|candidate| candidate.id.to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);

    let mut demo = MemoryLedger::new();
    let receipt = run_demo(&mut demo).expect("demo");
    assert_eq!(receipt.candidate_head, "NOT_PRODUCED");
    assert_eq!(receipt.evidence_result, "NOT_RUN");
    assert_eq!(receipt.effect_outcome, "NOT_DISPATCHED");
    assert_eq!(receipt.effect_unknown_outcome, "NOT_DISPATCHED");
    assert!(demo.list_candidates().expect("candidates").is_empty());
    assert!(demo.list_evidence().expect("evidence").is_empty());
    assert!(demo.list_effects().expect("effects").is_empty());
    assert!(demo.list_all_attempts().expect("attempts").len() >= 2);
}

#[test]
fn effect_intents_and_receipts_order_by_time_then_id() {
    let mut ledger = MemoryLedger::new();
    let late = intent("late", "2026-08-25T00:00:02.000Z");
    let early = intent("early", "2026-08-25T00:00:01.000Z");
    ledger.record_effect_intent(&late).expect("late");
    ledger.record_effect_intent(&early).expect("early");
    let intents = ledger.list_effect_intents().expect("intents");
    assert_eq!(
        intents
            .iter()
            .map(|i| i.created_at.as_str())
            .collect::<Vec<_>>(),
        ["2026-08-25T00:00:01.000Z", "2026-08-25T00:00:02.000Z"]
    );
    assert!(intents.iter().all(|i| i.state == EffectState::Proposed));

    ledger
        .record_effect_receipt(&receipt("r-late", &late.id, "2026-08-25T00:00:09.000Z"))
        .expect("late receipt");
    ledger
        .record_effect_receipt(&receipt("r-early", &early.id, "2026-08-25T00:00:05.000Z"))
        .expect("early receipt");
    let receipts = ledger.list_effect_receipts().expect("receipts");
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.recorded_at.as_str())
            .collect::<Vec<_>>(),
        ["2026-08-25T00:00:05.000Z", "2026-08-25T00:00:09.000Z"]
    );
    assert_eq!(receipts[0].effect_intent_id, early.id);
}
