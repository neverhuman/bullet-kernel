use super::fixtures::{event_count, fixture, id, source};
use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    verify_candidate_preparation_grant, CandidateNonceConsumption, CandidatePreparationExpectation,
    CandidatePreparationFinalCheckStore, CandidatePreparationIssuer,
    CandidatePreparationSigningKey, CandidatePreparationStore, LedgerCandidatePreparationIssuer,
    StoreCandidatePreparationNonceLedger,
};
use bullet_application::Ledger;
use bullet_domain::{AttemptId, Candidate, CandidateId, Digest};

#[test]
fn issuance_replay_and_nonce_consumption_survive_restart() {
    let built = fixture("candidate-restart");
    let directory = built._directory;
    let path = built.path;
    let attempt = built.attempt;
    let mut ledger = built.ledger;
    let source = source(&attempt, '1');
    let registered = ledger
        .register_candidate_preparation_source(&source)
        .unwrap();
    assert_eq!(
        ledger
            .register_candidate_preparation_source(&source)
            .unwrap(),
        registered
    );
    assert_eq!(
        event_count(&ledger, "candidate_preparation_source_registered"),
        1
    );
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
    let first = LedgerCandidatePreparationIssuer::new(&mut ledger, &key)
        .mint(&registered.request_digest)
        .unwrap();
    let outbox = ledger.outbox_all().unwrap();
    assert_eq!(
        outbox
            .iter()
            .filter(|item| item.kind == "candidate_verification_requested")
            .count(),
        1
    );
    assert_eq!(
        event_count(&ledger, "candidate_preparation_grant_issued"),
        1
    );
    let replay = LedgerCandidatePreparationIssuer::new(&mut ledger, &key)
        .mint(&registered.request_digest)
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(
        event_count(&ledger, "candidate_preparation_grant_issued"),
        1
    );
    let expectation = CandidatePreparationExpectation {
        now_unix_ms: first.grant.issued_at_unix_ms + 1,
        expected_grant: first.grant.clone(),
    };
    let verifier = key.verification_key().unwrap();
    let verified = verify_candidate_preparation_grant(
        &first.signed,
        &verifier,
        &expectation,
        &mut StoreCandidatePreparationNonceLedger(&mut ledger),
    )
    .unwrap();
    assert_eq!(verified.claims(), &first.grant);
    assert_eq!(
        event_count(&ledger, "candidate_preparation_grant_consumed"),
        1
    );
    drop(ledger);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        reopened
            .get_candidate_preparation_grant(&registered.request_digest)
            .unwrap()
            .unwrap(),
        first
    );
    assert_eq!(
        verify_candidate_preparation_grant(
            &first.signed,
            &verifier,
            &expectation,
            &mut StoreCandidatePreparationNonceLedger(&mut reopened),
        )
        .unwrap_err()
        .reason_code(),
        "CANDIDATE_PREPARATION_REPLAYED"
    );
    drop(reopened);
    drop(directory);
}

#[test]
fn every_issuance_boundary_rolls_back_grant_event_and_outbox() {
    for boundary in 0..3 {
        let mut built = fixture(&format!("candidate-fail-{boundary}"));
        let source = source(&built.attempt, char::from(b'2' + boundary));
        let registered = built
            .ledger
            .register_candidate_preparation_source(&source)
            .unwrap();
        built.ledger.set_candidate_preparation_failpoint(boundary);
        let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
        let error = LedgerCandidatePreparationIssuer::new(&mut built.ledger, &key)
            .mint(&registered.request_digest)
            .unwrap_err();
        assert_eq!(error.reason_code(), "STORE_FAILURE");
        assert!(built
            .ledger
            .get_candidate_preparation_grant(&registered.request_digest)
            .unwrap()
            .is_none());
        assert_eq!(
            event_count(&built.ledger, "candidate_preparation_grant_issued"),
            0
        );
        assert_eq!(
            built
                .ledger
                .outbox_all()
                .unwrap()
                .iter()
                .filter(|item| item.kind == "candidate_verification_requested")
                .count(),
            0
        );
        LedgerCandidatePreparationIssuer::new(&mut built.ledger, &key)
            .mint(&registered.request_digest)
            .unwrap();
    }
}

#[test]
fn missing_parent_stale_envelope_and_change_conflict_refuse() {
    let mut built = fixture("candidate-refusals");
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();

    let mut missing_parent = source(&built.attempt, '5');
    missing_parent.root_change = false;
    missing_parent.parent_candidate_ids = vec![id("can", 'a')];
    let registered = built
        .ledger
        .register_candidate_preparation_source(&missing_parent)
        .unwrap();
    assert_eq!(
        LedgerCandidatePreparationIssuer::new(&mut built.ledger, &key)
            .mint(&registered.request_digest)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_REFUSED"
    );

    let mut stale = source(&built.attempt, '6');
    stale.execution_envelope.authority_epoch = 2;
    let stale_registered = built
        .ledger
        .register_candidate_preparation_source(&stale)
        .unwrap();
    assert_eq!(
        LedgerCandidatePreparationIssuer::new(&mut built.ledger, &key)
            .mint(&stale_registered.request_digest)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_REFUSED"
    );

    let mut conflict = stale.clone();
    conflict.ttl_ms = 4_000;
    assert_eq!(
        built
            .ledger
            .register_candidate_preparation_source(&conflict)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_CONFLICT"
    );
}

#[test]
fn non_root_parent_order_is_preserved_from_durable_candidates() {
    let mut built = fixture("candidate-parents");
    let parent_a = Candidate {
        id: CandidateId::from_seed("parent-a"),
        attempt_id: built.attempt.id.clone(),
        base_sha: "1".repeat(40),
        head_sha: "2".repeat(40),
        tree_sha: "3".repeat(40),
        patch_digest: Digest::of(b"parent-a"),
    };
    let parent_b = Candidate {
        id: CandidateId::from_seed("parent-b"),
        attempt_id: built.attempt.id.clone(),
        base_sha: "4".repeat(40),
        head_sha: "5".repeat(40),
        tree_sha: "6".repeat(40),
        patch_digest: Digest::of(b"parent-b"),
    };
    built.ledger.put_candidate(&parent_a).unwrap();
    built.ledger.put_candidate(&parent_b).unwrap();
    let mut non_root = source(&built.attempt, '8');
    non_root.root_change = false;
    non_root.parent_candidate_ids = vec![parent_b.id.to_string(), parent_a.id.to_string()];
    let registered = built
        .ledger
        .register_candidate_preparation_source(&non_root)
        .unwrap();
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
    let issued = LedgerCandidatePreparationIssuer::new(&mut built.ledger, &key)
        .mint(&registered.request_digest)
        .unwrap();
    assert_eq!(
        issued.grant.parent_candidate_ids,
        vec![parent_b.id.to_string(), parent_a.id.to_string()]
    );
}

#[test]
fn exact_final_check_consumes_once_and_survives_restart() {
    let built = fixture("candidate-final-check");
    let directory = built._directory;
    let path = built.path;
    let attempt = built.attempt;
    let mut ledger = built.ledger;
    let registered = ledger
        .register_candidate_preparation_source(&source(&attempt, 'a'))
        .unwrap();
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
    let issued = LedgerCandidatePreparationIssuer::new(&mut ledger, &key)
        .mint(&registered.request_digest)
        .unwrap();
    assert_eq!(
        ledger
            .final_check_candidate_preparation_grant(&issued.grant, &issued.signed, &attempt.id,)
            .unwrap(),
        CandidateNonceConsumption::Consumed
    );
    assert_eq!(
        event_count(&ledger, "candidate_preparation_grant_consumed"),
        1
    );
    drop(ledger);
    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        reopened
            .final_check_candidate_preparation_grant(&issued.grant, &issued.signed, &attempt.id,)
            .unwrap(),
        CandidateNonceConsumption::Replayed
    );
    assert_eq!(
        event_count(&reopened, "candidate_preparation_grant_consumed"),
        1
    );
    drop(reopened);
    drop(directory);
}

#[test]
fn final_check_refuses_any_carrier_or_current_authority_drift() {
    let mut built = fixture("candidate-final-drift");
    let key = CandidatePreparationSigningKey::generate("bullet-kernel", "candidate-1").unwrap();
    let first = built
        .ledger
        .register_candidate_preparation_source(&source(&built.attempt, 'b'))
        .unwrap();
    let issued = LedgerCandidatePreparationIssuer::new(&mut built.ledger, &key)
        .mint(&first.request_digest)
        .unwrap();
    let mut changed = issued.signed.clone();
    changed.paseto.push('x');
    assert_eq!(
        built
            .ledger
            .final_check_candidate_preparation_grant(&issued.grant, &changed, &built.attempt.id,)
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_REFUSED"
    );
    assert_eq!(
        built
            .ledger
            .final_check_candidate_preparation_grant(
                &issued.grant,
                &issued.signed,
                &AttemptId::from_seed("wrong-final-check-attempt"),
            )
            .unwrap_err()
            .reason_code(),
        "CANDIDATE_PREPARATION_REFUSED"
    );
    let raw = rusqlite::Connection::open(&built.path).unwrap();
    raw.execute(
        "UPDATE authority_revisions SET authority_epoch = 2 WHERE singleton = 1",
        [],
    )
    .unwrap();
    drop(raw);
    assert_eq!(
        built
            .ledger
            .final_check_candidate_preparation_grant(
                &issued.grant,
                &issued.signed,
                &built.attempt.id,
            )
            .unwrap(),
        CandidateNonceConsumption::Unknown
    );
    assert_eq!(
        event_count(&built.ledger, "candidate_preparation_grant_consumed"),
        0
    );
}
