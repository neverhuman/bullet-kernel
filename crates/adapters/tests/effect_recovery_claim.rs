#[path = "effect_recovery_claim/support.rs"]
mod recovery_support;
#[path = "effect_recovery_claim/replay.rs"]
mod replay;
mod support;
#[path = "effect_recovery_claim/terminal_no_work.rs"]
mod terminal_no_work;

use bullet_application::{
    EffectRecoveryContainmentReason, EffectRecoveryDisposition as D, EffectRecoveryStore,
    EffectState, LeaseService, Ledger, ReceiptVerdict,
};
use bullet_domain::{CommandPhase, Digest, RunnerId};
use recovery_support::{
    authority, claim_disposition, claim_receipt_id, expire_active_lease, obs, outbox_phase,
    prepare, tx, AT,
};
use rusqlite::{params, Connection};

#[test]
fn same_owner_replays_and_live_other_owner_conflicts() {
    let mut env = prepare("owner-replay");
    let claim = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    claim.validate().expect("valid claim");
    assert_eq!(claim.disposition, D::Claimed);
    assert_eq!(
        env.ledger
            .claim_effect_recovery(&env.intent.id, &env.authority)
            .expect("replay"),
        Some(claim.clone())
    );
    let (payload, phase, delivered, acked) = outbox_phase(&env.path, claim.outbox_sequence);
    assert_eq!(payload, claim.claim_id);
    assert_eq!(phase, CommandPhase::Pending.as_str());
    assert!(delivered.is_none());
    assert!(acked.is_none());

    let mut foreign = env.authority.clone();
    foreign.runner_id = RunnerId::from_seed("foreign-recovery-owner");
    foreign.successor_authority_digest = Digest::of(b"foreign-owner-token");
    let error = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &foreign)
        .expect_err("foreign owner");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_CLAIM_CONFLICT");
}

#[test]
fn expired_owner_is_invalidated_and_successor_gets_next_generation() {
    let mut env = prepare("expired-successor");
    let first = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    expire_active_lease(&env.path);
    let (_, token, grant) =
        LeaseService::acquire(&mut env.ledger, &env.graph, 0, "expired-successor-next", 5)
            .expect("reacquire");
    let next_auth = authority(&env.ledger, &token);
    let second = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &next_auth)
        .expect("successor")
        .expect("row");
    assert_eq!(grant.attempt.fence, env.grant.attempt.fence + 1);
    assert_eq!(second.claim_generation, first.claim_generation + 1);
    assert_eq!(second.disposition, D::Claimed);
    assert_eq!(
        claim_disposition(&env.path, &first.claim_id),
        ("INVALIDATED".into(), Some("CLAIMED".into()))
    );
    let (_, old_phase, _, old_acked) = outbox_phase(&env.path, first.outbox_sequence);
    assert_eq!(old_phase, CommandPhase::Unknown.as_str());
    assert!(old_acked.is_some());
}

#[test]
fn stale_apply_commits_invalidation_before_returning_stale() {
    let mut env = prepare("stale-apply");
    let claim = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    expire_active_lease(&env.path);
    let request = tx(&claim, &env.authority, D::ReadbackUnknown, None, None);
    let error = env
        .ledger
        .apply_effect_recovery(&request, &env.authority)
        .expect_err("stale apply");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_AUTHORITY_STALE");
    assert_eq!(
        claim_disposition(&env.path, &claim.claim_id),
        ("INVALIDATED".into(), Some("CLAIMED".into()))
    );
    let (_, phase, _, acked) = outbox_phase(&env.path, claim.outbox_sequence);
    assert_eq!(phase, CommandPhase::Unknown.as_str());
    assert!(acked.is_some());
}

#[test]
fn inherited_retry_reserved_successor_reuses_receipt_and_applies_outbox() {
    let mut env = prepare("reserved-successor");
    let first = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    let reserved = env
        .ledger
        .apply_effect_recovery(
            &tx(
                &first,
                &env.authority,
                D::RetryReserved,
                Some(obs(&first.intent, ReceiptVerdict::Absent)),
                None,
            ),
            &env.authority,
        )
        .expect("reserve");
    let receipts = env
        .ledger
        .effect_receipts(&env.intent.id)
        .expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        claim_receipt_id(&env.path, &reserved.claim_id).as_deref(),
        Some(receipts[0].id.as_str())
    );
    let (_, first_phase, first_delivered, _) = outbox_phase(&env.path, first.outbox_sequence);
    assert_eq!(first_phase, CommandPhase::Applied.as_str());
    assert!(first_delivered.is_some());

    expire_active_lease(&env.path);
    let (_, token, _) =
        LeaseService::acquire(&mut env.ledger, &env.graph, 0, "reserved-successor-next", 5)
            .expect("reacquire");
    let next_auth = authority(&env.ledger, &token);
    let second = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &next_auth)
        .expect("successor")
        .expect("row");
    second.validate().expect("successor valid");
    assert_eq!(second.claim_generation, first.claim_generation + 1);
    assert_eq!(second.disposition, D::RetryReserved);
    assert_eq!(second.intent.state, EffectState::OutcomeUnknown);
    assert_eq!(second.intent.unknown_retries, 1);
    assert_eq!(
        claim_receipt_id(&env.path, &second.claim_id).as_deref(),
        Some(receipts[0].id.as_str())
    );
    assert_eq!(
        env.ledger.effect_receipts(&env.intent.id).expect("again"),
        receipts
    );
    assert_eq!(
        claim_disposition(&env.path, &first.claim_id),
        ("INVALIDATED".into(), Some("RETRY_RESERVED".into()))
    );
    let (_, old_phase, _, old_acked) = outbox_phase(&env.path, first.outbox_sequence);
    assert_eq!(old_phase, CommandPhase::Unknown.as_str());
    assert!(old_acked.is_some());
    let (_, new_phase, delivered, acked) = outbox_phase(&env.path, second.outbox_sequence);
    assert_eq!(new_phase, CommandPhase::Applied.as_str());
    assert!(delivered.is_some());
    assert!(acked.is_none());
}

#[test]
fn terminal_transitions_return_valid_claims_and_replay_deterministic_receipts() {
    for (seed, to, verdict, state) in [
        (
            "adopted",
            D::Adopted,
            ReceiptVerdict::Match,
            EffectState::Committed,
        ),
        (
            "orphaned",
            D::Orphaned,
            ReceiptVerdict::Mismatch,
            EffectState::OrphanedRemote,
        ),
    ] {
        let mut env = prepare(seed);
        let claim = env
            .ledger
            .claim_effect_recovery(&env.intent.id, &env.authority)
            .expect("claim")
            .expect("row");
        let request = tx(
            &claim,
            &env.authority,
            to,
            Some(obs(&claim.intent, verdict)),
            None,
        );
        let applied = env
            .ledger
            .apply_effect_recovery(&request, &env.authority)
            .expect("apply");
        applied.validate().expect("terminal valid");
        assert_eq!(applied.disposition, to);
        assert_eq!(applied.intent.state, state);
        assert_eq!(
            env.ledger
                .apply_effect_recovery(&request, &env.authority)
                .expect("replay"),
            applied
        );
        let receipts = env
            .ledger
            .effect_receipts(&env.intent.id)
            .expect("receipts");
        assert_eq!(receipts.len(), 1);
        assert_eq!(Some(&receipts[0].id), request.receipt_id.as_ref());
    }
}

#[test]
fn quarantined_return_claim_is_valid_for_both_closed_predicates() {
    let mut unavailable = prepare("quarantine-unavailable");
    let claim = unavailable
        .ledger
        .claim_effect_recovery(&unavailable.intent.id, &unavailable.authority)
        .expect("claim")
        .expect("row");
    let unknown = unavailable
        .ledger
        .apply_effect_recovery(
            &tx(
                &claim,
                &unavailable.authority,
                D::ReadbackUnknown,
                None,
                None,
            ),
            &unavailable.authority,
        )
        .expect("unknown");
    let quarantined = unavailable
        .ledger
        .apply_effect_recovery(
            &tx(
                &unknown,
                &unavailable.authority,
                D::Quarantined,
                None,
                Some(EffectRecoveryContainmentReason::ReadbackUnavailable),
            ),
            &unavailable.authority,
        )
        .expect("quarantine");
    quarantined.validate().expect("quarantine valid");
    assert_eq!(quarantined.intent.state, EffectState::Quarantined);

    let mut spent = prepare("quarantine-spent");
    let claim = spent
        .ledger
        .claim_effect_recovery(&spent.intent.id, &spent.authority)
        .expect("claim")
        .expect("row");
    let reserved = spent
        .ledger
        .apply_effect_recovery(
            &tx(
                &claim,
                &spent.authority,
                D::RetryReserved,
                Some(obs(&claim.intent, ReceiptVerdict::Absent)),
                None,
            ),
            &spent.authority,
        )
        .expect("reserve");
    let receipts = spent
        .ledger
        .effect_receipts(&spent.intent.id)
        .expect("receipts");
    assert_eq!(receipts.len(), 1);
    let unknown = spent
        .ledger
        .apply_effect_recovery(
            &tx(&reserved, &spent.authority, D::ReadbackUnknown, None, None),
            &spent.authority,
        )
        .expect("unknown");
    let quarantined = spent
        .ledger
        .apply_effect_recovery(
            &tx(
                &unknown,
                &spent.authority,
                D::Quarantined,
                Some(obs(&unknown.intent, ReceiptVerdict::Absent)),
                Some(EffectRecoveryContainmentReason::RetrySpentAfterAbsence),
            ),
            &spent.authority,
        )
        .expect("quarantine");
    quarantined.validate().expect("spent valid");
    assert_eq!(
        claim_receipt_id(&spent.path, &quarantined.claim_id).as_deref(),
        Some(receipts[0].id.as_str())
    );
    assert_eq!(
        spent
            .ledger
            .effect_receipts(&spent.intent.id)
            .expect("again"),
        receipts
    );
    assert_eq!(quarantined.intent.state, EffectState::Quarantined);
}

#[test]
fn direct_sql_cannot_paint_receipts_or_unbound_outbox() {
    let mut env = prepare("sql-hostile");
    let claim = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    let raw = Connection::open(&env.path).expect("raw");
    let fake_receipt = format!("efr_{}", "1".repeat(64));
    assert!(raw
        .execute(
            "UPDATE effect_recovery_claims SET receipt_id=?1 WHERE claim_id=?2",
            params![fake_receipt, claim.claim_id],
        )
        .is_err());
    assert!(raw
        .execute(
            "UPDATE effect_recovery_claims
             SET disposition='ADOPTED', intent_state='COMMITTED', updated_at=?2
             WHERE claim_id=?1",
            params![claim.claim_id, AT],
        )
        .is_err());
    raw.execute(
        "UPDATE effect_recovery_claims
         SET disposition='INVALIDATED', invalidated_from='CLAIMED', updated_at=?2
         WHERE claim_id=?1",
        params![claim.claim_id, AT],
    )
    .expect("manual invalidation");
    let (_, phase, _, acked) = outbox_phase(&env.path, claim.outbox_sequence);
    assert_eq!(phase, CommandPhase::Unknown.as_str());
    assert!(acked.is_some());

    raw.execute(
        "INSERT INTO outbox (kind, payload, phase) VALUES ('effect_recovery', 'wrong', 'pending')",
        [],
    )
    .expect("wrong outbox");
    let seq = raw.last_insert_rowid();
    let second_id = format!("ecl_{}", "2".repeat(64));
    assert!(raw
        .execute(
            "INSERT INTO effect_recovery_claims (
               claim_id,effect_intent_id,claim_generation,outbox_sequence,intent_payload_digest,
               intent_state,intent_unknown_retries,work_package_id,original_attempt_id,
               original_variant_id,original_fence,successor_authority_digest,
               successor_authority_fingerprint,recovery_attempt_id,recovery_variant_id,
               recovery_attempt_fence,recovery_runner_id,recovery_runner_epoch,recovery_workspace_id,
               recovery_workspace_nonce,graph_revision,workspace_generation,scope_digest,
               policy_generation,routing_generation,authority_epoch,freeze_generation,restore_epoch,
               disposition,invalidated_from,receipt_id,containment_reason,claimed_at,updated_at)
             SELECT ?1,effect_intent_id,claim_generation+1,?2,intent_payload_digest,
               intent_state,intent_unknown_retries,work_package_id,original_attempt_id,
               original_variant_id,original_fence,successor_authority_digest,
               successor_authority_fingerprint,recovery_attempt_id,recovery_variant_id,
               recovery_attempt_fence,recovery_runner_id,recovery_runner_epoch,recovery_workspace_id,
               recovery_workspace_nonce,graph_revision,workspace_generation,scope_digest,
               policy_generation,routing_generation,authority_epoch,freeze_generation,restore_epoch,
               'CLAIMED',NULL,NULL,NULL,?3,?3
             FROM effect_recovery_claims WHERE claim_id=?4",
            params![second_id, seq, AT, claim.claim_id],
        )
        .is_err());
}

#[test]
fn claim_and_apply_failpoints_roll_back_correlated_truth() {
    for boundary in 0..=2 {
        let mut env = prepare(&format!("claim-fail-{boundary}"));
        env.ledger.set_effect_recovery_claim_failpoint(boundary);
        assert_eq!(
            env.ledger
                .claim_effect_recovery(&env.intent.id, &env.authority)
                .expect_err("claim fail")
                .reason_code(),
            "EFFECT_RECOVERY_STORE_FAILURE"
        );
        let raw = Connection::open(&env.path).expect("raw");
        let claims: i64 = raw
            .query_row("SELECT COUNT(*) FROM effect_recovery_claims", [], |row| {
                row.get(0)
            })
            .expect("claims");
        let outbox: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE kind='effect_recovery'",
                [],
                |row| row.get(0),
            )
            .expect("outbox");
        assert_eq!((claims, outbox), (0, 0));
    }

    for boundary in 0..=3 {
        let mut env = prepare(&format!("apply-fail-{boundary}"));
        let claim = env
            .ledger
            .claim_effect_recovery(&env.intent.id, &env.authority)
            .expect("claim")
            .expect("row");
        let request = tx(
            &claim,
            &env.authority,
            D::Adopted,
            Some(obs(&claim.intent, ReceiptVerdict::Match)),
            None,
        );
        env.ledger.set_effect_recovery_apply_failpoint(boundary);
        assert_eq!(
            env.ledger
                .apply_effect_recovery(&request, &env.authority)
                .expect_err("apply fail")
                .reason_code(),
            "EFFECT_RECOVERY_STORE_FAILURE"
        );
        assert_eq!(
            env.ledger
                .readback_effect_recovery(&env.intent.id, &env.authority)
                .expect("readback")
                .expect("active")
                .disposition,
            D::Claimed
        );
        let receipts = env
            .ledger
            .effect_receipts(&env.intent.id)
            .expect("receipts");
        assert!(receipts.is_empty());
        let (_, phase, _, acked) = outbox_phase(&env.path, claim.outbox_sequence);
        assert_eq!(phase, CommandPhase::Pending.as_str());
        assert!(acked.is_none());
    }
}
