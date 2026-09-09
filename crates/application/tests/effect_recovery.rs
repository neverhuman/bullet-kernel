//! Hostile conformance vectors for the Phase-4B application contract.

use bullet_application::{
    recovery_receipt_id, EffectIntentRecord, EffectRecoveryAuthority, EffectRecoveryClaim,
    EffectRecoveryContainmentReason, EffectRecoveryDisposition, EffectRecoveryObservation,
    EffectRecoveryTransition, EffectState, ReceiptVerdict, CANDIDATE_REF_PREFIX,
    EFFECT_RECOVERY_CLAIM_SCHEMA, LOCAL_BARE_RECOVERY_PROVIDER, ZERO_OID,
};
use bullet_domain::{
    AcceptanceContractId, AttemptId, AuthorityToken, CandidateId, Digest, EffectId, MissionId,
    OrganizationId, PlanRevisionId, RepositoryId, RunnerId, SelectionGroupId, VariantId,
    WorkPackageId, WorkspaceId,
};
use serde::de::DeserializeOwned;

fn token(seed: &str, fence: u64) -> AuthorityToken {
    AuthorityToken {
        organization_id: OrganizationId::from_seed("recovery-org"),
        repository_id: RepositoryId::from_seed("recovery-repo"),
        mission_id: MissionId::from_seed("recovery-mission"),
        acceptance_contract_id: AcceptanceContractId::from_seed("recovery-contract"),
        plan_revision_id: PlanRevisionId::from_seed("recovery-plan"),
        graph_sequence: 9,
        work_package_id: WorkPackageId::from_seed("recovery-package"),
        selection_group_id: SelectionGroupId::from_seed("recovery-selection"),
        variant_id: VariantId::from_seed("recovery-variant"),
        attempt_id: AttemptId::from_seed(&format!("recovery-attempt-{seed}")),
        attempt_fence: fence,
        runner_id: RunnerId::from_seed(&format!("recovery-runner-{seed}")),
        runner_epoch: fence,
        workspace_id: WorkspaceId::from_seed(&format!("recovery-workspace-{seed}")),
        workspace_nonce: [fence.to_le_bytes()[0]; 32],
        scope_revision: 1,
        context_revision: 1,
        config_snapshot_hash: Digest::of(b"recovery-config"),
        policy_snapshot_hash: Digest::of(b"recovery-policy"),
        routing_policy_hash: Digest::of(b"recovery-routing"),
        credential_profile_id: None,
        credential_generation: None,
    }
}

fn intent() -> EffectIntentRecord {
    let candidate = CandidateId::from_seed("recovery-candidate");
    let mut intent = EffectIntentRecord {
        id: EffectId::from_seed("recovery-effect"),
        logical_effect_key: format!("push:{candidate}"),
        provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
        target_identity: format!("{CANDIDATE_REF_PREFIX}{candidate}"),
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: AttemptId::from_seed("original-attempt"),
        fence: 1,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: None,
        state: EffectState::OutcomeUnknown,
        unknown_retries: 0,
        created_at: "2026-08-28T03:00:00Z".into(),
    };
    intent.payload_hash = intent.payload_digest().expect("payload digest");
    intent
}

fn authority(seed: &str, fence: u64) -> EffectRecoveryAuthority {
    EffectRecoveryAuthority::from_token(&token(seed, fence), 7, 3, 2).expect("authority")
}

fn claim_for(
    intent: EffectIntentRecord,
    authority: &EffectRecoveryAuthority,
) -> EffectRecoveryClaim {
    let digest = intent.stable_payload_digest().expect("stable digest");
    EffectRecoveryClaim {
        schema_version: EFFECT_RECOVERY_CLAIM_SCHEMA.into(),
        claim_id: format!("ecl_{}", "a".repeat(64)),
        original_attempt_id: intent.attempt_id.clone(),
        original_fence: intent.fence,
        intent,
        intent_payload_digest: digest,
        successor_authority_digest: authority.successor_authority_digest,
        successor_authority_fingerprint: authority.fingerprint().expect("fingerprint"),
        recovery_runner_id: authority.runner_id.clone(),
        recovery_runner_epoch: authority.runner_epoch,
        recovery_attempt_id: authority.attempt_id.clone(),
        recovery_attempt_fence: authority.attempt_fence,
        recovery_variant_id: authority.variant_id.clone(),
        recovery_workspace_id: authority.workspace_id.clone(),
        recovery_workspace_nonce: authority.workspace_nonce,
        authority_epoch: authority.authority_epoch,
        freeze_generation: authority.freeze_generation,
        restore_epoch: authority.restore_epoch,
        claim_generation: 1,
        outbox_sequence: 41,
        disposition: EffectRecoveryDisposition::Claimed,
        invalidated_from: None,
        claimed_at: "2026-08-28T03:01:00Z".into(),
        updated_at: "2026-08-28T03:01:00Z".into(),
    }
}

fn claim() -> (EffectRecoveryClaim, EffectRecoveryAuthority) {
    let authority = authority("owner", 2);
    (claim_for(intent(), &authority), authority)
}

fn observation(verdict: ReceiptVerdict) -> EffectRecoveryObservation {
    let intent = intent();
    EffectRecoveryObservation {
        provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
        remote_identity: intent.target_identity,
        observed_state_hash: match verdict {
            ReceiptVerdict::Match => Some(intent.desired_state_hash),
            ReceiptVerdict::Mismatch => Some("c".repeat(40)),
            ReceiptVerdict::Absent => None,
        },
        verification_method: EffectRecoveryObservation::METHOD.into(),
        verdict,
    }
}

fn rebind_intent(claim: &mut EffectRecoveryClaim) {
    claim.original_attempt_id = claim.intent.attempt_id.clone();
    claim.original_fence = claim.intent.fence;
    claim.intent_payload_digest = claim.intent.stable_payload_digest().expect("digest");
    claim.intent.payload_hash = claim.intent_payload_digest.to_hex();
}

fn reject_unknown<T: DeserializeOwned>(mut value: serde_json::Value) {
    value
        .as_object_mut()
        .expect("object")
        .insert("unexpected".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<T>(value).is_err());
}

#[test]
fn wire_records_reject_unknown_fields_including_nested_intent() {
    let (claim, authority) = claim();
    let transition = EffectRecoveryTransition::new(
        &claim,
        &authority,
        EffectRecoveryDisposition::ReadbackUnknown,
        None,
        None,
    )
    .expect("transition");
    reject_unknown::<EffectRecoveryAuthority>(serde_json::to_value(&authority).expect("json"));
    reject_unknown::<EffectRecoveryClaim>(serde_json::to_value(&claim).expect("json"));
    reject_unknown::<EffectRecoveryObservation>(
        serde_json::to_value(observation(ReceiptVerdict::Absent)).expect("json"),
    );
    reject_unknown::<EffectRecoveryTransition>(serde_json::to_value(transition).expect("json"));
    let mut nested = serde_json::to_value(&claim).expect("json");
    nested["intent"]["unexpected"] = serde_json::json!(1);
    assert!(serde_json::from_value::<EffectRecoveryClaim>(nested).is_err());
}

#[test]
fn exact_persisted_intent_rejects_consistent_substitution() {
    let (mut painted, _) = claim();
    let durable = painted.intent.clone();
    painted.intent.desired_state_hash = "d".repeat(40);
    rebind_intent(&mut painted);
    painted.validate().expect("self-consistent claim");
    assert_eq!(
        painted
            .validate_persisted_intent(&durable)
            .expect_err("substitution")
            .reason_code(),
        "EFFECT_RECOVERY_SUBJECT_MISMATCH"
    );
}

#[test]
fn terminal_claims_require_their_exact_terminal_effect_state() {
    let cases = [
        (EffectRecoveryDisposition::Adopted, EffectState::Committed),
        (
            EffectRecoveryDisposition::Orphaned,
            EffectState::OrphanedRemote,
        ),
        (
            EffectRecoveryDisposition::Quarantined,
            EffectState::Quarantined,
        ),
    ];
    for (disposition, state) in cases {
        let (mut terminal, _) = claim();
        terminal.disposition = disposition;
        terminal.intent.state = state;
        terminal.validate().expect("exact terminal state");
        terminal.intent.state = EffectState::OutcomeUnknown;
        assert_eq!(
            terminal
                .validate()
                .expect_err("mismatched terminal state")
                .reason_code(),
            "EFFECT_RECOVERY_CLAIM_INVALID"
        );
    }
}

#[test]
fn provider_create_state_and_candidate_scope_are_closed() {
    let mutations: [fn(&mut EffectRecoveryClaim); 3] = [
        |claim| claim.intent.provider = "jeryu".into(),
        |claim| claim.intent.expected_old_oid = "1".repeat(40),
        |claim| claim.intent.target_identity = format!("{CANDIDATE_REF_PREFIX}not-a-candidate"),
    ];
    for mutate in mutations {
        let (mut claim, _) = claim();
        mutate(&mut claim);
        rebind_intent(&mut claim);
        assert_eq!(
            claim.validate().expect_err("unsupported").reason_code(),
            "EFFECT_RECOVERY_INTENT_UNSUPPORTED"
        );
    }
    let (mut wrong_state, _) = claim();
    wrong_state.intent.state = EffectState::Authorized;
    assert_eq!(
        wrong_state
            .validate()
            .expect_err("wrong active state")
            .reason_code(),
        "EFFECT_RECOVERY_CLAIM_INVALID"
    );
}

#[test]
fn exact_owner_replays_and_foreign_stale_or_painted_authority_refuses() {
    let (mut claim, authority) = claim();
    claim
        .validate_readback(&claim.intent.id, &authority)
        .expect("same owner");
    let mut foreign = authority.clone();
    foreign.runner_id = RunnerId::from_seed("foreign");
    assert_eq!(
        claim
            .validate_readback(&claim.intent.id, &foreign)
            .expect_err("foreign")
            .reason_code(),
        "EFFECT_RECOVERY_CLAIM_CONFLICT"
    );
    let mut stale = authority.clone();
    stale.freeze_generation += 1;
    assert_eq!(
        claim
            .validate_readback(&claim.intent.id, &stale)
            .expect_err("stale")
            .reason_code(),
        "EFFECT_RECOVERY_AUTHORITY_STALE"
    );
    claim.successor_authority_fingerprint = Digest::of(b"painted");
    assert_eq!(
        claim.validate().expect_err("painted").reason_code(),
        "EFFECT_RECOVERY_FINGERPRINT_MISMATCH"
    );
    let mut changed_token = token("owner", 2);
    changed_token.variant_id = VariantId::from_seed("other-variant");
    assert_eq!(
        authority
            .validate_token(&changed_token)
            .expect_err("variant")
            .reason_code(),
        "EFFECT_RECOVERY_AUTHORITY_STALE"
    );
}

#[test]
fn stale_owner_invalidation_preserves_phase_and_generation() {
    let (mut previous, old_authority) = claim();
    previous.disposition = EffectRecoveryDisposition::Invalidated;
    previous.invalidated_from = Some(EffectRecoveryDisposition::RetryReserved);
    previous.intent.state = EffectState::OutcomeUnknown;
    previous.intent.unknown_retries = 1;
    previous.validate().expect("invalidated lineage");
    assert_eq!(
        previous
            .validate_readback(&previous.intent.id, &old_authority)
            .expect_err("old owner")
            .reason_code(),
        "EFFECT_RECOVERY_CLAIM_UNKNOWN"
    );
    let next_authority = authority("next", 3);
    let mut next = claim_for(previous.intent.clone(), &next_authority);
    next.claim_id = format!("ecl_{}", "b".repeat(64));
    next.claim_generation = 2;
    next.disposition = EffectRecoveryDisposition::RetryReserved;
    next.validate_generation_after(Some(&previous))
        .expect("inherit");
    next.disposition = EffectRecoveryDisposition::ReadbackUnknown;
    assert_eq!(
        next.validate_generation_after(Some(&previous))
            .expect_err("phase reset")
            .reason_code(),
        "EFFECT_RECOVERY_CLAIM_CONFLICT"
    );
}

#[test]
fn retry_reservation_is_single_use_and_restart_reuses_it() {
    let (claim, authority) = claim();
    let absent = observation(ReceiptVerdict::Absent);
    EffectRecoveryTransition::new(
        &claim,
        &authority,
        EffectRecoveryDisposition::RetryReserved,
        Some(absent.clone()),
        None,
    )
    .expect("reserve");
    let mut reserved = claim.clone();
    reserved.disposition = EffectRecoveryDisposition::RetryReserved;
    reserved.intent.state = EffectState::Dispatching;
    reserved.intent.unknown_retries = 1;
    reserved
        .validate_reserved_retry(&authority, &absent)
        .expect("resume");
    assert_eq!(
        EffectRecoveryTransition::new(
            &reserved,
            &authority,
            EffectRecoveryDisposition::RetryReserved,
            Some(absent),
            None,
        )
        .expect_err("second reserve")
        .reason_code(),
        "EFFECT_RECOVERY_TRANSITION_INVALID"
    );
    EffectRecoveryTransition::new(
        &reserved,
        &authority,
        EffectRecoveryDisposition::ReadbackUnknown,
        None,
        None,
    )
    .expect("lost response");
    let mut spent = reserved;
    spent.disposition = EffectRecoveryDisposition::ReadbackUnknown;
    spent.intent.state = EffectState::OutcomeUnknown;
    assert_eq!(
        EffectRecoveryTransition::new(
            &spent,
            &authority,
            EffectRecoveryDisposition::RetryReserved,
            Some(observation(ReceiptVerdict::Absent)),
            None,
        )
        .expect_err("spent budget")
        .reason_code(),
        "EFFECT_RECOVERY_RETRY_BUDGET_EXHAUSTED"
    );
}

#[test]
fn quarantine_requires_second_ambiguity_or_spent_absence() {
    let (claimed, authority) = claim();
    assert_eq!(
        EffectRecoveryTransition::new(
            &claimed,
            &authority,
            EffectRecoveryDisposition::Quarantined,
            None,
            Some(EffectRecoveryContainmentReason::ReadbackUnavailable),
        )
        .expect_err("first ambiguity")
        .reason_code(),
        "EFFECT_RECOVERY_OBSERVATION_INVALID"
    );
    let mut unknown = claimed;
    unknown.disposition = EffectRecoveryDisposition::ReadbackUnknown;
    EffectRecoveryTransition::new(
        &unknown,
        &authority,
        EffectRecoveryDisposition::Quarantined,
        None,
        Some(EffectRecoveryContainmentReason::ReadbackUnavailable),
    )
    .expect("second unavailable");
    unknown.intent.unknown_retries = 1;
    EffectRecoveryTransition::new(
        &unknown,
        &authority,
        EffectRecoveryDisposition::Quarantined,
        Some(observation(ReceiptVerdict::Absent)),
        Some(EffectRecoveryContainmentReason::RetrySpentAfterAbsence),
    )
    .expect("spent absence");
}

#[test]
fn receipt_identity_is_time_free_and_observation_sensitive() {
    let intent = intent();
    let matched = observation(ReceiptVerdict::Match);
    let first = matched.receipt_id(&intent).expect("receipt");
    let mut later = intent.clone();
    later.created_at = "2099-01-01T00:00:00Z".into();
    later.unknown_retries = 1;
    assert_eq!(first, matched.receipt_id(&later).expect("stable"));
    assert_ne!(
        first,
        observation(ReceiptVerdict::Mismatch)
            .receipt_id(&intent)
            .expect("different")
    );
    assert_eq!(
        first,
        recovery_receipt_id(
            &intent,
            &matched.remote_identity,
            matched.observed_state_hash.as_deref(),
            &matched.verification_method,
            matched.verdict,
        )
        .expect("direct")
    );
}

#[test]
fn state_edges_and_unresolved_normalization_are_exhaustive() {
    use EffectRecoveryDisposition::{
        Adopted, Claimed, Invalidated, Orphaned, Quarantined, ReadbackUnknown, RetryReserved,
        Unresolved,
    };
    let legal = [
        (Unresolved, Claimed),
        (Claimed, RetryReserved),
        (Claimed, ReadbackUnknown),
        (Claimed, Adopted),
        (Claimed, Orphaned),
        (Claimed, Quarantined),
        (Claimed, Invalidated),
        (RetryReserved, ReadbackUnknown),
        (RetryReserved, Adopted),
        (RetryReserved, Orphaned),
        (RetryReserved, Quarantined),
        (RetryReserved, Invalidated),
        (ReadbackUnknown, RetryReserved),
        (ReadbackUnknown, Adopted),
        (ReadbackUnknown, Orphaned),
        (ReadbackUnknown, Quarantined),
        (ReadbackUnknown, Invalidated),
    ];
    for from in EffectRecoveryDisposition::all() {
        for to in EffectRecoveryDisposition::all() {
            assert_eq!(from.transition(to).is_ok(), legal.contains(&(from, to)));
        }
    }
    for state in [
        EffectState::Dispatching,
        EffectState::ReceiptPending,
        EffectState::OutcomeUnknown,
    ] {
        assert_eq!(
            state
                .normalize_unresolved_for_recovery()
                .expect("normalize"),
            EffectState::OutcomeUnknown
        );
    }
    assert_eq!(
        EffectState::Committed
            .normalize_unresolved_for_recovery()
            .expect_err("terminal")
            .reason_code(),
        "INVALID_TRANSITION"
    );
}
