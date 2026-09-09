//! Claim/readback side of durable effect recovery.

mod terminal;

use super::storage::{
    active_claim, claim_is_current, require_authority_lease, require_claim_current,
    require_current_authority, stored_by_id,
};
use super::transitions::{invalidate_claim, normalize_intent};
use super::*;
use crate::sqlite::{effects, events, graph, lease_time, outbox};
use bullet_application::{
    EffectIntentRecord, EffectRecoveryAuthority, EffectRecoveryClaim, EffectRecoveryDisposition,
    CANDIDATE_REF_PREFIX, EFFECT_RECOVERY_CLAIM_SCHEMA, LOCAL_BARE_RECOVERY_PROVIDER, ZERO_OID,
};
use bullet_domain::{Attempt, CandidateId, Digest, EffectId, EffectReceiptId, VariantId};
use rusqlite::{params, Connection, TransactionBehavior};

pub(super) fn claim(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    intent_id: &EffectId,
    authority: &EffectRecoveryAuthority,
) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
    authority.validate()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(recovery_store)?;
    let current = require_current_authority(&tx, authority)?;
    let Some(mut intent) =
        effects::get_effect_intent_by_id(&tx, intent_id).map_err(recovery_ledger)?
    else {
        tx.commit().map_err(recovery_store)?;
        return Ok(None);
    };
    if let Some(stored) = active_claim(&tx, intent_id)? {
        if owner_matches(&stored.claim, authority)? && claim_is_current(&tx, &stored)? {
            stored.claim.validate_persisted_intent(&intent)?;
            tx.commit().map_err(recovery_store)?;
            return Ok(Some(stored.claim));
        }
        if claim_is_current(&tx, &stored)? {
            return Err(EffectRecoveryError::ClaimConflict(
                "active recovery claim belongs to the current owner".into(),
            ));
        }
        invalidate_claim(&tx, fail_after, &stored)?;
    }
    let previous = super::storage::latest_claim(&tx, intent_id)?;
    if let Some(stored) = previous.as_ref() {
        if terminal::no_work(&tx, stored, &intent, authority, &current)? {
            tx.commit().map_err(recovery_store)?;
            return Ok(None);
        }
    }
    normalize_intent(&tx, fail_after, &mut intent)?;
    let recovery = require_authority_lease(&tx, authority, &current)?;
    let original = original_attempt(&tx, &intent)?;
    require_successor(&intent, &original, &recovery, authority)?;
    let disposition = next_disposition(previous.as_ref(), &intent)?;
    let receipt = inherited_receipt(previous.as_ref(), disposition)?;
    let generation = previous.as_ref().map_or(Ok(1), |prior| {
        prior
            .claim
            .claim_generation
            .checked_add(1)
            .ok_or_else(|| recovery_store("claim generation overflow"))
    })?;
    let outbox_sequence =
        outbox::enqueue(&tx, None, OUTBOX_KIND, "pending").map_err(recovery_ledger)?;
    let now = lease_time::database_time(&tx).map_err(recovery_ledger)?;
    let id = claim_id(&intent, generation, outbox_sequence, authority, &current)?;
    tx.execute(
        "UPDATE outbox SET payload=?1 WHERE seq=?2 AND kind=?3 AND phase='pending'
         AND command_id IS NULL AND delivered_at IS NULL AND acked_at IS NULL",
        params![id, to_i64(outbox_sequence)?, OUTBOX_KIND],
    )
    .map_err(recovery_store)?;
    fail_boundary(fail_after, "claim")?;
    let claim = build_claim(
        &id,
        intent.clone(),
        &original,
        &recovery,
        authority,
        &current,
        generation,
        outbox_sequence,
        disposition,
        &now,
    )?;
    claim.validate_generation_after(previous.as_ref().map(|value| &value.claim))?;
    claim.validate_persisted_intent(&intent)?;
    insert_claim(&tx, &claim, &original, &current, receipt.as_ref())?;
    fail_boundary(fail_after, "claim")?;
    events::insert_event(
        &tx,
        CLAIMED_EVENT,
        &claim.claim_id,
        Some(claim.intent.id.as_str()),
        Some(&claim.claim_id),
        Some(&claim.successor_authority_digest.to_hex()),
    )
    .map_err(recovery_ledger)?;
    fail_boundary(fail_after, "claim")?;
    tx.commit().map_err(recovery_store)?;
    Ok(Some(
        stored_by_id(conn, &claim.claim_id)?
            .ok_or(EffectRecoveryError::UnknownClaim)?
            .claim,
    ))
}

pub(super) fn readback(
    conn: &Connection,
    intent_id: &EffectId,
    authority: &EffectRecoveryAuthority,
) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
    authority.validate()?;
    let Some(stored) = active_claim(conn, intent_id)? else {
        return Ok(None);
    };
    stored.claim.validate_readback(intent_id, authority)?;
    require_claim_current(conn, &stored)?;
    Ok(Some(stored.claim))
}

fn original_attempt(
    conn: &Connection,
    intent: &EffectIntentRecord,
) -> Result<Attempt, EffectRecoveryError> {
    graph::get_attempt(conn, &intent.attempt_id)
        .map_err(recovery_ledger)?
        .ok_or_else(|| EffectRecoveryError::SubjectMismatch("original attempt is absent".into()))
}

fn require_successor(
    intent: &EffectIntentRecord,
    original: &Attempt,
    recovery: &Attempt,
    authority: &EffectRecoveryAuthority,
) -> Result<(), EffectRecoveryError> {
    let suffix = intent
        .target_identity
        .strip_prefix(CANDIDATE_REF_PREFIX)
        .unwrap_or_default();
    let stable = intent
        .stable_payload_digest()
        .map_err(|err| EffectRecoveryError::Encoding(err.to_string()))?;
    let scoped = intent.provider == LOCAL_BARE_RECOVERY_PROVIDER
        && CandidateId::parse(suffix).is_ok()
        && intent.desired_state_hash != ZERO_OID
        && intent.expected_old_oid == ZERO_OID
        && intent.provider_idempotency_key.is_none()
        && intent.payload_hash == stable.to_hex();
    if !scoped
        || original.id != intent.attempt_id
        || original.fence != intent.fence
        || original.variant_id != recovery.variant_id
        || original.work_package_id != recovery.work_package_id
        || recovery.variant_id != authority.variant_id
        || recovery.id != authority.attempt_id
        || recovery.fence <= original.fence
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "recovery subject is not the same current variant and successor lease".into(),
        ));
    }
    Ok(())
}

fn next_disposition(
    previous: Option<&StoredClaim>,
    intent: &EffectIntentRecord,
) -> Result<EffectRecoveryDisposition, EffectRecoveryError> {
    if let Some(prior) = previous {
        if prior.claim.disposition == EffectRecoveryDisposition::Invalidated {
            return prior
                .claim
                .invalidated_from
                .ok_or_else(|| recovery_store("invalidated claim has no source phase"));
        }
    }
    match intent.unknown_retries {
        0 => Ok(EffectRecoveryDisposition::Claimed),
        1 => Ok(EffectRecoveryDisposition::ReadbackUnknown),
        _ => Err(EffectRecoveryError::RetryBudgetExhausted),
    }
}

fn inherited_receipt(
    previous: Option<&StoredClaim>,
    disposition: EffectRecoveryDisposition,
) -> Result<Option<EffectReceiptId>, EffectRecoveryError> {
    if disposition != EffectRecoveryDisposition::RetryReserved {
        return Ok(None);
    }
    previous
        .and_then(|value| value.receipt_id.clone())
        .map(Some)
        .ok_or_else(|| {
            EffectRecoveryError::SubjectMismatch("retry successor lacks absent receipt".into())
        })
}

#[allow(clippy::too_many_arguments)]
fn build_claim(
    id: &str,
    intent: EffectIntentRecord,
    original: &Attempt,
    recovery: &Attempt,
    authority: &EffectRecoveryAuthority,
    current: &CurrentAuthority,
    generation: u64,
    outbox_sequence: u64,
    disposition: EffectRecoveryDisposition,
    now: &str,
) -> Result<EffectRecoveryClaim, EffectRecoveryError> {
    Ok(EffectRecoveryClaim {
        schema_version: EFFECT_RECOVERY_CLAIM_SCHEMA.into(),
        claim_id: id.into(),
        intent_payload_digest: intent
            .stable_payload_digest()
            .map_err(|err| EffectRecoveryError::Encoding(err.to_string()))?,
        original_attempt_id: original.id.clone(),
        original_fence: original.fence,
        successor_authority_digest: authority.successor_authority_digest,
        successor_authority_fingerprint: authority.fingerprint()?,
        recovery_runner_id: recovery.runner_id.clone(),
        recovery_runner_epoch: recovery.runner_epoch,
        recovery_attempt_id: recovery.id.clone(),
        recovery_attempt_fence: recovery.fence,
        recovery_variant_id: recovery.variant_id.clone(),
        recovery_workspace_id: recovery.workspace_id.clone(),
        recovery_workspace_nonce: recovery.workspace_nonce,
        authority_epoch: current.authority_epoch,
        freeze_generation: current.freeze_generation,
        restore_epoch: current.restore_epoch,
        claim_generation: generation,
        outbox_sequence,
        disposition,
        invalidated_from: None,
        claimed_at: now.into(),
        updated_at: now.into(),
        intent,
    })
}

fn claim_id(
    intent: &EffectIntentRecord,
    generation: u64,
    outbox_sequence: u64,
    authority: &EffectRecoveryAuthority,
    current: &CurrentAuthority,
) -> Result<String, EffectRecoveryError> {
    #[derive(serde::Serialize)]
    struct Subject<'a> {
        schema_version: &'static str,
        effect_intent_id: &'a EffectId,
        claim_generation: u64,
        outbox_sequence: u64,
        intent_payload_digest: Digest,
        successor_authority_digest: Digest,
        successor_authority_fingerprint: Digest,
        recovery_attempt_id: &'a bullet_domain::AttemptId,
        recovery_variant_id: &'a VariantId,
        recovery_attempt_fence: u64,
        graph_revision: u64,
        workspace_generation: u64,
        scope_digest: &'a str,
        policy_generation: u64,
        routing_generation: u64,
        authority_epoch: u64,
        freeze_generation: u64,
        restore_epoch: u64,
    }
    let subject = Subject {
        schema_version: EFFECT_RECOVERY_CLAIM_SCHEMA,
        effect_intent_id: &intent.id,
        claim_generation: generation,
        outbox_sequence,
        intent_payload_digest: intent
            .stable_payload_digest()
            .map_err(|err| EffectRecoveryError::Encoding(err.to_string()))?,
        successor_authority_digest: authority.successor_authority_digest,
        successor_authority_fingerprint: authority.fingerprint()?,
        recovery_attempt_id: &authority.attempt_id,
        recovery_variant_id: &authority.variant_id,
        recovery_attempt_fence: authority.attempt_fence,
        graph_revision: current.graph_revision,
        workspace_generation: current.workspace_generation,
        scope_digest: &current.scope_digest,
        policy_generation: current.policy_generation,
        routing_generation: current.routing_generation,
        authority_epoch: current.authority_epoch,
        freeze_generation: current.freeze_generation,
        restore_epoch: current.restore_epoch,
    };
    Ok(format!(
        "ecl_{}",
        Digest::of_json(&subject).map_err(recovery_domain)?.to_hex()
    ))
}

fn insert_claim(
    tx: &Connection,
    claim: &EffectRecoveryClaim,
    original: &Attempt,
    current: &CurrentAuthority,
    receipt: Option<&EffectReceiptId>,
) -> Result<(), EffectRecoveryError> {
    tx.execute(
        "INSERT INTO effect_recovery_claims (
           claim_id,effect_intent_id,claim_generation,outbox_sequence,intent_payload_digest,
           intent_state,intent_unknown_retries,work_package_id,original_attempt_id,
           original_variant_id,original_fence,successor_authority_digest,
           successor_authority_fingerprint,recovery_attempt_id,recovery_variant_id,
           recovery_attempt_fence,recovery_runner_id,recovery_runner_epoch,recovery_workspace_id,
           recovery_workspace_nonce,graph_revision,workspace_generation,scope_digest,
           policy_generation,routing_generation,authority_epoch,freeze_generation,restore_epoch,
           disposition,invalidated_from,receipt_id,containment_reason,claimed_at,updated_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,
                   ?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,NULL,?30,NULL,?31,?31)",
        params![
            claim.claim_id,
            claim.intent.id.as_str(),
            to_i64(claim.claim_generation)?,
            to_i64(claim.outbox_sequence)?,
            claim.intent_payload_digest.to_hex(),
            claim.intent.state.as_str(),
            i64::from(claim.intent.unknown_retries),
            original.work_package_id.as_str(),
            original.id.as_str(),
            original.variant_id.as_str(),
            to_i64(original.fence)?,
            claim.successor_authority_digest.to_hex(),
            claim.successor_authority_fingerprint.to_hex(),
            claim.recovery_attempt_id.as_str(),
            claim.recovery_variant_id.as_str(),
            to_i64(claim.recovery_attempt_fence)?,
            claim.recovery_runner_id.as_str(),
            to_i64(claim.recovery_runner_epoch)?,
            claim.recovery_workspace_id.as_str(),
            claim.recovery_workspace_nonce.to_vec(),
            to_i64(current.graph_revision)?,
            to_i64(current.workspace_generation)?,
            current.scope_digest,
            to_i64(current.policy_generation)?,
            to_i64(current.routing_generation)?,
            to_i64(claim.authority_epoch)?,
            to_i64(claim.freeze_generation)?,
            to_i64(claim.restore_epoch)?,
            claim.disposition.as_str(),
            receipt.map(EffectReceiptId::as_str),
            claim.claimed_at,
        ],
    )
    .map_err(recovery_store)?;
    Ok(())
}
