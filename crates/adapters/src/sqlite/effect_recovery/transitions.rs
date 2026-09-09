//! Recovery transition persistence.

use super::storage::{claim_is_current, stored_by_id};
use super::*;
use crate::sqlite::{effects, events, json};
use bullet_application::{
    EffectIntentRecord, EffectReceiptRecord, EffectRecoveryClaim, EffectRecoveryDisposition as D,
    EffectRecoveryObservation, EffectRecoveryTransition, EffectState, MAX_CREATE_RECOVERY_RETRIES,
};
use bullet_domain::CommandPhase;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

pub(super) fn apply(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    request: &EffectRecoveryTransition,
    authority: &EffectRecoveryAuthority,
) -> Result<EffectRecoveryClaim, EffectRecoveryError> {
    authority.validate()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(recovery_store)?;
    let stored = stored_by_id(&tx, &request.claim_id)?.ok_or(EffectRecoveryError::UnknownClaim)?;
    let current_intent = effects::get_effect_intent_by_id(&tx, &stored.claim.intent.id)
        .map_err(recovery_ledger)?
        .ok_or_else(|| recovery_store("effect intent disappeared"))?;
    stored.claim.validate_persisted_intent(&current_intent)?;
    if replay_matches(&tx, &stored, request, authority)? {
        tx.commit().map_err(recovery_store)?;
        return Ok(stored.claim);
    }
    request.validate_for(&stored.claim, authority)?;
    if !claim_is_current(&tx, &stored)? {
        invalidate_claim(&tx, fail_after, &stored)?;
        tx.commit().map_err(recovery_store)?;
        return Err(EffectRecoveryError::StaleAuthority(
            "claim owner ceased to be current".into(),
        ));
    }
    let now = crate::sqlite::lease_time::database_time(&tx).map_err(recovery_ledger)?;
    let receipt = request
        .observation
        .as_ref()
        .map(|obs| receipt_record(obs, request, &stored.claim, &now))
        .transpose()?;
    if let Some(row) = receipt.as_ref() {
        insert_receipt(&tx, row)?;
        fail_boundary(fail_after, "apply")?;
    }
    let (state, retries) = target_phase(&stored.claim, request.to)?;
    update_intent(&tx, &stored.claim, state, retries)?;
    fail_boundary(fail_after, "apply")?;
    update_outbox(&tx, &stored.claim, request.to, &now)?;
    fail_boundary(fail_after, "apply")?;
    update_claim(
        &tx,
        &stored,
        request,
        state,
        retries,
        receipt.as_ref(),
        &now,
    )?;
    fail_boundary(fail_after, "apply")?;
    events::insert_event(
        &tx,
        TRANSITION_EVENT,
        &json(request).map_err(recovery_ledger)?,
        Some(stored.claim.intent.id.as_str()),
        Some(&stored.claim.claim_id),
        Some(&stored.claim.successor_authority_digest.to_hex()),
    )
    .map_err(recovery_ledger)?;
    let updated = stored_by_id(&tx, &stored.claim.claim_id)?
        .ok_or_else(|| recovery_store("updated claim disappeared"))?;
    tx.commit().map_err(recovery_store)?;
    Ok(updated.claim)
}

pub(super) fn normalize_intent(
    tx: &Transaction<'_>,
    fail_after: &mut Option<u8>,
    intent: &mut EffectIntentRecord,
) -> Result<(), EffectRecoveryError> {
    let next = intent
        .state
        .normalize_unresolved_for_recovery()
        .map_err(recovery_domain)?;
    if next == intent.state {
        return Ok(());
    }
    let changed = tx
        .execute(
            "UPDATE effect_intents SET state='OUTCOME_UNKNOWN' WHERE id=?1 AND state=?2",
            params![intent.id.as_str(), intent.state.as_str()],
        )
        .map_err(recovery_store)?;
    require_one(
        changed,
        "effect intent changed during recovery normalization",
    )?;
    events::insert_event(
        tx,
        NORMALIZED_EVENT,
        intent.id.as_str(),
        Some(intent.id.as_str()),
        Some(intent.id.as_str()),
        None,
    )
    .map_err(recovery_ledger)?;
    fail_boundary(fail_after, "claim")?;
    intent.state = next;
    Ok(())
}

pub(super) fn invalidate_claim(
    tx: &Connection,
    fail_after: &mut Option<u8>,
    stored: &StoredClaim,
) -> Result<(), EffectRecoveryError> {
    if !stored.claim.disposition.is_active() {
        return Ok(());
    }
    let now = crate::sqlite::lease_time::database_time(tx).map_err(recovery_ledger)?;
    let changed = tx
        .execute(
            "UPDATE effect_recovery_claims
             SET disposition='INVALIDATED', invalidated_from=?1, updated_at=?2
             WHERE claim_id=?3 AND disposition=?1",
            params![
                stored.claim.disposition.as_str(),
                now,
                stored.claim.claim_id
            ],
        )
        .map_err(recovery_store)?;
    require_one(changed, "stale recovery claim changed during invalidation")?;
    fail_boundary(fail_after, "claim")
}

fn replay_matches(
    tx: &Connection,
    stored: &StoredClaim,
    request: &EffectRecoveryTransition,
    authority: &EffectRecoveryAuthority,
) -> Result<bool, EffectRecoveryError> {
    if stored.claim.disposition != request.to {
        return Ok(false);
    }
    if request.schema_version != bullet_application::EFFECT_RECOVERY_TRANSITION_SCHEMA
        || request.claim_id != stored.claim.claim_id
        || request.claim_generation != stored.claim.claim_generation
        || request.authority_fingerprint != stored.claim.successor_authority_fingerprint
        || !owner_matches(&stored.claim, authority)?
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "transition replay differs from retained claim".into(),
        ));
    }
    request.from.transition(request.to)?;
    if !claim_is_current(tx, stored)? {
        return Err(EffectRecoveryError::StaleAuthority(
            "terminal replay owner ceased to be current".into(),
        ));
    }
    if !retained_transition_matches(tx, stored, request)? {
        return Err(EffectRecoveryError::SubjectMismatch(
            "transition replay differs from retained command".into(),
        ));
    }
    let expected = request
        .observation
        .as_ref()
        .map(|obs| obs.receipt_id(&stored.claim.intent))
        .transpose()?;
    if request.receipt_id != expected
        || request.receipt_id != stored.receipt_id
        || request.containment_reason != stored.containment_reason
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "transition replay differs from retained receipt".into(),
        ));
    }
    Ok(true)
}

fn retained_transition_matches(
    tx: &Connection,
    stored: &StoredClaim,
    request: &EffectRecoveryTransition,
) -> Result<bool, EffectRecoveryError> {
    let body = json(request).map_err(recovery_ledger)?;
    let count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE kind=?1 AND stream_id=?2 AND correlation_id=?3
               AND authority_token_hash=?4 AND body=?5",
            params![
                TRANSITION_EVENT,
                stored.claim.intent.id.as_str(),
                stored.claim.claim_id,
                stored.claim.successor_authority_digest.to_hex(),
                body,
            ],
            |row| row.get(0),
        )
        .map_err(recovery_store)?;
    Ok(count == 1)
}

fn receipt_record(
    obs: &EffectRecoveryObservation,
    request: &EffectRecoveryTransition,
    claim: &EffectRecoveryClaim,
    now: &str,
) -> Result<EffectReceiptRecord, EffectRecoveryError> {
    let id = request.receipt_id.clone().ok_or_else(|| {
        EffectRecoveryError::SubjectMismatch("transition omitted deterministic receipt".into())
    })?;
    if id != obs.receipt_id(&claim.intent)? {
        return Err(EffectRecoveryError::SubjectMismatch(
            "transition receipt identity is not canonical".into(),
        ));
    }
    Ok(EffectReceiptRecord {
        id,
        effect_intent_id: claim.intent.id.clone(),
        observed_remote_identity: obs.remote_identity.clone(),
        observed_state_hash: obs.observed_state_hash.clone(),
        verification_method: obs.verification_method.clone(),
        verification_result: obs.verdict,
        adopted_after_unknown: request.to == D::Adopted,
        recorded_at: now.into(),
    })
}

fn insert_receipt(
    tx: &Connection,
    receipt: &EffectReceiptRecord,
) -> Result<(), EffectRecoveryError> {
    let changed = tx
        .execute(
            "INSERT INTO effect_receipts (
               id,effect_intent_id,observed_remote_identity,observed_state_hash,
               verification_method,verification_result,adopted_after_unknown,recorded_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO NOTHING",
            params![
                receipt.id.as_str(),
                receipt.effect_intent_id.as_str(),
                receipt.observed_remote_identity,
                receipt.observed_state_hash,
                receipt.verification_method,
                receipt.verification_result.as_str(),
                receipt.adopted_after_unknown,
                receipt.recorded_at,
            ],
        )
        .map_err(recovery_store)?;
    if changed == 1 {
        return Ok(());
    }
    let existing = tx
        .query_row(
            &format!(
                "SELECT {} FROM effect_receipts WHERE id=?1",
                effects::RECEIPT_COLUMNS
            ),
            [receipt.id.as_str()],
            effects::receipt_row,
        )
        .map_err(recovery_store)
        .and_then(|row| effects::read_receipt(row).map_err(recovery_ledger))?;
    if same_receipt_truth(&existing, receipt) {
        Ok(())
    } else {
        Err(EffectRecoveryError::SubjectMismatch(
            "effect recovery receipt id already names different truth".into(),
        ))
    }
}

fn same_receipt_truth(a: &EffectReceiptRecord, b: &EffectReceiptRecord) -> bool {
    a.id == b.id
        && a.effect_intent_id == b.effect_intent_id
        && a.observed_remote_identity == b.observed_remote_identity
        && a.observed_state_hash == b.observed_state_hash
        && a.verification_method == b.verification_method
        && a.verification_result == b.verification_result
        && a.adopted_after_unknown == b.adopted_after_unknown
}

fn target_phase(
    claim: &EffectRecoveryClaim,
    to: D,
) -> Result<(EffectState, u32), EffectRecoveryError> {
    use EffectState as S;
    let retry = claim.intent.unknown_retries;
    match to {
        D::RetryReserved => Ok((S::Dispatching, MAX_CREATE_RECOVERY_RETRIES)),
        D::ReadbackUnknown => Ok((S::OutcomeUnknown, retry)),
        D::Adopted => Ok((S::Committed, retry)),
        D::Orphaned => Ok((S::OrphanedRemote, retry)),
        D::Quarantined => Ok((S::Quarantined, retry)),
        D::Invalidated => Ok((claim.intent.state, retry)),
        D::Unresolved | D::Claimed => Err(EffectRecoveryError::InvalidTransition {
            from: claim.disposition.as_str().into(),
            to: to.as_str().into(),
        }),
    }
}

fn update_intent(
    tx: &Connection,
    claim: &EffectRecoveryClaim,
    state: EffectState,
    retries: u32,
) -> Result<(), EffectRecoveryError> {
    let changed = tx
        .execute(
            "UPDATE effect_intents SET state=?2, unknown_retries=?3
             WHERE id=?1 AND state=?4 AND unknown_retries=?5",
            params![
                claim.intent.id.as_str(),
                state.as_str(),
                i64::from(retries),
                claim.intent.state.as_str(),
                i64::from(claim.intent.unknown_retries),
            ],
        )
        .map_err(recovery_store)?;
    require_one(changed, "effect intent changed during recovery transition")
}

fn update_outbox(
    tx: &Connection,
    claim: &EffectRecoveryClaim,
    to: D,
    now: &str,
) -> Result<(), EffectRecoveryError> {
    let phase = match to {
        D::RetryReserved => Some(CommandPhase::Applied),
        D::Adopted => Some(CommandPhase::Verified),
        D::Orphaned | D::Quarantined => Some(CommandPhase::Unknown),
        D::ReadbackUnknown | D::Invalidated => None,
        D::Unresolved | D::Claimed => {
            return Err(EffectRecoveryError::InvalidTransition {
                from: claim.disposition.as_str().into(),
                to: to.as_str().into(),
            });
        }
    };
    let Some(phase) = phase else {
        return Ok(());
    };
    let (stamp, guard) = if phase == CommandPhase::Applied {
        ("delivered_at", "delivered_at")
    } else {
        ("acked_at", "acked_at")
    };
    let sql = format!(
        "UPDATE outbox SET phase=?1,{stamp}=?2
         WHERE seq=?3 AND kind=?4 AND payload=?5 AND command_id IS NULL
           AND phase IN ('pending','applied') AND {guard} IS NULL"
    );
    let changed = tx
        .execute(
            &sql,
            params![
                phase.as_str(),
                now,
                to_i64(claim.outbox_sequence)?,
                OUTBOX_KIND,
                claim.claim_id,
            ],
        )
        .map_err(recovery_store)?;
    require_one(changed, "recovery outbox changed during transition")
}

fn update_claim(
    tx: &Connection,
    stored: &StoredClaim,
    request: &EffectRecoveryTransition,
    state: EffectState,
    retries: u32,
    receipt: Option<&EffectReceiptRecord>,
    now: &str,
) -> Result<(), EffectRecoveryError> {
    let receipt_id = receipt.map(|row| row.id.as_str()).or_else(|| {
        if request.to == D::Invalidated {
            stored.receipt_id.as_ref().map(EffectReceiptId::as_str)
        } else {
            None
        }
    });
    let invalidated_from =
        (request.to == D::Invalidated).then_some(stored.claim.disposition.as_str());
    let reason = request.containment_reason.map(reason_str);
    let changed = tx
        .execute(
            "UPDATE effect_recovery_claims
             SET disposition=?1,invalidated_from=?2,receipt_id=?3,containment_reason=?4,
                 intent_state=?5,intent_unknown_retries=?6,updated_at=?7
             WHERE claim_id=?8 AND disposition=?9",
            params![
                request.to.as_str(),
                invalidated_from,
                receipt_id,
                reason,
                state.as_str(),
                i64::from(retries),
                now,
                stored.claim.claim_id,
                stored.claim.disposition.as_str(),
            ],
        )
        .map_err(recovery_store)?;
    require_one(changed, "recovery claim changed during transition")
}
