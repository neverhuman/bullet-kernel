//! Closed validation for mutation-free reads of completed recovery work.

use super::{original_attempt, require_authority_lease, require_successor};
use crate::sqlite::effect_recovery::{
    recovery_ledger, recovery_store, to_i64, CurrentAuthority, StoredClaim, OUTBOX_KIND,
    TRANSITION_EVENT,
};
use crate::sqlite::effects;
use bullet_application::{
    EffectIntentRecord, EffectReceiptRecord, EffectRecoveryAuthority,
    EffectRecoveryContainmentReason, EffectRecoveryDisposition, EffectRecoveryError,
    EffectRecoveryObservation, EffectRecoveryTransition, ReceiptVerdict,
    EFFECT_RECOVERY_TRANSITION_SCHEMA, LOCAL_BARE_RECOVERY_PROVIDER, MAX_CREATE_RECOVERY_RETRIES,
};
use bullet_domain::EffectReceiptId;
use rusqlite::{params, Connection};

pub(super) fn no_work(
    conn: &Connection,
    stored: &StoredClaim,
    intent: &EffectIntentRecord,
    authority: &EffectRecoveryAuthority,
    current: &CurrentAuthority,
) -> Result<bool, EffectRecoveryError> {
    use EffectRecoveryDisposition as D;
    if !matches!(
        stored.claim.disposition,
        D::Adopted | D::Orphaned | D::Quarantined
    ) {
        return Ok(false);
    }
    stored.claim.validate_persisted_intent(intent)?;
    let recovery = require_authority_lease(conn, authority, current)?;
    let original = original_attempt(conn, intent)?;
    require_successor(intent, &original, &recovery, authority)?;
    validate_terminal_truth(conn, stored)?;
    Ok(true)
}

fn validate_terminal_truth(
    conn: &Connection,
    stored: &StoredClaim,
) -> Result<(), EffectRecoveryError> {
    use EffectRecoveryContainmentReason as R;
    use EffectRecoveryDisposition as D;
    let claim = &stored.claim;
    let (count, body): (i64, Option<String>) = conn
        .query_row(
            "SELECT COUNT(*), MIN(body) FROM events
             WHERE kind=?1 AND stream_id=?2 AND correlation_id=?3
               AND authority_token_hash=?4 AND json_extract(body, '$.to')=?5",
            params![
                TRANSITION_EVENT,
                claim.intent.id.as_str(),
                claim.claim_id,
                claim.successor_authority_digest.to_hex(),
                claim.disposition.as_str(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(recovery_store)?;
    if count != 1 {
        return Err(recovery_store(
            "terminal recovery claim lacks one exact transition event",
        ));
    }
    let body = body.ok_or_else(|| recovery_store("terminal transition event body is absent"))?;
    let transition: EffectRecoveryTransition =
        crate::sqlite::from_json(&body).map_err(recovery_ledger)?;
    if transition.schema_version != EFFECT_RECOVERY_TRANSITION_SCHEMA
        || transition.claim_id != claim.claim_id
        || transition.claim_generation != claim.claim_generation
        || transition.authority_fingerprint != claim.successor_authority_fingerprint
        || transition.to != claim.disposition
        || transition.receipt_id != stored.receipt_id
        || transition.containment_reason != stored.containment_reason
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "terminal transition differs from retained claim".into(),
        ));
    }
    transition.from.transition(transition.to)?;
    let canonical_receipt = transition
        .observation
        .as_ref()
        .map(|value| value.receipt_id(&claim.intent))
        .transpose()?;
    if canonical_receipt != transition.receipt_id {
        return Err(EffectRecoveryError::SubjectMismatch(
            "terminal transition receipt is not canonical".into(),
        ));
    }
    let admitted = match claim.disposition {
        D::Adopted => {
            transition.containment_reason.is_none()
                && transition
                    .observation
                    .as_ref()
                    .is_some_and(|value| value.verdict == ReceiptVerdict::Match)
        }
        D::Orphaned => {
            transition.containment_reason.is_none()
                && transition
                    .observation
                    .as_ref()
                    .is_some_and(|value| value.verdict == ReceiptVerdict::Mismatch)
        }
        D::Quarantined => match transition.containment_reason {
            Some(R::RetrySpentAfterAbsence) => {
                transition.from == D::ReadbackUnknown
                    && claim.intent.unknown_retries == MAX_CREATE_RECOVERY_RETRIES
                    && transition
                        .observation
                        .as_ref()
                        .is_some_and(|value| value.verdict == ReceiptVerdict::Absent)
            }
            Some(R::ReadbackUnavailable) => {
                transition.from == D::ReadbackUnknown && transition.observation.is_none()
            }
            None => false,
        },
        _ => false,
    };
    if !admitted {
        return Err(EffectRecoveryError::SubjectMismatch(
            "terminal transition predicate is not admitted".into(),
        ));
    }
    let delivered_at = validate_outbox(conn, stored)?;
    let retry_receipt_at = validate_retry_lineage(conn, stored, delivered_at.as_deref())?;
    validate_receipt(conn, stored, &transition, retry_receipt_at.as_deref())
}

fn validate_outbox(
    conn: &Connection,
    stored: &StoredClaim,
) -> Result<Option<String>, EffectRecoveryError> {
    let claim = &stored.claim;
    let phase = if claim.disposition == EffectRecoveryDisposition::Adopted {
        "verified"
    } else {
        "unknown"
    };
    let row: (
        Option<String>,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT command_id,kind,payload,phase,delivered_at,acked_at
             FROM outbox WHERE seq=?1",
            [to_i64(claim.outbox_sequence)?],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(recovery_store)?;
    if row.0.is_some()
        || row.1 != OUTBOX_KIND
        || row.2 != claim.claim_id
        || row.3 != phase
        || row.5.as_deref() != Some(claim.updated_at.as_str())
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "terminal recovery outbox is not correlated".into(),
        ));
    }
    Ok(row.4)
}

fn validate_retry_lineage(
    conn: &Connection,
    stored: &StoredClaim,
    delivered_at: Option<&str>,
) -> Result<Option<String>, EffectRecoveryError> {
    use EffectRecoveryDisposition as D;
    let claim = &stored.claim;
    let absence = EffectRecoveryObservation {
        provider: LOCAL_BARE_RECOVERY_PROVIDER.into(),
        remote_identity: claim.intent.target_identity.clone(),
        observed_state_hash: None,
        verification_method: EffectRecoveryObservation::METHOD.into(),
        verdict: ReceiptVerdict::Absent,
    };
    let absence_id = absence.receipt_id(&claim.intent)?;
    let receipt = receipt_by_id(conn, &claim.intent, &absence_id)?;
    let reservation = retry_reservation(conn, stored, &absence, &absence_id, receipt.as_ref())?;
    let birth = predecessor_birth(conn, stored, &absence_id)?;
    match claim.intent.unknown_retries {
        0 if delivered_at.is_none() && reservation.is_none() && receipt.is_none() => Ok(None),
        MAX_CREATE_RECOVERY_RETRIES => {
            let current_reservation = reservation
                .as_ref()
                .is_some_and(|value| value.claim_id == claim.claim_id);
            let expected_delivery = if current_reservation {
                reservation.as_ref().map(|value| value.receipt_at.as_str())
            } else if birth == Some(D::RetryReserved) {
                if reservation.is_none() {
                    return Err(EffectRecoveryError::SubjectMismatch(
                        "inherited retry lacks its original reservation".into(),
                    ));
                }
                Some(claim.claimed_at.as_str())
            } else {
                None
            };
            if delivered_at != expected_delivery {
                return Err(EffectRecoveryError::SubjectMismatch(
                    "terminal retry delivery contradicts claim birth".into(),
                ));
            }
            if let Some(reservation) = reservation {
                return Ok(Some(reservation.receipt_at));
            }
            match receipt {
                Some(receipt)
                    if claim.disposition == D::Quarantined
                        && stored.containment_reason
                            == Some(EffectRecoveryContainmentReason::RetrySpentAfterAbsence)
                        && stored.receipt_id.as_ref() == Some(&absence_id)
                        && receipt_matches(&receipt, &absence, claim, false)
                        && receipt.recorded_at == claim.updated_at =>
                {
                    Ok(Some(receipt.recorded_at))
                }
                None => Ok(None),
                _ => Err(EffectRecoveryError::SubjectMismatch(
                    "absent receipt has no canonical retry origin".into(),
                )),
            }
        }
        _ => Err(EffectRecoveryError::SubjectMismatch(
            "terminal retry count contradicts durable lineage".into(),
        )),
    }
}

struct RetryReservation {
    claim_id: String,
    receipt_at: String,
}

fn retry_reservation(
    conn: &Connection,
    stored: &StoredClaim,
    absence: &EffectRecoveryObservation,
    absence_id: &EffectReceiptId,
    receipt: Option<&EffectReceiptRecord>,
) -> Result<Option<RetryReservation>, EffectRecoveryError> {
    use EffectRecoveryDisposition as D;
    let claim = &stored.claim;
    let row: (i64, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT COUNT(*),MIN(body),MIN(correlation_id),MIN(authority_token_hash)
             FROM events WHERE kind=?1 AND stream_id=?2
               AND json_extract(body, '$.to')='RETRY_RESERVED'",
            params![TRANSITION_EVENT, claim.intent.id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(recovery_store)?;
    if row.0 == 0 && row.1.is_none() && row.2.is_none() && row.3.is_none() {
        return Ok(None);
    }
    if row.0 != 1 {
        return Err(recovery_store(
            "retry lineage lacks one exact reservation transition",
        ));
    }
    let body = row
        .1
        .ok_or_else(|| recovery_store("retry reservation body is absent"))?;
    let transition: EffectRecoveryTransition =
        crate::sqlite::from_json(&body).map_err(recovery_ledger)?;
    let source: (i64, String, String, i64) = conn
        .query_row(
            "SELECT claim_generation,successor_authority_digest,
                    successor_authority_fingerprint,outbox_sequence
             FROM effect_recovery_claims
             WHERE effect_intent_id=?1 AND claim_id=?2",
            params![claim.intent.id.as_str(), transition.claim_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(recovery_store)?;
    let source_generation = u64::try_from(source.0).map_err(recovery_store)?;
    let source_sequence = u64::try_from(source.3).map_err(recovery_store)?;
    let receipt = receipt.ok_or_else(|| {
        EffectRecoveryError::SubjectMismatch("retry reservation lacks its absent receipt".into())
    })?;
    let source_delivery: Option<String> = conn
        .query_row(
            "SELECT delivered_at FROM outbox
             WHERE seq=?1 AND command_id IS NULL AND kind=?2 AND payload=?3",
            params![to_i64(source_sequence)?, OUTBOX_KIND, transition.claim_id],
            |row| row.get(0),
        )
        .map_err(recovery_store)?;
    if transition.schema_version != EFFECT_RECOVERY_TRANSITION_SCHEMA
        || !matches!(transition.from, D::Claimed | D::ReadbackUnknown)
        || transition.to != D::RetryReserved
        || transition.claim_generation != source_generation
        || source_generation > claim.claim_generation
        || transition.authority_fingerprint.to_hex() != source.2
        || row.2.as_deref() != Some(transition.claim_id.as_str())
        || row.3.as_deref() != Some(source.1.as_str())
        || transition.containment_reason.is_some()
        || transition.observation.as_ref() != Some(absence)
        || transition.receipt_id.as_ref() != Some(absence_id)
        || !receipt_matches(receipt, absence, claim, false)
        || source_delivery.as_deref() != Some(receipt.recorded_at.as_str())
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "retry reservation lineage is not canonical".into(),
        ));
    }
    transition.from.transition(transition.to)?;
    Ok(Some(RetryReservation {
        claim_id: transition.claim_id,
        receipt_at: receipt.recorded_at.clone(),
    }))
}

fn predecessor_birth(
    conn: &Connection,
    stored: &StoredClaim,
    absence_id: &EffectReceiptId,
) -> Result<Option<EffectRecoveryDisposition>, EffectRecoveryError> {
    use EffectRecoveryDisposition as D;
    let claim = &stored.claim;
    let Some(generation) = claim
        .claim_generation
        .checked_sub(1)
        .filter(|value| *value > 0)
    else {
        return Ok(None);
    };
    let row: (i64, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT COUNT(*),MIN(disposition),MIN(invalidated_from),MIN(receipt_id)
             FROM effect_recovery_claims
             WHERE effect_intent_id=?1 AND claim_generation=?2",
            params![claim.intent.id.as_str(), to_i64(generation)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(recovery_store)?;
    let birth = match row.2.as_deref() {
        Some("CLAIMED") if row.3.is_none() => D::Claimed,
        Some("READBACK_UNKNOWN") if row.3.is_none() => D::ReadbackUnknown,
        Some("RETRY_RESERVED") if row.3.as_deref() == Some(absence_id.as_str()) => D::RetryReserved,
        _ => {
            return Err(EffectRecoveryError::SubjectMismatch(
                "successor claim birth lineage is not canonical".into(),
            ));
        }
    };
    if row.0 != 1 || row.1.as_deref() != Some("INVALIDATED") {
        return Err(EffectRecoveryError::SubjectMismatch(
            "successor claim predecessor is not exact".into(),
        ));
    }
    Ok(Some(birth))
}

fn validate_receipt(
    conn: &Connection,
    stored: &StoredClaim,
    transition: &EffectRecoveryTransition,
    retry_receipt_at: Option<&str>,
) -> Result<(), EffectRecoveryError> {
    let Some(receipt_id) = stored.receipt_id.as_ref() else {
        return Ok(());
    };
    let observation = transition.observation.as_ref().ok_or_else(|| {
        EffectRecoveryError::SubjectMismatch("terminal receipt lacks its observation".into())
    })?;
    let receipt = receipt_by_id(conn, &stored.claim.intent, receipt_id)?
        .ok_or_else(|| recovery_store("terminal recovery receipt disappeared"))?;
    let expected_time = if stored.claim.disposition == EffectRecoveryDisposition::Quarantined {
        retry_receipt_at
    } else {
        Some(stored.claim.updated_at.as_str())
    };
    if !receipt_matches(
        &receipt,
        observation,
        &stored.claim,
        stored.claim.disposition == EffectRecoveryDisposition::Adopted,
    ) || Some(receipt.recorded_at.as_str()) != expected_time
    {
        return Err(EffectRecoveryError::SubjectMismatch(
            "terminal recovery receipt truth differs".into(),
        ));
    }
    Ok(())
}

fn receipt_by_id(
    conn: &Connection,
    intent: &EffectIntentRecord,
    receipt_id: &EffectReceiptId,
) -> Result<Option<EffectReceiptRecord>, EffectRecoveryError> {
    Ok(effects::effect_receipts(conn, &intent.id)
        .map_err(recovery_ledger)?
        .into_iter()
        .find(|value| value.id == *receipt_id))
}

fn receipt_matches(
    receipt: &EffectReceiptRecord,
    observation: &EffectRecoveryObservation,
    claim: &bullet_application::EffectRecoveryClaim,
    adopted: bool,
) -> bool {
    receipt.effect_intent_id == claim.intent.id
        && receipt.observed_remote_identity == observation.remote_identity
        && receipt.observed_state_hash == observation.observed_state_hash
        && receipt.verification_method == observation.verification_method
        && receipt.verification_result == observation.verdict
        && receipt.adopted_after_unknown == adopted
}
