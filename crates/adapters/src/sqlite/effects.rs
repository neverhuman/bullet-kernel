//! Effect intent and receipt persistence (migration 0003). An intent is
//! unique on `(provider, logical_effect_key)`; a replayed proposal returns
//! the stored row and never dispatches twice. Receipts are append-only.

use super::{events, store};
use bullet_application::{
    EffectIntentRecord, EffectReceiptRecord, EffectState, LedgerError, ReceiptVerdict,
};
use bullet_domain::{AttemptId, DomainError, EffectId, EffectReceiptId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub(super) const INTENT_COLUMNS: &str = "id, logical_effect_key, provider, target_identity, \
                              desired_state_hash, expected_old_oid, attempt_id, fence, \
                              policy_version, payload_hash, provider_idempotency_key, state, \
                              unknown_retries, created_at";

#[allow(clippy::type_complexity)]
pub(super) fn intent_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    Option<String>,
    String,
    i64,
    String,
)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    ))
}

#[allow(clippy::type_complexity)]
pub(super) fn read_intent(
    row: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
        String,
        i64,
        String,
    ),
) -> Result<EffectIntentRecord, LedgerError> {
    let (
        id,
        key,
        provider,
        target,
        desired,
        expected,
        attempt,
        fence,
        policy,
        payload,
        pik,
        state,
        retries,
        created,
    ) = row;
    Ok(EffectIntentRecord {
        id: EffectId::parse(&id)?,
        logical_effect_key: key,
        provider,
        target_identity: target,
        desired_state_hash: desired,
        expected_old_oid: expected,
        attempt_id: AttemptId::parse(&attempt)?,
        fence: u64::try_from(fence).map_err(store)?,
        policy_version: policy,
        payload_hash: payload,
        provider_idempotency_key: pik,
        state: EffectState::parse(&state)?,
        unknown_retries: u32::try_from(retries).map_err(store)?,
        created_at: created,
    })
}

fn select_by_key(
    conn: &Connection,
    provider: &str,
    logical_key: &str,
) -> Result<Option<EffectIntentRecord>, LedgerError> {
    conn.query_row(
        &format!(
            "SELECT {INTENT_COLUMNS} FROM effect_intents
             WHERE provider = ?1 AND logical_effect_key = ?2"
        ),
        params![provider, logical_key],
        intent_row,
    )
    .optional()
    .map_err(store)?
    .map(read_intent)
    .transpose()
}

fn select_by_id(
    conn: &Connection,
    id: &EffectId,
) -> Result<Option<EffectIntentRecord>, LedgerError> {
    conn.query_row(
        &format!("SELECT {INTENT_COLUMNS} FROM effect_intents WHERE id = ?1"),
        params![id.to_string()],
        intent_row,
    )
    .optional()
    .map_err(store)?
    .map(read_intent)
    .transpose()
}

pub(super) fn record_effect_intent(
    conn: &mut Connection,
    intent: &EffectIntentRecord,
) -> Result<(EffectIntentRecord, bool), LedgerError> {
    if intent.state != EffectState::Proposed {
        return Err(DomainError::Conflict(format!(
            "effect intent {} must be recorded as PROPOSED, not {}",
            intent.id,
            intent.state.as_str()
        ))
        .into());
    }
    let mut normalized = intent.clone();
    normalized.payload_hash = intent.payload_digest()?;
    normalized.unknown_retries = 0;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    if let Some(existing) = select_by_key(&tx, &intent.provider, &intent.logical_effect_key)? {
        if existing.payload_hash != normalized.payload_hash {
            return Err(DomainError::Idempotency(format!(
                "effect {}:{} exists with a different identity",
                intent.provider, intent.logical_effect_key
            ))
            .into());
        }
        return Ok((existing, false));
    }
    if select_by_id(&tx, &intent.id)?.is_some() {
        return Err(DomainError::Conflict(format!(
            "effect intent id {} already used by another logical key",
            intent.id
        ))
        .into());
    }
    tx.execute(
        "INSERT INTO effect_intents
           (id, logical_effect_key, provider, target_identity, desired_state_hash,
            expected_old_oid, attempt_id, fence, policy_version, payload_hash,
            provider_idempotency_key, state, unknown_retries, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13)",
        params![
            normalized.id.to_string(),
            normalized.logical_effect_key,
            normalized.provider,
            normalized.target_identity,
            normalized.desired_state_hash,
            normalized.expected_old_oid,
            normalized.attempt_id.to_string(),
            i64::try_from(normalized.fence).map_err(store)?,
            normalized.policy_version,
            normalized.payload_hash,
            normalized.provider_idempotency_key,
            normalized.state.as_str(),
            normalized.created_at,
        ],
    )
    .map_err(store)?;
    events::insert_event(
        &tx,
        "effect_intent_recorded",
        normalized.id.as_str(),
        Some(&normalized.attempt_id.to_string()),
        None,
        None,
    )?;
    tx.commit().map_err(store)?;
    Ok((normalized, true))
}

pub(super) fn get_effect_intent(
    conn: &Connection,
    provider: &str,
    logical_key: &str,
) -> Result<Option<EffectIntentRecord>, LedgerError> {
    select_by_key(conn, provider, logical_key)
}

pub(super) fn get_effect_intent_by_id(
    conn: &Connection,
    id: &EffectId,
) -> Result<Option<EffectIntentRecord>, LedgerError> {
    select_by_id(conn, id)
}

pub(super) fn transition_effect(
    conn: &mut Connection,
    id: &EffectId,
    to: EffectState,
) -> Result<EffectIntentRecord, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let existing = select_by_id(&tx, id)?
        .ok_or_else(|| LedgerError::Store(format!("unknown effect intent {id}")))?;
    let next = existing.state.transition(to)?;
    let mut updated = existing.clone();
    updated.state = next;
    if existing.state == EffectState::OutcomeUnknown && next == EffectState::Dispatching {
        updated.unknown_retries += 1;
    }
    tx.execute(
        "UPDATE effect_intents SET state = ?2, unknown_retries = ?3 WHERE id = ?1",
        params![
            id.to_string(),
            updated.state.as_str(),
            i64::from(updated.unknown_retries),
        ],
    )
    .map_err(store)?;
    events::insert_event(
        &tx,
        "effect_transition",
        &format!("{id}:{}->{}", existing.state.as_str(), next.as_str()),
        Some(&updated.attempt_id.to_string()),
        None,
        None,
    )?;
    tx.commit().map_err(store)?;
    Ok(updated)
}

pub(super) type ReceiptRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    bool,
    String,
);

pub(super) fn receipt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiptRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

pub(super) fn read_receipt(row: ReceiptRow) -> Result<EffectReceiptRecord, LedgerError> {
    let (id, intent, identity, observed, method, verdict, adopted, recorded) = row;
    Ok(EffectReceiptRecord {
        id: EffectReceiptId::parse(&id)?,
        effect_intent_id: EffectId::parse(&intent)?,
        observed_remote_identity: identity,
        observed_state_hash: observed,
        verification_method: method,
        verification_result: ReceiptVerdict::parse(&verdict)?,
        adopted_after_unknown: adopted,
        recorded_at: recorded,
    })
}

pub(super) const RECEIPT_COLUMNS: &str = "id, effect_intent_id, observed_remote_identity, \
                               observed_state_hash, verification_method, verification_result, \
                               adopted_after_unknown, recorded_at";

pub(super) fn record_effect_receipt(
    conn: &mut Connection,
    receipt: &EffectReceiptRecord,
) -> Result<bool, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let changed = tx
        .execute(
            "INSERT INTO effect_receipts
               (id, effect_intent_id, observed_remote_identity, observed_state_hash,
                verification_method, verification_result, adopted_after_unknown, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO NOTHING",
            params![
                receipt.id.as_str(),
                receipt.effect_intent_id.to_string(),
                receipt.observed_remote_identity,
                receipt.observed_state_hash,
                receipt.verification_method,
                receipt.verification_result.as_str(),
                receipt.adopted_after_unknown,
                receipt.recorded_at,
            ],
        )
        .map_err(store)?;
    if changed == 1 {
        events::insert_event(
            &tx,
            "effect_receipt_recorded",
            receipt.id.as_str(),
            Some(&receipt.effect_intent_id.to_string()),
            None,
            None,
        )?;
        tx.commit().map_err(store)?;
        return Ok(true);
    }
    let existing = tx
        .query_row(
            &format!("SELECT {RECEIPT_COLUMNS} FROM effect_receipts WHERE id = ?1"),
            params![receipt.id.as_str()],
            receipt_row,
        )
        .map_err(store)
        .and_then(read_receipt)?;
    if existing == *receipt {
        Ok(false)
    } else {
        Err(DomainError::Conflict(format!(
            "effect receipt {} differs from the stored row",
            receipt.id
        ))
        .into())
    }
}

pub(super) fn effect_receipts(
    conn: &Connection,
    intent: &EffectId,
) -> Result<Vec<EffectReceiptRecord>, LedgerError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {RECEIPT_COLUMNS} FROM effect_receipts
             WHERE effect_intent_id = ?1 ORDER BY recorded_at, id"
        ))
        .map_err(store)?;
    let rows = stmt
        .query_map(params![intent.to_string()], receipt_row)
        .map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(read_receipt(row.map_err(store)?)?);
    }
    Ok(out)
}

pub(super) fn unresolved_effects(
    conn: &Connection,
) -> Result<Vec<EffectIntentRecord>, LedgerError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {INTENT_COLUMNS} FROM effect_intents
             WHERE state IN ('DISPATCHING', 'RECEIPT_PENDING', 'OUTCOME_UNKNOWN')
             ORDER BY created_at, id"
        ))
        .map_err(store)?;
    let rows = stmt.query_map([], intent_row).map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(read_intent(row.map_err(store)?)?);
    }
    Ok(out)
}
