//! Stored recovery claim decoding and current-owner checks.

use super::*;
use crate::sqlite::{authority, graph, lease_time, leases};
use bullet_application::{
    check_active_lease_snapshot, ActiveLeaseSubject, EffectIntentRecord, EffectRecoveryAuthority,
    EffectState, LedgerError, EFFECT_RECOVERY_CLAIM_SCHEMA,
};
use bullet_domain::{
    Attempt, AttemptId, Digest, EffectId, EffectReceiptId, RunnerId, VariantId, WorkPackageId,
    WorkspaceId,
};
use rusqlite::{params, Connection, OptionalExtension, Params, Row};

const CLAIM_COLUMNS: &str = "c.claim_id,c.effect_intent_id,c.claim_generation,c.outbox_sequence,\
c.intent_payload_digest,c.intent_state,c.intent_unknown_retries,c.work_package_id,\
c.original_attempt_id,c.original_variant_id,c.original_fence,c.successor_authority_digest,\
c.successor_authority_fingerprint,c.recovery_attempt_id,c.recovery_variant_id,\
c.recovery_attempt_fence,c.recovery_runner_id,c.recovery_runner_epoch,c.recovery_workspace_id,\
c.recovery_workspace_nonce,c.graph_revision,c.workspace_generation,c.scope_digest,\
c.policy_generation,c.routing_generation,c.authority_epoch,c.freeze_generation,c.restore_epoch,\
c.disposition,c.invalidated_from,c.receipt_id,c.containment_reason,c.claimed_at,c.updated_at,\
i.logical_effect_key,i.provider,i.target_identity,i.desired_state_hash,i.expected_old_oid,\
i.attempt_id,i.fence,i.policy_version,i.payload_hash,i.provider_idempotency_key,i.created_at";

pub(super) fn stored_by_id(
    conn: &Connection,
    id: &str,
) -> Result<Option<StoredClaim>, EffectRecoveryError> {
    query_claim(
        conn,
        &format!(
            "SELECT {CLAIM_COLUMNS} FROM effect_recovery_claims c \
             JOIN effect_intents i ON i.id=c.effect_intent_id WHERE c.claim_id=?1"
        ),
        [id],
    )
}

pub(super) fn active_claim(
    conn: &Connection,
    intent_id: &EffectId,
) -> Result<Option<StoredClaim>, EffectRecoveryError> {
    query_claim(
        conn,
        &format!(
            "SELECT {CLAIM_COLUMNS} FROM effect_recovery_claims c \
             JOIN effect_intents i ON i.id=c.effect_intent_id \
             WHERE c.effect_intent_id=?1 \
               AND c.disposition IN ('CLAIMED','RETRY_RESERVED','READBACK_UNKNOWN')"
        ),
        [intent_id.as_str()],
    )
}

pub(super) fn latest_claim(
    conn: &Connection,
    intent_id: &EffectId,
) -> Result<Option<StoredClaim>, EffectRecoveryError> {
    query_claim(
        conn,
        &format!(
            "SELECT {CLAIM_COLUMNS} FROM effect_recovery_claims c \
             JOIN effect_intents i ON i.id=c.effect_intent_id \
             WHERE c.effect_intent_id=?1 ORDER BY c.claim_generation DESC LIMIT 1"
        ),
        [intent_id.as_str()],
    )
}

fn query_claim<P: Params>(
    conn: &Connection,
    sql: &str,
    args: P,
) -> Result<Option<StoredClaim>, EffectRecoveryError> {
    conn.query_row(sql, args, raw_claim)
        .optional()
        .map_err(recovery_store)?
        .map(decode_claim)
        .transpose()
}

#[rustfmt::skip]
type Raw = (String,String,i64,i64,String,String,i64,String,String,String,i64,String,String,String,String,i64,String,i64,String,Vec<u8>,i64,i64,String,i64,i64,i64,i64,i64,String,Option<String>,Option<String>,Option<String>,String,String,String,String,String,String,String,String,i64,String,String,Option<String>,String);

fn raw_claim(row: &Row<'_>) -> rusqlite::Result<Raw> {
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
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
        row.get(19)?,
        row.get(20)?,
        row.get(21)?,
        row.get(22)?,
        row.get(23)?,
        row.get(24)?,
        row.get(25)?,
        row.get(26)?,
        row.get(27)?,
        row.get(28)?,
        row.get(29)?,
        row.get(30)?,
        row.get(31)?,
        row.get(32)?,
        row.get(33)?,
        row.get(34)?,
        row.get(35)?,
        row.get(36)?,
        row.get(37)?,
        row.get(38)?,
        row.get(39)?,
        row.get(40)?,
        row.get(41)?,
        row.get(42)?,
        row.get(43)?,
        row.get(44)?,
    ))
}

fn decode_claim(raw: Raw) -> Result<StoredClaim, EffectRecoveryError> {
    let intent = EffectIntentRecord {
        id: EffectId::parse(&raw.1).map_err(recovery_store)?,
        logical_effect_key: raw.34,
        provider: raw.35,
        target_identity: raw.36,
        desired_state_hash: raw.37,
        expected_old_oid: raw.38,
        attempt_id: AttemptId::parse(&raw.39).map_err(recovery_store)?,
        fence: u64_from(raw.40)?,
        policy_version: raw.41,
        payload_hash: raw.42,
        provider_idempotency_key: raw.43,
        state: EffectState::parse(&raw.5).map_err(recovery_domain)?,
        unknown_retries: u32::try_from(raw.6).map_err(recovery_store)?,
        created_at: raw.44,
    };
    let claim = EffectRecoveryClaim {
        schema_version: EFFECT_RECOVERY_CLAIM_SCHEMA.into(),
        claim_id: raw.0,
        intent,
        intent_payload_digest: Digest::from_hex(&raw.4).map_err(recovery_store)?,
        original_attempt_id: AttemptId::parse(&raw.8).map_err(recovery_store)?,
        original_fence: u64_from(raw.10)?,
        successor_authority_digest: Digest::from_hex(&raw.11).map_err(recovery_store)?,
        successor_authority_fingerprint: Digest::from_hex(&raw.12).map_err(recovery_store)?,
        recovery_runner_id: RunnerId::parse(&raw.16).map_err(recovery_store)?,
        recovery_runner_epoch: u64_from(raw.17)?,
        recovery_attempt_id: AttemptId::parse(&raw.13).map_err(recovery_store)?,
        recovery_attempt_fence: u64_from(raw.15)?,
        recovery_variant_id: VariantId::parse(&raw.14).map_err(recovery_store)?,
        recovery_workspace_id: WorkspaceId::parse(&raw.18).map_err(recovery_store)?,
        recovery_workspace_nonce: graph::nonce_from(raw.19).map_err(recovery_ledger)?,
        authority_epoch: u64_from(raw.25)?,
        freeze_generation: u64_from(raw.26)?,
        restore_epoch: u64_from(raw.27)?,
        claim_generation: u64_from(raw.2)?,
        outbox_sequence: u64_from(raw.3)?,
        disposition: disposition_from(&raw.28)?,
        invalidated_from: raw.29.as_deref().map(disposition_from).transpose()?,
        claimed_at: raw.32,
        updated_at: raw.33,
    };
    claim.validate()?;
    Ok(StoredClaim {
        claim,
        receipt_id: raw
            .30
            .as_deref()
            .map(EffectReceiptId::parse)
            .transpose()
            .map_err(recovery_store)?,
        containment_reason: raw.31.as_deref().map(reason_from).transpose()?,
        work_package_id: WorkPackageId::parse(&raw.7).map_err(recovery_store)?,
        graph_revision: u64_from(raw.20)?,
        workspace_generation: u64_from(raw.21)?,
        scope_digest: raw.22,
        policy_generation: u64_from(raw.23)?,
        routing_generation: u64_from(raw.24)?,
    })
}

pub(super) fn require_claim_current(
    conn: &Connection,
    stored: &StoredClaim,
) -> Result<(), EffectRecoveryError> {
    if claim_is_current(conn, stored)? {
        Ok(())
    } else {
        Err(EffectRecoveryError::StaleAuthority(
            "active recovery claim is not current".into(),
        ))
    }
}

pub(super) fn claim_is_current(
    conn: &Connection,
    stored: &StoredClaim,
) -> Result<bool, EffectRecoveryError> {
    let current = match current_authority(conn) {
        Ok(value) => value,
        Err(EffectRecoveryError::StaleAuthority(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    if stored.graph_revision != current.graph_revision
        || stored.workspace_generation != current.workspace_generation
        || stored.scope_digest != current.scope_digest
        || stored.policy_generation != current.policy_generation
        || stored.routing_generation != current.routing_generation
        || stored.claim.authority_epoch != current.authority_epoch
        || stored.claim.freeze_generation != current.freeze_generation
        || stored.claim.restore_epoch != current.restore_epoch
    {
        return Ok(false);
    }
    let Some(attempt) =
        graph::get_attempt(conn, &stored.claim.recovery_attempt_id).map_err(recovery_ledger)?
    else {
        return Ok(false);
    };
    let Some(lease) =
        leases::get_lease(conn, &stored.claim.recovery_variant_id).map_err(recovery_ledger)?
    else {
        return Ok(false);
    };
    let now = lease_time::database_time(conn).map_err(recovery_ledger)?;
    match check_active_lease_snapshot(
        &lease,
        &attempt,
        &ActiveLeaseSubject::from_attempt(&attempt),
        &now,
    ) {
        Ok(()) => {}
        Err(LedgerError::Domain(bullet_domain::DomainError::StaleAuthority(_))) => {
            return Ok(false);
        }
        Err(error) => return Err(recovery_ledger(error)),
    }
    Ok(lease.attempt_id == stored.claim.recovery_attempt_id
        && lease.fence == stored.claim.recovery_attempt_fence
        && lease.runner_id == stored.claim.recovery_runner_id
        && lease.runner_epoch == stored.claim.recovery_runner_epoch
        && lease.workspace_nonce == stored.claim.recovery_workspace_nonce
        && attempt.work_package_id == stored.work_package_id
        && lease_binding(conn, &attempt, &current)?)
}

pub(super) fn require_current_authority(
    conn: &Connection,
    authority: &EffectRecoveryAuthority,
) -> Result<CurrentAuthority, EffectRecoveryError> {
    let current = current_authority(conn)?;
    if current.authority_epoch == authority.authority_epoch
        && current.freeze_generation == authority.freeze_generation
        && current.restore_epoch == authority.restore_epoch
    {
        Ok(current)
    } else {
        Err(EffectRecoveryError::StaleAuthority(
            "recovery authority epochs are not current".into(),
        ))
    }
}

fn current_authority(conn: &Connection) -> Result<CurrentAuthority, EffectRecoveryError> {
    let current = authority::current(conn).map_err(recovery_ledger)?;
    let restore: (i64, i64) = conn
        .query_row(
            "SELECT restore_epoch,pending_admission FROM restore_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(recovery_store)?;
    if restore.1 != 0 {
        return Err(EffectRecoveryError::StaleAuthority(
            "restore is quarantined".into(),
        ));
    }
    Ok(CurrentAuthority {
        graph_revision: current.graph_revision(),
        workspace_generation: current.workspace_generation(),
        scope_digest: current.scope_digest().to_owned(),
        policy_generation: current.policy_generation(),
        routing_generation: current.routing_generation(),
        authority_epoch: current.authority_epoch(),
        freeze_generation: current.freeze_generation(),
        restore_epoch: u64_from(restore.0)?,
    })
}

pub(super) fn require_authority_lease(
    conn: &Connection,
    authority: &EffectRecoveryAuthority,
    current: &CurrentAuthority,
) -> Result<Attempt, EffectRecoveryError> {
    let attempt = graph::get_attempt(conn, &authority.attempt_id)
        .map_err(recovery_ledger)?
        .ok_or_else(|| EffectRecoveryError::StaleAuthority("successor attempt is absent".into()))?;
    if attempt.variant_id != authority.variant_id
        || attempt.fence != authority.attempt_fence
        || attempt.runner_id != authority.runner_id
        || attempt.runner_epoch != authority.runner_epoch
        || attempt.workspace_id != authority.workspace_id
        || attempt.workspace_nonce != authority.workspace_nonce
    {
        return Err(EffectRecoveryError::StaleAuthority(
            "successor attempt differs from recovery authority".into(),
        ));
    }
    let lease = leases::get_lease(conn, &authority.variant_id)
        .map_err(recovery_ledger)?
        .ok_or_else(|| EffectRecoveryError::StaleAuthority("no current active lease".into()))?;
    let now = lease_time::database_time(conn).map_err(recovery_ledger)?;
    check_active_lease_snapshot(
        &lease,
        &attempt,
        &ActiveLeaseSubject::from_attempt(&attempt),
        &now,
    )
    .map_err(recovery_ledger)?;
    if !lease_binding(conn, &attempt, current)? {
        return Err(EffectRecoveryError::StaleAuthority(
            "successor lease lacks exact authority binding".into(),
        ));
    }
    Ok(attempt)
}

fn lease_binding(
    conn: &Connection,
    attempt: &Attempt,
    current: &CurrentAuthority,
) -> Result<bool, EffectRecoveryError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM lease_authority_fingerprints
         WHERE attempt_id=?1 AND variant_id=?2 AND fence=?3 AND authority_epoch=?4
           AND freeze_generation=?5 AND restore_epoch=?6 AND graph_revision=?7
           AND workspace_generation=?8 AND scope_digest=?9 AND policy_generation=?10
           AND routing_generation=?11)",
        params![
            attempt.id.as_str(),
            attempt.variant_id.as_str(),
            to_i64(attempt.fence)?,
            to_i64(current.authority_epoch)?,
            to_i64(current.freeze_generation)?,
            to_i64(current.restore_epoch)?,
            to_i64(current.graph_revision)?,
            to_i64(current.workspace_generation)?,
            current.scope_digest,
            to_i64(current.policy_generation)?,
            to_i64(current.routing_generation)?,
        ],
        |row| row.get(0),
    )
    .map_err(recovery_store)
}
