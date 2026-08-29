//! Persisted claim decoding and private dispatch-store helpers.

use super::super::{authority, commands, outbox};
use super::RECONCILED_EVENT;
use bullet_application::{
    CommandDispatchClaim, CommandDispatchDisposition, CommandDispatchError, CommandRecord,
    CommandRequest, COMMAND_DISPATCH_CLAIM_SCHEMA,
};
use bullet_domain::{CommandId, CommandPhase, Digest, RunnerId};
use rusqlite::{params, Connection, OptionalExtension};

type RawClaim = (
    String,
    String,
    i64,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    String,
    Option<String>,
    String,
    String,
);

pub(super) fn oldest_pending(
    conn: &Connection,
) -> Result<Option<(u64, CommandId, String)>, CommandDispatchError> {
    let raw: Option<(i64, String, String)> = conn
        .query_row(
            "SELECT seq, command_id, payload FROM outbox
             WHERE kind = 'command_dispatch' AND phase = 'pending'
             ORDER BY seq LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(dispatch_store)?;
    raw.map(|(sequence, command, payload)| {
        Ok((
            u64::try_from(sequence).map_err(dispatch_store)?,
            CommandId::parse(command).map_err(dispatch_store)?,
            payload,
        ))
    })
    .transpose()
}

pub(super) fn exact_request(
    conn: &Connection,
    record: &CommandRecord,
    sequence: u64,
    payload: &str,
) -> Result<CommandRequest, CommandDispatchError> {
    let request = CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)
        .map_err(dispatch_store)?;
    request.matches(record).map_err(dispatch_store)?;
    let encoded = serde_json::to_string(&request).map_err(dispatch_store)?;
    let rows = outbox::for_command(conn, &record.id).map_err(dispatch_ledger)?;
    if rows.len() != 1
        || rows[0].seq != sequence
        || rows[0].payload != encoded
        || payload != encoded
    {
        return Err(dispatch_store("command has conflicting dispatch truth"));
    }
    let events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE kind = 'command_submitted' AND body = ?1 AND correlation_id = ?1",
            [record.id.as_str()],
            |row| row.get(0),
        )
        .map_err(dispatch_store)?;
    require_one(
        events as usize,
        "command submitted audit truth is incomplete",
    )?;
    Ok(request)
}

pub(super) fn exact_settled_truth(
    conn: &Connection,
    claim: &CommandDispatchClaim,
    response: &str,
) -> Result<CommandRecord, CommandDispatchError> {
    let record = commands::get_command_by_id(conn, &claim.command_id)
        .map_err(dispatch_ledger)?
        .ok_or_else(|| dispatch_store("settled command is absent"))?;
    let rows = outbox::for_command(conn, &claim.command_id).map_err(dispatch_ledger)?;
    let events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE kind = ?1 AND correlation_id = ?2 AND body = ?3",
            params![RECONCILED_EVENT, claim.command_id.as_str(), response],
            |row| row.get(0),
        )
        .map_err(dispatch_store)?;
    if record.phase != CommandPhase::Unknown
        || record.response.as_deref() != Some(response)
        || rows.len() != 1
        || rows[0].phase != CommandPhase::Unknown
        || rows[0].delivered_at.is_none()
        || rows[0].acked_at.is_none()
        || events != 1
    {
        return Err(dispatch_store("component settlement truth conflicts"));
    }
    Ok(record)
}

pub(super) fn claim_for_runner(
    conn: &Connection,
    runner_id: &RunnerId,
    runner_epoch: u64,
) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
    query_claim(
        conn,
        "SELECT claim_id, command_id, outbox_sequence, request_digest, runner_id,
                runner_epoch, authority_epoch, freeze_generation, restore_epoch,
                disposition, completion_digest, claimed_at, updated_at
         FROM command_dispatch_claims
         WHERE runner_id = ?1 AND runner_epoch = ?2 AND disposition = 'CLAIMED'",
        params![runner_id.as_str(), to_i64(runner_epoch)?],
    )
}

pub(super) fn claim_for_command(
    conn: &Connection,
    command_id: &CommandId,
) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
    query_claim(
        conn,
        "SELECT claim_id, command_id, outbox_sequence, request_digest, runner_id,
                runner_epoch, authority_epoch, freeze_generation, restore_epoch,
                disposition, completion_digest, claimed_at, updated_at
         FROM command_dispatch_claims WHERE command_id = ?1",
        [command_id.as_str()],
    )
}

pub(super) fn claim_by_id(
    conn: &Connection,
    claim_id: &str,
) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
    query_claim(
        conn,
        "SELECT claim_id, command_id, outbox_sequence, request_digest, runner_id,
                runner_epoch, authority_epoch, freeze_generation, restore_epoch,
                disposition, completion_digest, claimed_at, updated_at
         FROM command_dispatch_claims WHERE claim_id = ?1",
        [claim_id],
    )
}

fn query_claim<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    parameters: P,
) -> Result<Option<CommandDispatchClaim>, CommandDispatchError> {
    let raw: Option<RawClaim> = conn
        .query_row(sql, parameters, |row| {
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
            ))
        })
        .optional()
        .map_err(dispatch_store)?;
    raw.map(|value| decode_claim(conn, value)).transpose()
}

fn decode_claim(
    conn: &Connection,
    raw: RawClaim,
) -> Result<CommandDispatchClaim, CommandDispatchError> {
    let command_id = CommandId::parse(&raw.1).map_err(dispatch_store)?;
    let record = commands::get_command_by_id(conn, &command_id)
        .map_err(dispatch_ledger)?
        .ok_or_else(|| dispatch_store("claim command is absent"))?;
    let request = CommandRequest::from_json(&record.idempotency_key, &record.kind, &record.payload)
        .map_err(dispatch_store)?;
    let claim = CommandDispatchClaim {
        schema_version: COMMAND_DISPATCH_CLAIM_SCHEMA.into(),
        claim_id: raw.0,
        command_id,
        outbox_sequence: u64::try_from(raw.2).map_err(dispatch_store)?,
        request,
        request_digest: Digest::from_hex(&raw.3).map_err(dispatch_store)?,
        runner_id: RunnerId::parse(raw.4).map_err(dispatch_store)?,
        runner_epoch: u64::try_from(raw.5).map_err(dispatch_store)?,
        authority_epoch: u64::try_from(raw.6).map_err(dispatch_store)?,
        freeze_generation: u64::try_from(raw.7).map_err(dispatch_store)?,
        restore_epoch: u64::try_from(raw.8).map_err(dispatch_store)?,
        disposition: CommandDispatchDisposition::parse(&raw.9)?,
        completion_digest: raw
            .10
            .map(|value| Digest::from_hex(&value))
            .transpose()
            .map_err(dispatch_store)?,
        claimed_at: raw.11,
        updated_at: raw.12,
    };
    claim.validate()?;
    Ok(claim)
}

pub(super) fn fingerprint(conn: &Connection) -> Result<(u64, u64, u64), CommandDispatchError> {
    let authority = authority::current(conn).map_err(dispatch_ledger)?;
    let restore: (i64, i64) = conn
        .query_row(
            "SELECT restore_epoch, pending_admission FROM restore_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(dispatch_store)?;
    if restore.1 != 0 {
        return Err(CommandDispatchError::StaleAuthority(
            "restore is quarantined".into(),
        ));
    }
    Ok((
        authority.authority_epoch(),
        authority.freeze_generation(),
        u64::try_from(restore.0).map_err(dispatch_store)?,
    ))
}

pub(super) fn require_current(
    conn: &Connection,
    claim: &CommandDispatchClaim,
) -> Result<(), CommandDispatchError> {
    let current = fingerprint(conn)?;
    if current
        != (
            claim.authority_epoch,
            claim.freeze_generation,
            claim.restore_epoch,
        )
    {
        return Err(CommandDispatchError::StaleAuthority(
            "authority fingerprint moved".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn derive_claim_id(
    command_id: &CommandId,
    sequence: u64,
    request_digest: Digest,
    runner_id: &RunnerId,
    runner_epoch: u64,
    authority_epoch: u64,
    freeze_generation: u64,
    restore_epoch: u64,
) -> String {
    let subject = format!(
        "bullet.command-dispatch-claim.v1\0{}\0{sequence}\0{}\0{}\0{runner_epoch}\0{authority_epoch}\0{freeze_generation}\0{restore_epoch}",
        command_id.as_str(), request_digest.to_hex(), runner_id.as_str()
    );
    format!("dcl_{}", Digest::of(subject.as_bytes()).to_hex())
}

pub(super) fn validate_epoch(value: u64) -> Result<(), CommandDispatchError> {
    if value == 0 || value > 9_007_199_254_740_991 {
        return Err(CommandDispatchError::InvalidClaim(
            "runner epoch is not a positive safe integer".into(),
        ));
    }
    Ok(())
}

pub(super) fn to_i64(value: u64) -> Result<i64, CommandDispatchError> {
    i64::try_from(value).map_err(dispatch_store)
}

pub(super) fn require_one(changed: usize, detail: &str) -> Result<(), CommandDispatchError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(dispatch_store(detail))
    }
}

pub(super) fn fail_boundary(
    fail_after: &mut Option<u8>,
    label: &str,
) -> Result<(), CommandDispatchError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(dispatch_store(format!(
                "injected command dispatch {label} boundary"
            )))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}

pub(super) fn dispatch_ledger(error: bullet_application::LedgerError) -> CommandDispatchError {
    dispatch_store(error)
}

pub(super) fn dispatch_store(error: impl ToString) -> CommandDispatchError {
    CommandDispatchError::Store(error.to_string())
}
