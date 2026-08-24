//! Idempotent command rows.

use super::store;
use bullet_application::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::{CommandId, CommandPhase, Digest, DomainError};
use rusqlite::{params, Connection, OptionalExtension};

pub(super) fn get_command(
    conn: &Connection,
    key: &str,
) -> Result<Option<CommandRecord>, LedgerError> {
    let row = conn
        .query_row(
            "SELECT id, kind, payload, payload_digest, phase, response_json
             FROM commands WHERE idempotency_key = ?1",
            params![key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(store)?;
    let Some((id, kind, payload, digest, phase, response)) = row else {
        return Ok(None);
    };
    Ok(Some(CommandRecord {
        id: CommandId::parse(&id)?,
        idempotency_key: key.to_string(),
        kind,
        payload,
        payload_digest: Digest::from_hex(&digest)?,
        phase: CommandPhase::parse(&phase)?,
        response,
    }))
}

pub(super) fn insert_command(conn: &Connection, record: &CommandRecord) -> Result<(), LedgerError> {
    conn.execute(
        "INSERT INTO commands
           (idempotency_key, id, kind, payload, payload_digest, phase, response_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.idempotency_key,
            record.id.to_string(),
            record.kind,
            record.payload,
            record.payload_digest.to_hex(),
            record.phase.as_str(),
            record.response,
        ],
    )
    .map_err(store)?;
    Ok(())
}

pub(super) fn record_command(
    conn: &Connection,
    request: &CommandRequest,
) -> Result<CommandRecord, LedgerError> {
    if let Some(existing) = get_command(conn, &request.idempotency_key)? {
        if existing.payload_digest != request.digest() {
            return Err(DomainError::Idempotency(request.idempotency_key.clone()).into());
        }
        return Ok(existing);
    }
    let record = CommandRecord {
        id: CommandId::from_seed(&request.idempotency_key),
        idempotency_key: request.idempotency_key.clone(),
        kind: request.kind.clone(),
        payload: request.payload.clone(),
        payload_digest: request.digest(),
        phase: CommandPhase::Pending,
        response: None,
    };
    insert_command(conn, &record)?;
    Ok(record)
}

pub(super) fn set_phase(
    conn: &Connection,
    key: &str,
    phase: CommandPhase,
    response: Option<&str>,
) -> Result<(), LedgerError> {
    let changed = if let Some(response) = response {
        conn.execute(
            "UPDATE commands SET phase = ?1, response_json = ?2 WHERE idempotency_key = ?3",
            params![phase.as_str(), response, key],
        )
        .map_err(store)?
    } else {
        conn.execute(
            "UPDATE commands SET phase = ?1 WHERE idempotency_key = ?2",
            params![phase.as_str(), key],
        )
        .map_err(store)?
    };
    if changed == 0 {
        return Err(LedgerError::Store(format!("unknown command key {key}")));
    }
    Ok(())
}
