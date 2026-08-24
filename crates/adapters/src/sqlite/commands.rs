//! Idempotent command rows.

use super::store;
use bullet_application::{CommandRecord, CommandRequest, LedgerError};
use bullet_domain::{CommandId, CommandPhase, Digest, DomainError};
use rusqlite::{params, Connection, OptionalExtension};

type CommandRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CommandRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn decode(row: CommandRow) -> Result<CommandRecord, LedgerError> {
    let (key, id, kind, payload, digest, phase, response) = row;
    let record = (|| -> Result<CommandRecord, DomainError> {
        Ok(CommandRecord {
            id: CommandId::parse(&id)?,
            idempotency_key: key,
            kind,
            payload,
            payload_digest: Digest::from_hex(&digest)?,
            phase: CommandPhase::parse(&phase)?,
            response,
        })
    })()
    .map_err(|error| store(format!("invalid persisted command: {error}")))?;
    record
        .validate()
        .map_err(|error| store(format!("invalid persisted command: {error}")))?;
    Ok(record)
}

pub(super) fn get_command(
    conn: &Connection,
    key: &str,
) -> Result<Option<CommandRecord>, LedgerError> {
    let row = conn
        .query_row(
            "SELECT idempotency_key, id, kind, payload, payload_digest, phase, response_json
             FROM commands WHERE idempotency_key = ?1",
            params![key],
            read_row,
        )
        .optional()
        .map_err(store)?;
    row.map(decode).transpose()
}

pub(super) fn get_command_by_id(
    conn: &Connection,
    id: &CommandId,
) -> Result<Option<CommandRecord>, LedgerError> {
    let row = conn
        .query_row(
            "SELECT idempotency_key, id, kind, payload, payload_digest, phase, response_json
             FROM commands WHERE id = ?1",
            params![id.to_string()],
            read_row,
        )
        .optional()
        .map_err(store)?;
    row.map(decode).transpose()
}

pub(super) fn insert_command(conn: &Connection, record: &CommandRecord) -> Result<(), LedgerError> {
    record.validate()?;
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
    request.validate()?;
    if let Some(existing) = get_command(conn, &request.idempotency_key)? {
        request.matches(&existing)?;
        return Ok(existing);
    }
    let record = CommandRecord {
        id: request.id(),
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
    let mut record = get_command(conn, key)?
        .ok_or_else(|| LedgerError::Store(format!("unknown command key {key}")))?;
    record.phase = phase;
    if let Some(response) = response {
        record.response = Some(response.to_string());
    }
    record.validate()?;
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
