//! Durable outbox rows with real delivery phases.

use super::store;
use bullet_application::{LedgerError, OutboxItem};
use bullet_domain::{CommandId, CommandPhase};
use rusqlite::{params, Connection, Row};

pub(super) fn enqueue(
    conn: &Connection,
    command_id: Option<&CommandId>,
    kind: &str,
    payload: &str,
) -> Result<u64, LedgerError> {
    conn.execute(
        "INSERT INTO outbox (command_id, kind, payload, phase) VALUES (?1, ?2, ?3, 'pending')",
        params![command_id.map(CommandId::as_str), kind, payload],
    )
    .map_err(store)?;
    u64::try_from(conn.last_insert_rowid()).map_err(store)
}

type OutboxRow = (
    i64,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

fn read_item(row: &Row<'_>) -> rusqlite::Result<OutboxRow> {
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

fn decode(row: OutboxRow) -> Result<OutboxItem, LedgerError> {
    let (seq, command_id, kind, payload, phase, delivered_at, acked_at) = row;
    let command_id = command_id
        .map(|value| CommandId::parse(&value))
        .transpose()
        .map_err(|error| store(format!("invalid persisted outbox command: {error}")))?;
    let phase = CommandPhase::parse(&phase)
        .map_err(|error| store(format!("invalid persisted outbox phase: {error}")))?;
    Ok(OutboxItem {
        seq: u64::try_from(seq).map_err(store)?,
        command_id,
        kind,
        payload,
        phase,
        delivered_at,
        acked_at,
    })
}

fn collect(conn: &Connection, sql: &str) -> Result<Vec<OutboxItem>, LedgerError> {
    let mut stmt = conn.prepare(sql).map_err(store)?;
    let rows = stmt.query_map([], read_item).map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(decode(row.map_err(store)?)?);
    }
    Ok(out)
}

pub(super) fn pending(conn: &Connection) -> Result<Vec<OutboxItem>, LedgerError> {
    collect(
        conn,
        "SELECT seq, command_id, kind, payload, phase, delivered_at, acked_at
         FROM outbox WHERE phase IN ('pending', 'applied') ORDER BY seq",
    )
}

pub(super) fn all(conn: &Connection) -> Result<Vec<OutboxItem>, LedgerError> {
    collect(
        conn,
        "SELECT seq, command_id, kind, payload, phase, delivered_at, acked_at
         FROM outbox ORDER BY seq",
    )
}

pub(super) fn for_command(
    conn: &Connection,
    command_id: &CommandId,
) -> Result<Vec<OutboxItem>, LedgerError> {
    let mut stmt = conn
        .prepare(
            "SELECT seq, command_id, kind, payload, phase, delivered_at, acked_at
             FROM outbox WHERE command_id = ?1 ORDER BY seq",
        )
        .map_err(store)?;
    let rows = stmt
        .query_map(params![command_id.as_str()], read_item)
        .map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(decode(row.map_err(store)?)?);
    }
    Ok(out)
}

pub(super) fn mark(
    conn: &Connection,
    seq: u64,
    phase: CommandPhase,
    now: &str,
) -> Result<(), LedgerError> {
    let seq = i64::try_from(seq).map_err(store)?;
    let changed = match phase {
        CommandPhase::Applied => conn
            .execute(
                "UPDATE outbox SET phase = ?1, delivered_at = ?2 WHERE seq = ?3",
                params![phase.as_str(), now, seq],
            )
            .map_err(store)?,
        CommandPhase::Verified | CommandPhase::Failed | CommandPhase::Unknown => conn
            .execute(
                "UPDATE outbox SET phase = ?1, acked_at = ?2 WHERE seq = ?3",
                params![phase.as_str(), now, seq],
            )
            .map_err(store)?,
        CommandPhase::Pending => conn
            .execute(
                "UPDATE outbox SET phase = ?1 WHERE seq = ?2",
                params![phase.as_str(), seq],
            )
            .map_err(store)?,
    };
    if changed == 0 {
        return Err(LedgerError::Store(format!("unknown outbox seq {seq}")));
    }
    Ok(())
}
