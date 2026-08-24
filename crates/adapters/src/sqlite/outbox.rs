//! Durable outbox rows with real delivery phases.

use super::store;
use bullet_application::{LedgerError, OutboxItem};
use bullet_domain::CommandPhase;
use rusqlite::{params, Connection, Row};

pub(super) fn enqueue(conn: &Connection, kind: &str, payload: &str) -> Result<u64, LedgerError> {
    conn.execute(
        "INSERT INTO outbox (kind, payload, phase) VALUES (?1, ?2, 'pending')",
        params![kind, payload],
    )
    .map_err(store)?;
    u64::try_from(conn.last_insert_rowid()).map_err(store)
}

type OutboxRow = (i64, String, String, String, Option<String>, Option<String>);

fn read_item(row: &Row<'_>) -> rusqlite::Result<OutboxRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn collect(conn: &Connection, sql: &str) -> Result<Vec<OutboxItem>, LedgerError> {
    let mut stmt = conn.prepare(sql).map_err(store)?;
    let rows = stmt.query_map([], read_item).map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, kind, payload, phase, delivered_at, acked_at) = row.map_err(store)?;
        out.push(OutboxItem {
            seq: u64::try_from(seq).map_err(store)?,
            kind,
            payload,
            phase: CommandPhase::parse(&phase)?,
            delivered_at,
            acked_at,
        });
    }
    Ok(out)
}

pub(super) fn pending(conn: &Connection) -> Result<Vec<OutboxItem>, LedgerError> {
    collect(
        conn,
        "SELECT seq, kind, payload, phase, delivered_at, acked_at
         FROM outbox WHERE phase IN ('pending', 'applied') ORDER BY seq",
    )
}

pub(super) fn all(conn: &Connection) -> Result<Vec<OutboxItem>, LedgerError> {
    collect(
        conn,
        "SELECT seq, kind, payload, phase, delivered_at, acked_at FROM outbox ORDER BY seq",
    )
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
        CommandPhase::Verified | CommandPhase::Unknown => conn
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
