//! Durable audit events with correlation columns.

use super::store;
use bullet_application::{LedgerError, LedgerEvent};
use bullet_domain::Digest;
use rusqlite::{params, Connection, Row};

pub(super) fn insert_event(
    conn: &Connection,
    kind: &str,
    body: &str,
    stream_id: Option<&str>,
    correlation_id: Option<&str>,
    authority_token_hash: Option<&str>,
) -> Result<(), LedgerError> {
    conn.execute(
        "INSERT INTO events (kind, body, at, stream_id, correlation_id, authority_token_hash)
         VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4, ?5)",
        params![kind, body, stream_id, correlation_id, authority_token_hash],
    )
    .map_err(store)?;
    let seq = conn.last_insert_rowid();
    let event_id = Digest::of(format!("evt:{seq}:{kind}:{body}").as_bytes()).to_hex();
    conn.execute(
        "UPDATE events SET event_id = ?1, sequence = ?2 WHERE seq = ?3",
        params![event_id, seq, seq],
    )
    .map_err(store)?;
    Ok(())
}

fn read_event(row: &Row<'_>) -> rusqlite::Result<(i64, LedgerEvent)> {
    let seq: i64 = row.get(0)?;
    Ok((
        seq,
        LedgerEvent {
            seq: 0,
            kind: row.get(1)?,
            body: row.get(2)?,
            at: row.get(3)?,
            event_id: row.get(4)?,
            stream_id: row.get(5)?,
            sequence: row.get::<_, Option<i64>>(6)?.map(|v| v.unsigned_abs()),
            causation_id: row.get(7)?,
            correlation_id: row.get(8)?,
            authority_token_hash: row.get(9)?,
        },
    ))
}

const EVENT_COLUMNS: &str = "seq, kind, body, at, event_id, stream_id, sequence, causation_id, \
                             correlation_id, authority_token_hash";

fn collect(
    conn: &Connection,
    sql: &str,
    args: &[&dyn rusqlite::types::ToSql],
) -> Result<Vec<LedgerEvent>, LedgerError> {
    let mut stmt = conn.prepare(sql).map_err(store)?;
    let rows = stmt.query_map(args, read_event).map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, mut event) = row.map_err(store)?;
        event.seq = u64::try_from(seq).map_err(store)?;
        out.push(event);
    }
    Ok(out)
}

pub(super) fn list_events(conn: &Connection) -> Result<Vec<LedgerEvent>, LedgerError> {
    collect(
        conn,
        &format!("SELECT {EVENT_COLUMNS} FROM events ORDER BY seq"),
        &[],
    )
}

pub(super) fn list_events_after(
    conn: &Connection,
    after: u64,
    limit: usize,
) -> Result<Vec<LedgerEvent>, LedgerError> {
    let after = i64::try_from(after).map_err(store)?;
    let limit = i64::try_from(limit).map_err(store)?;
    collect(
        conn,
        &format!("SELECT {EVENT_COLUMNS} FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2"),
        &[&after, &limit],
    )
}

pub(super) fn latest_sequence(conn: &Connection) -> Result<u64, LedgerError> {
    let sequence: i64 = conn
        .query_row("SELECT COALESCE(MAX(seq), 0) FROM events", [], |row| {
            row.get(0)
        })
        .map_err(store)?;
    u64::try_from(sequence).map_err(store)
}
