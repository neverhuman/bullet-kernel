//! Read-only spec section 25 projection reads. Every query is a plain
//! `SELECT` with a deterministic `ORDER BY`; callers wrap them in
//! [`SqliteLedger::read_snapshot`] so rows and watermark share one view.

use super::{context, effects, from_json, graph, lease_time, leases, store, SqliteLedger};
use bullet_application::store::ProjectionReader;
use bullet_application::ContextCapsule;
use bullet_application::{ActiveLease, EffectIntentRecord, EffectReceiptRecord, LedgerError};
use bullet_domain::{Attempt, Candidate, Effect, Evidence};
use rusqlite::{Connection, Row};
use serde::de::DeserializeOwned;

fn json_rows<T: DeserializeOwned>(conn: &Connection, table: &str) -> Result<Vec<T>, LedgerError> {
    let mut stmt = conn
        .prepare(&format!("SELECT body FROM {table} ORDER BY id"))
        .map_err(store)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(from_json(&row.map_err(store)?)?);
    }
    Ok(out)
}

fn typed_rows<R, T, F, C>(
    conn: &Connection,
    sql: &str,
    read_row: F,
    convert: C,
) -> Result<Vec<T>, LedgerError>
where
    F: FnMut(&Row<'_>) -> rusqlite::Result<R>,
    C: Fn(R) -> Result<T, LedgerError>,
{
    let mut stmt = conn.prepare(sql).map_err(store)?;
    let rows = stmt.query_map([], read_row).map_err(store)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(convert(row.map_err(store)?)?);
    }
    Ok(out)
}

impl ProjectionReader for SqliteLedger {
    fn list_context_capsules(&self) -> Result<Vec<ContextCapsule>, LedgerError> {
        context::list_all(&self.conn)
    }

    fn authority_time(&self) -> Result<String, LedgerError> {
        lease_time::database_time(&self.conn)
    }

    fn list_leases(&self) -> Result<Vec<ActiveLease>, LedgerError> {
        typed_rows(
            &self.conn,
            &format!(
                "SELECT {} FROM active_leases ORDER BY variant_id",
                leases::LEASE_COLUMNS
            ),
            leases::read_lease,
            leases::lease_from,
        )
    }

    fn list_all_attempts(&self) -> Result<Vec<Attempt>, LedgerError> {
        typed_rows(
            &self.conn,
            &format!(
                "SELECT {} FROM attempts ORDER BY variant_id, fence",
                graph::ATTEMPT_COLUMNS
            ),
            graph::attempt_row,
            graph::read_attempt,
        )
    }

    fn list_candidates(&self) -> Result<Vec<Candidate>, LedgerError> {
        json_rows(&self.conn, "candidates")
    }

    fn list_evidence(&self) -> Result<Vec<Evidence>, LedgerError> {
        json_rows(&self.conn, "evidence")
    }

    fn list_effects(&self) -> Result<Vec<Effect>, LedgerError> {
        json_rows(&self.conn, "effects")
    }

    fn list_effect_intents(&self) -> Result<Vec<EffectIntentRecord>, LedgerError> {
        typed_rows(
            &self.conn,
            &format!(
                "SELECT {} FROM effect_intents ORDER BY created_at, id",
                effects::INTENT_COLUMNS
            ),
            effects::intent_row,
            effects::read_intent,
        )
    }

    fn list_effect_receipts(&self) -> Result<Vec<EffectReceiptRecord>, LedgerError> {
        typed_rows(
            &self.conn,
            &format!(
                "SELECT {} FROM effect_receipts ORDER BY recorded_at, id",
                effects::RECEIPT_COLUMNS
            ),
            effects::receipt_row,
            effects::read_receipt,
        )
    }
}
