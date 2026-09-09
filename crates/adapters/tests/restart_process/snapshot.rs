use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

const TABLES: &[&str] = &[
    "effect_intents",
    "effect_receipts",
    "effect_recovery_claims",
    "outbox",
    "events",
    "attempts",
    "active_leases",
];

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ClaimSubject {
    pub(crate) id: String,
    pub(crate) generation: u64,
    pub(crate) authority_digest: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OutboxSubject {
    pub(crate) payload: String,
    pub(crate) phase: String,
    pub(crate) delivered: bool,
    pub(crate) acknowledged: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReceiptSubject {
    pub(crate) id: String,
    pub(crate) effect_intent_id: String,
    pub(crate) remote_identity: String,
    pub(crate) verdict: String,
    pub(crate) observed_oid: Option<String>,
    pub(crate) method: String,
    pub(crate) adopted_after_unknown: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EventSubject {
    pub(crate) kind: String,
    pub(crate) stream_id: Option<String>,
    pub(crate) correlation_id: Option<String>,
    pub(crate) authority_digest: Option<String>,
}

pub(crate) fn durable(path: &Path) -> Result<String, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut output = String::new();
    for table in TABLES {
        output.push_str(table);
        output.push('\n');
        let columns = columns(&connection, table)?;
        let expression = columns
            .iter()
            .map(|column| format!("quote(\"{}\")", column.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" || char(31) || ");
        let sql = format!("SELECT {expression} FROM \"{table}\" ORDER BY rowid");
        let mut statement = connection
            .prepare(&sql)
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        for row in rows {
            output.push_str(&row.map_err(|error| error.to_string())?);
            output.push('\n');
        }
    }
    Ok(output)
}

pub(crate) fn claims(path: &Path) -> Result<Vec<(u64, String, Option<String>)>, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "SELECT claim_generation, disposition, invalidated_from \
             FROM effect_recovery_claims ORDER BY claim_generation",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows)
}

pub(crate) fn claim_subjects(path: &Path) -> Result<Vec<ClaimSubject>, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "SELECT claim_id, claim_generation, successor_authority_digest \
             FROM effect_recovery_claims ORDER BY claim_generation",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(ClaimSubject {
                id: row.get(0)?,
                generation: row.get(1)?,
                authority_digest: row.get(2)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows)
}

pub(crate) fn recovery_outbox(path: &Path) -> Result<Vec<OutboxSubject>, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "SELECT payload, phase, delivered_at IS NOT NULL, acked_at IS NOT NULL \
             FROM outbox WHERE kind='effect_recovery' ORDER BY seq",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(OutboxSubject {
                payload: row.get(0)?,
                phase: row.get(1)?,
                delivered: row.get(2)?,
                acknowledged: row.get(3)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows)
}

pub(crate) fn recovery_receipts(path: &Path) -> Result<Vec<ReceiptSubject>, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "SELECT id, effect_intent_id, observed_remote_identity, verification_result, \
                    observed_state_hash, verification_method, adopted_after_unknown \
             FROM effect_receipts ORDER BY rowid",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(ReceiptSubject {
                id: row.get(0)?,
                effect_intent_id: row.get(1)?,
                remote_identity: row.get(2)?,
                verdict: row.get(3)?,
                observed_oid: row.get(4)?,
                method: row.get(5)?,
                adopted_after_unknown: row.get(6)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows)
}

pub(crate) fn recovery_events(path: &Path) -> Result<Vec<EventSubject>, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "SELECT kind, stream_id, correlation_id, authority_token_hash FROM events \
             WHERE kind IN ('effect_recovery_claimed','effect_recovery_transition', \
                            'effect_recovery_normalized') ORDER BY seq",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(EventSubject {
                kind: row.get(0)?,
                stream_id: row.get(1)?,
                correlation_id: row.get(2)?,
                authority_digest: row.get(3)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows)
}

pub(crate) fn intent(path: &Path) -> Result<(String, u32), String> {
    Connection::open(path)
        .map_err(|error| error.to_string())?
        .query_row(
            "SELECT state, unknown_retries FROM effect_intents LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())
}

pub(crate) fn claim_receipt(path: &Path) -> Result<Option<String>, String> {
    Connection::open(path)
        .map_err(|error| error.to_string())?
        .query_row(
            "SELECT receipt_id FROM effect_recovery_claims ORDER BY claim_generation DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .flatten()
        .ok_or_else(|| "terminal claim receipt absent".to_string())
        .map(Some)
}

pub(crate) fn forge_log(path: &Path) -> Result<Vec<String>, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    Ok(text.lines().map(str::to_owned).collect())
}

pub(crate) fn push_count(path: &Path) -> Result<usize, String> {
    Ok(forge_log(path)?
        .iter()
        .filter(|line| line.as_str() == "PUSH_OK")
        .count())
}

pub(crate) fn push_attempt_count(path: &Path) -> Result<usize, String> {
    Ok(forge_log(path)?
        .iter()
        .filter(|line| line.as_str() == "PUSH_BEGIN")
        .count())
}

fn columns(connection: &Connection, table: &str) -> Result<Vec<String>, String> {
    let sql = format!("PRAGMA table_info(\"{table}\")");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| error.to_string())?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    if columns.is_empty() {
        return Err(format!("snapshot table {table} has no columns"));
    }
    Ok(columns)
}
