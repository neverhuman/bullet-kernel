//! Durable single-use launch-grant nonces (migration 0010). Consumption runs
//! in one immediate transaction against the database clock so two verifiers
//! can never both spend the same nonce.

use super::{lease_time, store};
use bullet_application::launch_grant::{
    classify_stored_nonce, LaunchGrantNonceRecord, NonceConsumption, StoredLaunchGrantNonce,
};
use bullet_application::LedgerError;
use bullet_domain::{AttemptId, DomainError};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const COLUMNS: &str = "grant_nonce, grant_id, attempt_id, attempt_fence, expires_at_unix_ms, \
                       issued_at, consumed_at";

type NonceRow = (String, String, String, i64, i64, String, Option<String>);

pub(super) fn record(
    conn: &Connection,
    record: &LaunchGrantNonceRecord,
) -> Result<(), LedgerError> {
    record.validate()?;
    let result = conn.execute(
        "INSERT INTO launch_grant_nonces
           (grant_nonce, grant_id, attempt_id, attempt_fence, expires_at_unix_ms, issued_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            record.grant_nonce,
            record.grant_id,
            record.attempt_id.to_string(),
            i64::try_from(record.attempt_fence).map_err(store)?,
            i64::try_from(record.expires_at_unix_ms).map_err(store)?,
            record.issued_at,
        ],
    );
    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(DomainError::Conflict(format!(
                "launch grant {} nonce already persisted",
                record.grant_id
            ))
            .into())
        }
        Err(error) => Err(store(error)),
    }
}

pub(super) fn consume(
    conn: &mut Connection,
    nonce: &str,
    attempt_id: &AttemptId,
) -> Result<NonceConsumption, LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let now = lease_time::database_time(&tx)?;
    let now_unix_ms = database_unix_ms(&tx)?;
    let stored = get(&tx, nonce)?;
    let outcome = classify_stored_nonce(stored.as_ref(), attempt_id, now_unix_ms);
    if outcome == NonceConsumption::Consumed {
        let changed = tx
            .execute(
                "UPDATE launch_grant_nonces SET consumed_at = ?1
                 WHERE grant_nonce = ?2 AND attempt_id = ?3 AND consumed_at IS NULL
                   AND expires_at_unix_ms > ?4",
                params![
                    now,
                    nonce,
                    attempt_id.to_string(),
                    i64::try_from(now_unix_ms).map_err(store)?
                ],
            )
            .map_err(store)?;
        if changed != 1 {
            return Err(store("launch grant nonce consumption matched zero rows"));
        }
    }
    tx.commit().map_err(store)?;
    Ok(outcome)
}

pub(super) fn get(
    conn: &Connection,
    nonce: &str,
) -> Result<Option<StoredLaunchGrantNonce>, LedgerError> {
    let row: Option<NonceRow> = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM launch_grant_nonces WHERE grant_nonce = ?1"),
            params![nonce],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(store)?;
    let Some((grant_nonce, grant_id, attempt, fence, expires, issued_at, consumed_at)) = row else {
        return Ok(None);
    };
    let record = LaunchGrantNonceRecord {
        grant_nonce,
        grant_id,
        attempt_id: AttemptId::parse(&attempt)?,
        attempt_fence: u64::try_from(fence).map_err(store)?,
        expires_at_unix_ms: u64::try_from(expires).map_err(store)?,
        issued_at,
    };
    record.validate()?;
    Ok(Some(StoredLaunchGrantNonce {
        record,
        consumed_at,
    }))
}

fn database_unix_ms(conn: &Connection) -> Result<u64, LedgerError> {
    let millis: i64 = conn
        .query_row(
            "SELECT CAST(strftime('%s', 'now') AS INTEGER) * 1000
                    + CAST(substr(strftime('%f', 'now'), 4, 3) AS INTEGER)",
            [],
            |row| row.get(0),
        )
        .map_err(store)?;
    u64::try_from(millis).map_err(store)
}
