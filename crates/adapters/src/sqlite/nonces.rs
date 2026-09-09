//! Durable generic nonce issue/consume (migration 0013).

use super::lease_time;
use bullet_application::{IssuedNonce, NonceError, NonceState};
use chrono::DateTime;
use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

struct StoredRow {
    digest: String,
    state: NonceState,
}

pub(super) fn issue(
    conn: &mut Connection,
    key: &str,
    digest: &str,
) -> Result<IssuedNonce, NonceError> {
    let requested = IssuedNonce::validated(key, digest)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    if let Some(existing) = get(&tx, key)? {
        if existing.state == NonceState::Consumed {
            return Err(NonceError::Consumed(key.into()));
        }
        if existing.digest == digest {
            return Err(NonceError::AlreadyIssued(key.into()));
        }
        return Err(NonceError::SubjectMismatch(key.into()));
    }
    let issued_at = database_time(&tx)?;
    tx.execute(
        "INSERT INTO authority_nonces
         (nonce_key, request_digest, issued_at, consumed_at)
         VALUES (?1, ?2, ?3, NULL)",
        params![key, digest, issued_at],
    )
    .map_err(store)?;
    tx.commit().map_err(store)?;
    Ok(requested)
}

pub(super) fn consume(conn: &mut Connection, key: &str, digest: &str) -> Result<(), NonceError> {
    let requested = IssuedNonce::validated(key, digest)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    let existing = get(&tx, key)?.ok_or_else(|| NonceError::NotFound(key.into()))?;
    if existing.state == NonceState::Consumed {
        return Err(NonceError::Consumed(key.into()));
    }
    if existing.digest != requested.digest {
        return Err(NonceError::SubjectMismatch(key.into()));
    }
    let consumed_at = database_time(&tx)?;
    let changed = tx
        .execute(
            "UPDATE authority_nonces SET consumed_at = ?2
             WHERE nonce_key = ?1 AND consumed_at IS NULL",
            params![key, consumed_at],
        )
        .map_err(store)?;
    if changed != 1 {
        return Err(NonceError::Corrupt(format!(
            "conditional consume for {key} matched {changed} rows"
        )));
    }
    tx.commit().map_err(store)
}

pub(super) fn state(conn: &Connection, key: &str) -> Result<Option<NonceState>, NonceError> {
    IssuedNonce::validate_key(key)?;
    Ok(get(conn, key)?.map(|row| row.state))
}

fn get(conn: &Connection, key: &str) -> Result<Option<StoredRow>, NonceError> {
    let row: Option<(Value, Value, Value, Value)> = conn
        .query_row(
            "SELECT nonce_key, request_digest, issued_at, consumed_at
             FROM authority_nonces WHERE nonce_key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(store)?;
    row.map(|row| decode_row(key, row)).transpose()
}

fn decode_row(
    requested_key: &str,
    (key, digest, issued_at, consumed_at): (Value, Value, Value, Value),
) -> Result<StoredRow, NonceError> {
    let Value::Text(key) = key else {
        return Err(corrupt(
            requested_key,
            "nonce_key has the wrong SQLite type",
        ));
    };
    let Value::Text(digest) = digest else {
        return Err(corrupt(
            requested_key,
            "request_digest has the wrong SQLite type",
        ));
    };
    let Value::Text(issued_at) = issued_at else {
        return Err(corrupt(
            requested_key,
            "issued_at has the wrong SQLite type",
        ));
    };
    if key != requested_key || IssuedNonce::validated(&key, &digest).is_err() {
        return Err(corrupt(requested_key, "identity or digest is malformed"));
    }
    let issued_at = parse_time(requested_key, "issued_at", &issued_at)?;
    let state = match consumed_at {
        Value::Null => NonceState::Issued,
        Value::Text(value) => {
            let consumed_at = parse_time(requested_key, "consumed_at", &value)?;
            if consumed_at < issued_at {
                return Err(corrupt(
                    requested_key,
                    "consumed_at is earlier than issued_at",
                ));
            }
            NonceState::Consumed
        }
        _ => {
            return Err(corrupt(
                requested_key,
                "consumed_at has the wrong SQLite type",
            ));
        }
    };
    Ok(StoredRow { digest, state })
}

fn parse_time(
    key: &str,
    field: &str,
    value: &str,
) -> Result<DateTime<chrono::FixedOffset>, NonceError> {
    DateTime::parse_from_rfc3339(value)
        .map_err(|_| corrupt(key, &format!("{field} is not RFC 3339")))
}

fn database_time(conn: &Connection) -> Result<String, NonceError> {
    lease_time::database_time(conn).map_err(|error| store(error.to_string()))
}

fn corrupt(key: &str, reason: &str) -> NonceError {
    NonceError::Corrupt(format!("{key}: {reason}"))
}

fn store(error: impl ToString) -> NonceError {
    NonceError::StoreFailure(error.to_string())
}
