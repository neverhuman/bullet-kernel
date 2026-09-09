//! SQLite-owned lease time and strict persisted-window validation.

use super::store;
use bullet_application::LedgerError;
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection};

pub(super) fn database_time(conn: &Connection) -> Result<String, LedgerError> {
    let value: String = conn
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(store)?;
    parse_canonical(&value, "database time")?;
    Ok(value)
}

pub(super) fn database_window(
    conn: &Connection,
    ttl_seconds: i64,
) -> Result<(String, String), LedgerError> {
    let window: (String, String) = conn
        .query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?1))",
            params![ttl_seconds],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(store)?;
    validate_window(&window.0, &window.1, ttl_seconds)?;
    Ok(window)
}

pub(super) fn validate_window(
    heartbeat_at: &str,
    expires_at: &str,
    ttl_seconds: i64,
) -> Result<(), LedgerError> {
    let heartbeat = parse_canonical(heartbeat_at, "heartbeat_at")?;
    let expiry = parse_canonical(expires_at, "expires_at")?;
    let expected_millis = ttl_seconds
        .checked_mul(1_000)
        .ok_or_else(|| store("active lease persisted TTL overflows milliseconds"))?;
    if expiry.signed_duration_since(heartbeat).num_milliseconds() != expected_millis {
        return Err(store(
            "active lease persisted time window does not equal its admitted TTL",
        ));
    }
    Ok(())
}

fn parse_canonical(value: &str, field: &str) -> Result<DateTime<Utc>, LedgerError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| store(format!("active lease {field} is not RFC 3339")))?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(SecondsFormat::Millis, true) != value {
        return Err(store(format!(
            "active lease {field} is not canonical fixed-width UTC"
        )));
    }
    Ok(parsed)
}
