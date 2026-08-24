//! Exact, disposable pre-1.0 SQLite schema authority.

use super::store;
use bullet_application::LedgerError;
use bullet_domain::Digest;
use rusqlite::types::Value;
use rusqlite::{params, Connection, TransactionBehavior};

const CHECKSUM_DOMAIN: &[u8] = b"bullet-kernel.sqlite-migration.v1";
const CREATE_METADATA: &str = "CREATE TABLE schema_version (
    version INTEGER NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);";

#[derive(Clone, Copy)]
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_ledger.sql",
        sql: include_str!("../../../../db/migrations/0001_ledger.sql"),
    },
    Migration {
        version: 2,
        name: "0002_authority.sql",
        sql: include_str!("../../../../db/migrations/0002_authority.sql"),
    },
    Migration {
        version: 3,
        name: "0003_effects.sql",
        sql: include_str!("../../../../db/migrations/0003_effects.sql"),
    },
    Migration {
        version: 4,
        name: "0004_event_time.sql",
        sql: include_str!("../../../../db/migrations/0004_event_time.sql"),
    },
    Migration {
        version: 5,
        name: "0005_lease_ttl.sql",
        sql: include_str!("../../../../db/migrations/0005_lease_ttl.sql"),
    },
    Migration {
        version: 6,
        name: "0006_command_correlation.sql",
        sql: include_str!("../../../../db/migrations/0006_command_correlation.sql"),
    },
];

#[derive(Debug, PartialEq, Eq)]
struct Column {
    position: i64,
    name: String,
    declared_type: String,
    not_null: i64,
    default_value: Option<String>,
    primary_key_position: i64,
    hidden: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct SchemaObject {
    kind: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

const EXPECTED_COLUMNS: &[(&str, &str, i64)] = &[
    ("version", "INTEGER", 1),
    ("name", "TEXT", 0),
    ("checksum", "TEXT", 0),
    ("applied_at", "TEXT", 0),
];

pub(super) fn enable_foreign_keys(conn: &Connection) -> Result<(), LedgerError> {
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(store)?;
    let enabled: i64 = conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(store)?;
    if enabled != 1 {
        return Err(store("SQLite refused PRAGMA foreign_keys=ON"));
    }
    Ok(())
}

pub(super) fn verify_or_initialize(conn: &mut Connection) -> Result<(), LedgerError> {
    verify_unclaimed_pragmas(conn)?;
    if metadata_table_exists(conn)? {
        verify_metadata_schema(conn)?;
        verify_applied_migrations(conn)?;
        verify_product_schema(conn)?;
        verify_foreign_key_integrity(conn)
    } else if has_user_schema(conn)? {
        Err(unsupported(
            "database contains schema objects but no checksummed schema_version table",
        ))
    } else {
        initialize_fresh(conn)
    }
}

fn metadata_table_exists(conn: &Connection) -> Result<bool, LedgerError> {
    conn.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM sqlite_schema
           WHERE type = 'table' AND name = 'schema_version'
         )",
        [],
        |row| row.get(0),
    )
    .map_err(store)
}

fn has_user_schema(conn: &Connection) -> Result<bool, LedgerError> {
    conn.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'
         )",
        [],
        |row| row.get(0),
    )
    .map_err(store)
}

fn verify_unclaimed_pragmas(conn: &Connection) -> Result<(), LedgerError> {
    let user_version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(store)?;
    let application_id: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(store)?;
    if user_version != 0 || application_id != 0 {
        return Err(unsupported(
            "unrecognized SQLite user_version or application_id metadata",
        ));
    }
    Ok(())
}

fn verify_metadata_schema(conn: &Connection) -> Result<(), LedgerError> {
    let mut statement = conn
        .prepare("PRAGMA table_xinfo(schema_version)")
        .map_err(store)?;
    let columns = statement
        .query_map([], |row| {
            Ok(Column {
                position: row.get(0)?,
                name: row.get(1)?,
                declared_type: row.get(2)?,
                not_null: row.get(3)?,
                default_value: row.get(4)?,
                primary_key_position: row.get(5)?,
                hidden: row.get(6)?,
            })
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    if columns.len() != EXPECTED_COLUMNS.len() {
        return Err(unsupported(
            "schema_version columns are incomplete or unrecognized",
        ));
    }
    for (position, (actual, expected)) in columns.iter().zip(EXPECTED_COLUMNS).enumerate() {
        let expected_position = i64::try_from(position).map_err(store)?;
        let (name, declared_type, primary_key_position) = expected;
        if actual.position != expected_position
            || actual.name != *name
            || actual.declared_type != *declared_type
            || actual.not_null != 1
            || actual.default_value.is_some()
            || actual.primary_key_position != *primary_key_position
            || actual.hidden != 0
        {
            return Err(unsupported(
                "schema_version column authority does not match",
            ));
        }
    }
    Ok(())
}

fn verify_applied_migrations(conn: &Connection) -> Result<(), LedgerError> {
    let mut statement = conn
        .prepare(
            "SELECT version, name, checksum, applied_at
             FROM schema_version ORDER BY version",
        )
        .map_err(store)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
            ))
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    if rows.len() != MIGRATIONS.len() {
        return Err(unsupported(
            "schema_version is partial or contains a future migration",
        ));
    }
    for (row, migration) in rows.iter().zip(MIGRATIONS) {
        let version = integer(&row.0, "version")?;
        let name = text(&row.1, "name")?;
        let checksum = text(&row.2, "checksum")?;
        let applied_at = text(&row.3, "applied_at")?;
        if version != migration.version
            || name != migration.name
            || checksum != migration_checksum(migration)
        {
            return Err(unsupported(
                "stored migration version, name, or checksum is unrecognized",
            ));
        }
        if applied_at.is_empty() {
            return Err(unsupported("stored migration applied_at is empty"));
        }
    }
    Ok(())
}

fn verify_product_schema(conn: &Connection) -> Result<(), LedgerError> {
    let expected_connection = Connection::open_in_memory().map_err(store)?;
    let mut expected_connection = expected_connection;
    initialize_fresh(&mut expected_connection)?;
    if schema_objects(conn)? != schema_objects(&expected_connection)? {
        return Err(unsupported(
            "product sqlite_schema does not match the applied migration authority",
        ));
    }
    Ok(())
}

fn verify_foreign_key_integrity(conn: &Connection) -> Result<(), LedgerError> {
    let mut statement = conn.prepare("PRAGMA foreign_key_check").map_err(store)?;
    let mut rows = statement.query([]).map_err(store)?;
    if rows.next().map_err(store)?.is_some() {
        return Err(unsupported(
            "persisted rows violate a declared foreign-key constraint",
        ));
    }
    Ok(())
}

fn schema_objects(conn: &Connection) -> Result<Vec<SchemaObject>, LedgerError> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_schema
             WHERE name NOT GLOB 'sqlite_*'
             ORDER BY type, name, tbl_name",
        )
        .map_err(store)?;
    let objects = statement
        .query_map([], |row| {
            Ok(SchemaObject {
                kind: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    Ok(objects)
}

fn initialize_fresh(conn: &mut Connection) -> Result<(), LedgerError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store)?;
    tx.execute_batch(CREATE_METADATA).map_err(store)?;
    for migration in MIGRATIONS {
        tx.execute_batch(migration.sql).map_err(store)?;
        tx.execute(
            "INSERT INTO schema_version (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                migration.version,
                migration.name,
                migration_checksum(migration)
            ],
        )
        .map_err(store)?;
    }
    tx.commit().map_err(store)
}

fn migration_checksum(migration: &Migration) -> String {
    let mut bytes = Vec::new();
    frame(&mut bytes, CHECKSUM_DOMAIN);
    frame(&mut bytes, &migration.version.to_le_bytes());
    frame(&mut bytes, migration.name.as_bytes());
    frame(&mut bytes, migration.sql.as_bytes());
    Digest::of(&bytes).to_hex()
}

fn frame(target: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("embedded migration length fits in u64");
    target.extend_from_slice(&length.to_le_bytes());
    target.extend_from_slice(bytes);
}

fn integer(value: &Value, field: &str) -> Result<i64, LedgerError> {
    match value {
        Value::Integer(value) => Ok(*value),
        _ => Err(unsupported(format!(
            "schema_version {field} has the wrong SQLite type"
        ))),
    }
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, LedgerError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(unsupported(format!(
            "schema_version {field} has the wrong SQLite type"
        ))),
    }
}

fn unsupported(detail: impl Into<String>) -> LedgerError {
    LedgerError::UnsupportedSchema {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests;
