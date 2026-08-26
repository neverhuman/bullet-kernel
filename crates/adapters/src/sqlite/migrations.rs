//! Exact, disposable pre-1.0 SQLite schema authority.

use super::store;
use bullet_application::LedgerError;
use bullet_domain::Digest;
use chrono::DateTime;
use rusqlite::types::Value;
use rusqlite::{params, Connection, TransactionBehavior};

mod catalog;
mod identity;

pub(super) use catalog::{
    valid_digest, valid_mutation_contract, validate_mutation_row, Migration, MIGRATIONS,
};

const CHECKSUM_DOMAIN: &[u8] = b"bullet-kernel.sqlite-migration.v1";
const CREATE_METADATA: &str = "CREATE TABLE schema_version (
    version INTEGER NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RestoreState {
    pub(super) epoch: u64,
    pub(super) pending_admission: bool,
}

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
        verify_existing(conn, false).map(|_| ())
    } else if has_user_schema(conn)? {
        Err(unsupported(
            "database contains schema objects but no checksummed schema_version table",
        ))
    } else {
        initialize_fresh(conn)
    }
}

pub(super) fn verify_existing(
    conn: &Connection,
    allow_pending_restore: bool,
) -> Result<RestoreState, LedgerError> {
    verify_unclaimed_pragmas(conn)?;
    if !metadata_table_exists(conn)? {
        return Err(unsupported(
            "database has no checksummed schema_version authority",
        ));
    }
    verify_metadata_schema(conn)?;
    verify_applied_migrations(conn)?;
    verify_product_schema(conn)?;
    verify_foreign_key_integrity(conn)?;
    identity::verify(conn)?;
    super::authority::current(conn)?;
    let state = read_restore_state(conn)?;
    if state.pending_admission && !allow_pending_restore {
        return Err(store(
            "RESTORE_ADMISSION_REQUIRED: this physically restored database is quarantined; \
             no production authority-admission operation exists in V1",
        ));
    }
    Ok(state)
}

pub(super) fn schema_contract_digest() -> String {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"bullet-kernel.sqlite-schema.v1");
    for migration in MIGRATIONS {
        frame(&mut bytes, &migration.version.to_le_bytes());
        frame(&mut bytes, migration.name.as_bytes());
        frame(&mut bytes, migration_checksum(migration).as_bytes());
    }
    Digest::of(&bytes).to_hex()
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

fn read_restore_state(conn: &Connection) -> Result<RestoreState, LedgerError> {
    let mut statement = conn
        .prepare(
            "SELECT singleton, restore_epoch, pending_admission,
                    source_snapshot_digest, restored_at
             FROM restore_state ORDER BY singleton",
        )
        .map_err(store)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
                row.get::<_, Value>(4)?,
            ))
        })
        .map_err(store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store)?;
    let [row] = rows.as_slice() else {
        return Err(unsupported(
            "restore_state must contain exactly its singleton row",
        ));
    };
    if exact_integer(&row.0, "restore_state.singleton")? != 1 {
        return Err(unsupported("restore_state singleton is invalid"));
    }
    let epoch = exact_integer(&row.1, "restore_state.restore_epoch")?;
    let pending = exact_integer(&row.2, "restore_state.pending_admission")?;
    let epoch = u64::try_from(epoch).map_err(|_| unsupported("restore epoch is negative"))?;
    if !matches!(pending, 0 | 1) {
        return Err(unsupported("restore pending flag is invalid"));
    }
    match (&row.3, &row.4, epoch) {
        (Value::Null, Value::Null, 0) if pending == 0 => {}
        (Value::Text(digest), Value::Text(at), value) if value > 0 => {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(unsupported("restore source digest is not lowercase BLAKE3"));
            }
            DateTime::parse_from_rfc3339(at)
                .map_err(|_| unsupported("restore timestamp is not RFC 3339"))?;
        }
        _ => return Err(unsupported("restore_state row is internally inconsistent")),
    }
    Ok(RestoreState {
        epoch,
        pending_admission: pending == 1,
    })
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
    super::authority::seed_genesis(&tx)?;
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

fn exact_integer(value: &Value, field: &str) -> Result<i64, LedgerError> {
    match value {
        Value::Integer(value) => Ok(*value),
        _ => Err(unsupported(format!("{field} has the wrong SQLite type"))),
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
