use super::{migration_checksum, Migration, MIGRATIONS};
use crate::sqlite::SqliteLedger;
use bullet_application::LedgerError;
use rusqlite::{params, Connection, Error};
use tempfile::TempDir;

fn database() -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("ledger.sqlite3");
    (directory, path)
}

fn sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

fn unsupported(result: Result<SqliteLedger, LedgerError>) -> LedgerError {
    let error = match result {
        Ok(_) => panic!("unsupported database opened"),
        Err(error) => error,
    };
    assert_eq!(error.reason_code(), "UNSUPPORTED_SCHEMA");
    assert!(matches!(error, LedgerError::UnsupportedSchema { .. }));
    let message = error.to_string();
    assert!(message.contains("Export any data you need"));
    assert!(message.contains("removing the database file"));
    error
}

#[test]
fn fresh_creation_records_exact_checksums_and_reopens() {
    let (_directory, path) = database();
    let ledger = SqliteLedger::open(&path).unwrap();
    let enabled: i64 = ledger
        .conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(enabled, 1);
    let rows: Vec<(i64, String, String)> = ledger
        .conn
        .prepare("SELECT version, name, checksum FROM schema_version ORDER BY version")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), MIGRATIONS.len());
    for (row, migration) in rows.iter().zip(MIGRATIONS) {
        assert_eq!(row.0, migration.version);
        assert_eq!(row.1, migration.name);
        assert_eq!(row.2, migration_checksum(migration));
    }
    drop(ledger);

    let reopened = SqliteLedger::open(path).unwrap();
    let enabled: i64 = reopened
        .conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(enabled, 1);
}

#[test]
fn legacy_checksumless_metadata_is_refused_without_touching_truth() {
    let (_directory, path) = database();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_version (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_at TEXT NOT NULL
         );
         INSERT INTO schema_version VALUES (1, '0001_ledger.sql', 'legacy');
         CREATE TABLE operator_truth (body TEXT NOT NULL);
         INSERT INTO operator_truth VALUES ('preserve-me');",
    )
    .unwrap();
    drop(conn);
    let bytes_before = std::fs::read(&path).unwrap();
    assert!(!sidecar(&path, "-wal").exists());
    assert!(!sidecar(&path, "-journal").exists());

    unsupported(SqliteLedger::open(&path));
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
    assert!(!sidecar(&path, "-wal").exists());
    assert!(!sidecar(&path, "-journal").exists());
    let conn = Connection::open(path).unwrap();
    let truth: String = conn
        .query_row("SELECT body FROM operator_truth", [], |row| row.get(0))
        .unwrap();
    assert_eq!(truth, "preserve-me");
}

#[test]
fn legacy_schema_without_metadata_is_refused_without_mutation() {
    let (_directory, path) = database();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE operator_truth (body TEXT NOT NULL);
         INSERT INTO operator_truth VALUES ('preserve-me');",
    )
    .unwrap();
    drop(conn);

    unsupported(SqliteLedger::open(&path));
    let conn = Connection::open(path).unwrap();
    let metadata_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM sqlite_schema WHERE name = 'schema_version'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!metadata_exists);
}

#[test]
fn altered_name_and_checksum_are_refused() {
    for statement in [
        "UPDATE schema_version SET name = 'renamed.sql' WHERE version = 2",
        "UPDATE schema_version SET checksum = '00' WHERE version = 3",
    ] {
        let (_directory, path) = database();
        drop(SqliteLedger::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute(statement, []).unwrap();
        drop(conn);
        unsupported(SqliteLedger::open(path));
    }
}

#[test]
fn partial_future_and_unrecognized_versions_are_refused() {
    for statement in [
        "DELETE FROM schema_version WHERE version = 4",
        "INSERT INTO schema_version VALUES (5, 'future.sql', '00', 'future')",
        "UPDATE schema_version SET version = 99 WHERE version = 4",
    ] {
        let (_directory, path) = database();
        drop(SqliteLedger::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute(statement, []).unwrap();
        drop(conn);
        unsupported(SqliteLedger::open(path));
    }
}

#[test]
fn altered_metadata_schema_is_refused() {
    let (_directory, path) = database();
    drop(SqliteLedger::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute("ALTER TABLE schema_version ADD COLUMN extra TEXT", [])
        .unwrap();
    drop(conn);
    unsupported(SqliteLedger::open(path));
}

#[test]
fn missing_product_table_is_refused_despite_valid_migration_rows() {
    let (_directory, path) = database();
    drop(SqliteLedger::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute("DROP TABLE effect_receipts", []).unwrap();
    drop(conn);
    unsupported(SqliteLedger::open(path));
}

#[test]
fn unclaimed_sqlite_version_metadata_is_refused() {
    for statement in ["PRAGMA user_version = 1", "PRAGMA application_id = 1"] {
        let (_directory, path) = database();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(statement).unwrap();
        drop(conn);
        unsupported(SqliteLedger::open(path));
    }
}

#[test]
fn configured_connection_enforces_the_receipt_foreign_key() {
    let (_directory, path) = database();
    let ledger = SqliteLedger::open(path).unwrap();
    let error = ledger
        .conn
        .execute(
            "INSERT INTO effect_receipts (
               id, effect_intent_id, observed_remote_identity, observed_state_hash,
               verification_method, verification_result, adopted_after_unknown, recorded_at
             ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, 0, ?6)",
            params![
                "receipt_missing_intent",
                "effect_missing",
                "remote",
                "read_back",
                "pass",
                "2026-08-24T00:00:00Z"
            ],
        )
        .unwrap_err();
    assert!(matches!(
        error,
        Error::SqliteFailure(ref code, _) if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY
    ));
    let count: i64 = ledger
        .conn
        .query_row("SELECT COUNT(*) FROM effect_receipts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn preexisting_foreign_key_violation_prevents_reopen() {
    let (_directory, path) = database();
    drop(SqliteLedger::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
    let enabled: i64 = conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(enabled, 0);
    conn.execute(
        "INSERT INTO effect_receipts (
           id, effect_intent_id, observed_remote_identity, observed_state_hash,
           verification_method, verification_result, adopted_after_unknown, recorded_at
         ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, 0, ?6)",
        params![
            "receipt_missing_intent",
            "effect_missing",
            "remote",
            "read_back",
            "pass",
            "2026-08-24T00:00:00Z"
        ],
    )
    .unwrap();
    drop(conn);

    unsupported(SqliteLedger::open(path));
}

#[test]
fn checksum_binds_domain_version_name_and_sql() {
    let migration = MIGRATIONS[0];
    let baseline = migration_checksum(&migration);
    assert_ne!(
        baseline,
        migration_checksum(&Migration {
            version: migration.version + 1,
            ..migration
        })
    );
    assert_ne!(
        baseline,
        migration_checksum(&Migration {
            name: "different.sql",
            ..migration
        })
    );
    assert_ne!(
        baseline,
        migration_checksum(&Migration {
            sql: "SELECT 1;",
            ..migration
        })
    );
}
