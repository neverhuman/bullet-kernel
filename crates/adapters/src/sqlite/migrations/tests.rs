use super::{migration_checksum, Migration, CREATE_METADATA, MIGRATIONS};
use crate::sqlite::SqliteLedger;
use bullet_application::{Ledger, LedgerError, NormalizedAuthority};
use bullet_domain::{EffectId, EffectReceiptId};
use rusqlite::{params, Connection, Error};
use tempfile::TempDir;

fn database() -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("ledger.sqlite3");
    (directory, path)
}

#[test]
fn lease_migration_matches_the_frozen_phase_one_maximum() {
    let expected = format!(
        "CHECK (ttl_seconds BETWEEN 1 AND {})",
        bullet_application::records::MAX_LEASE_TTL_SECONDS
    );
    assert!(MIGRATIONS[4].sql.contains(&expected));
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

fn assert_connection_pragmas(ledger: &SqliteLedger) {
    let foreign_keys: i64 = ledger
        .conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    let journal_mode: String = ledger
        .conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    let synchronous: i64 = ledger
        .conn
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    let busy_timeout: i64 = ledger
        .conn
        .pragma_query_value(None, "busy_timeout", |row| row.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1);
    assert_eq!(journal_mode, "wal");
    assert_eq!(synchronous, 2);
    assert_eq!(busy_timeout, 5_000);
}

#[test]
fn fresh_creation_records_exact_checksums_and_reopens() {
    let (directory, path) = database();
    let ledger = SqliteLedger::open(&path).unwrap();
    assert_connection_pragmas(&ledger);
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

    assert_eq!(
        ledger.current_authority().unwrap(),
        NormalizedAuthority::genesis()
    );

    assert!(ledger
        .conn
        .execute(
            "INSERT INTO budget_reservations (reservation_id, amount) VALUES ('zero', 0)",
            [],
        )
        .is_err());
    assert!(ledger
        .conn
        .execute_batch(
            "INSERT INTO budget_reservations (reservation_id, amount)
             VALUES ('too-large', 9223372036854775808);",
        )
        .is_err());
    ledger
        .conn
        .execute(
            "INSERT INTO budget_reservations (reservation_id, amount) VALUES ('valid', 1)",
            [],
        )
        .expect("valid budget reservation");

    let uppercase = "A".repeat(64);
    assert!(ledger
        .conn
        .execute(
            "INSERT INTO authority_revisions (
               singleton, graph_revision, workspace_generation, scope_digest,
               policy_generation, routing_generation, authority_epoch, freeze_generation
             ) VALUES (1, 1, 1, ?1, 1, 1, 1, 0)",
            [&uppercase],
        )
        .is_err());
    let nul_suffix = format!("{}\0x", "a".repeat(64));
    assert!(ledger
        .conn
        .execute(
            "INSERT INTO authority_revisions (
               singleton, graph_revision, workspace_generation, scope_digest,
               policy_generation, routing_generation, authority_epoch, freeze_generation
             ) VALUES (1, 1, 1, ?1, 1, 1, 1, 0)",
            [&nul_suffix],
        )
        .is_err());
    let embedded_nul = format!("{}\0{}", "a".repeat(32), "a".repeat(31));
    assert_eq!(embedded_nul.len(), 64);
    assert!(ledger
        .conn
        .execute(
            "INSERT INTO authority_revisions (
               singleton, graph_revision, workspace_generation, scope_digest,
               policy_generation, routing_generation, authority_epoch, freeze_generation
             ) VALUES (1, 1, 1, ?1, 1, 1, 1, 0)",
            [&embedded_nul],
        )
        .is_err());
    assert!(ledger
        .conn
        .execute_batch(
            "INSERT INTO authority_revisions (
               singleton, graph_revision, workspace_generation, scope_digest,
               policy_generation, routing_generation, authority_epoch, freeze_generation
             ) VALUES (
               1, 9223372036854775808, 1,
               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
               1, 1, 1, 0
             );",
        )
        .is_err());
    ledger
        .conn
        .execute(
            "UPDATE authority_revisions SET graph_revision = 2 WHERE singleton = 1",
            [],
        )
        .expect("monotonic advance from genesis");
    assert!(ledger
        .conn
        .execute(
            "UPDATE authority_revisions SET graph_revision = 1 WHERE singleton = 1",
            [],
        )
        .is_err());
    assert!(ledger
        .conn
        .execute(
            "UPDATE authority_revisions SET scope_digest = ?1 WHERE singleton = 1",
            ["b".repeat(64)],
        )
        .is_err());
    ledger
        .conn
        .execute(
            "UPDATE authority_revisions SET graph_revision = 3 WHERE singleton = 1",
            [],
        )
        .expect("monotonic advance");
    ledger
        .conn
        .execute(
            "UPDATE authority_revisions
             SET scope_digest = ?1, authority_epoch = 2
             WHERE singleton = 1",
            ["b".repeat(64)],
        )
        .expect("scope change advances authority epoch");
    assert!(ledger
        .conn
        .execute("DELETE FROM authority_revisions WHERE singleton = 1", [])
        .is_err());
    assert!(ledger
        .conn
        .execute(
            "INSERT OR REPLACE INTO authority_revisions (
               singleton, graph_revision, workspace_generation, scope_digest,
               policy_generation, routing_generation, authority_epoch, freeze_generation
             ) VALUES (1, 1, 1, ?1, 1, 1, 1, 0)",
            ["a".repeat(64)],
        )
        .is_err());
    let persisted = ledger
        .conn
        .query_row(
            "SELECT graph_revision, scope_digest, authority_epoch
             FROM authority_revisions WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .expect("persisted authority");
    assert_eq!(persisted, (3, "b".repeat(64), 2));
    drop(ledger);

    let reopened = SqliteLedger::open(&path).unwrap();
    assert_connection_pragmas(&reopened);
    drop(reopened);

    #[cfg(target_os = "linux")]
    crate::sqlite::open::assert_hostile_contract(directory.path(), &path);
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
fn schema_seven_with_legacy_subject_is_refused_byte_for_byte() {
    let (_directory, path) = database();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(CREATE_METADATA).unwrap();
    for migration in &MIGRATIONS[..7] {
        conn.execute_batch(migration.sql).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, 'prior-schema')",
            params![
                migration.version,
                migration.name,
                migration_checksum(migration)
            ],
        )
        .unwrap();
    }
    let legacy_attempt = format!("atm_{}", "a".repeat(32));
    conn.execute(
        "INSERT INTO attempts (
           id, variant_id, work_package_id, fence, runner_id, runner_epoch,
           workspace_id, workspace_nonce, scope_revision, context_revision, state
         ) VALUES (?1, ?2, ?3, 1, ?4, 1, ?5, zeroblob(32), 1, 1, 'CREATED')",
        params![
            legacy_attempt,
            format!("var_{}", "b".repeat(32)),
            format!("wpk_{}", "c".repeat(32)),
            format!("run_{}", "d".repeat(32)),
            format!("wks_{}", "e".repeat(32)),
        ],
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
    let persisted: String = conn
        .query_row("SELECT id FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(persisted, legacy_attempt);
}

#[test]
fn schema_ten_without_context_authority_is_refused_byte_for_byte() {
    let (_directory, path) = database();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(CREATE_METADATA).unwrap();
    for migration in &MIGRATIONS[..10] {
        conn.execute_batch(migration.sql).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, 'prior-schema')",
            params![
                migration.version,
                migration.name,
                migration_checksum(migration)
            ],
        )
        .unwrap();
    }
    drop(conn);

    let bytes_before = std::fs::read(&path).unwrap();
    unsupported(SqliteLedger::open(&path));
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
    assert!(!sidecar(&path, "-wal").exists());
    assert!(!sidecar(&path, "-journal").exists());
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
    let future = MIGRATIONS.last().unwrap().version + 1;
    for statement in [
        "DELETE FROM schema_version WHERE version = 9".to_string(),
        format!("INSERT INTO schema_version VALUES ({future}, 'future.sql', '00', 'future')"),
        "UPDATE schema_version SET version = 99 WHERE version = 9".to_string(),
    ] {
        let (_directory, path) = database();
        drop(SqliteLedger::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute(&statement, []).unwrap();
        drop(conn);
        unsupported(SqliteLedger::open(path));
    }
}

#[test]
fn missing_or_corrupt_identity_contract_is_refused() {
    for statement in [
        "DELETE FROM identity_contract",
        "UPDATE identity_contract SET identity_format = 'legacy-short-ids'",
        "DELETE FROM effect_receipt_identity_contract",
        "UPDATE effect_receipt_identity_contract SET identity_format = 'legacy-rcp-ids'",
    ] {
        let (_directory, path) = database();
        drop(SqliteLedger::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        conn.execute(statement, []).unwrap();
        drop(conn);
        unsupported(SqliteLedger::open(path));
    }
}

#[test]
fn corrupt_or_pending_restore_state_fails_closed() {
    for statement in [
        "UPDATE restore_state SET restore_epoch = 'wrong'",
        "UPDATE restore_state SET pending_admission = 1, restore_epoch = 1,
          source_snapshot_digest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          restored_at = '2026-08-25T00:00:00Z'",
    ] {
        let (_directory, path) = database();
        drop(SqliteLedger::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        conn.execute(statement, []).unwrap();
        drop(conn);
        let error = match SqliteLedger::open(path) {
            Ok(_) => panic!("corrupt or quarantined restore state opened"),
            Err(error) => error,
        };
        assert!(matches!(error, LedgerError::Store(_) | LedgerError::UnsupportedSchema { .. }));
    }
}

#[test]
fn command_identity_is_unique_and_outbox_correlation_is_foreign_keyed() {
    let (_directory, path) = database();
    let ledger = SqliteLedger::open(path).unwrap();
    ledger
        .conn
        .execute(
            "INSERT INTO commands
               (idempotency_key, id, kind, payload, payload_digest, phase, response_json)
             VALUES ('key-one', 'command-same', 'kind', '{}', '00', 'pending', NULL)",
            [],
        )
        .unwrap();
    let duplicate = ledger
        .conn
        .execute(
            "INSERT INTO commands
               (idempotency_key, id, kind, payload, payload_digest, phase, response_json)
             VALUES ('key-two', 'command-same', 'kind', '{}', '00', 'pending', NULL)",
            [],
        )
        .unwrap_err();
    assert!(matches!(
        duplicate,
        Error::SqliteFailure(ref code, _)
            if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    ));

    let missing = ledger
        .conn
        .execute(
            "INSERT INTO outbox (command_id, kind, payload, phase)
             VALUES ('command-missing', 'dispatch', '{}', 'pending')",
            [],
        )
        .unwrap_err();
    assert!(matches!(
        missing,
        Error::SqliteFailure(ref code, _)
            if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY
    ));
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
                EffectReceiptId::from_seed("missing-intent-receipt").to_string(),
                EffectId::from_seed("missing-intent").to_string(),
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
            EffectReceiptId::from_seed("orphan-receipt").to_string(),
            EffectId::from_seed("orphan-intent").to_string(),
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
