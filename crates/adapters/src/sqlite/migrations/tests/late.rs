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
        let conn = sqlite_fixture(&path);
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
    let conn = sqlite_fixture(&path);
    conn.execute("ALTER TABLE schema_version ADD COLUMN extra TEXT", [])
        .unwrap();
    drop(conn);
    unsupported(SqliteLedger::open(path));
}

#[test]
fn missing_product_table_is_refused_despite_valid_migration_rows() {
    let (_directory, path) = database();
    drop(SqliteLedger::open(&path).unwrap());
    let conn = sqlite_fixture(&path);
    conn.execute("DROP TABLE effect_receipts", []).unwrap();
    drop(conn);
    unsupported(SqliteLedger::open(path));
}

#[test]
fn unclaimed_sqlite_version_metadata_is_refused() {
    for statement in ["PRAGMA user_version = 1", "PRAGMA application_id = 1"] {
        let (_directory, path) = database();
        let conn = sqlite_fixture(&path);
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
    let conn = sqlite_fixture(&path);
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
