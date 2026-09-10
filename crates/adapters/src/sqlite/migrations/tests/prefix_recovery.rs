fn verify_schema_twenty_two_refusals() {
    if let Some(path) = std::env::var_os("BULLET_SCHEMA_PREFIX_WAL_CHILD") {
        let mut conn = sqlite_fixture(std::path::Path::new(&path));
        let mode = std::env::var("BULLET_SCHEMA_PREFIX_CHILD_MODE").unwrap();
        if mode.contains("wal") {
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        }
        let version = if mode.starts_with("26") {
            26
        } else if mode.starts_with("25") {
            25
        } else if mode.starts_with("24") {
            24
        } else if mode.starts_with("23") {
            23
        } else {
            22
        };
        super::initialize_prefix(&mut conn, &MIGRATIONS[..version]).unwrap();
        if mode.ends_with("hot") {
            conn.execute_batch("BEGIN IMMEDIATE; UPDATE schema_version SET name = 'uncommitted' WHERE version = 1;").unwrap();
            conn.cache_flush().unwrap();
        }
        // No destructors: retain the WAL or hot rollback journal after process death.
        let terminate = std::process::exit;
        terminate(0);
    }
    for rows in [
        vec![],
        vec!["ok", "ok"],
        vec!["ok", "corrupt"],
        vec!["corrupt", "ok"],
    ] {
        let rows: Vec<_> = rows.into_iter().map(String::from).collect();
        assert_eq!(
            super::inspection::verify_integrity_rows(&rows)
                .unwrap_err()
                .reason_code(),
            "UNSUPPORTED_SCHEMA"
        );
    }
    super::inspection::verify_integrity_rows(&["ok".into()]).unwrap();
    for (statement, expected) in [
        ("", "UPGRADE_REQUIRED"),
        ("missing-authority", "UNSUPPORTED_SCHEMA"),
        ("DELETE FROM schema_version WHERE version = 9", "UNSUPPORTED_SCHEMA"),
        ("UPDATE schema_version SET checksum = '00' WHERE version = 3", "UNSUPPORTED_SCHEMA"),
        ("UPDATE schema_version SET name = 'renamed.sql' WHERE version = 2", "UNSUPPORTED_SCHEMA"),
        ("UPDATE schema_version SET applied_at = 'not-a-time' WHERE version = 1", "UNSUPPORTED_SCHEMA"),
        ("ALTER TABLE schema_version ADD COLUMN extra TEXT", "UNSUPPORTED_SCHEMA"),
        ("CREATE TABLE injected_authority (id TEXT)", "UNSUPPORTED_SCHEMA"),
        ("DROP TABLE effect_receipts", "UNSUPPORTED_SCHEMA"),
        ("DELETE FROM identity_contract", "UNSUPPORTED_SCHEMA"),
        ("DELETE FROM command_dispatch_claim_identity_contract", "UNSUPPORTED_SCHEMA"),
        ("UPDATE authority_revisions SET scope_digest = 'bad', authority_epoch = authority_epoch + 1", "UNSUPPORTED_SCHEMA"),
        ("INSERT INTO budget_reservations (reservation_id, amount) VALUES ('invalid-budget', -1)", "UNSUPPORTED_SCHEMA"),
        ("INSERT INTO outbox (command_id, kind, payload, phase) VALUES ('absent', 'dispatch', '{}', 'pending')", "UNSUPPORTED_SCHEMA"),
        ("PRAGMA application_id = 1", "UNSUPPORTED_SCHEMA"),
        ("UPDATE restore_state SET restore_epoch = 'wrong'", "UNSUPPORTED_SCHEMA"),
        ("UPDATE restore_state SET pending_admission = 1, restore_epoch = 1, source_snapshot_digest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', restored_at = '2026-09-08T00:00:00Z'", "RESTORE_ADMISSION_REQUIRED"),
    ] {
        let (_directory, path) = database();
        let conn = sqlite_fixture(&path);
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.pragma_update(None, "ignore_check_constraints", "ON").unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        install_legacy_migrations(&conn, &MIGRATIONS[..22]);
        if statement != "missing-authority" {
            crate::sqlite::authority::seed_genesis(&conn).unwrap();
        }
        conn.execute("UPDATE schema_version SET applied_at = '2026-09-08T00:00:00Z'", []).unwrap();
        conn.execute_batch(
            "INSERT INTO commands (idempotency_key, id, kind, payload, payload_digest, phase, response_json)
             VALUES ('retained-key', 'retained-command', 'document', '{}', '00', 'pending', NULL);",
        ).unwrap();
        if statement != "missing-authority" {
            conn.execute_batch(statement).unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        conn.pragma_update(None, "ignore_check_constraints", "OFF").unwrap();
        assert_typed_prefix_inspection(&conn, &path, expected);
        drop(conn);
        let bytes_before = std::fs::read(&path).unwrap();
        // Repeat the exact startup after refusal: neither attempt may migrate or clean truth.
        for _ in 0..2 {
            let error = match SqliteLedger::open(&path) {
                Ok(_) => panic!("schema 22 was served: {statement}"),
                Err(error) => error,
            };
            if expected == "UNSUPPORTED_SCHEMA" {
                assert_eq!(error.reason_code(), expected, "{statement}: {error}");
            } else {
                assert!(matches!(error, LedgerError::Store(_)), "{error}");
                assert!(error.to_string().contains(expected), "{statement}: {error}");
                assert!(!error.to_string().contains("removing the database"));
            }
            assert_eq!(std::fs::read(&path).unwrap(), bytes_before, "{statement}");
            for suffix in ["-wal", "-shm", "-journal"] {
                assert!(!sidecar(&path, suffix).exists(), "{statement}: {suffix}");
            }
        }
    }
    verify_schema_twenty_two_wal_refusal();
    let (_directory, oversized) = database();
    drop(sqlite_fixture(&oversized));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&oversized)
        .unwrap();
    let length = 1024 * 1024 * 1024 + 1;
    file.set_len(length).unwrap();
    let error = match SqliteLedger::open(&oversized) {
        Ok(_) => panic!("oversized database opened"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("SQLITE_PREFLIGHT_TOO_LARGE"));
    assert_eq!(file.metadata().unwrap().len(), length);
}

fn assert_typed_prefix_inspection(
    conn: &rusqlite::Connection,
    path: &std::path::Path,
    expected: &str,
) {
    let before = std::fs::read(path).unwrap();
    let inspected = super::inspect_existing(conn, false);
    if expected == "UPGRADE_REQUIRED" {
        let schema = inspected.expect("authentic prefix produces a typed inspection");
        assert_eq!(
            schema.schema_state(),
            super::SchemaState::UpgradeRequired { from: 22, to: 26 }
        );
        assert!(super::valid_digest(schema.schema_digest()));
        assert_ne!(schema.schema_digest(), super::schema_contract_digest());
        assert_eq!(schema.restore_state().epoch, 0);
        assert!(!schema.restore_state().pending_admission);
        assert_eq!(
            schema.authority(),
            &bullet_application::NormalizedAuthority::genesis()
        );
        assert!(schema
            .require_current()
            .unwrap_err()
            .to_string()
            .contains("UPGRADE_REQUIRED"));
    } else {
        let error = inspected.unwrap_err();
        if expected == "UNSUPPORTED_SCHEMA" {
            assert_eq!(error.reason_code(), expected);
        } else {
            assert!(error.to_string().contains("RESTORE_ADMISSION_REQUIRED"));
            assert!(!error.to_string().contains("UPGRADE_REQUIRED"));
            let quarantined = super::inspect_existing(conn, true).unwrap();
            assert!(quarantined.restore_state().pending_admission);
            assert_eq!(quarantined.restore_state().epoch, 1);
            assert!(quarantined.require_current().is_err());
        }
    }
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "typed inspection changed source bytes"
    );
}

fn verify_schema_twenty_two_wal_refusal() {
    for mode in [
        "22-wal",
        "22-hot",
        "22-wal-no-shm",
        "23-wal",
        "23-hot",
        "24-wal",
        "24-hot",
        "25-wal",
        "25-hot",
        "26-wal",
        "26-hot",
        "22-super-hot",
        "23-super-hot",
        "24-super-hot",
        "25-super-hot",
        "26-super-hot",
        "22-large-hot",
        "22-large-page-wal",
        "22-large-size-wal",
    ] {
        verify_crashed_schema(mode);
    }
}

fn verify_crashed_schema(mode: &str) {
    let (directory, path) = database();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sqlite::migrations::tests::schema_twenty_two_without_effect_recovery_claims_is_refused_byte_for_byte"])
        .env("BULLET_SCHEMA_PREFIX_WAL_CHILD", &path)
        .env("BULLET_SCHEMA_PREFIX_CHILD_MODE", mode)
        .output().unwrap();
    assert!(child.status.success(), "{child:?}");
    let external = crate::test_support::private_tempdir();
    let sentinel = external.path().join("external-super-journal");
    let sentinel_bytes = b"/absent-bullet-preflight-child-journal\0";
    if mode.contains("super") {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        std::fs::write(&sentinel, sentinel_bytes).unwrap();
        let name = sentinel.as_os_str().as_bytes();
        let checksum = name
            .iter()
            .fold(0_u32, |sum, byte| sum.wrapping_add((*byte as i8) as u32));
        let mut journal = std::fs::OpenOptions::new()
            .append(true)
            .open(sidecar(&path, "-journal"))
            .unwrap();
        journal.write_all(&0_u32.to_be_bytes()).unwrap();
        journal.write_all(name).unwrap();
        journal
            .write_all(&u32::try_from(name.len()).unwrap().to_be_bytes())
            .unwrap();
        journal.write_all(&checksum.to_be_bytes()).unwrap();
        journal
            .write_all(&[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7])
            .unwrap();
        journal.sync_all().unwrap();
    }
    if mode.contains("large") {
        use std::os::unix::fs::FileExt;
        let (suffix, offset) = if mode.ends_with("hot") {
            ("-journal", 16)
        } else if mode.contains("page") {
            ("-wal", 32)
        } else {
            ("-wal", 36)
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(sidecar(&path, suffix))
            .unwrap();
        file.write_all_at(&u32::MAX.to_be_bytes(), offset).unwrap();
        file.sync_all().unwrap();
    }
    if mode.ends_with("no-shm") {
        std::fs::remove_file(sidecar(&path, "-shm")).unwrap();
    }
    let snapshot = || {
        let mut entries = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    };
    let before = snapshot();
    let files = if mode.ends_with("hot") || mode.ends_with("no-shm") {
        2
    } else {
        3
    };
    assert_eq!(before.len(), files, "crash inventory: {mode}");
    if mode.ends_with("hot") {
        let journal = std::fs::read(sidecar(&path, "-journal")).unwrap();
        assert_eq!(
            &journal[..8],
            &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        );
    } else {
        assert!(sidecar(&path, "-wal").is_file());
    }
    for _ in 0..2 {
        let opened = SqliteLedger::open(&path);
        if mode.starts_with("26") && !mode.contains("super") {
            drop(opened.unwrap_or_else(|error| panic!("current recovery failed: {mode}: {error}")));
            continue;
        }
        let error = match opened {
            Ok(_) => panic!("prefix served: {mode}"),
            Err(error) => error,
        };
        let expected = if mode.contains("super") {
            "SQLITE_PREFLIGHT_SUPER_JOURNAL"
        } else if mode.contains("large") {
            "SQLITE_PREFLIGHT_REPLAY_TOO_LARGE"
        } else {
            "UPGRADE_REQUIRED"
        };
        assert!(error.to_string().contains(expected), "{mode}: {error}");
        if mode.contains("super") {
            assert_eq!(std::fs::read(&sentinel).unwrap(), sentinel_bytes);
        }
        let after = snapshot();
        assert_eq!(after.len(), before.len(), "startup changed WAL inventory");
        for (actual, expected) in after.iter().zip(&before) {
            assert_eq!(actual.0, expected.0);
            assert!(actual.1 == expected.1, "startup changed {:?}", actual.0);
        }
    }
}
