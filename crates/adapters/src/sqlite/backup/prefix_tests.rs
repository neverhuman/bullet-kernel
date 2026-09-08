//! Prefix backups preserve schema 22; they are not yet ordinary restore inputs.

use super::{create_backup_inner, migrations, verify_published_backup, BackupReceipt, FaultPoint};
use crate::sqlite::{backup::restore_backup, SqliteLedger};
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const PREFIX_TEST: &str = "sqlite::backup::create::prefix_tests::supported_prefix_backup_preserves_sources_and_refuses_restore";

fn fixture(path: &Path, mode: &str) -> Connection {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let mut connection = Connection::open(path).unwrap();
    if mode.starts_with("wal") {
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0")
            .unwrap();
    }
    migrations::initialize_backup_prefix_fixture(&mut connection).unwrap();
    connection
        .execute_batch("UPDATE authority_revisions SET authority_epoch=2 WHERE singleton=1")
        .unwrap();
    if mode == "hot" {
        connection.execute_batch("BEGIN IMMEDIATE; UPDATE authority_revisions SET authority_epoch=3 WHERE singleton=1").unwrap();
        connection.cache_flush().unwrap();
    }
    connection
}

fn inventory(directory: &Path) -> Vec<(OsString, u64, u64, Vec<u8>)> {
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            (
                entry.file_name(),
                metadata.dev(),
                metadata.ino(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[test]
fn supported_prefix_backup_preserves_sources_and_refuses_restore() {
    if let Some(path) = std::env::var_os("BULLET_PREFIX_BACKUP_FIXTURE") {
        let mode = std::env::var("BULLET_PREFIX_BACKUP_MODE").unwrap();
        let _connection = fixture(Path::new(&path), &mode);
        std::process::exit(0); // Leave committed WAL or a hot journal without destructors.
    }
    for mode in ["standalone", "wal", "wal-no-shm", "hot"] {
        let source_root = crate::test_support::private_tempdir();
        let source = source_root.path().join("source.sqlite");
        if mode == "standalone" {
            fixture(&source, mode).close().unwrap();
        } else {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", PREFIX_TEST])
                .env("BULLET_PREFIX_BACKUP_FIXTURE", &source)
                .env("BULLET_PREFIX_BACKUP_MODE", mode)
                .output()
                .unwrap();
            assert!(
                child.status.success(),
                "{}",
                String::from_utf8_lossy(&child.stderr)
            );
            let suffix = if mode == "hot" { "-journal" } else { "-wal" };
            assert!(source_root
                .path()
                .join(format!("source.sqlite{suffix}"))
                .exists());
            if mode == "wal-no-shm" {
                fs::remove_file(source_root.path().join("source.sqlite-shm")).unwrap();
            }
        }
        let before = inventory(source_root.path());
        let serving = SqliteLedger::open(&source)
            .err()
            .expect("prefix cannot serve");
        assert!(serving.to_string().contains("UPGRADE_REQUIRED"));
        assert_eq!(inventory(source_root.path()), before);
        let output_root = crate::test_support::private_tempdir();
        let output = output_root.path().join("backup.sqlite");
        let receipt = create_backup_inner(&source, &output, None).unwrap();
        assert_eq!(
            inventory(source_root.path()),
            before,
            "source changed for {mode}"
        );
        verify_published_backup(&output, &receipt).unwrap();
        let copy = Connection::open_with_flags(&output, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let inspected = migrations::inspect_existing(&copy, false).unwrap();
        assert_eq!(
            inspected.schema_state(),
            migrations::SchemaState::UpgradeRequired { from: 22, to: 23 }
        );
        assert_eq!(receipt.schema_digest, inspected.schema_digest());
        assert_ne!(receipt.schema_digest, migrations::schema_contract_digest());
        assert_eq!(receipt.restore_epoch, inspected.restore_state().epoch);
        assert_eq!(
            copy.query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            22
        );
        assert_eq!(
            copy.query_row(
                "SELECT authority_epoch FROM authority_revisions",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        copy.close().unwrap();
        let receipt: BackupReceipt =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        let retained = inventory(output_root.path());
        let restored = output_root.path().join("restore.sqlite");
        let error = restore_backup(&output, &receipt, &restored).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("receipt schema contract is not owned"),
            "{error}"
        );
        assert_eq!(inventory(output_root.path()), retained);
        let forged_current = BackupReceipt {
            schema_digest: migrations::schema_contract_digest(),
            ..receipt
        };
        let error = restore_backup(&output, &forged_current, &restored).unwrap_err();
        assert!(error.to_string().contains("UPGRADE_REQUIRED"), "{error}");
        assert_eq!(inventory(output_root.path()), retained);
        assert_eq!(inventory(source_root.path()), before);
    }
}

#[test]
fn malformed_and_quarantined_prefix_backups_publish_nothing() {
    for (sql, expected) in [
        ("DELETE FROM schema_version WHERE version=22", "unsupported schema:"),
        ("DELETE FROM schema_version WHERE version=9", "unsupported schema:"),
        ("UPDATE schema_version SET checksum='00' WHERE version=3", "unsupported schema:"),
        ("UPDATE schema_version SET name='renamed.sql' WHERE version=2", "unsupported schema:"),
        ("INSERT INTO schema_version VALUES (24, 'future.sql', '00', 'future')", "unsupported schema:"),
        ("ALTER TABLE schema_version ADD COLUMN extra TEXT", "unsupported schema:"),
        ("CREATE TABLE injected_authority (id TEXT)", "unsupported schema:"),
        ("DROP TABLE effect_receipts", "unsupported schema:"),
        ("DELETE FROM identity_contract", "unsupported schema:"),
        ("UPDATE authority_revisions SET scope_digest='bad', authority_epoch=authority_epoch+1", "unsupported schema:"),
        ("PRAGMA ignore_check_constraints=ON; INSERT INTO budget_reservations (reservation_id, amount) VALUES ('invalid-budget', -1)", "unsupported schema:"),
        ("INSERT INTO outbox (command_id, kind, payload, phase) VALUES ('absent', 'dispatch', '{}', 'pending')", "unsupported schema:"),
        ("PRAGMA application_id=1", "unsupported schema:"),
        ("UPDATE restore_state SET pending_admission=1, restore_epoch=1, source_snapshot_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', restored_at='2026-09-08T00:00:00Z'", "RESTORE_ADMISSION_REQUIRED"),
    ] {
        let root = crate::test_support::private_tempdir();
        let source = root.path().join("source.sqlite");
        let connection = fixture(&source, "standalone");
        connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON").unwrap();
        connection.execute_batch(sql).unwrap();
        connection.close().unwrap();
        let before = inventory(root.path());
        let output = root.path().join("backup.sqlite");
        for _ in 0..2 {
            let error = create_backup_inner(&source, &output, None).unwrap_err();
            assert!(matches!(&error, super::SqliteMaintenanceError::Operation { phase: "OPEN", .. }), "{error}");
            assert!(error.to_string().contains(expected), "{sql}: {error}");
            assert_eq!(inventory(root.path()), before);
        }
    }
}

#[test]
fn prefix_backup_custody_and_publication_faults_preserve_sources() {
    use rustix::fs::{flock, FlockOperation};
    let root = crate::test_support::private_tempdir();
    let source = root.path().join("source.sqlite");
    fixture(&source, "standalone").close().unwrap();
    let before = inventory(root.path());
    let outputs = crate::test_support::private_tempdir();
    let output = outputs.path().join("backup.sqlite");
    let exclusive = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    flock(&exclusive, FlockOperation::NonBlockingLockExclusive).unwrap();
    let error = create_backup_inner(&source, &output, None).unwrap_err();
    assert!(error.to_string().contains("SQLITE_CUSTODY_BUSY"));
    assert!(inventory(outputs.path()).is_empty());
    assert_eq!(inventory(root.path()), before);
    drop(exclusive);
    for point in [
        FaultPoint::AfterCopy,
        FaultPoint::AfterSync,
        FaultPoint::AfterVerify,
        FaultPoint::BeforePublish,
    ] {
        let error = create_backup_inner(&source, &output, Some(point)).unwrap_err();
        assert!(error.to_string().contains("injected maintenance failure"));
        assert!(inventory(outputs.path()).is_empty());
        assert_eq!(inventory(root.path()), before);
    }
    let receipt = create_backup_inner(&source, &output, None).unwrap();
    verify_published_backup(&output, &receipt).unwrap();
    let retained = inventory(outputs.path());
    assert!(create_backup_inner(&source, &output, None).is_err());
    assert_eq!(inventory(outputs.path()), retained);
    assert_eq!(inventory(root.path()), before);
}
