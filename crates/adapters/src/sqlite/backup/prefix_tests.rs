//! Supported prefix backups restore only into an independently verified quarantine.

use super::{create_backup_inner, migrations, verify_published_backup, BackupReceipt, FaultPoint};
use crate::sqlite::{
    backup::{restore, restore_backup, restore_backup_inner},
    SqliteLedger,
};
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const PREFIX_TEST: &str = "sqlite::backup::create::prefix_tests::supported_prefix_backup_preserves_sources_and_restores_quarantined";

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
fn supported_prefix_backup_preserves_sources_and_restores_quarantined() {
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
        let forged_current = BackupReceipt {
            schema_digest: migrations::schema_contract_digest(),
            ..receipt.clone()
        };
        let error = restore_backup(&output, &forged_current, &restored).unwrap_err();
        assert!(
            error.to_string().contains("schema contract does not match"),
            "{error}"
        );
        assert_eq!(inventory(output_root.path()), retained);
        let completed = restore_backup(&output, &receipt, &restored).unwrap();
        assert_eq!(completed.restore_epoch, receipt.restore_epoch + 1);
        assert!(completed.pending_authority_admission);
        let bytes = fs::read(&restored).unwrap();
        assert_eq!(
            completed.restored_digest,
            blake3::hash(&bytes).to_hex().to_string()
        );
        assert_eq!(completed.restored_bytes, bytes.len() as u64);
        let copy =
            Connection::open_with_flags(&restored, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let quarantined = migrations::inspect_existing(&copy, true).unwrap();
        assert_eq!(quarantined.schema_state(), inspected.schema_state());
        assert_eq!(quarantined.schema_digest(), inspected.schema_digest());
        assert_eq!(quarantined.authority(), inspected.authority());
        assert_eq!(quarantined.restore_state().epoch, completed.restore_epoch);
        assert!(quarantined.restore_state().pending_admission);
        copy.close().unwrap();
        let after = inventory(output_root.path());
        assert!(SqliteLedger::open(&restored)
            .err()
            .unwrap()
            .to_string()
            .contains("RESTORE_ADMISSION_REQUIRED"));
        assert!(create_backup_inner(
            &restored,
            &output_root.path().join("forbidden.sqlite"),
            None
        )
        .unwrap_err()
        .to_string()
        .contains("RESTORE_ADMISSION_REQUIRED"));
        assert_eq!(inventory(output_root.path()), after);
        assert_eq!(fs::read(&output).unwrap(), retained[0].3);
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

#[test]
fn prefix_restore_faults_verify_published_quarantine_and_cleanup() {
    let input = crate::test_support::private_tempdir();
    let source = input.path().join("source.sqlite");
    fixture(&source, "standalone").close().unwrap();
    let backup = input.path().join("backup.sqlite");
    let receipt = create_backup_inner(&source, &backup, None).unwrap();
    let retained = inventory(input.path());
    for point in [
        FaultPoint::AfterCopy,
        FaultPoint::AfterSync,
        FaultPoint::AfterTransition,
        FaultPoint::AfterVerify,
        FaultPoint::BeforePublish,
        FaultPoint::AfterPublish,
        FaultPoint::AfterReadback,
    ] {
        let output = crate::test_support::private_tempdir();
        let restored = output.path().join("restored.sqlite");
        let error = restore_backup_inner(&backup, &receipt, &restored, Some(point)).unwrap_err();
        assert!(
            error.to_string().contains("injected maintenance failure"),
            "{error}"
        );
        let published = matches!(point, FaultPoint::AfterPublish | FaultPoint::AfterReadback);
        assert_eq!(inventory(output.path()).len(), usize::from(published));
        if published {
            assert!(SqliteLedger::open(&restored)
                .err()
                .unwrap()
                .to_string()
                .contains("RESTORE_ADMISSION_REQUIRED"));
            let bytes = fs::read(&restored).unwrap();
            assert!(restore_backup(&backup, &receipt, &restored).is_err());
            assert_eq!(fs::read(&restored).unwrap(), bytes);
        } else {
            restore_backup(&backup, &receipt, &restored).unwrap();
        }
        assert_eq!(inventory(input.path()), retained);
    }
    for changed in ["schema", "epoch", "size", "digest"] {
        let output = crate::test_support::private_tempdir();
        let mut wrong = receipt.clone();
        match changed {
            "schema" => wrong.schema_digest = "a".repeat(64),
            "epoch" => wrong.restore_epoch += 1,
            "size" => wrong.snapshot_bytes = 1024 * 1024 * 1024 + 1,
            _ => wrong.snapshot_digest = "a".repeat(64),
        }
        assert!(restore_backup(&backup, &wrong, output.path().join("no.sqlite")).is_err());
        assert!(inventory(output.path()).is_empty());
        assert_eq!(inventory(input.path()), retained);
    }
    // A changed published byte cannot acquire a successful receipt. The published
    // quarantine is retained; no SQLite open against that name repairs its bytes.
    let output = crate::test_support::private_tempdir();
    let restored = output.path().join("restored.sqlite");
    let error = restore::with_hook(
        Box::new(|phase, _, path| {
            if phase == "PUBLISHED" {
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
            }
        }),
        || restore_backup(&backup, &receipt, &restored),
    )
    .unwrap_err();
    assert!(error.to_string().contains("descriptor length"), "{error}");
    assert_eq!(fs::metadata(&restored).unwrap().len(), 0);
    // A substitution detected after confirmed close preserves the peer and does
    // not poison future admissions. This proves the sampled check, not an atomic rename barrier.
    for primary in [false, true] {
        let output = crate::test_support::private_tempdir();
        let restored = output.path().join("restored.sqlite");
        let error = restore::with_hook(
            Box::new(|phase, _, path| {
                if phase == "CLEANUP" {
                    fs::rename(path, path.with_extension("retained")).unwrap();
                    fs::write(path, b"peer-generation").unwrap();
                }
            }),
            || {
                restore_backup_inner(
                    &backup,
                    &receipt,
                    &restored,
                    primary.then_some(FaultPoint::AfterTransition),
                )
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("staging path no longer identifies"),
            "{error}"
        );
        if primary {
            assert!(error.to_string().contains("injected maintenance failure"));
        }
        assert!(inventory(output.path())
            .iter()
            .any(|entry| entry.3 == b"peer-generation"));
        restore_backup(&backup, &receipt, output.path().join("retry.sqlite")).unwrap();
    }
}

#[test]
fn prefix_restore_close_failure_retains_handles_and_poison_is_process_scoped() {
    const TEST: &str = "sqlite::backup::create::prefix_tests::prefix_restore_close_failure_retains_handles_and_poison_is_process_scoped";
    if let Some(root) = std::env::var_os("BULLET_RESTORE_CLOSE_CHILD") {
        let root = Path::new(&root);
        let backup = root.join("backup.sqlite");
        let receipt: BackupReceipt =
            serde_json::from_slice(&fs::read(root.join("receipt.json")).unwrap()).unwrap();
        let selected = std::env::var("BULLET_RESTORE_CLOSE_PHASE").unwrap();
        let paired = std::env::var_os("BULLET_RESTORE_CLOSE_PRIMARY").is_some();
        let fault = paired.then_some(if selected == "TRANSITION" {
            FaultPoint::AfterTransition
        } else {
            FaultPoint::AfterReadback
        });
        let marker = root.join("retained-path");
        let marker_copy = marker.clone();
        let error = restore::with_hook(
            Box::new(move |phase, connection, path| {
                if phase == selected {
                    let statement = connection.unwrap().prepare("SELECT 1").unwrap();
                    std::mem::forget(statement); // A real SQLITE_BUSY on Connection::close.
                    fs::write(&marker_copy, path.as_os_str().as_encoded_bytes()).unwrap();
                }
            }),
            || restore_backup_inner(&backup, &receipt, &root.join("restored.sqlite"), fault),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("SQLITE_CLOSE_RESTART_REQUIRED"),
            "{error}"
        );
        if paired {
            assert!(
                error.to_string().contains("injected maintenance failure"),
                "{error}"
            );
        }
        let retained = std::path::PathBuf::from(fs::read_to_string(marker).unwrap());
        assert!(error.to_string().contains(retained.to_str().unwrap()));
        assert!(retained.exists());
        let descriptors = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .collect::<Vec<_>>();
        assert!(
            descriptors.iter().filter(|path| **path == retained).count() >= 2,
            "SQLite and tempfile handles were not both retained: {descriptors:?}"
        );
        let before = inventory(root);
        assert!(restore_backup(&backup, &receipt, root.join("retry.sqlite"))
            .unwrap_err()
            .to_string()
            .contains("SQLITE_CLOSE_RESTART_REQUIRED"));
        assert!(
            create_backup_inner(&backup, &root.join("retry-backup.sqlite"), None)
                .unwrap_err()
                .to_string()
                .contains("SQLITE_CLOSE_RESTART_REQUIRED")
        );
        assert!(SqliteLedger::open(root.join("new.sqlite"))
            .err()
            .unwrap()
            .to_string()
            .contains("SQLITE_CLOSE_RESTART_REQUIRED"));
        assert_eq!(inventory(root), before);
        return;
    }
    for selected in ["TRANSITION", "READBACK"] {
        for paired in [false, true] {
            let root = crate::test_support::private_tempdir();
            let source = root.path().join("source.sqlite");
            fixture(&source, "standalone").close().unwrap();
            let backup = root.path().join("backup.sqlite");
            let receipt = create_backup_inner(&source, &backup, None).unwrap();
            fs::write(
                root.path().join("receipt.json"),
                serde_json::to_vec(&receipt).unwrap(),
            )
            .unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", TEST])
                .env("BULLET_RESTORE_CLOSE_CHILD", root.path())
                .env("BULLET_RESTORE_CLOSE_PHASE", selected);
            if paired {
                child.env("BULLET_RESTORE_CLOSE_PRIMARY", "1");
            }
            let child = child.output().unwrap();
            assert!(
                child.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
            let retained = fs::read_to_string(root.path().join("retained-path")).unwrap();
            assert!(Path::new(&retained).exists());
            let connection = Connection::open(&retained).unwrap();
            connection
                .execute_batch("BEGIN EXCLUSIVE; ROLLBACK")
                .unwrap();
            connection.close().unwrap();
            // Child process death releases handles; the parent's health remains usable.
            restore_backup(&backup, &receipt, root.path().join("parent-retry.sqlite")).unwrap();
        }
    }
}
