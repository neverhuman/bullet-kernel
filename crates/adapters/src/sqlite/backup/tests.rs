#[cfg(unix)]
use super::{copy_and_digest, open_regular_nofollow};
use super::{
    create_backup, create_backup_inner, restore_backup, restore_backup_inner, BackupReceipt,
    FaultPoint, SqliteMaintenanceError,
};
use crate::sqlite::SqliteLedger;
use bullet_application::Ledger;
use rusqlite::Connection;
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn paths() -> (TempDir, PathBuf, PathBuf, PathBuf) {
    let directory = crate::test_support::private_tempdir();
    let source = directory.path().join("source.sqlite");
    let backup = directory.path().join("backup.sqlite");
    let restored = directory.path().join("restored.sqlite");
    (directory, source, backup, restored)
}

fn receipt_for_bytes(path: &Path, template: &BackupReceipt) -> BackupReceipt {
    let bytes = fs::read(path).unwrap();
    BackupReceipt {
        snapshot_digest: blake3::hash(&bytes).to_hex().to_string(),
        snapshot_bytes: u64::try_from(bytes.len()).unwrap(),
        ..template.clone()
    }
}

#[test]
fn online_backup_includes_uncheckpointed_wal_and_restores_quarantined() {
    let (_directory, source, backup, restored) = paths();
    let mut ledger = SqliteLedger::open(&source).unwrap();
    ledger.append_event("wal_subject", "exact-row").unwrap();
    let wal = PathBuf::from(format!("{}-wal", source.display()));
    assert!(wal.exists(), "fixture must exercise an uncheckpointed WAL");

    let receipt = create_backup(&source, &backup).unwrap();
    assert_eq!(receipt.restore_epoch, 0);
    assert_eq!(receipt.integrity, "PASS");
    let backup_bytes = fs::read(&backup).unwrap();
    assert_eq!(
        receipt.snapshot_digest,
        blake3::hash(&backup_bytes).to_hex().to_string()
    );
    assert_eq!(
        receipt.snapshot_bytes,
        u64::try_from(backup_bytes.len()).unwrap()
    );
    assert!(backup.exists());
    assert!(!PathBuf::from(format!("{}-wal", backup.display())).exists());
    let copy = Connection::open(&backup).unwrap();
    let body: String = copy
        .query_row(
            "SELECT body FROM events WHERE kind = 'wal_subject'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(body, "exact-row");
    drop(copy);

    let restored_receipt = restore_backup(&backup, &receipt, &restored).unwrap();
    assert_eq!(restored_receipt.previous_restore_epoch, 0);
    assert_eq!(restored_receipt.restore_epoch, 1);
    assert!(restored_receipt.pending_authority_admission);
    let restored_bytes = fs::read(&restored).unwrap();
    assert_eq!(
        restored_receipt.restored_digest,
        blake3::hash(&restored_bytes).to_hex().to_string()
    );
    assert_eq!(
        restored_receipt.restored_bytes,
        u64::try_from(restored_bytes.len()).unwrap()
    );
    let error = match SqliteLedger::open(&restored) {
        Ok(_) => panic!("quarantined restore opened as production truth"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("RESTORE_ADMISSION_REQUIRED"));

    let conn = Connection::open(restored).unwrap();
    let state: (i64, i64, String) = conn
        .query_row(
            "SELECT restore_epoch, pending_admission, source_snapshot_digest
             FROM restore_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(state, (1, 1, receipt.snapshot_digest));
}

#[test]
fn restore_faults_publish_nothing_and_retry_completes() {
    for point in [
        FaultPoint::AfterCopy,
        FaultPoint::AfterSync,
        FaultPoint::AfterVerify,
        FaultPoint::BeforePublish,
    ] {
        let (_directory, source, backup, restored) = paths();
        drop(SqliteLedger::open(&source).unwrap());
        let receipt = create_backup(&source, &backup).unwrap();
        let error = restore_backup_inner(&backup, &receipt, &restored, Some(point)).unwrap_err();
        assert!(error.to_string().contains("injected maintenance failure"));
        assert!(!restored.exists(), "{point:?} published a partial database");
        let complete = restore_backup(&backup, &receipt, &restored).unwrap();
        assert_eq!(complete.restore_epoch, 1);
    }
}

#[test]
fn backup_faults_publish_nothing() {
    for point in [
        FaultPoint::AfterCopy,
        FaultPoint::AfterSync,
        FaultPoint::AfterVerify,
        FaultPoint::BeforePublish,
    ] {
        let (_directory, source, backup, _restored) = paths();
        drop(SqliteLedger::open(&source).unwrap());
        create_backup_inner(&source, &backup, Some(point)).unwrap_err();
        assert!(!backup.exists(), "{point:?} published a partial backup");
    }
}

#[test]
fn existing_destination_is_never_replaced() {
    let (_directory, source, backup, restored) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let receipt = create_backup(&source, &backup).unwrap();
    fs::write(&restored, b"preserve-existing-authority").unwrap();

    let error = restore_backup(&backup, &receipt, &restored).unwrap_err();
    assert!(matches!(
        error,
        SqliteMaintenanceError::DestinationExists(_)
    ));
    assert_eq!(fs::read(&restored).unwrap(), b"preserve-existing-authority");
}

#[test]
fn corrupt_partial_and_mismatched_backup_fail_closed() {
    let (_directory, source, backup, restored) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let receipt = create_backup(&source, &backup).unwrap();

    let mut corrupt = fs::read(&backup).unwrap();
    corrupt[100] ^= 0xff;
    fs::write(&backup, corrupt).unwrap();
    let mismatch = restore_backup(&backup, &receipt, &restored).unwrap_err();
    assert!(matches!(
        mismatch,
        SqliteMaintenanceError::ReceiptMismatch(_)
    ));
    assert!(!restored.exists());

    let forged = receipt_for_bytes(&backup, &receipt);
    let corrupt_error = restore_backup(&backup, &forged, &restored).unwrap_err();
    assert!(corrupt_error
        .to_string()
        .contains("SQLITE_MAINTENANCE_VERIFY"));
    assert!(!restored.exists());

    fs::write(&backup, b"SQLite format 3\0partial").unwrap();
    let partial = receipt_for_bytes(&backup, &receipt);
    assert!(restore_backup(&backup, &partial, &restored).is_err());
    assert!(!restored.exists());
}

#[test]
fn future_schema_and_future_receipt_are_rejected() {
    let (_directory, source, backup, restored) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let receipt = create_backup(&source, &backup).unwrap();
    let conn = Connection::open(&backup).unwrap();
    let current_version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    let future_version = current_version
        .checked_add(1)
        .expect("migration version must have a representable successor");
    conn.execute(
        "INSERT INTO schema_version VALUES (?1, 'future.sql', '00', 'future')",
        rusqlite::params![future_version],
    )
    .unwrap();
    drop(conn);
    let future_schema = receipt_for_bytes(&backup, &receipt);
    let error = restore_backup(&backup, &future_schema, &restored).unwrap_err();
    assert!(error
        .to_string()
        .contains("partial or contains a future migration"));
    assert!(!restored.exists());

    let future_receipt = BackupReceipt {
        format_version: receipt.format_version + 1,
        ..receipt
    };
    let error = restore_backup(&backup, &future_receipt, &restored).unwrap_err();
    assert!(matches!(error, SqliteMaintenanceError::ReceiptMismatch(_)));
}

#[cfg(unix)]
#[test]
fn backup_symlink_is_refused_without_following_it() {
    use std::os::unix::fs::symlink;
    let (_directory, source, backup, restored) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let receipt = create_backup(&source, &backup).unwrap();
    let backup_link = backup.with_extension("link");
    symlink(&backup, &backup_link).unwrap();
    assert!(restore_backup(&backup_link, &receipt, &restored).is_err());
    assert!(!restored.exists());

    let source_target_before = fs::read(&source).unwrap();
    let source_link = source.with_extension("link");
    symlink(&source, &source_link).unwrap();
    let error = create_backup(&source_link, &restored).unwrap_err();
    assert!(error.to_string().contains("SQLITE_MAINTENANCE_OPEN"));
    assert_eq!(fs::read(&source).unwrap(), source_target_before);
    assert!(!restored.exists());
}

#[cfg(unix)]
#[test]
fn validated_input_growth_is_bounded_to_expected_plus_one() {
    let (_directory, source, backup, _restored) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let receipt = create_backup(&source, &backup).unwrap();
    let mut admitted = open_regular_nofollow(&backup, receipt.snapshot_bytes).unwrap();

    let growth = vec![0xa5; 1024 * 1024];
    OpenOptions::new()
        .append(true)
        .open(&backup)
        .unwrap()
        .write_all(&growth)
        .unwrap();
    let mut staged = tempfile::tempfile().unwrap();
    let error = copy_and_digest(&mut admitted, &mut staged, receipt.snapshot_bytes).unwrap_err();
    assert!(matches!(error, SqliteMaintenanceError::ReceiptMismatch(_)));
    assert_eq!(
        staged.metadata().unwrap().len(),
        receipt.snapshot_bytes + 1,
        "growth after metadata admission must consume only one sentinel byte"
    );
}

#[cfg(unix)]
#[test]
fn short_and_long_descriptor_lengths_fail_before_staging() {
    for grow in [false, true] {
        let (_directory, source, backup, restored) = paths();
        drop(SqliteLedger::open(&source).unwrap());
        let receipt = create_backup(&source, &backup).unwrap();
        let changed_len = if grow {
            receipt.snapshot_bytes + 1
        } else {
            receipt.snapshot_bytes - 1
        };
        OpenOptions::new()
            .write(true)
            .open(&backup)
            .unwrap()
            .set_len(changed_len)
            .unwrap();

        let error = restore_backup(&backup, &receipt, &restored).unwrap_err();
        assert!(error.to_string().contains("descriptor length"));
        assert!(!restored.exists());
    }
}
