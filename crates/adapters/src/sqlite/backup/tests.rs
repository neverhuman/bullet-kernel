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
    #[cfg(target_os = "linux")]
    if std::env::var_os("BULLET_BACKUP_SNAPSHOT_FIXTURE").is_some() {
        crate::sqlite::open::assert_snapshot_sources();
        return;
    }
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
    drop(conn);
    drop(ledger);
    #[cfg(target_os = "linux")]
    {
        crate::sqlite::open::assert_backup_obeys_custody(_directory.path(), &source);
        crate::sqlite::open::assert_snapshot_sources();
    }
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
    #[cfg(target_os = "linux")]
    if let Some(root) = std::env::var_os("BULLET_BACKUP_CLOSE_CHILD") {
        failed_close_child(Path::new(&root));
        return;
    }
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
        #[cfg(target_os = "linux")]
        drop(exclusive(&source).expect("producer failure released confirmed-closed custody"));
    }
    #[cfg(target_os = "linux")]
    assert_close_contract();
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

#[cfg(target_os = "linux")]
fn exclusive(source: &Path) -> Result<std::fs::File, rustix::io::Errno> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(source)
        .unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn assert_close_contract() {
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for (primary, preflight) in [(false, false), (true, false), (false, true), (true, true)] {
        let (directory, source, _, _) = paths();
        drop(SqliteLedger::open(&source).unwrap());
        let before = fs::metadata(&source).unwrap();
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sqlite::backup::tests::backup_faults_publish_nothing",
                    "--nocapture",
                ])
                .env("BULLET_BACKUP_CLOSE_CHILD", directory.path())
                .env(
                    "BULLET_BACKUP_CLOSE_PRIMARY",
                    if primary { "yes" } else { "no" },
                )
                .env(
                    "BULLET_BACKUP_PREFLIGHT_CLOSE",
                    if preflight { "yes" } else { "no" },
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let ready = directory.path().join("ready");
        let started = Instant::now();
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "close child exited before retaining custody"
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "close child timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            exclusive(&source),
            Err(rustix::io::Errno::WOULDBLOCK)
        ));
        child.0.stdin.take().unwrap().write_all(b"q").unwrap();
        assert!(child.0.wait().unwrap().success());
        drop(exclusive(&source).expect("process death released retained custody"));
        let after = fs::metadata(&source).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        if preflight && primary {
            Connection::open(&source)
                .unwrap()
                .execute_batch("PRAGMA user_version=0")
                .unwrap();
        }
        drop(SqliteLedger::open(&source).expect("same source reopens after failed process exits"));
    }
    let (_directory, source, backup, _) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let changed = source.clone();
    let error = super::create::with_before_close(
        move |_| {
            fs::set_permissions(changed, fs::Permissions::from_mode(0o640)).unwrap();
        },
        || create_backup_inner(&source, &backup, Some(FaultPoint::AfterCopy)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected maintenance failure"));
    assert!(error
        .to_string()
        .contains("SQLITE_CLOSE_FINALIZATION_FAILED"));
    assert!(!error.to_string().contains("SQLITE_CLOSE_RESTART_REQUIRED"));
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    drop(exclusive(&source).expect("confirmed close releases custody despite postflight failure"));
    create_backup(&source, &backup).expect("postflight error did not poison admission");
    drop(exclusive(&source).expect("successful backup explicitly closed and released custody"));
    let (directory, source, backup, _) = paths();
    drop(SqliteLedger::open(&source).unwrap());
    let moved = directory.path().join("retained-private");
    let recorded = directory.path().join("registered-path");
    let marker = recorded.clone();
    let error = super::create::with_before_close(
        move |admitted| {
            let path = Path::new(admitted.connection.path().unwrap())
                .parent()
                .unwrap();
            fs::write(marker, path.as_os_str().as_encoded_bytes()).unwrap();
            fs::rename(path, moved).unwrap();
            fs::create_dir(path).unwrap();
            fs::write(path.join("peer"), b"preserve-peer").unwrap();
        },
        || create_backup_inner(&source, &backup, Some(FaultPoint::AfterCopy)),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("SQLITE_PREFLIGHT_CLEANUP_FAILED"));
    assert!(error.to_string().contains("injected maintenance failure"));
    assert!(!error.to_string().contains("SQLITE_CLOSE_RESTART_REQUIRED"));
    let registered = PathBuf::from(fs::read_to_string(recorded).unwrap());
    assert!(error.to_string().contains(registered.to_str().unwrap()));
    assert_eq!(fs::read(registered.join("peer")).unwrap(), b"preserve-peer");
    fs::remove_dir_all(registered).unwrap();
    drop(exclusive(&source).unwrap());
    create_backup(&source, &backup).expect("cleanup failure did not poison admission");
}

#[cfg(target_os = "linux")]
fn failed_close_child(root: &Path) {
    use std::io::Read;
    let source = root.join("source.sqlite");
    let output = root.join("close.sqlite");
    let primary = std::env::var("BULLET_BACKUP_CLOSE_PRIMARY").unwrap() == "yes";
    let preflight = std::env::var("BULLET_BACKUP_PREFLIGHT_CLOSE").unwrap() == "yes";
    if preflight && primary {
        Connection::open(&source)
            .unwrap()
            .execute_batch("PRAGMA user_version=999")
            .unwrap();
    }
    let error = super::create::with_before_close(
        |source| {
            // A real outstanding sqlite3_stmt makes sqlite3_close return SQLITE_BUSY.
            std::mem::forget(source.connection.prepare("SELECT 1").unwrap());
        },
        || create_backup_inner(&source, &output, primary.then_some(FaultPoint::AfterCopy)),
    )
    .unwrap_err();
    let detail = error.to_string();
    assert!(detail.contains("SQLITE_CLOSE_RESTART_REQUIRED"), "{detail}");
    assert!(detail.contains("unfinalized statements"), "{detail}");
    assert_eq!(
        detail.contains("injected maintenance failure"),
        primary && !preflight
    );
    assert_eq!(output.exists(), !primary && !preflight);
    if preflight && primary {
        assert!(detail.contains("user_version"), "{detail}");
    }
    let retained = fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("bullet-sqlite-preflight-")
        })
        .unwrap()
        .path();
    assert!(detail.contains(retained.to_str().unwrap()), "{detail}");
    assert!(retained.join("source.sqlite").exists());
    for _ in 0..2 {
        let absent = root.join("must-not-create.sqlite");
        let error = crate::sqlite::open::connection(&absent).err().unwrap();
        assert!(error.to_string().contains("SQLITE_CLOSE_RESTART_REQUIRED"));
        assert!(!absent.exists());
        assert!(create_backup(&source, root.join("must-not-backup.sqlite"))
            .unwrap_err()
            .to_string()
            .contains("SQLITE_CLOSE_RESTART_REQUIRED"));
        assert!(!root.join("must-not-backup.sqlite").exists());
    }
    fs::write(root.join("ready"), detail).unwrap();
    std::io::stdin().read_exact(&mut [0_u8]).unwrap();
}
