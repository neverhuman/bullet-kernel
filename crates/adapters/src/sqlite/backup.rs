//! Offline, receipt-bound SQLite backup and quarantined restore.

use super::migrations;
use rusqlite::{backup::Backup, params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const INTEGRITY_PASS: &str = "PASS";

/// Exact subject receipt for one consistent SQLite snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    /// Backup receipt schema version.
    pub format_version: u32,
    /// BLAKE3 of the exact standalone SQLite bytes.
    pub snapshot_digest: String,
    /// Exact byte count hashed by `snapshot_digest`.
    pub snapshot_bytes: u64,
    /// BLAKE3 contract for the ordered embedded migration set.
    pub schema_digest: String,
    /// Restore epoch observed inside this snapshot.
    pub restore_epoch: u64,
    /// `PASS` only after exact-schema, FK, and SQLite integrity checks.
    pub integrity: String,
}

/// Receipt for an atomically published but authority-quarantined restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    /// Exact backup subject admitted by the caller.
    pub backup: BackupReceipt,
    /// BLAKE3 of the restored bytes after the epoch transition.
    pub restored_digest: String,
    /// Exact restored byte count.
    pub restored_bytes: u64,
    /// Epoch in the admitted backup.
    pub previous_restore_epoch: u64,
    /// Epoch persisted in the quarantined restored database.
    pub restore_epoch: u64,
    /// Always true in V1: production admission is deliberately unavailable.
    pub pending_authority_admission: bool,
    /// `PASS` only after post-transition schema, FK, and integrity checks.
    pub integrity: String,
}

/// Offline backup/restore failure.
#[derive(Debug, Error)]
pub enum SqliteMaintenanceError {
    /// V1 cannot prove durable no-replace publication on this platform.
    #[error("UNSUPPORTED_PLATFORM: durable no-replace SQLite publication is Unix-only in V1")]
    UnsupportedPlatform,
    /// The destination was already materialized and was not touched.
    #[error("DESTINATION_EXISTS: refusing to replace {0}")]
    DestinationExists(PathBuf),
    /// The retained receipt does not identify the supplied bytes or schema.
    #[error("BACKUP_RECEIPT_MISMATCH: {0}")]
    ReceiptMismatch(String),
    /// A bounded maintenance phase failed before a verified receipt existed.
    #[error("SQLITE_MAINTENANCE_{phase}: {detail}")]
    Operation {
        /// Stable phase for logs and negative tests.
        phase: &'static str,
        /// Underlying failure without optimistic interpretation.
        detail: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPoint {
    AfterCopy,
    AfterSync,
    AfterVerify,
    BeforePublish,
}

/// Create a WAL-consistent, standalone SQLite backup at an absent path.
/// The returned receipt is an integrity/subject receipt, not an authenticity
/// claim. Retain it separately and require it when restoring.
///
/// # Errors
/// Fails closed for an unrecognized, corrupt, or quarantined source; any I/O
/// or SQLite failure; or an existing output path.
pub fn create_backup(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<BackupReceipt, SqliteMaintenanceError> {
    create_backup_inner(source.as_ref(), destination.as_ref(), None)
}

/// Restore exact admitted backup bytes into a new, quarantined database.
/// The destination must not exist. V1 intentionally has no authority-admission
/// operation, so normal `SqliteLedger::open` rejects the published result.
///
/// # Errors
/// Fails closed on receipt mismatch, corruption, partial/future schema,
/// restore-epoch mismatch, I/O failure, or an existing destination.
pub fn restore_backup(
    backup: impl AsRef<Path>,
    receipt: &BackupReceipt,
    destination: impl AsRef<Path>,
) -> Result<RestoreReceipt, SqliteMaintenanceError> {
    restore_backup_inner(backup.as_ref(), receipt, destination.as_ref(), None)
}

fn create_backup_inner(
    source: &Path,
    destination: &Path,
    fault: Option<FaultPoint>,
) -> Result<BackupReceipt, SqliteMaintenanceError> {
    require_unix()?;
    require_absent(destination)?;
    let source = open_database_read_only(source)?;
    let source_state = migrations::verify_existing(&source, false).map_err(schema_error)?;
    let mut staged = staging_file(destination, "backup")?;
    let mut snapshot = Connection::open(staged.path()).map_err(|err| phase("COPY", err))?;
    {
        let copy = Backup::new(&source, &mut snapshot).map_err(|err| phase("COPY", err))?;
        copy.run_to_completion(128, Duration::from_millis(5), None)
            .map_err(|err| phase("COPY", err))?;
    }
    force_single_file(&snapshot)?;
    drop(snapshot);
    fail(fault, FaultPoint::AfterCopy, "COPY")?;

    staged
        .as_file()
        .sync_all()
        .map_err(|err| phase("SYNC", err))?;
    fail(fault, FaultPoint::AfterSync, "SYNC")?;

    let verified = Connection::open_with_flags(
        staged.path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| phase("VERIFY", err))?;
    let copied_state = migrations::verify_existing(&verified, false).map_err(schema_error)?;
    verify_integrity(&verified)?;
    if copied_state != source_state {
        return Err(receipt_mismatch(
            "restore epoch changed during online backup",
        ));
    }
    drop(verified);
    let (snapshot_digest, snapshot_bytes) = digest_file(staged.as_file_mut())?;
    let receipt = BackupReceipt {
        format_version: FORMAT_VERSION,
        snapshot_digest,
        snapshot_bytes,
        schema_digest: migrations::schema_contract_digest(),
        restore_epoch: copied_state.epoch,
        integrity: INTEGRITY_PASS.into(),
    };
    fail(fault, FaultPoint::AfterVerify, "VERIFY")?;
    fail(fault, FaultPoint::BeforePublish, "PUBLISH")?;
    publish(staged, destination)?;
    Ok(receipt)
}

fn restore_backup_inner(
    backup: &Path,
    receipt: &BackupReceipt,
    destination: &Path,
    fault: Option<FaultPoint>,
) -> Result<RestoreReceipt, SqliteMaintenanceError> {
    require_unix()?;
    validate_receipt(receipt)?;
    require_absent(destination)?;
    let mut input = open_regular_nofollow(backup, receipt.snapshot_bytes)?;
    let mut staged = staging_file(destination, "restore")?;
    let copied_digest = copy_and_digest(&mut input, staged.as_file_mut(), receipt.snapshot_bytes)?;
    fail(fault, FaultPoint::AfterCopy, "COPY")?;
    if copied_digest != receipt.snapshot_digest {
        return Err(receipt_mismatch(
            "backup bytes do not match the retained receipt",
        ));
    }

    staged
        .as_file()
        .sync_all()
        .map_err(|err| phase("SYNC", err))?;
    fail(fault, FaultPoint::AfterSync, "SYNC")?;

    let mut restored = Connection::open(staged.path()).map_err(|err| phase("VERIFY", err))?;
    let prior = migrations::verify_existing(&restored, false).map_err(schema_error)?;
    verify_integrity(&restored)?;
    if prior.epoch != receipt.restore_epoch {
        return Err(receipt_mismatch(
            "backup restore epoch does not match the retained receipt",
        ));
    }
    force_single_file(&restored)?;
    let next_epoch = prior
        .epoch
        .checked_add(1)
        .ok_or_else(|| receipt_mismatch("restore epoch cannot advance"))?;
    let next_epoch_i64 = i64::try_from(next_epoch)
        .map_err(|_| receipt_mismatch("restore epoch exceeds SQLite range"))?;
    let transaction = restored
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| phase("VERIFY", err))?;
    let changed = transaction
        .execute(
            "UPDATE restore_state
             SET restore_epoch = ?1, pending_admission = 1,
                 source_snapshot_digest = ?2,
                 restored_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE singleton = 1 AND restore_epoch = ?3 AND pending_admission = 0",
            params![
                next_epoch_i64,
                receipt.snapshot_digest,
                i64::try_from(prior.epoch)
                    .map_err(|_| receipt_mismatch("backup restore epoch exceeds SQLite range"))?
            ],
        )
        .map_err(|err| phase("VERIFY", err))?;
    if changed != 1 {
        return Err(receipt_mismatch(
            "restore epoch transition matched zero rows",
        ));
    }
    transaction.commit().map_err(|err| phase("VERIFY", err))?;
    let state = migrations::verify_existing(&restored, true).map_err(schema_error)?;
    verify_integrity(&restored)?;
    if state.epoch != next_epoch || !state.pending_admission {
        return Err(receipt_mismatch(
            "restored database did not enter quarantine at the next epoch",
        ));
    }
    drop(restored);
    staged
        .as_file()
        .sync_all()
        .map_err(|err| phase("SYNC", err))?;
    let (restored_digest, restored_bytes) = digest_file(staged.as_file_mut())?;
    fail(fault, FaultPoint::AfterVerify, "VERIFY")?;
    fail(fault, FaultPoint::BeforePublish, "PUBLISH")?;
    publish(staged, destination)?;
    Ok(RestoreReceipt {
        backup: receipt.clone(),
        restored_digest,
        restored_bytes,
        previous_restore_epoch: prior.epoch,
        restore_epoch: next_epoch,
        pending_authority_admission: true,
        integrity: INTEGRITY_PASS.into(),
    })
}

fn validate_receipt(receipt: &BackupReceipt) -> Result<(), SqliteMaintenanceError> {
    if receipt.format_version != FORMAT_VERSION {
        return Err(receipt_mismatch("unsupported or future receipt format"));
    }
    if receipt.integrity != INTEGRITY_PASS {
        return Err(receipt_mismatch("receipt has no passing integrity result"));
    }
    if receipt.schema_digest != migrations::schema_contract_digest() {
        return Err(receipt_mismatch(
            "receipt schema contract is not owned by this binary",
        ));
    }
    if !is_digest(&receipt.snapshot_digest) || receipt.snapshot_bytes == 0 {
        return Err(receipt_mismatch("receipt snapshot subject is malformed"));
    }
    Ok(())
}

fn open_database_read_only(path: &Path) -> Result<Connection, SqliteMaintenanceError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|err| phase("OPEN", err))?;
    if !metadata.file_type().is_file() {
        return Err(phase("OPEN", "source database is not a regular file"));
    }
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| phase("OPEN", err))
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path, expected_bytes: u64) -> Result<File, SqliteMaintenanceError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| phase("OPEN", err))?;
    let metadata = file.metadata().map_err(|err| phase("OPEN", err))?;
    if !metadata.is_file() {
        return Err(phase("OPEN", "backup input is not a regular file"));
    }
    if metadata.len() != expected_bytes {
        return Err(receipt_mismatch(format!(
            "backup descriptor length is {}, receipt requires {expected_bytes}",
            metadata.len()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_nofollow(
    _path: &Path,
    _expected_bytes: u64,
) -> Result<File, SqliteMaintenanceError> {
    Err(SqliteMaintenanceError::UnsupportedPlatform)
}

fn staging_file(destination: &Path, kind: &str) -> Result<NamedTempFile, SqliteMaintenanceError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(phase("OPEN", "destination parent is not a directory"));
    }
    Builder::new()
        .prefix(&format!(".bullet-{kind}-"))
        .tempfile_in(parent)
        .map_err(|err| phase("OPEN", err))
}

fn force_single_file(conn: &Connection) -> Result<(), SqliteMaintenanceError> {
    conn.pragma_update(None, "journal_mode", "DELETE")
        .map_err(|err| phase("COPY", err))?;
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|err| phase("COPY", err))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(phase("COPY", "SQLite refused single-file journal mode"));
    }
    Ok(())
}

fn verify_integrity(conn: &Connection) -> Result<(), SqliteMaintenanceError> {
    let mut statement = conn
        .prepare("PRAGMA integrity_check")
        .map_err(|err| phase("VERIFY", err))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| phase("VERIFY", err))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| phase("VERIFY", err))?;
    if rows.as_slice() != ["ok"] {
        return Err(phase(
            "VERIFY",
            format!("SQLite integrity_check did not return exactly ok: {rows:?}"),
        ));
    }
    Ok(())
}

fn copy_and_digest(
    source: &mut File,
    destination: &mut File,
    expected_bytes: u64,
) -> Result<String, SqliteMaintenanceError> {
    let read_limit = expected_bytes
        .checked_add(1)
        .ok_or_else(|| receipt_mismatch("receipt byte count cannot be bounded"))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|err| phase("COPY", err))?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|err| phase("COPY", err))?;
    destination.set_len(0).map_err(|err| phase("COPY", err))?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut bounded = source.take(read_limit);
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(|err| phase("COPY", err))?;
        if read == 0 {
            break;
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|err| phase("COPY", err))?;
        hasher.update(&buffer[..read]);
        total = total
            .checked_add(u64::try_from(read).map_err(|err| phase("COPY", err))?)
            .ok_or_else(|| phase("COPY", "backup size overflow"))?;
    }
    if total < expected_bytes {
        return Err(receipt_mismatch(
            "backup ended before the receipt byte count",
        ));
    }
    if total > expected_bytes {
        return Err(receipt_mismatch("backup exceeds the receipt byte count"));
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn digest_file(file: &mut File) -> Result<(String, u64), SqliteMaintenanceError> {
    let mut source = file.try_clone().map_err(|err| phase("VERIFY", err))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|err| phase("VERIFY", err))?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|err| phase("VERIFY", err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total
            .checked_add(u64::try_from(read).map_err(|err| phase("VERIFY", err))?)
            .ok_or_else(|| phase("VERIFY", "backup size overflow"))?;
    }
    Ok((hasher.finalize().to_hex().to_string(), total))
}

fn publish(staged: NamedTempFile, destination: &Path) -> Result<(), SqliteMaintenanceError> {
    let file = staged.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            SqliteMaintenanceError::DestinationExists(destination.to_path_buf())
        } else {
            phase("PUBLISH", error.error)
        }
    })?;
    file.sync_all().map_err(|err| phase("PUBLISH", err))?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| phase("PUBLISH", err))
}

include!("backup/support.rs");

#[cfg(test)]
mod tests;
