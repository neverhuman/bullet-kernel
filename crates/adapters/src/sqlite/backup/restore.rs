//! Supported snapshots restore into quarantine without migration or activation.

use super::{
    copy_and_digest, digest_file, fail, force_single_file, migrations, open, open_regular_nofollow,
    phase, receipt_mismatch, require_absent, require_unix, schema_error, staging_file,
    validate_receipt, verify_integrity, verify_published_backup, BackupReceipt, Connection,
    FaultPoint, File, NamedTempFile, Path, RestoreReceipt, SqliteMaintenanceError, INTEGRITY_PASS,
};
use rusqlite::{params, OpenFlags, TransactionBehavior};
use std::sync::atomic::Ordering;

type Result<T> = std::result::Result<T, SqliteMaintenanceError>;

struct Transition {
    prior: migrations::VerifiedSchema,
    next_epoch: u64,
}

pub(super) fn restore_backup_inner(
    backup: &Path,
    receipt: &BackupReceipt,
    destination: &Path,
    fault: Option<FaultPoint>,
) -> Result<RestoreReceipt> {
    // Shares admission poison with serving and backup. In-flight calls are not revoked.
    if open::CLOSE_FAILED.load(Ordering::Acquire) {
        return Err(phase(
            "OPEN",
            "SQLITE_CLOSE_RESTART_REQUIRED: a prior SQLite handle failed to close",
        ));
    }
    require_unix()?;
    validate_receipt(receipt)?;
    require_absent(destination)?;
    let staged = copy_subject(backup, receipt, destination, "restore", fault)?;
    let (mut staged, transition) = with_connection(
        staged,
        false,
        "TRANSITION",
        fault,
        FaultPoint::AfterTransition,
        |connection| transition(connection, receipt),
    )?;
    let subject = (|| {
        staged
            .as_file()
            .sync_all()
            .map_err(|error| phase("SYNC", error))?;
        let subject = digest_file(staged.as_file_mut())?;
        if subject.1 > 1024 * 1024 * 1024 {
            return Err(phase(
                "VERIFY",
                "restored database exceeds the 1 GiB snapshot bound",
            ));
        }
        fail(fault, FaultPoint::AfterVerify, "VERIFY")?;
        fail(fault, FaultPoint::BeforePublish, "PUBLISH")?;
        Ok(subject)
    })();
    let (restored_digest, restored_bytes) = match subject {
        Ok(subject) => subject,
        Err(error) => return finish(Err(error), cleanup(staged)),
    };
    publish(staged, destination)?;
    #[cfg(test)]
    hook("PUBLISHED", None, destination);
    fail(fault, FaultPoint::AfterPublish, "PUBLISH")?;
    // SQLite never opens the published name or the admitted backup name. Sidecars
    // there cannot cause recovery writes during this sampled receipt readback.
    let published = BackupReceipt {
        snapshot_digest: restored_digest.clone(),
        snapshot_bytes: restored_bytes,
        ..receipt.clone()
    };
    let readback = copy_subject(
        destination,
        &published,
        destination,
        "restore-readback",
        None,
    )?;
    let (readback, ()) = with_connection(
        readback,
        true,
        "READBACK",
        fault,
        FaultPoint::AfterReadback,
        |connection| verify_quarantine(connection, &transition, receipt),
    )?;
    cleanup(readback)?;
    verify_published_backup(destination, &published)?;
    Ok(RestoreReceipt {
        backup: receipt.clone(),
        restored_digest,
        restored_bytes,
        previous_restore_epoch: transition.prior.restore_state().epoch,
        restore_epoch: transition.next_epoch,
        pending_authority_admission: true,
        integrity: INTEGRITY_PASS.into(),
    })
}

fn copy_subject(
    source: &Path,
    receipt: &BackupReceipt,
    destination: &Path,
    kind: &str,
    fault: Option<FaultPoint>,
) -> Result<NamedTempFile> {
    let mut input = open_regular_nofollow(source, receipt.snapshot_bytes)?;
    let mut staged = staging_file(destination, kind)?;
    let copied = (|| {
        let digest = copy_and_digest(&mut input, staged.as_file_mut(), receipt.snapshot_bytes)?;
        fail(fault, FaultPoint::AfterCopy, "COPY")?;
        if digest != receipt.snapshot_digest {
            return Err(receipt_mismatch(
                "backup bytes do not match the retained receipt",
            ));
        }
        staged
            .as_file()
            .sync_all()
            .map_err(|error| phase("SYNC", error))?;
        fail(fault, FaultPoint::AfterSync, "SYNC")
    })();
    match copied {
        Ok(()) => Ok(staged),
        Err(error) => finish(Err(error), cleanup(staged)),
    }
}

fn transition(connection: &mut Connection, receipt: &BackupReceipt) -> Result<Transition> {
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(schema_error)?;
    let prior = migrations::inspect_existing(connection, false).map_err(schema_error)?;
    verify_integrity(connection)?;
    let schema_digest = match prior.schema_state() {
        migrations::SchemaState::Current => migrations::schema_contract_digest(),
        migrations::SchemaState::UpgradeRequired { .. } => prior.schema_digest().to_owned(),
    };
    if schema_digest != receipt.schema_digest {
        return Err(receipt_mismatch(
            "backup schema contract does not match the retained receipt",
        ));
    }
    if prior.restore_state().epoch != receipt.restore_epoch {
        return Err(receipt_mismatch(
            "backup restore epoch does not match the retained receipt",
        ));
    }
    force_single_file(connection)?;
    let next_epoch = prior
        .restore_state()
        .epoch
        .checked_add(1)
        .ok_or_else(|| receipt_mismatch("restore epoch cannot advance"))?;
    let next_epoch_i64 = i64::try_from(next_epoch)
        .map_err(|_| receipt_mismatch("restore epoch exceeds SQLite range"))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(schema_error)?;
    let changed = transaction
        .execute(
            "UPDATE restore_state SET restore_epoch = ?1, pending_admission = 1,
         source_snapshot_digest = ?2, restored_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE singleton = 1 AND restore_epoch = ?3 AND pending_admission = 0",
            params![
                next_epoch_i64,
                receipt.snapshot_digest,
                receipt.restore_epoch
            ],
        )
        .map_err(schema_error)?;
    if changed != 1 {
        return Err(receipt_mismatch(
            "restore epoch transition matched zero rows",
        ));
    }
    // Existing restore invalidation triggers remain active in both supported catalogs.
    transaction.commit().map_err(schema_error)?;
    let transition = Transition { prior, next_epoch };
    verify_quarantine(connection, &transition, receipt)?;
    Ok(transition)
}

fn verify_quarantine(
    connection: &Connection,
    expected: &Transition,
    receipt: &BackupReceipt,
) -> Result<()> {
    let actual = migrations::inspect_existing(connection, true).map_err(schema_error)?;
    verify_integrity(connection)?;
    let source: String = connection
        .query_row(
            "SELECT source_snapshot_digest FROM restore_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(schema_error)?;
    if actual.schema_state() != expected.prior.schema_state()
        || actual.schema_digest() != expected.prior.schema_digest()
        || actual.authority() != expected.prior.authority()
        || actual.restore_state().epoch != expected.next_epoch
        || !actual.restore_state().pending_admission
        || source != receipt.snapshot_digest
    {
        return Err(receipt_mismatch(
            "restored schema, authority or quarantine differs from the admitted transition",
        ));
    }
    Ok(())
}

fn with_connection<T>(
    staged: NamedTempFile,
    readonly: bool,
    phase_name: &'static str,
    fault: Option<FaultPoint>,
    close_fault: FaultPoint,
    operation: impl FnOnce(&mut Connection) -> Result<T>,
) -> Result<(NamedTempFile, T)> {
    let access = if readonly {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let opened = Connection::open_with_flags(
        staged.path(),
        access | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    );
    let mut connection = match opened {
        Ok(connection) => connection,
        Err(error) => return finish(Err(phase(phase_name, error)), cleanup(staged)),
    };
    let result = operation(&mut connection).and_then(|value| {
        fail(fault, close_fault, phase_name)?;
        Ok(value)
    });
    #[cfg(test)]
    hook(phase_name, Some(&connection), staged.path());
    if let Err((connection, error)) = connection.close() {
        open::CLOSE_FAILED.store(true, Ordering::Release);
        let failure = phase(
            "CLOSE",
            format!(
                "SQLITE_CLOSE_RESTART_REQUIRED: {phase_name} handle retained at {}: {error}",
                staged.path().display(),
            ),
        );
        // rusqlite Drop retries and discards SQLITE_BUSY. Retain both owners until
        // process death instead; future admissions fail before filesystem effects.
        std::mem::forget((connection, staged));
        return Err(match result {
            Ok(_) => failure,
            Err(primary) => phase("FINALIZE", format!("{primary}; additionally {failure}")),
        });
    }
    match result {
        Ok(value) => Ok((staged, value)),
        Err(error) => finish(Err(error), cleanup(staged)),
    }
}

fn finish<T>(primary: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (primary, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(phase(
            "FINALIZE",
            format!("{primary}; additionally {cleanup}"),
        )),
    }
}

fn cleanup(mut staged: NamedTempFile) -> Result<()> {
    #[cfg(test)]
    hook("CLEANUP", None, staged.path());
    let path = staged.path().to_path_buf();
    let checked = same_file(&staged);
    if let Err(error) = checked {
        // Sampled same-UID substitution refusal, not atomic hostile path custody.
        staged.disable_cleanup(true);
        return Err(phase(
            "CLEANUP",
            format!("retained {}: {error}", path.display()),
        ));
    }
    staged
        .close()
        .map_err(|error| phase("CLEANUP", format!("retained {}: {error}", path.display())))
}

#[cfg(unix)]
fn same_file(staged: &NamedTempFile) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let held = staged.as_file().metadata()?;
    let named = std::fs::symlink_metadata(staged.path())?;
    if !named.is_file() || (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(std::io::Error::other(
            "staging path no longer identifies the held file",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn same_file(_staged: &NamedTempFile) -> std::io::Result<()> {
    Err(std::io::Error::other("unsupported publication platform"))
}

fn publish(staged: NamedTempFile, destination: &Path) -> Result<()> {
    let file = match staged.persist_noclobber(destination) {
        Ok(file) => file,
        Err(error) => {
            let primary = if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                SqliteMaintenanceError::DestinationExists(destination.to_path_buf())
            } else {
                phase("PUBLISH", error.error)
            };
            return finish(Err(primary), cleanup(error.file));
        }
    };
    file.sync_all().map_err(|error| phase("PUBLISH", error))?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| phase("PUBLISH", error))
}

#[cfg(test)]
type Hook = Box<dyn FnMut(&str, Option<&Connection>, &Path)>;
#[cfg(test)]
thread_local! { static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
fn hook(phase: &str, connection: Option<&Connection>, path: &Path) {
    HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(phase, connection, path);
        }
    });
}
#[cfg(test)]
pub(super) fn with_hook<T>(hook: Hook, operation: impl FnOnce() -> T) -> T {
    struct Reset(Option<Hook>);
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(HOOK.with(|slot| slot.replace(Some(hook))));
    operation()
}
