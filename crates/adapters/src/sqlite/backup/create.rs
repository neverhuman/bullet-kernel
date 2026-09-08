//! Verified backup production with explicit admitted-source finalization.
//! Authentic supported prefixes may be preserved. Restores of verified receipts
//! remain quarantined and grant no serving or upgrade authority.

use super::{
    digest_file, fail, force_single_file, migrations, open, phase, publish, receipt_mismatch,
    require_absent, require_unix, schema_error, staging_file, verify_integrity,
    verify_published_backup, BackupReceipt, FaultPoint, SqliteMaintenanceError, FORMAT_VERSION,
    INTEGRITY_PASS,
};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use std::{path::Path, time::Duration};

pub(super) fn create_backup_inner(
    source: &Path,
    destination: &Path,
    fault: Option<FaultPoint>,
) -> Result<BackupReceipt, SqliteMaintenanceError> {
    require_unix()?;
    require_absent(destination)?;
    let source = open::backup_read_only(source).map_err(|error| phase("OPEN", error))?;
    let produced = copy_snapshot(&source, destination, fault);
    #[cfg(test)]
    if let Some(hook) = BEFORE_CLOSE.with(|slot| slot.borrow_mut().take()) {
        hook(&source);
    }
    let finalized = open::close_backup(source).map_err(|error| phase("CLOSE", error));
    match (produced, finalized) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(phase("CLOSE", format!("{primary}; {cleanup}"))),
    }
}

fn copy_snapshot(
    source: &open::AdmittedConnection,
    destination: &Path,
    fault: Option<FaultPoint>,
) -> Result<BackupReceipt, SqliteMaintenanceError> {
    let source_schema =
        migrations::inspect_existing(&source.connection, false).map_err(schema_error)?;
    let mut staged = staging_file(destination, "backup")?;
    let mut snapshot = Connection::open(staged.path()).map_err(|err| phase("COPY", err))?;
    {
        let copy =
            Backup::new(&source.connection, &mut snapshot).map_err(|err| phase("COPY", err))?;
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
    let copied_schema = migrations::inspect_existing(&verified, false).map_err(schema_error)?;
    verify_integrity(&verified)?;
    if copied_schema.schema_state() != source_schema.schema_state()
        || copied_schema.restore_state() != source_schema.restore_state()
        || copied_schema.schema_digest() != source_schema.schema_digest()
    {
        return Err(receipt_mismatch(
            "schema or restore state changed during online backup",
        ));
    }
    drop(verified);
    let (snapshot_digest, snapshot_bytes) = digest_file(staged.as_file_mut())?;
    let receipt = BackupReceipt {
        format_version: FORMAT_VERSION,
        snapshot_digest,
        snapshot_bytes,
        schema_digest: copied_schema.schema_digest().to_owned(),
        restore_epoch: copied_schema.restore_state().epoch,
        integrity: INTEGRITY_PASS.into(),
    };
    fail(fault, FaultPoint::AfterVerify, "VERIFY")?;
    fail(fault, FaultPoint::BeforePublish, "PUBLISH")?;
    open::postflight(source).map_err(|error| phase("PUBLISH", error))?;
    publish(staged, destination)?;
    verify_published_backup(destination, &receipt)?;
    open::postflight(source).map_err(|error| phase("READBACK", error))?;
    Ok(receipt)
}

#[cfg(test)]
type CloseHook = Box<dyn FnOnce(&open::AdmittedConnection)>;

#[cfg(test)]
thread_local! {
    static BEFORE_CLOSE: std::cell::RefCell<Option<CloseHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn with_before_close<T>(
    hook: impl FnOnce(&open::AdmittedConnection) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<CloseHook>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BEFORE_CLOSE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(BEFORE_CLOSE.with(|slot| slot.replace(Some(Box::new(hook)))));
    operation()
}

#[cfg(all(test, target_os = "linux"))]
#[path = "prefix_tests.rs"]
mod prefix_tests;
