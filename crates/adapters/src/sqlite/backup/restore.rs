// jankurai:allow repo-rot.path.fake-versioned-source reason=live quarantined restore, not a parked tree copy owner=adapters expires=2027-03-08
//! Supported snapshots restore into quarantine without migration or activation.

use super::staged::{cleanup, ensure_healthy, finish, publish, with_connection};
#[cfg(test)]
pub(super) use super::staged::{hook, with_hook};
use super::{
    copy_and_digest, digest_file, fail, force_single_file, migrations, open_regular_nofollow,
    phase, receipt_mismatch, require_absent, require_unix, schema_error, staging_file,
    validate_receipt, verify_integrity, verify_published_backup, BackupReceipt, Connection,
    FaultPoint, NamedTempFile, Path, RestoreReceipt, SqliteMaintenanceError, INTEGRITY_PASS,
};
use rusqlite::{params, TransactionBehavior};

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
    ensure_healthy()?;
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
