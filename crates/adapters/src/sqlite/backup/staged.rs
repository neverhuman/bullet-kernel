// jankurai:allow repo-rot.path.fake-versioned-source reason=live backup/restore staging, not a parked tree copy owner=adapters expires=2027-03-08
//! Shared ownership for real backup and restore staging operations.

use super::{
    fail, open, phase, Connection, FaultPoint, File, NamedTempFile, Path, SqliteMaintenanceError,
};
use rusqlite::OpenFlags;
use std::sync::atomic::Ordering;

type Result<T> = std::result::Result<T, SqliteMaintenanceError>;

pub(super) fn ensure_healthy() -> Result<()> {
    // A failed close does not revoke calls already in flight.
    if open::CLOSE_FAILED.load(Ordering::Acquire) {
        return Err(phase(
            "OPEN",
            "SQLITE_CLOSE_RESTART_REQUIRED: a prior SQLite handle failed to close",
        ));
    }
    Ok(())
}

pub(super) fn with_connection<T>(
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

pub(super) fn finish<T>(primary: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (primary, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(phase(
            "FINALIZE",
            format!("{primary}; additionally {cleanup}"),
        )),
    }
}

pub(super) fn cleanup(mut staged: NamedTempFile) -> Result<()> {
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

pub(super) fn publish(staged: NamedTempFile, destination: &Path) -> Result<()> {
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
pub(super) fn hook(phase: &str, connection: Option<&Connection>, path: &Path) {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::sqlite::{
        backup::{create_backup_inner, migrations, restore_backup},
        SqliteLedger,
    };
    use rustix::fs::{flock, FlockOperation};
    use std::{
        ffi::OsString,
        fs::{self, OpenOptions},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };

    fn fixture(path: &Path, prefix: bool) {
        if prefix {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            let mut connection = Connection::open(path).unwrap();
            migrations::initialize_backup_prefix_fixture(&mut connection).unwrap();
            connection.close().unwrap();
        } else {
            drop(SqliteLedger::open(path).unwrap());
        }
    }

    fn inventory(path: &Path) -> Vec<(OsString, u64, u64, Vec<u8>)> {
        let mut entries = fs::read_dir(path)
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
    fn backup_output_busy_retains_handles_and_source_finalizes_before_process_exit() {
        const TEST: &str = "sqlite::backup::staged::tests::backup_output_busy_retains_handles_and_source_finalizes_before_process_exit";
        if let Some(source) = std::env::var_os("BULLET_BACKUP_STAGE_SOURCE") {
            let source = std::path::PathBuf::from(source);
            let output =
                std::path::PathBuf::from(std::env::var_os("BULLET_BACKUP_STAGE_OUTPUT").unwrap());
            let selected = std::env::var("BULLET_BACKUP_STAGE_PHASE").unwrap();
            let paired = std::env::var_os("BULLET_BACKUP_STAGE_PRIMARY").is_some();
            let fault = paired.then_some(if selected == "COPY" {
                FaultPoint::AfterCopy
            } else {
                FaultPoint::AfterVerify
            });
            let source_before = inventory(source.parent().unwrap());
            let marker = output.join("retained-path");
            let marker_copy = marker.clone();
            let source_copy = source.clone();
            let error = with_hook(
                Box::new(move |phase, connection, path| {
                    if phase == selected {
                        // The original admitted source remains under SH through the producer.
                        let contender = File::open(&source_copy).unwrap();
                        assert!(
                            flock(&contender, FlockOperation::NonBlockingLockExclusive).is_err()
                        );
                        let statement = connection.unwrap().prepare("SELECT 1").unwrap();
                        std::mem::forget(statement);
                        fs::write(&marker_copy, path.as_os_str().as_encoded_bytes()).unwrap();
                    }
                }),
                || create_backup_inner(&source, &output.join("backup.sqlite"), fault),
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
            assert!(!output.join("backup.sqlite").exists());
            let descriptors = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                .collect::<Vec<_>>();
            assert!(
                descriptors.iter().filter(|path| **path == retained).count() >= 2,
                "both output owners must remain live: {descriptors:?}"
            );
            // All Backup objects ended before close; independent private output
            // retention cannot keep the successfully finalized source in use.
            let source_probe = File::open(&source).unwrap();
            flock(&source_probe, FlockOperation::NonBlockingLockExclusive).unwrap();
            drop(source_probe);
            assert_eq!(inventory(source.parent().unwrap()), source_before);
            fs::write(output.join("existing"), b"peer").unwrap();
            let before = inventory(&output);
            let error = create_backup_inner(&source, &output.join("existing"), None).unwrap_err();
            assert!(
                error.to_string().contains("SQLITE_CLOSE_RESTART_REQUIRED"),
                "poison must precede destination admission: {error}"
            );
            assert!(SqliteLedger::open(output.join("new.sqlite"))
                .err()
                .unwrap()
                .to_string()
                .contains("SQLITE_CLOSE_RESTART_REQUIRED"));
            assert_eq!(inventory(&output), before);
            return;
        }
        for prefix in [false, true] {
            let input = crate::test_support::private_tempdir();
            let source = input.path().join("source.sqlite");
            fixture(&source, prefix);
            let before = inventory(input.path());
            for selected in ["COPY", "VERIFY"] {
                for paired in [false, true] {
                    let output = crate::test_support::private_tempdir();
                    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                    command
                        .args(["--exact", TEST])
                        .env("BULLET_BACKUP_STAGE_SOURCE", &source)
                        .env("BULLET_BACKUP_STAGE_OUTPUT", output.path())
                        .env("BULLET_BACKUP_STAGE_PHASE", selected);
                    if paired {
                        command.env("BULLET_BACKUP_STAGE_PRIMARY", "1");
                    }
                    let child = command.output().unwrap();
                    assert!(
                        child.status.success(),
                        "{}\n{}",
                        String::from_utf8_lossy(&child.stdout),
                        String::from_utf8_lossy(&child.stderr)
                    );
                    let retained = fs::read_to_string(output.path().join("retained-path")).unwrap();
                    let connection = Connection::open(&retained).unwrap();
                    connection
                        .execute_batch("BEGIN EXCLUSIVE; ROLLBACK")
                        .unwrap();
                    migrations::inspect_existing(&connection, false).unwrap();
                    connection.close().unwrap();
                    let backup = output.path().join("retry.sqlite");
                    let receipt = create_backup_inner(&source, &backup, None).unwrap();
                    restore_backup(&backup, &receipt, output.path().join("restore.sqlite"))
                        .unwrap();
                    assert_eq!(inventory(input.path()), before);
                }
            }
        }
    }

    #[test]
    fn backup_closed_stages_preserve_cleanup_peers_and_publication_collisions() {
        for prefix in [false, true] {
            let input = crate::test_support::private_tempdir();
            let source = input.path().join("source.sqlite");
            fixture(&source, prefix);
            let before = inventory(input.path());
            for point in [
                FaultPoint::AfterCopy,
                FaultPoint::AfterSync,
                FaultPoint::AfterVerify,
                FaultPoint::BeforePublish,
            ] {
                let output = crate::test_support::private_tempdir();
                let error = with_hook(
                    Box::new(|phase, _, path| {
                        if phase == "CLEANUP" {
                            fs::rename(path, path.with_extension("retained")).unwrap();
                            fs::write(path, b"peer-generation").unwrap();
                        }
                    }),
                    || {
                        create_backup_inner(
                            &source,
                            &output.path().join("backup.sqlite"),
                            Some(point),
                        )
                    },
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains("injected maintenance failure"),
                    "{error}"
                );
                assert!(
                    error
                        .to_string()
                        .contains("staging path no longer identifies"),
                    "{error}"
                );
                assert!(!output.path().join("backup.sqlite").exists());
                let retained = inventory(output.path());
                assert_eq!(retained.len(), 2);
                assert!(retained.iter().any(|entry| entry.3 == b"peer-generation"));
                create_backup_inner(&source, &output.path().join("retry.sqlite"), None).unwrap();
                assert_eq!(inventory(input.path()), before);
            }
            for substitution in [false, true] {
                let output = crate::test_support::private_tempdir();
                let destination = output.path().join("backup.sqlite");
                let peer = destination.clone();
                let error = with_hook(
                    Box::new(move |phase, _, path| {
                        if phase == "VERIFY" {
                            fs::write(&peer, b"existing-published-peer").unwrap();
                        }
                        if phase == "CLEANUP" && substitution {
                            fs::rename(path, path.with_extension("retained")).unwrap();
                            fs::write(path, b"cleanup-peer").unwrap();
                        }
                    }),
                    || create_backup_inner(&source, &destination, None),
                )
                .unwrap_err();
                assert!(error.to_string().contains("DESTINATION_EXISTS"), "{error}");
                assert_eq!(fs::read(&destination).unwrap(), b"existing-published-peer");
                assert_eq!(
                    inventory(output.path()).len(),
                    if substitution { 3 } else { 1 }
                );
                if substitution {
                    assert!(
                        error
                            .to_string()
                            .contains("staging path no longer identifies"),
                        "{error}"
                    );
                }
                create_backup_inner(&source, &output.path().join("retry.sqlite"), None).unwrap();
                assert_eq!(inventory(input.path()), before);
            }
        }
    }
}
