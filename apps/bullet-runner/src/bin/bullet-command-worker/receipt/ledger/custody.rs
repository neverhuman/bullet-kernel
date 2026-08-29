//! Descriptor-bound, quiescent SQLite snapshot custody.

use super::{invalid, WorkerError};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

pub(super) fn with_snapshot<T>(
    path: &Path,
    file: &File,
    read: impl FnOnce(&Connection) -> Result<T, WorkerError>,
) -> Result<T, WorkerError> {
    reject_sidecars(path)?;
    let descriptor = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    if !descriptor.is_absolute() || descriptor.components().count() != 5 {
        return Err(invalid("ledger descriptor path is not normalized"));
    }
    let uri = format!("file:{}?mode=ro&immutable=1", descriptor.display());
    let mut connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(invalid)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(invalid)?;
    let query_only: u8 = connection
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .map_err(invalid)?;
    if query_only != 1 {
        return Err(invalid("retained ledger connection is not query-only"));
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(invalid)?;
    test_point(path, TestStage::BeforeReads);
    let result = read(&transaction);
    test_point(path, TestStage::AfterReads);
    let value = result?;
    transaction.commit().map_err(invalid)?;
    reject_sidecars(path)?;
    Ok(value)
}

fn reject_sidecars(path: &Path) -> Result<(), WorkerError> {
    // `immutable=1` deliberately prevents SQLite from performing recovery.
    // Admit only a main-file snapshot with none of SQLite's three ordinary
    // journal companions present; a hot rollback journal is no more durable
    // truth than uncheckpointed WAL state.
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(sidecar)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(invalid(error)),
            Ok(_) => return Err(invalid("retained ledger is not sidecar-free and quiescent")),
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum TestStage {
    BeforeReads,
    BetweenQueries,
    AfterReads,
}

#[cfg(not(test))]
pub(super) fn test_point(_path: &Path, _stage: TestStage) {}

#[cfg(test)]
type Hook = Box<dyn FnMut(&Path, &'static str)>;

#[cfg(test)]
thread_local! {
    static TEST_HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn test_point(path: &Path, stage: TestStage) {
    let stage = match stage {
        TestStage::BeforeReads => "before_reads",
        TestStage::BetweenQueries => "between_queries",
        TestStage::AfterReads => "after_reads",
    };
    TEST_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(path, stage);
        }
    });
}

#[cfg(test)]
pub(crate) fn install_test_hook(hook: impl FnMut(&Path, &'static str) + 'static) {
    TEST_HOOK.with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}

#[cfg(test)]
pub(crate) fn clear_test_hook() {
    TEST_HOOK.with(|slot| {
        slot.borrow_mut().take();
    });
}
