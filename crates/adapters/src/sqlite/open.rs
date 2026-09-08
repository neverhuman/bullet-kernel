use super::{migrations, store};
use bullet_application::LedgerError;
use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;

// A failed SQLite close leaves a live handle. Retain its custody until process
// exit and reject new admissions, bounding retention to already in-flight work.
static CLOSE_FAILED: AtomicBool = AtomicBool::new(false);

pub(super) struct AdmissionGuard {
    #[cfg(target_os = "linux")]
    inner: linux::Guard,
    snapshot: Option<Snapshot>,
}

struct Snapshot {
    directory: tempfile::TempDir,
    #[cfg(target_os = "linux")]
    descriptor: std::fs::File,
}
impl Snapshot {
    fn path(&self) -> &Path {
        self.directory.path()
    }
}

pub(super) struct AdmittedConnection {
    pub(super) connection: Connection,
    pub(super) guard: AdmissionGuard,
}

#[derive(Clone, Copy)]
enum ConnectionPurpose {
    Serving,
    BackupReadOnly,
}

#[cfg(target_os = "linux")]
impl ConnectionPurpose {
    fn flags(self) -> rusqlite::OpenFlags {
        use rusqlite::OpenFlags;
        let access = match self {
            Self::Serving => OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            Self::BackupReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
        };
        access | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW
    }
}

pub(super) fn connection(path: &Path) -> Result<AdmittedConnection, LedgerError> {
    admitted_connection(path, ConnectionPurpose::Serving)
}

pub(super) fn backup_read_only(path: &Path) -> Result<AdmittedConnection, LedgerError> {
    admitted_connection(path, ConnectionPurpose::BackupReadOnly)
}

fn admitted_connection(
    path: &Path,
    purpose: ConnectionPurpose,
) -> Result<AdmittedConnection, LedgerError> {
    if CLOSE_FAILED.load(Ordering::Acquire) {
        return Err(store(
            "SQLITE_CLOSE_RESTART_REQUIRED: an unclosed SQLite connection and its custody are retained until process exit; new admission is refused",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::connection(path, purpose)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, purpose);
        Err(store(
            "descriptor-admitted SQLite authority storage requires Linux",
        ))
    }
}

pub(super) fn initialized(path: &Path) -> Result<AdmittedConnection, LedgerError> {
    let mut admitted = connection(path)?;
    let initialized = (|| {
        admitted
            .connection
            .busy_timeout(Duration::from_millis(5_000))
            .map_err(store)?;
        migrations::enable_foreign_keys(&admitted.connection)?;
        migrations::verify_or_initialize(&mut admitted.connection)?;
        configure_durability(&admitted.connection)?;
        postflight(&admitted)
    })();
    match initialized {
        Ok(()) => Ok(admitted),
        Err(error) => Err(cleanup_after_failure(admitted, error)),
    }
}

pub(super) fn postflight(admitted: &AdmittedConnection) -> Result<(), LedgerError> {
    postflight_guard(&admitted.guard)
}

fn postflight_guard(guard: &AdmissionGuard) -> Result<(), LedgerError> {
    #[cfg(target_os = "linux")]
    {
        linux::postflight(&guard.inner)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = guard;
        Err(store(
            "descriptor-admitted SQLite authority storage requires Linux",
        ))
    }
}

/// Finalize a backup source while retaining custody through confirmed close.
/// A close error must not drop the returned handle: rusqlite's Drop ignores a
/// repeated SQLITE_BUSY and could leave SQLite alive after custody is released.
pub(super) fn close_backup(admitted: AdmittedConnection) -> Result<(), LedgerError> {
    let before = postflight(&admitted);
    let prior = before.as_ref().err().map(ToString::to_string);
    let guard = close_handle(admitted, prior)?;
    let after = postflight_guard(&guard);
    let cleanup = cleanup_guard(guard);
    let errors = [
        ("pre-close admission", before),
        ("post-close admission", after),
        ("cleanup", cleanup),
    ]
    .into_iter()
    .filter_map(|(phase, result)| result.err().map(|error| format!("{phase}: {error}")))
    .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(store(format!(
            "SQLITE_CLOSE_FINALIZATION_FAILED: {}",
            errors.join("; ")
        )))
    }
}

// On failure ownership deliberately remains live until process exit, including
// private files. Callers must not turn a failed close into a retryable cleanup.
fn close_handle(
    admitted: AdmittedConnection,
    prior: Option<String>,
) -> Result<AdmissionGuard, LedgerError> {
    let AdmittedConnection { connection, guard } = admitted;
    if let Err((connection, error)) = connection.close() {
        CLOSE_FAILED.store(true, Ordering::Release);
        let snapshot = guard
            .snapshot
            .as_ref()
            .map(|dir| dir.path().display().to_string());
        std::mem::forget(AdmittedConnection { connection, guard });
        return Err(store(format!(
            "SQLITE_CLOSE_RESTART_REQUIRED: SQLite close failed: {error}; connection and custody retained until process exit; private snapshot={snapshot:?}; prior={prior:?}"
        )));
    }
    Ok(guard)
}

fn cleanup_snapshot(guard: &mut AdmissionGuard) -> Result<(), LedgerError> {
    if let Some(snapshot) = guard.snapshot.take() {
        let retained = snapshot.path().to_path_buf();
        #[cfg(target_os = "linux")]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            snapshot.descriptor.metadata().and_then(|held| {
                let current = std::fs::symlink_metadata(&retained)?;
                if !current.is_dir() || held.dev() != current.dev() || held.ino() != current.ino() {
                    return Err(std::io::Error::other("private directory identity changed"));
                }
                Ok(())
            })
        };
        #[cfg(not(target_os = "linux"))]
        let identity: Result<(), std::io::Error> = Err(std::io::Error::other("Linux required"));
        let result = match identity {
            Ok(()) => snapshot.directory.close(),
            Err(error) => {
                let _ = snapshot.directory.keep();
                Err(error)
            }
        };
        result.map_err(|error| {
            store(format!(
                "SQLITE_PREFLIGHT_CLEANUP_FAILED: private snapshot cleanup refused at {}; {error}",
                retained.display()
            ))
        })?;
    }
    Ok(())
}

fn cleanup_guard(mut guard: AdmissionGuard) -> Result<(), LedgerError> {
    let snapshot = cleanup_snapshot(&mut guard);
    #[cfg(target_os = "linux")]
    let source = linux::cleanup(guard.inner);
    #[cfg(not(target_os = "linux"))]
    let source = Err(store("backup finalization requires Linux admission"));
    match (snapshot, source) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(snapshot), Err(source)) => Err(store(format!("{snapshot}; source cleanup: {source}"))),
    }
}

pub(super) fn close_quiescent(admitted: AdmittedConnection) -> Result<(), LedgerError> {
    postflight(&admitted)?;
    let checkpoint: (i64, i64, i64) = admitted
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(store)?;
    if checkpoint != (0, 0, 0) {
        return Err(store(format!(
            "SQLite quiescent checkpoint refused: {checkpoint:?}"
        )));
    }
    postflight(&admitted)?;
    let AdmittedConnection { connection, guard } = admitted;
    connection.close().map_err(|(_, error)| store(error))?;
    #[cfg(target_os = "linux")]
    {
        linux::finish_snapshot(guard.inner)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = guard;
        Err(store("quiescent SQLite snapshots require Linux admission"))
    }
}

pub(super) fn cleanup_after_failure(
    admitted: AdmittedConnection,
    original: LedgerError,
) -> LedgerError {
    #[cfg(target_os = "linux")]
    {
        let AdmittedConnection { connection, guard } = admitted;
        drop(connection);
        match linux::cleanup(guard.inner) {
            Ok(()) => original,
            Err(cleanup) => store(format!("{original}; SQLite cleanup refused: {cleanup}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(admitted);
        original
    }
}

pub(super) fn configure_durability(conn: &Connection) -> Result<(), LedgerError> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(store)?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(store)?;
    let journal_mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(store)?;
    let synchronous: i64 = conn
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(store)?;
    if journal_mode != "wal" || synchronous != 2 {
        return Err(store(format!(
            "SQLite refused required durability pragmas: journal_mode={journal_mode}, synchronous={synchronous}"
        )));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn assert_hostile_contract(directory: &Path, database: &Path) {
    use super::SqliteLedger;
    use std::os::unix::fs::{symlink, PermissionsExt};

    linux::assert_policy_contract(directory);
    let protected = directory.join("protected.sqlite3");
    let protected_bytes = b"preserve-authority-truth";
    std::fs::write(&protected, protected_bytes).unwrap();
    let refused = |result: Result<SqliteLedger, LedgerError>| match result {
        Ok(_) => panic!("hostile SQLite path opened"),
        Err(error) => {
            assert_eq!(error.reason_code(), "STORE_FAILURE");
            error
        }
    };

    let linked = directory.join("hard-linked.sqlite3");
    std::fs::hard_link(&protected, &linked).unwrap();
    assert!(refused(SqliteLedger::open(&linked))
        .to_string()
        .contains("single-link"));
    let symlinked = directory.join("symlinked.sqlite3");
    symlink(&protected, &symlinked).unwrap();
    refused(SqliteLedger::open(&symlinked));
    let wrong_mode = directory.join("wrong-mode.sqlite3");
    std::fs::write(&wrong_mode, protected_bytes).unwrap();
    std::fs::set_permissions(&wrong_mode, std::fs::Permissions::from_mode(0o4600)).unwrap();
    refused(SqliteLedger::open(&wrong_mode));
    assert_eq!(std::fs::read(&protected).unwrap(), protected_bytes);
    assert_eq!(std::fs::read(&wrong_mode).unwrap(), protected_bytes);

    let actual_parent = directory.join("actual-parent");
    std::fs::create_dir(&actual_parent).unwrap();
    let linked_parent = directory.join("linked-parent");
    symlink(&actual_parent, &linked_parent).unwrap();
    refused(SqliteLedger::open(linked_parent.join("new.sqlite3")));
    assert!(!actual_parent.join("new.sqlite3").exists());
    let group_parent = directory.join("group-writable-parent");
    std::fs::create_dir(&group_parent).unwrap();
    std::fs::set_permissions(&group_parent, std::fs::Permissions::from_mode(0o770)).unwrap();
    refused(SqliteLedger::open(group_parent.join("new.sqlite3")));
    let group_ancestor = directory.join("group-writable-ancestor");
    std::fs::create_dir(&group_ancestor).unwrap();
    std::fs::set_permissions(&group_ancestor, std::fs::Permissions::from_mode(0o770)).unwrap();
    let exact_parent = group_ancestor.join("state");
    std::fs::create_dir(&exact_parent).unwrap();
    std::fs::set_permissions(&exact_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    refused(SqliteLedger::open(exact_parent.join("new.sqlite3")));

    for (suffix, attack) in [
        ("-wal", "hardlink"),
        ("-shm", "symlink"),
        ("-journal", "mode"),
    ] {
        let sidecar = sidecar(database, suffix);
        match attack {
            "hardlink" => std::fs::hard_link(&protected, &sidecar).unwrap(),
            "symlink" => symlink(&protected, &sidecar).unwrap(),
            _ => {
                std::fs::write(&sidecar, protected_bytes).unwrap();
                std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
        }
        refused(SqliteLedger::open(database));
        assert_eq!(std::fs::read(&protected).unwrap(), protected_bytes);
        std::fs::remove_file(sidecar).unwrap();
    }

    let cleanup_path = directory.join("cleanup-retry.sqlite3");
    let admitted = connection(&cleanup_path).unwrap();
    assert!(linux::was_created(&admitted.guard.inner));
    cleanup_after_failure(admitted, store("injected later refusal"));
    assert!(!cleanup_path.exists());
    drop(SqliteLedger::open(&cleanup_path).unwrap());

    let nonempty_path = directory.join("cleanup-nonempty.sqlite3");
    let admitted = connection(&nonempty_path).unwrap();
    std::fs::write(&nonempty_path, protected_bytes).unwrap();
    cleanup_after_failure(admitted, store("injected nonempty refusal"));
    assert_eq!(std::fs::read(&nonempty_path).unwrap(), protected_bytes);

    let sidecar_path = directory.join("cleanup-sidecar.sqlite3");
    let admitted = connection(&sidecar_path).unwrap();
    let cleanup_sidecar = sidecar(&sidecar_path, "-wal");
    std::fs::write(&cleanup_sidecar, protected_bytes).unwrap();
    cleanup_after_failure(admitted, store("injected sidecar refusal"));
    assert!(sidecar_path.exists());
    assert_eq!(std::fs::read(&cleanup_sidecar).unwrap(), protected_bytes);

    let unsafe_parent = directory.join("cleanup-unsafe-parent");
    std::fs::create_dir(&unsafe_parent).unwrap();
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let unsafe_path = unsafe_parent.join("database.sqlite3");
    let admitted = connection(&unsafe_path).unwrap();
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o770)).unwrap();
    cleanup_after_failure(admitted, store("injected unsafe-parent refusal"));
    assert!(unsafe_path.exists());
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    let substitute_path = directory.join("cleanup-substitute.sqlite3");
    let displaced = directory.join("cleanup-displaced.sqlite3");
    let admitted = connection(&substitute_path).unwrap();
    std::fs::rename(&substitute_path, &displaced).unwrap();
    std::fs::hard_link(&protected, &substitute_path).unwrap();
    cleanup_after_failure(admitted, store("injected substituted refusal"));
    assert_eq!(std::fs::read(&substitute_path).unwrap(), protected_bytes);
    assert!(displaced.exists());

    assert!(connection(Path::new("")).is_err());
    let non_normal = format!("{}/./bad.sqlite3", directory.display());
    assert!(connection(Path::new(&non_normal)).is_err());
    let mut too_deep = directory.to_path_buf();
    for _ in 0..65 {
        too_deep.push("d");
    }
    too_deep.push("bad.sqlite3");
    assert!(connection(&too_deep).is_err());
}

#[cfg(all(test, target_os = "linux"))]
fn sidecar(database: &Path, suffix: &str) -> std::path::PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn assert_backup_obeys_custody(directory: &Path, source: &Path) {
    use crate::sqlite::backup::create_backup;
    use rustix::fs::{flock, FlockOperation};
    use std::fs::{self, OpenOptions};
    use std::time::{Duration, Instant};

    let admitted = crate::sqlite::open::backup_read_only(source).unwrap();
    let private = Path::new(admitted.connection.path().unwrap()).to_path_buf();
    assert_ne!(private, source);
    let error = admitted
        .connection
        .execute_batch("CREATE TABLE forbidden_backup_write (id INTEGER)")
        .unwrap_err();
    assert!(
        matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::ReadOnly)
    );
    crate::sqlite::open::close_backup(admitted).unwrap();
    assert!(!private.parent().unwrap().exists());
    let snapshot = || {
        let mut files = fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    };
    let output = directory.join("custody-backup.sqlite");
    let descriptor = OpenOptions::new()
        .read(true)
        .write(true)
        .open(source)
        .unwrap();
    flock(&descriptor, FlockOperation::NonBlockingLockExclusive).unwrap();
    let before = snapshot();
    for _ in 0..2 {
        let started = Instant::now();
        let error = create_backup(source, &output).unwrap_err();
        assert!(error.to_string().contains("SQLITE_CUSTODY_BUSY"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            snapshot(),
            before,
            "exclusive-custody refusal changed source or output"
        );
    }
    drop(descriptor);
    let receipt = create_backup(source, &output).expect("backup resumes after exclusive custody");
    assert_eq!(
        receipt.snapshot_digest,
        blake3::hash(&fs::read(&output).unwrap()).to_hex().as_str()
    );

    let empty = directory.join("empty-source.sqlite");
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&empty)
        .unwrap();
    assert!(create_backup(&empty, directory.join("empty-backup.sqlite")).is_err());
    assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0);
    assert!(!directory.join("empty-backup.sqlite").exists());
    let missing = directory.join("absent-source.sqlite");
    let absent_output = directory.join("absent-source-backup.sqlite");
    let before = snapshot();
    for _ in 0..2 {
        assert!(create_backup(&missing, &absent_output).is_err());
        assert_eq!(
            snapshot(),
            before,
            "read-only backup created a missing source or output"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) use linux::preflight::assert_snapshot_sources;

#[cfg(all(test, target_os = "linux"))]
fn inject_close(copy: &Connection) {
    if std::env::var("BULLET_BACKUP_PREFLIGHT_CLOSE").as_deref() == Ok("yes") {
        std::mem::forget(copy.prepare("SELECT 1").unwrap());
    }
}
