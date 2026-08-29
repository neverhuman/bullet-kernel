use super::{migrations, store};
use bullet_application::LedgerError;
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;

pub(super) struct AdmissionGuard {
    #[cfg(target_os = "linux")]
    inner: linux::Guard,
}

pub(super) struct AdmittedConnection {
    pub(super) connection: Connection,
    pub(super) guard: AdmissionGuard,
}

pub(super) fn connection(path: &Path) -> Result<AdmittedConnection, LedgerError> {
    #[cfg(target_os = "linux")]
    {
        let (connection, inner) = linux::connection(path)?;
        Ok(AdmittedConnection {
            connection,
            guard: AdmissionGuard { inner },
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
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
    #[cfg(target_os = "linux")]
    {
        linux::postflight(&admitted.guard.inner)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = admitted;
        Err(store(
            "descriptor-admitted SQLite authority storage requires Linux",
        ))
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

    linux::assert_policy_contract();
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
