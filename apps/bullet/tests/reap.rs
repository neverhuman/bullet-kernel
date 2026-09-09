//! `bullet farm reap` is the offline operator entry point for expiry
//! reclamation. It grants no authority, refuses a database that does not exist,
//! and prints one stable JSON report. It runs only the `bullet` binary itself.

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

fn private_temp_dir() -> TempDir {
    let directory = TempDir::new().expect("tempdir");
    #[cfg(target_os = "linux")]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("0700");
    directory
}

fn reap(database: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(["farm", "reap", "--database"])
        .arg(database)
        .output()
        .expect("run bullet farm reap")
}

#[test]
fn reap_refuses_a_missing_database_and_reports_an_empty_sweep_idempotently() {
    let directory = private_temp_dir();
    let data = directory.path().join("data");
    let database = data.join("ledger.sqlite");

    let missing = reap(&database);
    assert!(
        !missing.status.success(),
        "a database that does not exist must never report a successful sweep"
    );
    assert!(String::from_utf8_lossy(&missing.stderr).contains("ledger database not found"));
    assert!(
        !database.exists(),
        "reap must not create the ledger it was pointed at"
    );

    let init = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(["farm", "init"])
        .env("BULLET_DATA_DIR", &data)
        .output()
        .expect("run bullet farm init");
    assert!(init.status.success(), "init: {init:?}");

    let first = reap(&database);
    assert!(first.status.success(), "first sweep: {first:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("stable JSON report");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "farm reap");
    assert_eq!(report["database"], database.display().to_string());
    assert_eq!(
        report["reclaimed"]
            .as_array()
            .expect("reclaimed array")
            .len(),
        0,
        "a ledger with no lease reclaims nothing"
    );

    let second = reap(&database);
    assert!(second.status.success());
    assert_eq!(
        first.stdout, second.stdout,
        "reclamation is idempotent: a second sweep is byte-identical"
    );
}
