use super::setup;
use bullet_adapters::SqliteLedger;
use bullet_application::{Ledger, LedgerError};
use rusqlite::Connection;

pub(super) fn missing_singleton_refuses_lease(table: &str) {
    let directory = secure_tempdir();
    let path = directory.path().join(format!("missing-{table}.sqlite3"));
    let (_graph, request) = setup(&path, table);
    let mut ledger = SqliteLedger::open(&path).expect("open before corruption");
    let raw = Connection::open(&path).expect("raw singleton corruption");
    let before = authority_row_counts(&raw);
    let deleted_trigger = if table == "authority_revisions" {
        raw.execute_batch(
            "UPDATE authority_revisions SET graph_revision = 7, workspace_generation = 8,
             policy_generation = 9, routing_generation = 10, authority_epoch = 11,
             freeze_generation = 12 WHERE singleton = 1;",
        )
        .expect("advance authority before corruption");
        let sql = raw
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
                 AND name = 'authority_revisions_no_delete'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("authority no-delete trigger");
        raw.execute_batch("DROP TRIGGER authority_revisions_no_delete;")
            .expect("drop fixture guard");
        Some(sql)
    } else {
        None
    };
    raw.execute(&format!("DELETE FROM {table} WHERE singleton = 1"), [])
        .expect("remove singleton fixture");
    if let Some(sql) = deleted_trigger {
        raw.execute_batch(&sql)
            .expect("restore exact fixture guard");
    }
    drop(raw);

    let first = ledger
        .acquire_lease(&request)
        .expect_err("missing singleton");
    let replay = ledger
        .acquire_lease(&request)
        .expect_err("missing singleton replay");
    assert_eq!(first.reason_code(), "STORE_FAILURE");
    assert_eq!(replay.reason_code(), "STORE_FAILURE");
    assert_eq!(replay.to_string(), first.to_string());
    drop(ledger);

    let mut reopen_error = None;
    for _ in 0..2 {
        let error = refused_open(&path);
        let expected = if table == "authority_revisions" {
            "STORE_FAILURE"
        } else {
            "UNSUPPORTED_SCHEMA"
        };
        assert_eq!(error.reason_code(), expected);
        assert_eq!(
            reopen_error.get_or_insert_with(|| error.to_string()),
            &error.to_string()
        );
    }
    let raw = Connection::open(path).expect("inspect refusal");
    assert_eq!(
        authority_row_counts(&raw),
        before,
        "reopen created authority rows"
    );
    if table == "authority_revisions" {
        let count: i64 = raw
            .query_row("SELECT COUNT(*) FROM authority_revisions", [], |row| {
                row.get(0)
            })
            .expect("authority singleton count");
        assert_eq!(count, 0, "authority singleton must never be reseeded");
    }
}

fn authority_row_counts(raw: &Connection) -> Vec<i64> {
    ["active_leases", "lease_authority_fingerprints", "commands"]
        .iter()
        .map(|table| {
            raw.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("authority row count")
        })
        .collect()
}

fn refused_open(path: &std::path::Path) -> LedgerError {
    match SqliteLedger::open(path) {
        Ok(_) => panic!("missing singleton reopened"),
        Err(error) => error,
    }
}

fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure tempdir mode");
    }
    directory
}
