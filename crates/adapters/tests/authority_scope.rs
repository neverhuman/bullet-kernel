use bullet_adapters::{create_backup, SqliteLedger};
use bullet_application::{
    AuthorityScopeError, AuthorityScopeStore, Ledger, AUTHORITY_SCOPE_ENVELOPE_CLASS,
};
use bullet_domain::schema_bundle::ScopeGrantV1;
use rusqlite::Connection;

mod support;

fn grant(seed: char, paths: &[&str]) -> ScopeGrantV1 {
    ScopeGrantV1 {
        schema_version: "v1alpha1".to_owned(),
        scope_grant_id: format!("sgr_{}", seed.to_string().repeat(64)),
        scope_revision: 1,
        normalized_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        protected_resources: Vec::new(),
        envelope_class: AUTHORITY_SCOPE_ENVELOPE_CLASS.to_owned(),
    }
}

#[test]
fn scope_admission_replays_exactly_across_restart_and_binds_backup() {
    let directory = support::private_tempdir();
    let path = directory.path().join("ledger.sqlite3");
    let backup = directory.path().join("backup.sqlite3");
    let subject = grant('a', &["src/lib.rs", "tests/scope.rs"]);
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let first = ledger
        .admit_scope_grant(&subject, 1, "scope-admission-a", "2026-08-27T12:00:00Z")
        .unwrap();
    assert_eq!(first.previous_authority_epoch, 1);
    assert_eq!(first.new_authority_epoch, 2);
    assert_eq!(first.freeze_generation, 0);
    assert_eq!(
        ledger.current_authority().unwrap().scope_digest(),
        first.scope_paths_digest
    );
    let event = ledger
        .list_events()
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "authority_scope_admitted")
        .expect("scope event");
    assert_eq!(event.seq, first.event_sequence);
    assert_eq!(
        event.correlation_id.as_deref(),
        Some(first.command_id.as_str())
    );
    drop(ledger);

    let mut reopened = SqliteLedger::open(&path).unwrap();
    let replay = reopened
        .admit_scope_grant(&subject, 1, "scope-admission-a", "2026-08-27T12:00:00Z")
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(
        reopened
            .list_events()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "authority_scope_admitted")
            .count(),
        1
    );
    drop(reopened);

    let receipt = create_backup(&path, &backup).unwrap();
    assert_eq!(receipt.schema_digest.len(), 64);
    let copied = Connection::open(&backup).unwrap();
    let schema: i64 = copied
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    let admissions: i64 = copied
        .query_row(
            "SELECT COUNT(*) FROM authority_scope_admissions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((schema, admissions), (23, 1));
}

#[test]
fn changed_subject_stale_epoch_and_freeze_refuse_with_typed_results() {
    let directory = support::private_tempdir();
    let path = directory.path().join("ledger.sqlite3");
    let first = grant('a', &["src/lib.rs"]);
    let changed = grant('b', &["src/main.rs"]);
    let mut ledger = SqliteLedger::open(&path).unwrap();
    ledger
        .admit_scope_grant(&first, 1, "scope-key", "2026-08-27T12:00:00Z")
        .unwrap();
    let conflict = ledger
        .admit_scope_grant(&changed, 1, "scope-key", "2026-08-27T12:00:00Z")
        .unwrap_err();
    assert_eq!(conflict.reason_code(), "IDEMPOTENCY_CONFLICT");
    let rebound = ledger
        .admit_scope_grant(&first, 2, "rebound-key", "2026-08-27T12:00:01Z")
        .unwrap_err();
    assert_eq!(rebound.reason_code(), "IDEMPOTENCY_CONFLICT");
    let stale = ledger
        .admit_scope_grant(&changed, 1, "changed-key", "2026-08-27T12:00:01Z")
        .unwrap_err();
    assert!(matches!(
        stale,
        AuthorityScopeError::StaleAuthority {
            expected: 1,
            current: 2
        }
    ));
    drop(ledger);

    let frozen_path = directory.path().join("frozen.sqlite3");
    drop(SqliteLedger::open(&frozen_path).unwrap());
    let conn = Connection::open(&frozen_path).unwrap();
    conn.execute(
        "UPDATE authority_revisions SET freeze_generation = 1 WHERE singleton = 1",
        [],
    )
    .unwrap();
    drop(conn);
    let mut frozen = SqliteLedger::open(&frozen_path).unwrap();
    let error = frozen
        .admit_scope_grant(&first, 1, "frozen-key", "2026-08-27T12:00:00Z")
        .unwrap_err();
    assert!(matches!(error, AuthorityScopeError::Frozen(1)));
    assert_eq!(error.reason_code(), "AUTHORITY_FROZEN");
}

#[test]
fn every_injected_write_failure_rolls_back_epoch_event_and_replay_truth() {
    for boundary in 0..=2 {
        let directory = support::private_tempdir();
        let path = directory.path().join("ledger.sqlite3");
        let subject = grant('c', &["src/lib.rs"]);
        let mut ledger = SqliteLedger::open(&path).unwrap();
        ledger.set_authority_scope_failpoint(boundary);
        let error = ledger
            .admit_scope_grant(&subject, 1, "crash-key", "2026-08-27T12:00:00Z")
            .unwrap_err();
        assert_eq!(error.reason_code(), "STORE_FAILURE");
        assert_eq!(ledger.current_authority().unwrap().authority_epoch(), 1);
        assert!(ledger
            .list_events()
            .unwrap()
            .iter()
            .all(|event| event.kind != "authority_scope_admitted"));
        let admitted = ledger
            .admit_scope_grant(&subject, 1, "crash-key", "2026-08-27T12:00:00Z")
            .unwrap();
        assert_eq!(admitted.new_authority_epoch, 2);
    }
}
