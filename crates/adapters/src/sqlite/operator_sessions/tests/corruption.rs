//! Explicit damaged-database fixtures, never a production repair path.
use super::*;

#[test]
fn corrupt_persisted_bootstrap_never_mints_a_session() {
    for change in [
        "expires_at = issued_at + 601",
        "issued_at = -1",
        "expires_at = 253402300800",
        "issued_at = -9223372036854775808, expires_at = 9223372036854775807",
        "operator_id = 'corrupt'",
    ] {
        let directory = crate::test_support::private_tempdir();
        let mut ledger = SqliteLedger::open(directory.path().join("auth.sqlite")).unwrap();
        ledger
            .register_operator_bootstrap(&registration("one"))
            .unwrap();
        ledger.conn.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON; DROP TRIGGER operator_bootstraps_no_update;").unwrap();
        ledger
            .conn
            .execute(&format!("UPDATE operator_bootstraps SET {change}"), [])
            .unwrap();
        assert!(
            matches!(
                ledger.exchange_operator_bootstrap(&issue("one")),
                Err(AuthError::Store(_))
            ),
            "{change}"
        );
        let count: i64 = ledger
            .conn
            .query_row("SELECT count(*) FROM operator_sessions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{change}");
    }
}

#[test]
fn restore_epoch_and_quarantine_invalidate_existing_auth_on_an_open_connection() {
    let directory = crate::test_support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    ledger
        .register_operator_bootstrap(&registration("one"))
        .unwrap();
    let request = issue("one");
    ledger.exchange_operator_bootstrap(&request).unwrap();
    ledger
        .register_operator_bootstrap(&registration("unused"))
        .unwrap();
    let external = Connection::open(&path).unwrap();
    external.execute("UPDATE restore_state SET restore_epoch=1, pending_admission=1, source_snapshot_digest=?1, restored_at='2026-09-10T00:00:00Z' WHERE singleton=1", ["a".repeat(64)]).unwrap();
    for result in [
        ledger
            .read_operator_session(request.bearer_digest, ORIGIN)
            .map(|_| ()),
        ledger
            .revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN)
            .map(|_| ()),
        ledger
            .exchange_operator_bootstrap(&issue("unused"))
            .map(|_| ()),
        ledger.register_operator_bootstrap(&registration("new")),
    ] {
        assert!(
            matches!(result, Err(AuthError::Store(ref error)) if error.to_string().contains("RESTORE_ADMISSION_REQUIRED"))
        );
    }
    // A future admitted epoch still must not revive pre-restore authority.
    external
        .execute(
            "UPDATE restore_state SET pending_admission=0 WHERE singleton=1",
            [],
        )
        .unwrap();
    assert!(matches!(
        ledger.read_operator_session(request.bearer_digest, ORIGIN),
        Err(AuthError::SessionInvalid)
    ));
    assert!(matches!(
        ledger.exchange_operator_bootstrap(&issue("unused")),
        Err(AuthError::BootstrapInvalid)
    ));
    assert!(matches!(
        ledger.register_operator_bootstrap(&registration("unused")),
        Err(AuthError::BootstrapInvalid)
    ));
    ledger
        .register_operator_bootstrap(&registration("new"))
        .unwrap();
    let current = ledger.exchange_operator_bootstrap(&issue("new")).unwrap();
    assert!(ledger
        .read_operator_session(current.bearer_digest, ORIGIN)
        .is_ok());
}
