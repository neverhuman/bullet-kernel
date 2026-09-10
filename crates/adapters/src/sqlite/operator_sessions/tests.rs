use super::*;

mod corruption;

const ORIGIN: &str = "http://127.0.0.1:7420";

fn registration(seed: &str) -> BootstrapRegistration {
    BootstrapRegistration {
        digest: Digest::of(seed.as_bytes()),
        proposed_operator_id: format!("opr_{}", Digest::of(b"operator").to_hex()),
        origin: ORIGIN.into(),
        lifetime_seconds: 600,
    }
}
fn issue(seed: &str) -> SessionIssue {
    SessionIssue {
        bootstrap_digest: Digest::of(seed.as_bytes()),
        session_id: format!("sid_{}", Digest::of(seed.as_bytes()).to_hex()),
        bearer_digest: Digest::of(format!("bearer:{seed}").as_bytes()),
        csrf_digest: Digest::of(format!("csrf:{seed}").as_bytes()),
        origin: ORIGIN.into(),
        lifetime_seconds: 28_800,
    }
}

#[test]
fn operator_auth_rows_are_immutable_and_replacement_cannot_reopen_authority() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("auth.sqlite")).unwrap();
    ledger
        .register_operator_bootstrap(&registration("one"))
        .unwrap();
    let request = issue("one");
    let session = ledger.exchange_operator_bootstrap(&request).unwrap();
    let revoke = ledger
        .revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN)
        .unwrap();
    assert_eq!(revoke.operator_id, session.operator_id);
    for statement in [
        "UPDATE local_operator SET created_at = created_at",
        "DELETE FROM local_operator",
        "INSERT OR REPLACE INTO local_operator SELECT * FROM local_operator",
        "UPDATE operator_bootstraps SET expires_at = expires_at",
        "DELETE FROM operator_bootstraps",
        "INSERT OR REPLACE INTO operator_bootstraps SELECT * FROM operator_bootstraps",
        "UPDATE operator_sessions SET expires_at = expires_at",
        "DELETE FROM operator_sessions",
        "INSERT OR REPLACE INTO operator_sessions SELECT * FROM operator_sessions",
        "UPDATE operator_session_revocations SET revoked_at = revoked_at",
        "DELETE FROM operator_session_revocations",
        "INSERT OR REPLACE INTO operator_session_revocations SELECT * FROM operator_session_revocations",
    ] {
        assert!(ledger.conn.execute(statement, []).unwrap_err().to_string().contains("OPERATOR_AUTH_IMMUTABLE"), "{statement}");
    }
    ledger
        .register_operator_bootstrap(&registration("one"))
        .unwrap();
    assert!(matches!(
        ledger.exchange_operator_bootstrap(&request),
        Err(AuthError::BootstrapConsumed)
    ));
    assert!(matches!(
        ledger.read_operator_session(request.bearer_digest, ORIGIN),
        Err(AuthError::SessionInvalid)
    ));
}

#[test]
fn digest_and_identity_constraints_reject_nul_suffixes_and_noninteger_time() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("auth.sqlite")).unwrap();
    ledger
        .register_operator_bootstrap(&registration("one"))
        .unwrap();
    let operator = registration("one").proposed_operator_id;
    for digest in [
        format!("{}\0ignored", "a".repeat(64)),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        assert!(ledger.conn.execute("INSERT INTO operator_bootstraps (digest,operator_id,origin,issued_at,expires_at,restore_epoch) VALUES (?1,?2,?3,1,2,0)",
            params![digest, operator, ORIGIN]).is_err());
    }
    assert!(ledger.conn.execute("INSERT INTO operator_bootstraps (digest,operator_id,origin,issued_at,expires_at,restore_epoch) VALUES (?1,?2,?3,1.5,2.5,0)",
        params![Digest::of(b"other").to_hex(), operator, ORIGIN]).is_err());
    let mut hostile = registration("two");
    hostile.proposed_operator_id.push_str("\0ignored");
    assert!(matches!(
        ledger.register_operator_bootstrap(&hostile),
        Err(AuthError::InvalidRequest)
    ));
}

#[test]
fn failed_session_insert_does_not_consume_the_next_bootstrap() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("auth.sqlite")).unwrap();
    for seed in ["one", "two"] {
        ledger
            .register_operator_bootstrap(&registration(seed))
            .unwrap();
    }
    ledger.exchange_operator_bootstrap(&issue("one")).unwrap();
    let mut conflicting = issue("two");
    conflicting.bearer_digest = issue("one").bearer_digest;
    assert!(matches!(
        ledger.exchange_operator_bootstrap(&conflicting),
        Err(AuthError::Store(_))
    ));
    assert!(ledger.exchange_operator_bootstrap(&issue("two")).is_ok());
}

#[test]
fn absolute_expiry_and_wrong_csrf_refuse_without_renewing_or_revoking_another_client() {
    let directory = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("auth.sqlite")).unwrap();
    let mut short = registration("bootstrap-expiry");
    short.lifetime_seconds = 1;
    ledger.register_operator_bootstrap(&short).unwrap();
    ledger
        .register_operator_bootstrap(&registration("session-expiry"))
        .unwrap();
    let mut request = issue("session-expiry");
    request.lifetime_seconds = 1;
    ledger.exchange_operator_bootstrap(&request).unwrap();
    ledger
        .register_operator_bootstrap(&registration("long-lived"))
        .unwrap();
    let long = issue("long-lived");
    ledger.exchange_operator_bootstrap(&long).unwrap();
    assert!(matches!(
        ledger.revoke_operator_session(long.bearer_digest, Digest::of(b"wrong"), ORIGIN),
        Err(AuthError::CsrfInvalid)
    ));
    assert!(ledger
        .read_operator_session(long.bearer_digest, ORIGIN)
        .is_ok());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    ledger
        .register_operator_bootstrap(&registration("bootstrap-expiry"))
        .unwrap();
    assert!(matches!(
        ledger.exchange_operator_bootstrap(&issue("bootstrap-expiry")),
        Err(AuthError::BootstrapExpired)
    ));
    assert!(matches!(
        ledger.read_operator_session(request.bearer_digest, ORIGIN),
        Err(AuthError::SessionInvalid)
    ));
    assert!(matches!(
        ledger.revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN),
        Err(AuthError::SessionInvalid)
    ));
}
