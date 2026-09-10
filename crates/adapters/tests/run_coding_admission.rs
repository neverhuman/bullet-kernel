mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{
    CommandDispatchDisposition, CommandDispatchStore, CommandRequest, Ledger, NonceLedger,
    NonceState, RunCodingPayload, MAX_CODING_QUOTA_UNITS, RUN_CODING_KIND,
};
use bullet_domain::{CommandPhase, DomainError, RunnerId};
use rusqlite::Connection;

fn payload(nonce: &str, reservation: &str, units: u64, revision: u64) -> serde_json::Value {
    serde_json::json!({
        "account_id": "acct-main",
        "provider": "claude",
        "model": "claude-opus-4-6",
        "expected_revision": revision,
        "launch_nonce": nonce,
        "quota_reservation": reservation,
        "quota_units": units,
        "allocated_run": RunnerId::from_seed("coding-run").to_string(),
    })
}

fn hex(ch: char) -> String {
    ch.to_string().repeat(64)
}

fn reservation(ch: char) -> String {
    format!("rsv_{}", hex(ch))
}

fn submit_coding(
    ledger: &mut SqliteLedger,
    key: &str,
    nonce: &str,
    reservation: &str,
    units: u64,
) -> bullet_application::CommandRecord {
    let request = CommandRequest::new(key, RUN_CODING_KIND, &payload(nonce, reservation, units, 1))
        .expect("request");
    ledger
        .issue(nonce, &request.digest().to_hex())
        .expect("issue");
    ledger.submit_command(&request).expect("submit")
}

#[test]
fn run_coding_binds_command_outbox_reservation_and_nonce() {
    let directory = support::private_tempdir();
    let path = directory.path().join("coding.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let nonce = hex('a');
    let reservation = reservation('b');
    let request = CommandRequest::new(
        "coding-once",
        RUN_CODING_KIND,
        &payload(&nonce, &reservation, 4, 1),
    )
    .unwrap();
    ledger.issue(&nonce, &request.digest().to_hex()).unwrap();
    let first = ledger.submit_command(&request).unwrap();
    let replay = ledger.submit_command(&request).unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.kind, RUN_CODING_KIND);
    assert_eq!(first.phase, CommandPhase::Pending);
    assert_eq!(ledger.state(&nonce).unwrap(), Some(NonceState::Consumed));
    let amount: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT amount FROM budget_reservations WHERE reservation_id = ?1",
            [&reservation],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(amount, 4);
    let outbox = ledger.outbox_for_command(&first.id).unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].kind, "command_dispatch");
}

#[test]
fn stale_revision_exhausted_quota_and_consumed_nonce_leave_no_row() {
    let directory = support::private_tempdir();
    let path = directory.path().join("coding-refuse.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();

    let stale = CommandRequest::new(
        "coding-stale",
        RUN_CODING_KIND,
        &payload(&hex('1'), &reservation('2'), 1, 99),
    )
    .unwrap();
    ledger.issue(&hex('1'), &stale.digest().to_hex()).unwrap();
    assert!(matches!(
        ledger.submit_command(&stale).unwrap_err(),
        bullet_application::LedgerError::Domain(DomainError::StaleAuthority(_))
    ));
    assert!(ledger
        .get_command(&stale.idempotency_key)
        .unwrap()
        .is_none());
    assert_eq!(ledger.state(&hex('1')).unwrap(), Some(NonceState::Issued));

    let first = submit_coding(&mut ledger, "coding-fill", &hex('3'), &reservation('4'), 1);
    assert_eq!(first.kind, RUN_CODING_KIND);
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE budget_reservations SET amount = ?1",
            [i64::try_from(MAX_CODING_QUOTA_UNITS).unwrap()],
        )
        .unwrap();
    drop(ledger);
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let exhausted = CommandRequest::new(
        "coding-exhausted",
        RUN_CODING_KIND,
        &payload(&hex('5'), &reservation('6'), 1, 1),
    )
    .unwrap();
    ledger
        .issue(&hex('5'), &exhausted.digest().to_hex())
        .unwrap();
    assert!(ledger.submit_command(&exhausted).is_err());
    assert!(ledger
        .get_command(&exhausted.idempotency_key)
        .unwrap()
        .is_none());
    assert_eq!(ledger.state(&hex('5')).unwrap(), Some(NonceState::Issued));
}

#[test]
fn first_insert_issues_and_consumes_portal_minted_nonce() {
    let directory = support::private_tempdir();
    let path = directory.path().join("coding-portal-nonce.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let nonce = hex('9');
    let reservation = reservation('a');
    let request = CommandRequest::new(
        "coding-portal",
        RUN_CODING_KIND,
        &payload(&nonce, &reservation, 1, 1),
    )
    .unwrap();
    assert_eq!(ledger.state(&nonce).unwrap(), None);
    let first = ledger.submit_command(&request).unwrap();
    let replay = ledger.submit_command(&request).unwrap();
    assert_eq!(first, replay);
    assert_eq!(ledger.state(&nonce).unwrap(), Some(NonceState::Consumed));
}

#[test]
fn dispatch_claims_run_coding_and_still_refuses_unknown_kinds() {
    let directory = support::private_tempdir();
    let path = directory.path().join("coding-dispatch.sqlite3");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let command = submit_coding(&mut ledger, "coding-claim", &hex('7'), &reservation('8'), 2);
    let runner = bullet_domain::RunnerId::from_seed("coding-dispatch");
    let claimed = ledger
        .claim_next_command_dispatch(&runner, 1, "2026-08-27T13:00:00.000Z")
        .unwrap()
        .expect("claim");
    assert_eq!(claimed.command_id, command.id);
    assert_eq!(claimed.request.kind, RUN_CODING_KIND);
    assert_eq!(claimed.disposition, CommandDispatchDisposition::Claimed);
    let parsed = RunCodingPayload::parse(&claimed.request.payload).unwrap();
    assert_eq!(parsed.provider.as_str(), "claude");
    assert_eq!(parsed.model, "claude-opus-4-6");
}
