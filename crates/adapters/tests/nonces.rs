//! Durable generic nonce replay, corruption, outage, and process-race proof.

use bullet_adapters::SqliteLedger;
use bullet_application::{NonceLedger, NonceState};
use rusqlite::Connection;
use std::process::Command;

const CHILD_DB: &str = "BULLET_TEST_NONCE_CHILD_DB";
const CHILD_OUT: &str = "BULLET_TEST_NONCE_CHILD_OUT";
const CHILD_KEY: &str = "BULLET_TEST_NONCE_CHILD_KEY";
const CHILD_DIGEST: &str = "BULLET_TEST_NONCE_CHILD_DIGEST";

fn hex(value: char) -> String {
    value.to_string().repeat(64)
}

#[test]
fn restart_preserves_issue_consume_replay_mismatch_and_unknown() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nonces.sqlite");
    let key = hex('1');
    let digest = hex('a');
    let unknown = hex('2');
    {
        let mut ledger = SqliteLedger::open(&path).unwrap();
        assert_eq!(ledger.state(&unknown).unwrap(), None);
        let missing = ledger.consume(&unknown, &digest).unwrap_err();
        assert_eq!(missing.reason_code(), "NONCE_NOT_FOUND");
        assert_eq!(ledger.state(&unknown).unwrap(), None);
        ledger.issue(&key, &digest).unwrap();
        assert_eq!(ledger.state(&key).unwrap(), Some(NonceState::Issued));
        assert_eq!(
            ledger.issue(&key, &digest).unwrap_err().reason_code(),
            "NONCE_ALREADY_ISSUED"
        );
        assert_eq!(
            ledger.issue(&key, &hex('b')).unwrap_err().reason_code(),
            "NONCE_SUBJECT_MISMATCH"
        );
    }
    {
        let mut reopened = SqliteLedger::open(&path).unwrap();
        let mismatch = reopened.consume(&key, &hex('b')).unwrap_err();
        assert_eq!(mismatch.reason_code(), "NONCE_SUBJECT_MISMATCH");
        assert_eq!(reopened.state(&key).unwrap(), Some(NonceState::Issued));
        reopened.consume(&key, &digest).unwrap();
    }
    let mut replay = SqliteLedger::open(&path).unwrap();
    assert_eq!(replay.state(&key).unwrap(), Some(NonceState::Consumed));
    assert_eq!(
        replay.consume(&key, &digest).unwrap_err().reason_code(),
        "NONCE_CONSUMED"
    );
    assert_eq!(
        replay.issue(&key, &digest).unwrap_err().reason_code(),
        "NONCE_CONSUMED"
    );
}

#[test]
fn corrupt_persisted_row_fails_closed_without_repair() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("corrupt.sqlite");
    let key = hex('3');
    let reversed = hex('6');
    let digest = hex('c');
    let mut ledger = SqliteLedger::open(&path).unwrap();
    ledger.issue(&key, &digest).unwrap();
    ledger.issue(&reversed, &digest).unwrap();
    drop(ledger);

    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    conn.execute(
        "UPDATE authority_nonces SET consumed_at = 42 WHERE nonce_key = ?1",
        [&key],
    )
    .unwrap();
    conn.execute(
        "UPDATE authority_nonces SET consumed_at = '2000-01-01T00:00:00.000Z'
         WHERE nonce_key = ?1",
        [&reversed],
    )
    .unwrap();
    drop(conn);

    let mut reopened = SqliteLedger::open(&path).unwrap();
    assert_eq!(
        reopened.state(&key).unwrap_err().reason_code(),
        "NONCE_CORRUPT"
    );
    assert_eq!(
        reopened.consume(&key, &digest).unwrap_err().reason_code(),
        "NONCE_CORRUPT"
    );
    assert_eq!(
        reopened.state(&reversed).unwrap_err().reason_code(),
        "NONCE_CORRUPT"
    );
    let raw = Connection::open(path).unwrap();
    let persisted: String = raw
        .query_row(
            "SELECT consumed_at FROM authority_nonces WHERE nonce_key = ?1",
            [&key],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        persisted, "42",
        "read and consume must not repair corruption"
    );
}

#[test]
fn locked_writer_is_store_failure_and_creates_no_nonce() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("busy.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let key = hex('4');
    let error = ledger.issue(&key, &hex('d')).unwrap_err();
    assert_eq!(error.reason_code(), "NONCE_STORE_FAILURE");
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(ledger.state(&key).unwrap(), None);
}

#[test]
fn child_nonce_consumer_process() {
    let Ok(path) = std::env::var(CHILD_DB) else {
        return;
    };
    let output = std::env::var(CHILD_OUT).unwrap();
    let key = std::env::var(CHILD_KEY).unwrap();
    let digest = std::env::var(CHILD_DIGEST).unwrap();
    let mut ledger = SqliteLedger::open(path).unwrap();
    let outcome = match ledger.consume(&key, &digest) {
        Ok(()) => "CONSUMED".to_string(),
        Err(error) => error.reason_code().to_string(),
    };
    std::fs::write(output, outcome).unwrap();
}

#[test]
fn two_processes_have_exactly_one_consumer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("race.sqlite");
    let first_out = directory.path().join("first.out");
    let second_out = directory.path().join("second.out");
    let key = hex('5');
    let digest = hex('e');
    let mut ledger = SqliteLedger::open(&path).unwrap();
    ledger.issue(&key, &digest).unwrap();
    drop(ledger);

    let spawn = |output: &std::path::Path| {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_nonce_consumer_process", "--nocapture"])
            .env(CHILD_DB, &path)
            .env(CHILD_OUT, output)
            .env(CHILD_KEY, &key)
            .env(CHILD_DIGEST, &digest)
            .spawn()
            .unwrap()
    };
    let mut first = spawn(&first_out);
    let mut second = spawn(&second_out);
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    let mut outcomes = [
        std::fs::read_to_string(first_out).unwrap(),
        std::fs::read_to_string(second_out).unwrap(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, ["CONSUMED", "NONCE_CONSUMED"]);
}
