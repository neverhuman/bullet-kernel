//! Durable generic nonce replay, corruption, outage, and process-race proof.

use bullet_adapters::SqliteLedger;
use bullet_application::{NonceLedger, NonceState};
use rusqlite::Connection;
use std::process::Command;
use std::sync::mpsc::sync_channel;

#[path = "cross_process/support.rs"]
mod process_support;
use process_support::{private_tempdir, wait_until, ChildSet, PROCESS_TIMEOUT};

const CHILD_DB: &str = "BULLET_TEST_NONCE_CHILD_DB";
const CHILD_OUT: &str = "BULLET_TEST_NONCE_CHILD_OUT";
const CHILD_KEY: &str = "BULLET_TEST_NONCE_CHILD_KEY";
const CHILD_DIGEST: &str = "BULLET_TEST_NONCE_CHILD_DIGEST";
const CHILD_GO: &str = "BULLET_TEST_NONCE_CHILD_GO";
const CHILD_READY: &str = "BULLET_TEST_NONCE_CHILD_READY";

const WORKER_ENV: [&str; 6] = [
    CHILD_DB,
    CHILD_OUT,
    CHILD_KEY,
    CHILD_DIGEST,
    CHILD_GO,
    CHILD_READY,
];

fn hex(value: char) -> String {
    value.to_string().repeat(64)
}

#[test]
fn restart_preserves_issue_consume_replay_mismatch_and_unknown() {
    let directory = private_tempdir();
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
    let directory = private_tempdir();
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
    let directory = private_tempdir();
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
    let present = WORKER_ENV
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .count();
    if present == 0 {
        assert!(
            WORKER_ENV
                .iter()
                .all(|name| std::env::var_os(name).is_none()),
            "standalone invocation must not inherit a partial worker channel"
        );
        return;
    }
    assert_eq!(present, WORKER_ENV.len(), "worker channel must be complete");
    let path = std::env::var(CHILD_DB).expect("worker db");
    let output = std::env::var(CHILD_OUT).expect("worker output");
    let key = std::env::var(CHILD_KEY).expect("worker key");
    let digest = std::env::var(CHILD_DIGEST).expect("worker digest");
    let go = std::path::PathBuf::from(std::env::var(CHILD_GO).expect("worker barrier"));
    let ready = std::env::var(CHILD_READY).expect("worker ready path");
    let mut ledger = SqliteLedger::open(path).expect("worker opens durable ledger");
    std::fs::write(ready, b"ready").expect("worker announces readiness");
    wait_until("parent nonce barrier", || go.exists());
    let outcome = match ledger.consume(&key, &digest) {
        Ok(()) => "CONSUMED".to_string(),
        Err(error) => error.reason_code().to_string(),
    };
    std::fs::write(output, outcome).expect("worker writes outcome");
}

#[test]
fn two_processes_have_exactly_one_consumer() {
    let directory = private_tempdir();
    let path = directory.path().join("race.sqlite");
    let first_out = directory.path().join("first.out");
    let second_out = directory.path().join("second.out");
    let first_ready = directory.path().join("first.ready");
    let second_ready = directory.path().join("second.ready");
    let go = directory.path().join("go");
    let key = hex('5');
    let digest = hex('e');
    let mut ledger = SqliteLedger::open(&path).unwrap();
    ledger.issue(&key, &digest).unwrap();
    drop(ledger);

    let executable = std::env::current_exe().expect("test executable");
    let mut children = ChildSet::default();
    for (output, ready) in [(&first_out, &first_ready), (&second_out, &second_ready)] {
        let mut command = Command::new(&executable);
        command
            .env_clear()
            .env("RUST_BACKTRACE", "0")
            .args(["--exact", "child_nonce_consumer_process", "--quiet"])
            .env(CHILD_DB, &path)
            .env(CHILD_OUT, output)
            .env(CHILD_KEY, &key)
            .env(CHILD_DIGEST, &digest)
            .env(CHILD_GO, &go)
            .env(CHILD_READY, ready);
        children.spawn(&mut command);
    }

    let (thread_ready_tx, thread_ready_rx) = sync_channel(0);
    let (thread_go_tx, thread_go_rx) = sync_channel(0);
    let thread_path = path.clone();
    let thread_key = key.clone();
    let thread_digest = digest.clone();
    let thread_outcome = std::thread::spawn(move || {
        let mut ledger = SqliteLedger::open(thread_path).expect("thread opens durable ledger");
        thread_ready_tx
            .send(())
            .expect("thread announces readiness");
        thread_go_rx
            .recv_timeout(PROCESS_TIMEOUT)
            .expect("parent releases thread before deadline");
        match ledger.consume(&thread_key, &thread_digest) {
            Ok(()) => "CONSUMED".to_string(),
            Err(error) => error.reason_code().to_string(),
        }
    });
    wait_until("process nonce workers", || {
        first_ready.exists() && second_ready.exists()
    });
    thread_ready_rx
        .recv_timeout(PROCESS_TIMEOUT)
        .expect("thread reaches nonce barrier");
    std::fs::write(&go, b"go").expect("release process nonce workers");
    thread_go_tx.send(()).expect("release thread nonce worker");
    for status in children.wait_all() {
        assert!(status.success(), "nonce child failed: {status}");
    }
    let mut outcomes = vec![
        std::fs::read_to_string(first_out).expect("first process outcome"),
        std::fs::read_to_string(second_out).expect("second process outcome"),
        thread_outcome.join().expect("thread nonce worker joins"),
    ];
    outcomes.sort();
    assert_eq!(
        outcomes,
        ["CONSUMED", "NONCE_CONSUMED", "NONCE_CONSUMED"],
        "two processes and one thread contend on the same durable one-use nonce"
    );
}
