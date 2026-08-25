//! Issue and consume are separate. Observation never registers.

use bullet_application::nonce_ledger::{MemoryNonceLedger, NonceError, NonceLedger, NonceState};

fn nonce(value: char) -> String {
    value.to_string().repeat(64)
}

#[test]
fn issue_does_not_consume() {
    let mut ledger = MemoryNonceLedger::new();
    let key = nonce('1');
    let digest = nonce('a');
    let issued = ledger.issue(&key, &digest).expect("issue");
    assert_eq!(issued.key, key);
    assert_eq!(ledger.state(&key).unwrap(), Some(NonceState::Issued));
    assert_eq!(
        ledger.issue(&key, &digest).unwrap_err().reason_code(),
        "NONCE_ALREADY_ISSUED"
    );
    assert_eq!(
        ledger.issue(&key, &nonce('b')).unwrap_err().reason_code(),
        "NONCE_SUBJECT_MISMATCH"
    );
    ledger.consume(&key, &digest).expect("consume");
    assert_eq!(ledger.state(&key).unwrap(), Some(NonceState::Consumed));
}

#[test]
fn consume_replay_is_refused() {
    let mut ledger = MemoryNonceLedger::new();
    let key = nonce('2');
    let digest = nonce('b');
    ledger.issue(&key, &digest).expect("issue");
    ledger.consume(&key, &digest).expect("first");
    let err = ledger.consume(&key, &digest).expect_err("replay");
    assert_eq!(err, NonceError::Consumed(key));
    assert_eq!(err.reason_code(), "NONCE_CONSUMED");
}

#[test]
fn observation_and_unknown_consume_never_register() {
    let mut ledger = MemoryNonceLedger::new();
    let key = nonce('3');
    let digest = nonce('c');
    assert_eq!(ledger.state(&key).unwrap(), None);
    let err = ledger.consume(&key, &digest).expect_err("missing");
    assert_eq!(err.reason_code(), "NONCE_NOT_FOUND");
    assert_eq!(ledger.state(&key).unwrap(), None);
}

#[test]
fn mismatch_does_not_consume() {
    let mut ledger = MemoryNonceLedger::new();
    let key = nonce('4');
    let digest = nonce('d');
    ledger.issue(&key, &digest).unwrap();
    let error = ledger.consume(&key, &nonce('e')).unwrap_err();
    assert_eq!(error.reason_code(), "NONCE_SUBJECT_MISMATCH");
    assert_eq!(ledger.state(&key).unwrap(), Some(NonceState::Issued));
    ledger.consume(&key, &digest).unwrap();
}

#[test]
fn malformed_inputs_fail_before_state_changes() {
    let mut ledger = MemoryNonceLedger::new();
    let uppercase = nonce('A');
    for (key, digest) in [("short", nonce('a')), (nonce('1').as_str(), uppercase)] {
        let error = ledger.issue(key, &digest).unwrap_err();
        assert_eq!(error.reason_code(), "NONCE_INVALID");
    }
    assert_eq!(ledger.state(&nonce('1')).unwrap(), None);
}
