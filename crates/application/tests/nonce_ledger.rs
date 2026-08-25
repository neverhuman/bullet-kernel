//! Issue and consume are separate. Verification never registers.

use bullet_application::nonce_ledger::{MemoryNonceLedger, NonceError, NonceLedger};

#[test]
fn issue_does_not_consume() {
    let mut ledger = MemoryNonceLedger::new();
    let issued = ledger.issue("n1", "aa").expect("issue");
    assert_eq!(issued.key, "n1");
    assert!(!ledger.is_consumed("n1"));
    ledger.consume("n1", "aa").expect("consume");
    assert!(ledger.is_consumed("n1"));
}

#[test]
fn consume_replay_is_refused() {
    let mut ledger = MemoryNonceLedger::new();
    ledger.issue("n1", "aa").expect("issue");
    ledger.consume("n1", "aa").expect("first");
    let err = ledger.consume("n1", "aa").expect_err("replay");
    assert_eq!(err, NonceError::Consumed("n1".into()));
    assert_eq!(err.reason_code(), "NONCE_CONSUMED");
}

#[test]
fn verification_does_not_register() {
    let ledger = MemoryNonceLedger::new();
    assert!(!ledger.is_consumed("ghost"));
    assert!(!ledger.is_consumed("ghost"));
}

#[test]
fn consume_without_issue_is_not_found() {
    let mut ledger = MemoryNonceLedger::new();
    let err = ledger.consume("n1", "aa").expect_err("missing");
    assert_eq!(err.reason_code(), "NONCE_NOT_FOUND");
}
