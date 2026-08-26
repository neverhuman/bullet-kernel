//! The public transaction command reports exact ABSENT truth and cannot go green.

use std::process::Command;

#[test]
fn transaction_json_is_exact_ineligible_absence() {
    let output = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(["transaction", "--json"])
        .output()
        .expect("run bullet transaction");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).expect("receipt JSON");
    assert_eq!(receipt["transaction_proof"], "ABSENT");
    assert_eq!(receipt["transaction_gate_eligible"], false);
    assert_eq!(receipt["reason_code"], "TRANSACTION_PROOF_UNAVAILABLE");
}
