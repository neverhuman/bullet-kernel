//! Five-plane transaction receipt. Production admission is still absent.

use serde_json::json;
use std::process::ExitCode;

/// Print the honest ABSENT receipt. Never claims `transaction_gate_eligible`.
#[must_use]
pub fn run_json() -> ExitCode {
    println!(
        "{}",
        json!({
            "transaction_proof": "ABSENT",
            "transaction_gate_eligible": false,
            "reason_code": "TRANSACTION_PROOF_UNAVAILABLE",
            "message": "signed five-plane TRANSACTION_PROOF is not admitted; OD-D and L-24 remain",
        })
    );
    ExitCode::from(2)
}
