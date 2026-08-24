//! Binary round-trip: the broker demo runs a real bare-repo flow and
//! reports honest states.

use std::process::Command;

#[test]
fn broker_demo_commits_and_reconciles_honestly() {
    let out = Command::new(env!("CARGO_BIN_EXE_bullet-effects"))
        .output()
        .expect("run bullet-effects");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON summary");
    assert_eq!(summary["first"], "COMMITTED");
    assert_eq!(summary["created"], true);
    assert_eq!(summary["replay_created"], false);
    assert_eq!(summary["read_back_matches"], true);
    assert_eq!(summary["after_lost_response"], "OUTCOME_UNKNOWN");
    assert_eq!(summary["reconcile"], "Retried(Committed)");
    assert_eq!(summary["lost_intent_settled"], "COMMITTED");
}
