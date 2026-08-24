//! End-to-end synthetic run: council events, fenced attempts with a live
//! stale refusal, a real bullet-gitd private clone, the real verifier
//! binary, and a LocalBareForge effect — proven offline against a
//! temporary data dir.

use std::path::PathBuf;
use std::process::Command;

const DEFAULT_GITD: &str = "/home/ubuntu/bullet/bullet-git/target/debug/bullet-gitd";

fn gitd_binary() -> PathBuf {
    std::env::var_os("BULLET_GITD_BIN").map_or_else(|| PathBuf::from(DEFAULT_GITD), PathBuf::from)
}

fn verifier_sibling() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bullet"))
        .parent()
        .map(|dir| dir.join("bullet-verifier"))
        .unwrap_or_default()
}

#[test]
fn synthetic_end_to_end_receipt_holds() {
    if !gitd_binary().is_file() {
        eprintln!("SKIP GITD_BINARY_ABSENT: build bullet-gitd or set BULLET_GITD_BIN");
        return;
    }
    let verifier = if verifier_sibling().is_file() {
        verifier_sibling()
    } else if let Some(bin) = std::env::var_os("BULLET_VERIFIER_BIN") {
        PathBuf::from(bin)
    } else {
        eprintln!("SKIP VERIFIER_BINARY_ABSENT: cargo build -p bullet-verifier first");
        return;
    };
    if !verifier.is_file() {
        eprintln!("SKIP VERIFIER_BINARY_ABSENT: cargo build -p bullet-verifier first");
        return;
    }
    let data = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .arg("demo-synthetic")
        .env("BULLET_DATA_DIR", data.path())
        .env("BULLET_VERIFIER_BIN", &verifier)
        .output()
        .expect("spawn bullet");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let raw = std::fs::read_to_string(data.path().join("synthetic-integration-receipt.json"))
        .expect("receipt file");
    let receipt: serde_json::Value = serde_json::from_str(&raw).expect("receipt json");
    assert_eq!(receipt["classification"], "SYNTHETIC_INTEGRATION_SCAFFOLD");
    assert_eq!(receipt["transaction_gate_eligible"], false);
    assert_eq!(receipt["mission_materialized_once"], true);
    assert_eq!(receipt["fence_first"], 1);
    assert_eq!(receipt["fence_second"], 2);
    assert_eq!(receipt["stale_refused"], true);
    assert_eq!(receipt["planning"]["degraded"], false);
    assert_eq!(receipt["planning"]["fused_by"], "sim");
    let candidate = &receipt["candidate"];
    assert_ne!(candidate["base"], candidate["head"]);
    assert_eq!(candidate["actual_scope"][0], "PONG.txt");
    assert_eq!(receipt["gate"]["writer_outcome"], "PASS");
    assert_eq!(receipt["evidence"]["verifier_outcome"], "PASS");
    assert_eq!(receipt["evidence"]["tier"], "E2");
    assert_eq!(receipt["effect"]["local"]["read_back_verified"], true);
    assert_eq!(receipt["effect"]["local"]["state"], "COMMITTED");
    let jeryu = receipt["effect"]["jeryu"]["status"]
        .as_str()
        .unwrap_or_default();
    assert!(
        jeryu == "LIVE_FORGE_QUARANTINED"
            || jeryu == "FORGE_UNAUTHENTICATED"
            || jeryu == "CAPABILITY_UNPROBED",
        "jeryu status {jeryu}"
    );
    let failures = receipt["scaffold_failures"]
        .as_array()
        .expect("failures array");
    assert!(failures.is_empty(), "failures: {raw}");
}
