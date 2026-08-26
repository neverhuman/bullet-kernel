//! Product scaffold conformance while production BulletGit authority is unavailable.

use bullet_runner_core::gitd_binary;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn private_temp_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(target_os = "linux")]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("0700");
    directory
}

fn verifier_sibling() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bullet"))
        .parent()
        .map(|dir| dir.join("bullet-verifier"))
        .unwrap_or_default()
}

#[test]
fn synthetic_scaffold_records_typed_authority_refusal_without_evidence() {
    gitd_binary().unwrap_or_else(|error| {
        panic!(
            "{}: family lane must admit BULLET_GITD_BIN with BULLET_GITD_SHA256",
            error.reason_code()
        )
    });
    let verifier = std::env::var_os("BULLET_VERIFIER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(verifier_sibling);
    assert!(
        verifier.is_file(),
        "VERIFIER_BINARY_ABSENT: cargo must build bullet-verifier with this test"
    );
    let data = private_temp_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_bullet"))
        .arg("demo-synthetic")
        .env("BULLET_DATA_DIR", data.path())
        .env("BULLET_VERIFIER_BIN", &verifier)
        .output()
        .expect("spawn bullet");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "scaffold laundered refusal as success"
    );
    assert!(stderr.contains("SYNTHETIC_INTEGRATION_SCAFFOLD failed"));
    let raw = std::fs::read_to_string(data.path().join("synthetic-integration-receipt.json"))
        .expect("receipt file");
    let receipt: serde_json::Value = serde_json::from_str(&raw).expect("receipt json");
    assert_eq!(receipt["classification"], "SYNTHETIC_INTEGRATION_SCAFFOLD");
    assert_eq!(receipt["transaction_gate_eligible"], false);
    assert_eq!(receipt["mission_materialized_once"], true);
    assert_eq!(receipt["fence_first"], 1);
    assert!(receipt["fence_second"].is_null());
    assert_eq!(receipt["stale_refused"], false);
    assert_eq!(receipt["planning"]["degraded"], false);
    assert_eq!(receipt["planning"]["fused_by"], "sim");
    assert!(receipt["candidate"].is_null());
    assert!(receipt["gate"].is_null());
    assert!(receipt["evidence"].is_null());
    assert!(receipt["effect"]["local"].is_null());
    assert!(receipt["effect"]["jeryu"].is_null());
    let failures = receipt["scaffold_failures"]
        .as_array()
        .expect("failures array");
    assert!(failures.iter().any(|failure| {
        failure
            .as_str()
            .is_some_and(|text| text.contains("RUNNER:AUTHORITY_CONTRACT_UNAVAILABLE"))
    }));
    assert!(!data.path().join("runner").exists());
    assert!(stdout.contains("\"transaction_gate_eligible\": false"));
}
