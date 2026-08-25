//! `bullet provider live-conformance` is a fail-closed process boundary: under
//! the checked-in v1alpha1 policy it refuses (exit 78) before spawning any
//! provider, writes a receipt, and never touches the real provider binary. It
//! runs only the `bullet` binary itself, pointed at a marker executable.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const POLICY: &[u8] =
    include_bytes!("../../../crates/application/tests/fixtures/policy-v1alpha1.json");

fn bullet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(args)
        .env_remove("BULLET_POLICY_PATH")
        .env_remove("BULLET_DATA_DIR")
        .output()
        .unwrap()
}

fn write_marker(path: &Path, spawned: &Path) {
    let script = format!("#!/bin/bash\necho spawned >> '{}'\n", spawned.display());
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn live_conformance_refuses_under_v1alpha1_without_spawning() {
    let directory = TempDir::new().unwrap();
    let base = directory.path().canonicalize().unwrap();
    let data_dir = base.join("data");
    fs::create_dir_all(data_dir.join("policy")).unwrap();
    fs::write(data_dir.join("policy/policy.json"), POLICY).unwrap();

    let marker = base.join("claude");
    let spawned = base.join("SPAWNED");
    write_marker(&marker, &spawned);

    let data = data_dir.to_string_lossy().into_owned();
    let executable = marker.to_string_lossy().into_owned();
    let output = bullet(&[
        "provider",
        "live-conformance",
        "--data-dir",
        &data,
        "--provider",
        "claude",
        "--executable",
        &executable,
    ]);

    assert_eq!(
        output.status.code(),
        Some(78),
        "policy refusal must exit 78 (neutral); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("POLICY_LIVE_ADMISSION_DISABLED"),
        "stdout: {stdout}"
    );
    assert!(
        !spawned.exists(),
        "the provider binary must never be spawned"
    );

    let live_dir = data_dir.join("live");
    let receipt = fs::read_dir(&live_dir)
        .expect("live directory")
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("claude-"))
        .expect("a receipt was written");
    let json = fs::read_to_string(receipt.path()).unwrap();
    assert!(json.contains("\"outcome\": \"REFUSED\""), "{json}");
    assert!(json.contains("\"failed_step\": \"POLICY\""), "{json}");
}

#[test]
fn live_conformance_rejects_a_relative_data_dir() {
    let output = bullet(&[
        "provider",
        "live-conformance",
        "--data-dir",
        "relative/data",
        "--provider",
        "claude",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--data-dir must be absolute"));
}
