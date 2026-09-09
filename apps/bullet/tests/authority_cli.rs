//! `bullet authority` is an offline operator boundary: keygen creates 0600
//! material once, and minting refuses without policy, without an admitted
//! key, or with loose key custody. It runs only the `bullet` binary itself.

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
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn mint(data_dir: &Path, receipt: &Path) -> Output {
    let data = data_dir.to_string_lossy().into_owned();
    let receipt = receipt.to_string_lossy().into_owned();
    let attempt = format!("atm_{}", "d".repeat(64));
    let gate = format!("gat_{}", "8".repeat(64));
    bullet(&[
        "authority",
        "mint-launch-grant",
        "--data-dir",
        &data,
        "--attempt",
        &attempt,
        "--receipt",
        &receipt,
        "--provider",
        "claude",
        "--executable",
        "/usr/local/bin/claude",
        "--profile",
        &format!("prf_{}", "4".repeat(64)),
        "--model",
        "claude-test",
        "--sandbox-manifest-digest",
        &"7".repeat(64),
        "--environment-digest",
        &"c".repeat(64),
        "--budget-invocations",
        "1",
        "--budget-wall-ms",
        "1000",
        "--budget-cost-micro-usd",
        "0",
        "--gate-id",
        &gate,
    ])
}

#[test]
fn keygen_is_private_and_single_shot() {
    let directory = TempDir::new().unwrap();
    let data_dir = directory.path().canonicalize().unwrap();
    let data = data_dir.to_string_lossy().into_owned();
    let first = bullet(&["authority", "keygen", "--data-dir", &data]);
    assert!(first.status.success(), "{}", stderr(&first));
    let stdout = String::from_utf8_lossy(&first.stdout).into_owned();
    assert!(stdout.contains("public_key_hex: "));
    assert!(stdout.contains("\"audiences\": [\n    \"provider-runner\"\n  ]"));
    assert!(stdout.contains("\"key_purpose\": \"authority-signing\""));
    let key = data_dir.join("authority/launch-grant.key");
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(data_dir.join("authority"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let material = fs::read(&key).unwrap();
    assert_eq!(material.len(), 64);
    let material_hex: String = material.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!stdout.contains(&material_hex));
    let second = bullet(&["authority", "keygen", "--data-dir", &data]);
    assert!(!second.status.success());
    assert!(stderr(&second).contains("refusing to overwrite"));
    assert_eq!(fs::read(&key).unwrap(), material);
    let relative = bullet(&["authority", "keygen", "--data-dir", "relative"]);
    assert!(!relative.status.success());
}

#[test]
fn mint_refuses_without_policy_admitted_key_or_strict_custody() {
    let directory = TempDir::new().unwrap();
    let data_dir = directory.path().canonicalize().unwrap();
    let data = data_dir.to_string_lossy().into_owned();
    let receipt = data_dir.join("receipt.json");
    fs::write(&receipt, b"{}").unwrap();
    assert!(bullet(&["authority", "keygen", "--data-dir", &data])
        .status
        .success());

    let no_policy = mint(&data_dir, &receipt);
    assert!(!no_policy.status.success());
    assert!(
        stderr(&no_policy).contains("POLICY_UNAVAILABLE"),
        "{}",
        stderr(&no_policy)
    );

    fs::create_dir_all(data_dir.join("policy")).unwrap();
    fs::write(data_dir.join("policy/policy.json"), POLICY).unwrap();
    let unadmitted = mint(&data_dir, &receipt);
    assert!(!unadmitted.status.success());
    assert!(
        stderr(&unadmitted).contains("LAUNCH_GRANT_KEY_UNKNOWN"),
        "{}",
        stderr(&unadmitted)
    );
    assert!(
        stderr(&unadmitted).contains(
            "policy schema_version=v1alpha1 generation=1 live_admission_enabled=false digest="
        ),
        "{}",
        stderr(&unadmitted)
    );

    let key = data_dir.join("authority/launch-grant.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let loose = mint(&data_dir, &receipt);
    assert!(!loose.status.success());
    assert!(stderr(&loose).contains("0600"), "{}", stderr(&loose));
    assert!(
        !data_dir.join("ledger.sqlite").exists(),
        "no ledger was touched"
    );
}
