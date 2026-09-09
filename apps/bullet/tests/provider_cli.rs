//! `bullet provider live-conformance` is a fail-closed process boundary: under
//! the checked-in v1alpha1 policy it refuses (exit 78) before spawning any
//! provider, writes a receipt, and never touches the real provider binary. A
//! v1alpha2 policy (ADR 0012) is admitted only by the production loader's
//! rules and is reported with its schema version and generation. Each real
//! provider selector then refuses at runtime observation before credentials,
//! authority writes, egress, or child execution. It runs only the `bullet`
//! binary itself, pointed at marker executables.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const POLICY: &[u8] =
    include_bytes!("../../../crates/application/tests/fixtures/policy-v1alpha1.json");
const V1ALPHA2_POLICY: &[u8] =
    include_bytes!("../../../crates/application/tests/fixtures/policy-v1alpha2-live-enabled.json");
const WIDE_EXPIRY_MS: u64 = 4_000_000_000_000;

type Mutate = fn(&mut serde_json::Value);

fn private_temp_dir() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn create_private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn bullet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(args)
        .env_remove("BULLET_POLICY_PATH")
        .env_remove("BULLET_DATA_DIR")
        .output()
        .unwrap()
}

fn bullet_with_policy(args: &[&str], policy: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(args)
        .env("BULLET_POLICY_PATH", policy)
        .env_remove("BULLET_DATA_DIR")
        .output()
        .unwrap()
}

/// The v1alpha2 fixture with the policy and runner-key windows widened so the
/// wall clock always lands inside them; `mutate` applies the case under test.
fn v1alpha2_policy(mutate: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(V1ALPHA2_POLICY).unwrap();
    value["activation_at_unix_ms"] = serde_json::json!(0);
    value["expires_at_unix_ms"] = serde_json::json!(WIDE_EXPIRY_MS);
    for key in value["issuer_keys"].as_array_mut().unwrap() {
        key["activates_at_unix_ms"] = serde_json::json!(0);
        key["expires_at_unix_ms"] = serde_json::json!(WIDE_EXPIRY_MS);
        key["retain_until_unix_ms"] = serde_json::json!(WIDE_EXPIRY_MS + 100_000_000);
    }
    mutate(&mut value);
    bullet_harness_core::launch_grant::canonical_json(&value).unwrap()
}

fn live_conformance_args<'a>(
    data: &'a str,
    provider: &'a str,
    executable: &'a str,
) -> [&'a str; 8] {
    [
        "provider",
        "live-conformance",
        "--data-dir",
        data,
        "--provider",
        provider,
        "--executable",
        executable,
    ]
}

fn receipt_json(data_dir: &Path, provider: &str) -> String {
    let receipt = fs::read_dir(data_dir.join("live"))
        .expect("live directory")
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{provider}-"))
        })
        .expect("a receipt was written");
    fs::read_to_string(receipt.path()).unwrap()
}

fn write_marker(path: &Path, spawned: &Path) {
    let script = format!("#!/bin/bash\necho spawned >> '{}'\n", spawned.display());
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn live_conformance_refuses_under_v1alpha1_without_spawning() {
    let directory = private_temp_dir();
    let base = directory.path().canonicalize().unwrap();
    let data_dir = base.join("data");
    create_private_dir(&data_dir);
    create_private_dir(&data_dir.join("policy"));
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
        stdout.contains(
            "policy: schema_version=v1alpha1 generation=1 live_admission_enabled=false digest="
        ),
        "stdout: {stdout}"
    );
    assert!(
        !spawned.exists(),
        "the provider binary must never be spawned"
    );

    let json = receipt_json(&data_dir, "claude");
    assert!(json.contains("\"outcome\": \"REFUSED\""), "{json}");
    assert!(json.contains("\"failed_step\": \"POLICY\""), "{json}");
}

#[test]
fn live_conformance_admits_a_ratified_v1alpha2_policy_and_reports_it() {
    for (provider, basename) in [
        ("claude", "claude"),
        ("codex", "codex"),
        ("cursor", "cursor-agent"),
        ("agy", "agy"),
    ] {
        let directory = private_temp_dir();
        let base = directory.path().canonicalize().unwrap();
        let data_dir = base.join("data");
        create_private_dir(&data_dir);
        let policy = base.join("policy-v1alpha2.json");
        fs::write(&policy, v1alpha2_policy(|_| {})).unwrap();
        let marker = base.join(basename);
        let spawned = base.join("SPAWNED");
        write_marker(&marker, &spawned);

        // No enrollment record is written. Per the live_conformance module
        // contract, a valid v1alpha2 policy without an enrollment refuses at
        // ENROLLMENT_MISSING before key read, authority mutation, egress, or
        // spawn -- Enrollment is step 2 of LiveStep::ALL, well before
        // ProbeExecution and ADMISSION. All four adapters inherit this.
        let data = data_dir.to_string_lossy().into_owned();
        let executable = marker.to_string_lossy().into_owned();
        let output = bullet_with_policy(
            &live_conformance_args(&data, provider, &executable),
            &policy,
        );
        assert_eq!(
            output.status.code(),
            Some(78),
            "{provider}: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(
                "policy: schema_version=v1alpha2 generation=2 live_admission_enabled=true digest="
            ),
            "{provider}: stdout: {stdout}"
        );
        assert!(
            stdout.contains(&format!(
                "live-conformance {provider}: refused (ENROLLMENT_MISSING); neutral"
            )),
            "{provider}: stdout: {stdout}"
        );
        assert!(
            !spawned.exists(),
            "{provider}: the provider binary must never be spawned"
        );
        assert!(
            !data_dir.join("authority/launch-grant.key").exists(),
            "{provider}: operator custody must not be read or created"
        );
        let json = receipt_json(&data_dir, provider);
        assert!(
            json.contains("\"outcome\": \"REFUSED\""),
            "{provider}: {json}"
        );
        assert!(
            json.contains("\"failed_step\": \"ENROLLMENT\""),
            "{provider}: {json}"
        );
        assert!(
            json.contains("\"refusal_reason\": \"ENROLLMENT_MISSING\""),
            "{provider}: {json}"
        );
        assert!(
            json.contains("\"policy_generation\": 2"),
            "{provider}: {json}"
        );
    }
}

#[test]
fn live_conformance_refuses_v1alpha2_policies_the_hub_validator_rejects() {
    let cases: [(&str, Mutate, &str); 4] = [
        (
            "generation 1",
            |p| p["policy_generation"] = serde_json::json!(1),
            "LIVE_ADMISSION_REQUIRES_GENERATION",
        ),
        (
            "no runner key",
            |p| {
                p["issuer_keys"].as_array_mut().unwrap().pop();
            },
            "LIVE_ADMISSION_REQUIRES_RUNNER_KEY",
        ),
        (
            "evolutionary authority",
            |p| p["route_policy"]["evolutionary_authority"] = serde_json::json!(true),
            "UNSAFE_POLICY",
        ),
        (
            "v1alpha1 with live admission",
            |p| p["schema_version"] = serde_json::json!("v1alpha1"),
            "UNSAFE_POLICY",
        ),
    ];
    for (name, mutate, expected) in cases {
        let directory = private_temp_dir();
        let base = directory.path().canonicalize().unwrap();
        let data_dir = base.join("data");
        create_private_dir(&data_dir);
        let policy = base.join("policy.json");
        fs::write(&policy, v1alpha2_policy(mutate)).unwrap();
        let marker = base.join("claude");
        let spawned = base.join("SPAWNED");
        write_marker(&marker, &spawned);

        let data = data_dir.to_string_lossy().into_owned();
        let executable = marker.to_string_lossy().into_owned();
        let output = bullet_with_policy(
            &live_conformance_args(&data, "claude", &executable),
            &policy,
        );
        assert_eq!(output.status.code(), Some(1), "{name}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("POLICY_INVALID") && stderr.contains(&format!("{expected}: ")),
            "{name}: {stderr}"
        );
        assert!(!spawned.exists(), "{name}: the provider binary was spawned");
        assert!(
            !data_dir.join("live").exists(),
            "{name}: the loader refused before the path started"
        );
        assert!(!data_dir.join("ledger.sqlite").exists(), "{name}");
    }
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
