//! v1alpha1 policy loading: exact digest, conservatism refusals, key
//! resolution, and the by-design live-admission refusal.

use bullet_application::policy_snapshot::{
    load_policy, ActivationLedger, ActivationState, Component, ConfigurationGeneration,
    GenerationContent, LoadedPolicy, LIVE_ADMISSION_FIELD,
};
use bullet_domain::schema_bundle::POLICY_SNAPSHOT_HASH;
use bullet_harness_core::launch_grant::{canonical_json, LaunchGrantSigningKey};
use serde_json::{json, Value};
use std::path::Path;

const POLICY: &[u8] = include_bytes!("fixtures/policy-v1alpha1.json");
const NOW: u64 = 1_800_000_000_000;

type Relax = fn(&mut Value);

fn policy_value() -> Value {
    serde_json::from_slice(POLICY).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    canonical_json(value).unwrap()
}

fn invalid_reason(value: &Value) -> String {
    let error = LoadedPolicy::from_bytes(&bytes(value)).unwrap_err();
    assert_eq!(error.reason_code(), "POLICY_INVALID");
    error.to_string()
}

fn provider_runner_key(key: &LaunchGrantSigningKey) -> Value {
    json!({
        "schema_version": "v1alpha1",
        "issuer": key.issuer(),
        "key_id": key.key_id(),
        "key_purpose": "authority-signing",
        "algorithm": "paseto-v4.public",
        "public_key": key.public_key_hex(),
        "audiences": ["provider-runner"],
        "activates_at_unix_ms": NOW - 1_000,
        "expires_at_unix_ms": NOW + 1_000_000,
        "revoked_at_unix_ms": null,
        "retain_until_unix_ms": NOW + 2_000_000,
    })
}

#[test]
fn the_hub_policy_loads_with_its_pinned_digest_and_refuses_live_admission() {
    let loaded = LoadedPolicy::from_bytes(POLICY).unwrap();
    assert_eq!(loaded.generation(), 1);
    assert_eq!(
        loaded.digest(),
        POLICY_SNAPSHOT_HASH,
        "policy.snapshot identity"
    );
    assert!(!loaded.live_admission_enabled());
    let binding = loaded.binding();
    assert_eq!(binding.policy_generation, 1);
    assert!(!binding.live_admission_enabled);
    let refusal = loaded.require_live_admission().unwrap_err();
    assert_eq!(refusal.reason_code(), "POLICY_LIVE_ADMISSION_DISABLED");
    let message = refusal.to_string();
    assert!(message.contains("generation 1"), "{message}");
    assert!(message.contains(LIVE_ADMISSION_FIELD), "{message}");
    assert!(message.contains("= false"), "{message}");
}

#[test]
fn every_relaxation_is_unsafe_policy() {
    let relaxations: [(&str, Relax); 9] = [
        ("live_admission", |p| {
            p["sandbox_policy"]["live_admission_enabled"] = json!(true)
        }),
        ("shell_gates", |p| {
            p["sandbox_policy"]["arbitrary_shell_gates"] = json!(true)
        }),
        ("lease_ttl", |p| {
            p["budget_policy"]["maximum_lease_ttl_seconds"] = json!(16)
        }),
        ("headroom", |p| {
            p["budget_policy"]["unknown_quota_is_headroom"] = json!(true)
        }),
        ("author_evidence", |p| {
            p["evidence_policy"]["author_evidence_is_independent"] = json!(true)
        }),
        ("unknown_gate", |p| {
            p["evidence_policy"]["unknown_satisfies_gate"] = json!(true)
        }),
        ("holdout", |p| {
            p["evidence_policy"]["r2_requires_sealed_product_holdout"] = json!(false)
        }),
        ("incumbent", |p| {
            p["route_policy"]["universal_incumbent"] = json!("T1")
        }),
        ("evolution", |p| {
            p["route_policy"]["evolutionary_authority"] = json!(true)
        }),
    ];
    for (name, relax) in relaxations {
        let mut policy = policy_value();
        relax(&mut policy);
        let reason = invalid_reason(&policy);
        assert!(reason.contains("UNSAFE_POLICY"), "{name}: {reason}");
    }
}

#[test]
fn malformed_policies_are_typed_refusals() {
    let pretty = serde_json::to_vec_pretty(&policy_value()).unwrap();
    let error = LoadedPolicy::from_bytes(&pretty).unwrap_err();
    assert_eq!(error.reason_code(), "POLICY_INVALID");
    assert!(error.to_string().contains("NON_CANONICAL_POLICY"));
    assert_eq!(
        LoadedPolicy::from_bytes(b"").unwrap_err().reason_code(),
        "POLICY_INVALID"
    );

    let cases: [(&str, Relax, &str); 9] = [
        (
            "unknown_field",
            |p| p["extra"] = json!(1),
            "NON_CANONICAL_POLICY",
        ),
        (
            "schema",
            |p| p["schema_version"] = json!("v2"),
            "UNSUPPORTED_POLICY_SCHEMA",
        ),
        (
            "nested_schema",
            |p| p["risk_policy"]["schema_version"] = json!("v0"),
            "UNSUPPORTED_POLICY_SCHEMA",
        ),
        (
            "generation",
            |p| p["policy_generation"] = json!(0),
            "INVALID_POLICY_WINDOW",
        ),
        (
            "window",
            |p| p["expires_at_unix_ms"] = p["activation_at_unix_ms"].clone(),
            "INVALID_POLICY_WINDOW",
        ),
        (
            "no_keys",
            |p| p["issuer_keys"] = json!([]),
            "INVALID_POLICY_WINDOW",
        ),
        (
            "bundle_hash",
            |p| p["schema_bundle_hash"] = json!("short"),
            "INVALID_POLICY_WINDOW",
        ),
        (
            "duplicate_key",
            |p| {
                let key = p["issuer_keys"][0].clone();
                p["issuer_keys"].as_array_mut().unwrap().push(key);
            },
            "INVALID_ISSUER_KEY_LIFECYCLE",
        ),
        (
            "release_with_audience",
            |p| p["issuer_keys"][0]["audiences"] = json!(["bullet-gitd"]),
            "INVALID_RELEASE_PUBLIC_KEY",
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut policy = policy_value();
        mutate(&mut policy);
        let reason = invalid_reason(&policy);
        assert!(reason.contains(expected), "{name}: {reason}");
    }

    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let mut no_audience = policy_value();
    let mut silent = provider_runner_key(&key);
    silent["audiences"] = json!([]);
    no_audience["issuer_keys"]
        .as_array_mut()
        .unwrap()
        .push(silent);
    assert!(invalid_reason(&no_audience).contains("INVALID_AUTHORITY_PUBLIC_KEY"));
    let mut mixed = policy_value();
    let mut wrong_use = provider_runner_key(&key);
    wrong_use["algorithm"] = json!("ssh-ed25519");
    mixed["issuer_keys"].as_array_mut().unwrap().push(wrong_use);
    assert!(invalid_reason(&mixed).contains("INVALID_KEY_USE"));
    let mut short_retention = policy_value();
    let mut early = provider_runner_key(&key);
    early["retain_until_unix_ms"] = early["expires_at_unix_ms"].clone();
    short_retention["issuer_keys"]
        .as_array_mut()
        .unwrap()
        .push(early);
    assert!(invalid_reason(&short_retention).contains("INVALID_ISSUER_KEY_LIFECYCLE"));
}

#[test]
fn authority_keys_resolve_only_for_the_admitted_audience_and_instant() {
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let mut policy = policy_value();
    policy["activation_at_unix_ms"] = json!(NOW - 10_000);
    policy["expires_at_unix_ms"] = json!(NOW + 10_000_000);
    policy["issuer_keys"]
        .as_array_mut()
        .unwrap()
        .push(provider_runner_key(&key));
    let loaded = LoadedPolicy::from_bytes(&bytes(&policy)).unwrap();
    assert_ne!(loaded.digest(), POLICY_SNAPSHOT_HASH);
    let resolved = loaded
        .authority_key_at(
            "bullet-kernel",
            "launch-grant-alpha",
            "provider-runner",
            NOW,
        )
        .unwrap();
    assert_eq!(resolved.public_key_hex(), key.public_key_hex());

    let unknown = |issuer: &str, key_id: &str, audience: &str, now: u64| {
        let error = loaded
            .authority_key_at(issuer, key_id, audience, now)
            .unwrap_err();
        assert_eq!(error.reason_code(), "LAUNCH_GRANT_KEY_UNKNOWN");
        error.to_string()
    };
    assert!(
        unknown("bullet-kernel", "launch-grant-alpha", "bullet-gitd", NOW).contains("audience")
    );
    assert!(
        unknown("bullet-kernel", "launch-grant-beta", "provider-runner", NOW)
            .contains("not registered")
    );
    assert!(unknown(
        "bullet-kernel",
        "launch-grant-alpha",
        "provider-runner",
        NOW - 5_000
    )
    .contains("not active"));
    assert!(unknown(
        "bullet-farm-offline-policy",
        "release-signing-alpha",
        "provider-runner",
        NOW
    )
    .contains("not an authority-signing"));

    let inactive = loaded
        .authority_key_at(
            "bullet-kernel",
            "launch-grant-alpha",
            "provider-runner",
            NOW - 20_000,
        )
        .unwrap_err();
    assert_eq!(inactive.reason_code(), "POLICY_INVALID");
    assert!(inactive.to_string().contains("POLICY_NOT_ACTIVE"));

    let mut revoked = policy.clone();
    revoked["issuer_keys"][1]["revoked_at_unix_ms"] = json!(NOW - 1);
    let revoked = LoadedPolicy::from_bytes(&bytes(&revoked)).unwrap();
    let error = revoked
        .authority_key_at(
            "bullet-kernel",
            "launch-grant-alpha",
            "provider-runner",
            NOW,
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_KEY_UNKNOWN");
}

#[test]
#[cfg(unix)]
fn policy_files_are_admitted_only_from_absolute_regular_paths() {
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path().canonicalize().unwrap();
    let absent = load_policy(&data_dir, None).unwrap_err();
    assert_eq!(absent.reason_code(), "POLICY_UNAVAILABLE");
    assert_eq!(
        load_policy(Path::new("relative"), None)
            .unwrap_err()
            .reason_code(),
        "POLICY_UNAVAILABLE"
    );
    assert_eq!(
        load_policy(&data_dir, Some(Path::new("relative/policy.json")))
            .unwrap_err()
            .reason_code(),
        "POLICY_UNAVAILABLE"
    );
    std::fs::create_dir_all(data_dir.join("policy")).unwrap();
    std::fs::write(data_dir.join("policy/policy.json"), POLICY).unwrap();
    let loaded = load_policy(&data_dir, None).unwrap();
    assert_eq!(loaded.digest(), POLICY_SNAPSHOT_HASH);
    let linked = data_dir.join("linked.json");
    std::os::unix::fs::symlink(data_dir.join("policy/policy.json"), &linked).unwrap();
    let error = load_policy(&data_dir, Some(&linked)).unwrap_err();
    assert_eq!(error.reason_code(), "POLICY_UNAVAILABLE");
    assert!(error.to_string().contains("symlink"));
    let unsafe_path = data_dir.join("unsafe.json");
    let mut relaxed = policy_value();
    relaxed["sandbox_policy"]["live_admission_enabled"] = json!(true);
    std::fs::write(&unsafe_path, bytes(&relaxed)).unwrap();
    let error = load_policy(&data_dir, Some(&unsafe_path)).unwrap_err();
    assert_eq!(error.reason_code(), "POLICY_INVALID");
    assert!(error.to_string().contains("UNSAFE_POLICY"));
}

#[test]
fn the_hub_policy_digest_is_what_an_admitted_attempt_binds_through_its_generation() {
    let loaded = LoadedPolicy::from_bytes(POLICY).unwrap();
    let content = GenerationContent {
        generation: 1,
        policy_digest: loaded.digest().to_string(),
        routing_digest: "0".repeat(64),
        activation_subject: "operator:hub".to_string(),
        created_at_unix_ms: NOW,
        required_components: Component::ALL.into_iter().collect(),
    };
    let generation = ConfigurationGeneration::seal(content).unwrap();
    let mut ledger = ActivationLedger::default();
    assert_eq!(
        ledger.activate(generation.recorded(), NOW + 1).unwrap(),
        ActivationState::Activating
    );
    assert_eq!(
        ledger.generation_for_admission().unwrap_err().reason_code(),
        "GENERATION_ACTIVATING"
    );
    for component in Component::ALL {
        ledger
            .acknowledge(component, 1, generation.digest())
            .unwrap();
    }
    let binding = ledger.generation_for_admission().unwrap().binding();
    assert_eq!(binding.policy_digest, POLICY_SNAPSHOT_HASH);
    assert_eq!(
        binding.policy_digest,
        loaded.binding().policy_snapshot_digest
    );

    let mut relaxed = policy_value();
    relaxed["activation_at_unix_ms"] = json!(NOW - 10_000);
    let other = LoadedPolicy::from_bytes(&bytes(&relaxed)).unwrap();
    assert_ne!(other.digest(), POLICY_SNAPSHOT_HASH);
    let mut substituted = generation.recorded();
    substituted.content.policy_digest = other.digest().to_string();
    let error = ledger.activate(substituted, NOW + 2).unwrap_err();
    assert_eq!(
        error.reason_code(),
        "GENERATION_DIGEST_MISMATCH",
        "a substituted policy under the recorded address never activates"
    );
    assert_eq!(ledger.generation_for_admission().unwrap(), &generation);
}
