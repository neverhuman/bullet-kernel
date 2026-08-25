//! v1alpha2 policy snapshots (ADR 0012) through the Kernel loader, mirroring
//! bullet-wire `tests/policy_v1alpha2.rs` one-for-one: live provider admission
//! is representable only behind an operator generation and a provider-runner
//! authority key. v1alpha1 behaviour is asserted unchanged here while the
//! existing `policy_snapshot.rs` suite stays untouched. The Kernel cannot
//! import bullet-wire; every refusal below is `POLICY_INVALID` whose reason
//! starts with the hub's code.

use bullet_application::policy_snapshot::{
    validate_policy, validate_policy_at, LoadedPolicy, PolicySchemaVersion,
    LIVE_ADMISSION_MIN_GENERATION, POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_V1ALPHA2,
};
use bullet_domain::schema_bundle::{
    AuthorityAudienceV1, KeyAlgorithmV1, KeyPurposeV1, PolicySnapshotV1, INVARIANT_REGISTRY_HASH,
    POLICY_SNAPSHOT_HASH, SCHEMA_BUNDLE_HASH,
};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical};
use bullet_harness_core::HarnessError;

const FIXTURE: &[u8] = include_bytes!("fixtures/policy-v1alpha2-live-enabled.json");
const COMMITTED_POLICY: &[u8] = include_bytes!("fixtures/policy-v1alpha1.json");
const ISSUER: &str = "bullet-kernel-local";
const KEY_ID: &str = "authority-test-1";
const PUBLIC_KEY_HEX: &str = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
const V1ALPHA1_UNSAFE_REASON: &str =
    "v1alpha1 Gate 0 policy must remain offline, conservative, and T0-anchored";
const V1ALPHA2_UNSAFE_REASON: &str =
    "v1alpha2 policy must remain conservative, T0-anchored, and without evolutionary authority";

type Relax = fn(&mut PolicySnapshotV1);

fn fixture() -> PolicySnapshotV1 {
    decode_canonical(FIXTURE).unwrap()
}

fn committed() -> PolicySnapshotV1 {
    decode_canonical(COMMITTED_POLICY).unwrap()
}

fn runner_key(policy: &PolicySnapshotV1) -> usize {
    policy
        .issuer_keys
        .iter()
        .position(|key| key.issuer == ISSUER && key.key_id == KEY_ID)
        .unwrap()
}

/// Hub reason code carried as the `POLICY_INVALID` reason prefix.
fn wire_code(error: &HarnessError) -> String {
    assert_eq!(error.reason_code(), "POLICY_INVALID");
    let text = error.to_string();
    let start = text
        .find(|ch: char| ch.is_ascii_uppercase())
        .expect("reason starts with a hub code");
    let rest = &text[start..];
    rest[..rest.find(": ").expect("hub code delimiter")].to_string()
}

fn wire_reason(error: &HarnessError) -> String {
    let text = error.to_string();
    let code = wire_code(error);
    let start = text.find(&format!("{code}: ")).unwrap() + code.len() + 2;
    text[start..].to_string()
}

fn load(policy: &PolicySnapshotV1) -> Result<LoadedPolicy, HarnessError> {
    LoadedPolicy::from_bytes(&canonical_json(policy).unwrap())
}

/// Every refusal must be identical through `validate_policy` and through the
/// byte loader.
fn refusal(policy: &PolicySnapshotV1) -> String {
    let structural = validate_policy(policy).unwrap_err();
    let loaded = load(policy).unwrap_err();
    assert_eq!(structural.to_string(), loaded.to_string());
    wire_code(&structural)
}

fn accepted(policy: &PolicySnapshotV1) -> LoadedPolicy {
    validate_policy(policy).unwrap();
    load(policy).unwrap()
}

#[test]
fn fixture_is_canonical_strict_and_validates() {
    let policy = fixture();
    assert_eq!(canonical_json(&policy).unwrap(), FIXTURE);
    let loaded = LoadedPolicy::from_bytes(FIXTURE).unwrap();
    assert_eq!(loaded.snapshot(), &policy);
    validate_policy_at(&policy, policy.activation_at_unix_ms).unwrap();
    loaded.validate_at(policy.activation_at_unix_ms).unwrap();
    assert_eq!(loaded.schema(), PolicySchemaVersion::V1Alpha2);
    assert_eq!(policy.schema_version, POLICY_SCHEMA_VERSION_V1ALPHA2);
    assert_eq!(loaded.generation(), LIVE_ADMISSION_MIN_GENERATION);
    assert!(loaded.live_admission_enabled());
    assert!(loaded.binding().live_admission_enabled);
    loaded.require_live_admission().unwrap();
    assert_eq!(policy.schema_bundle_hash, SCHEMA_BUNDLE_HASH);
    assert_eq!(policy.invariant_registry_hash, INVARIANT_REGISTRY_HASH);
    assert_ne!(
        loaded.digest(),
        POLICY_SNAPSHOT_HASH,
        "not the Gate 0 digest"
    );
}

#[test]
fn fixture_differs_from_the_committed_policy_only_by_design() {
    let policy = fixture();
    let committed = committed();
    assert_eq!(committed.schema_version, POLICY_SCHEMA_VERSION);
    assert_eq!(committed.policy_generation, 1);
    assert!(!committed.sandbox_policy.live_admission_enabled);
    assert_eq!(policy.schema_bundle_hash, committed.schema_bundle_hash);
    assert_eq!(
        policy.invariant_registry_hash,
        committed.invariant_registry_hash
    );
    assert_eq!(
        policy.activation_at_unix_ms,
        committed.activation_at_unix_ms
    );
    assert_eq!(policy.expires_at_unix_ms, committed.expires_at_unix_ms);
    assert_eq!(policy.risk_policy, committed.risk_policy);
    assert_eq!(policy.evidence_policy, committed.evidence_policy);
    assert_eq!(policy.budget_policy, committed.budget_policy);
    assert_eq!(policy.route_policy, committed.route_policy);
    let mut sandbox = policy.sandbox_policy.clone();
    sandbox.live_admission_enabled = false;
    assert_eq!(sandbox, committed.sandbox_policy);
    assert_eq!(policy.issuer_keys.len(), 2);
    assert_eq!(policy.issuer_keys[0], committed.issuer_keys[0]);
    let key = &policy.issuer_keys[runner_key(&policy)];
    assert_eq!(key.key_purpose, KeyPurposeV1::AuthoritySigning);
    assert_eq!(key.algorithm, KeyAlgorithmV1::PasetoV4Public);
    assert_eq!(key.audiences, vec![AuthorityAudienceV1::ProviderRunner]);
    assert_eq!(key.public_key, PUBLIC_KEY_HEX);
    assert_eq!(key.revoked_at_unix_ms, None);
    // The committed Gate 0 fixture keeps its pinned identity.
    assert_eq!(
        LoadedPolicy::from_bytes(COMMITTED_POLICY).unwrap().digest(),
        POLICY_SNAPSHOT_HASH
    );
}

#[test]
fn live_admission_requires_a_qualifying_provider_runner_key() {
    let mut removed = fixture();
    removed.issuer_keys.remove(runner_key(&removed));
    assert_eq!(refusal(&removed), "LIVE_ADMISSION_REQUIRES_RUNNER_KEY");

    let mut wrong_audience = fixture();
    let index = runner_key(&wrong_audience);
    wrong_audience.issuer_keys[index].audiences = vec![AuthorityAudienceV1::BulletGitd];
    assert_eq!(
        refusal(&wrong_audience),
        "LIVE_ADMISSION_REQUIRES_RUNNER_KEY"
    );

    let mut revoked = fixture();
    let index = runner_key(&revoked);
    revoked.issuer_keys[index].revoked_at_unix_ms = Some(revoked.expires_at_unix_ms - 1);
    assert_eq!(refusal(&revoked), "LIVE_ADMISSION_REQUIRES_RUNNER_KEY");

    let mut lapsed = fixture();
    let index = runner_key(&lapsed);
    let activation = lapsed.activation_at_unix_ms;
    lapsed.issuer_keys[index].activates_at_unix_ms = activation - 2_000_000;
    lapsed.issuer_keys[index].expires_at_unix_ms = activation - 1_000_000;
    lapsed.issuer_keys[index].retain_until_unix_ms = activation;
    assert_eq!(refusal(&lapsed), "LIVE_ADMISSION_REQUIRES_RUNNER_KEY");

    let mut offline = removed;
    offline.sandbox_policy.live_admission_enabled = false;
    accepted(&offline);
}

#[test]
fn live_admission_requires_generation_two() {
    let mut first = fixture();
    first.policy_generation = 1;
    let error = validate_policy(&first).unwrap_err();
    assert_eq!(wire_code(&error), "LIVE_ADMISSION_REQUIRES_GENERATION");
    assert!(
        wire_reason(&error).contains("generation 2"),
        "{}",
        wire_reason(&error)
    );
    assert_eq!(refusal(&first), "LIVE_ADMISSION_REQUIRES_GENERATION");

    let mut zero = fixture();
    zero.policy_generation = 0;
    assert_eq!(refusal(&zero), "INVALID_POLICY_WINDOW");

    let mut later = fixture();
    later.policy_generation = 7;
    assert_eq!(accepted(&later).generation(), 7);

    let mut offline = fixture();
    offline.policy_generation = 1;
    offline.sandbox_policy.live_admission_enabled = false;
    let loaded = accepted(&offline);
    assert_eq!(loaded.schema(), PolicySchemaVersion::V1Alpha2);
    assert_eq!(
        loaded.require_live_admission().unwrap_err().reason_code(),
        "POLICY_LIVE_ADMISSION_DISABLED"
    );
}

#[test]
fn immutable_conservatism_set_is_unsafe_in_v1alpha2() {
    let relaxations: [(&str, Relax); 8] = [
        ("evolutionary_authority", |policy| {
            policy.route_policy.evolutionary_authority = true;
        }),
        ("maximum_lease_ttl_seconds", |policy| {
            policy.budget_policy.maximum_lease_ttl_seconds = 16;
        }),
        ("unknown_quota_is_headroom", |policy| {
            policy.budget_policy.unknown_quota_is_headroom = true;
        }),
        ("arbitrary_shell_gates", |policy| {
            policy.sandbox_policy.arbitrary_shell_gates = true;
        }),
        ("author_evidence_is_independent", |policy| {
            policy.evidence_policy.author_evidence_is_independent = true;
        }),
        ("unknown_satisfies_gate", |policy| {
            policy.evidence_policy.unknown_satisfies_gate = true;
        }),
        ("r2_requires_sealed_product_holdout", |policy| {
            policy.evidence_policy.r2_requires_sealed_product_holdout = false;
        }),
        ("universal_incumbent", |policy| {
            policy.route_policy.universal_incumbent = "T1".to_owned();
        }),
    ];
    for (name, relax) in relaxations {
        let mut policy = fixture();
        relax(&mut policy);
        let error = validate_policy(&policy).unwrap_err();
        assert_eq!(wire_code(&error), "UNSAFE_POLICY", "{name}");
        assert_eq!(wire_reason(&error), V1ALPHA2_UNSAFE_REASON, "{name}");
        assert_eq!(refusal(&policy), "UNSAFE_POLICY", "{name}");
    }

    // The conservatism set is checked before the live-admission rule.
    let mut stacked = fixture();
    stacked.route_policy.evolutionary_authority = true;
    stacked.policy_generation = 1;
    stacked.issuer_keys.remove(runner_key(&stacked));
    assert_eq!(refusal(&stacked), "UNSAFE_POLICY");
}

#[test]
fn v1alpha1_live_admission_remains_unsafe_policy_unchanged() {
    let mut downgraded = fixture();
    downgraded.schema_version = POLICY_SCHEMA_VERSION.to_owned();
    let error = validate_policy(&downgraded).unwrap_err();
    assert_eq!(wire_code(&error), "UNSAFE_POLICY");
    assert_eq!(wire_reason(&error), V1ALPHA1_UNSAFE_REASON);
    assert_eq!(refusal(&downgraded), "UNSAFE_POLICY");

    let mut committed_live = committed();
    committed_live.sandbox_policy.live_admission_enabled = true;
    let error = validate_policy(&committed_live).unwrap_err();
    assert_eq!(wire_code(&error), "UNSAFE_POLICY");
    assert_eq!(wire_reason(&error), V1ALPHA1_UNSAFE_REASON);
    assert_eq!(refusal(&committed_live), "UNSAFE_POLICY");

    let committed = committed();
    let loaded = accepted(&committed);
    validate_policy_at(&committed, committed.activation_at_unix_ms).unwrap();
    loaded.validate_at(committed.activation_at_unix_ms).unwrap();
    assert_eq!(loaded.schema(), PolicySchemaVersion::V1Alpha1);
    assert_eq!(
        loaded.require_live_admission().unwrap_err().reason_code(),
        "POLICY_LIVE_ADMISSION_DISABLED"
    );
}

#[test]
fn unsupported_and_nested_schema_versions_fail_closed() {
    for version in ["v1alpha3", "v1alpha", "V1ALPHA2", ""] {
        let mut policy = fixture();
        policy.schema_version = version.to_owned();
        assert_eq!(refusal(&policy), "UNSUPPORTED_POLICY_SCHEMA", "{version}");
        assert_eq!(
            wire_code(&PolicySchemaVersion::parse(version).unwrap_err()),
            "UNSUPPORTED_POLICY_SCHEMA"
        );
    }
    let mut nested = fixture();
    nested.sandbox_policy.schema_version = POLICY_SCHEMA_VERSION_V1ALPHA2.to_owned();
    assert_eq!(refusal(&nested), "UNSUPPORTED_POLICY_SCHEMA");
    let mut keyed = fixture();
    let index = runner_key(&keyed);
    keyed.issuer_keys[index].schema_version = POLICY_SCHEMA_VERSION_V1ALPHA2.to_owned();
    assert_eq!(refusal(&keyed), "UNSUPPORTED_POLICY_SCHEMA");

    assert_eq!(
        PolicySchemaVersion::ACCEPTED,
        [POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_V1ALPHA2]
    );
    for version in PolicySchemaVersion::ACCEPTED {
        assert_eq!(
            PolicySchemaVersion::parse(version).unwrap().as_str(),
            version
        );
    }
}

#[test]
fn authority_key_lookup_admits_the_fixture_runner_key() {
    let loaded = LoadedPolicy::from_bytes(FIXTURE).unwrap();
    let now = loaded.snapshot().activation_at_unix_ms;
    let key = loaded
        .authority_key_at(ISSUER, KEY_ID, "provider-runner", now)
        .unwrap();
    assert_eq!(key.key_id(), KEY_ID);
    assert_eq!(key.public_key_hex(), PUBLIC_KEY_HEX);
    // The Kernel folds the hub's AUTHORITY_KEY_AUDIENCE_MISMATCH and
    // AUTHORITY_KEY_WRONG_PURPOSE into LAUNCH_GRANT_KEY_UNKNOWN (unchanged).
    let mismatch = loaded
        .authority_key_at(ISSUER, KEY_ID, "effect-broker", now)
        .unwrap_err();
    assert_eq!(mismatch.reason_code(), "LAUNCH_GRANT_KEY_UNKNOWN");
    assert!(mismatch.to_string().contains("audience"));
    let wrong_purpose = loaded
        .authority_key_at(
            "bullet-farm-offline-policy",
            "release-signing-alpha",
            "provider-runner",
            now,
        )
        .unwrap_err();
    assert_eq!(wrong_purpose.reason_code(), "LAUNCH_GRANT_KEY_UNKNOWN");
    assert!(wrong_purpose
        .to_string()
        .contains("not an authority-signing"));
}

#[test]
fn validate_at_applies_the_authority_key_instant_semantics() {
    let policy = fixture();
    let loaded = LoadedPolicy::from_bytes(FIXTURE).unwrap();
    let activation = policy.activation_at_unix_ms;
    let expiry = policy.expires_at_unix_ms;
    for now in [activation, expiry - 1] {
        validate_policy_at(&policy, now).unwrap();
        loaded.validate_at(now).unwrap();
    }
    for now in [activation - 1, expiry] {
        assert_eq!(
            wire_code(&validate_policy_at(&policy, now).unwrap_err()),
            "POLICY_NOT_ACTIVE"
        );
        assert_eq!(
            wire_code(&loaded.validate_at(now).unwrap_err()),
            "POLICY_NOT_ACTIVE"
        );
    }

    let mut delayed = fixture();
    let index = runner_key(&delayed);
    delayed.issuer_keys[index].activates_at_unix_ms = activation + 1_000;
    let loaded_delayed = accepted(&delayed);
    assert_eq!(
        wire_code(&validate_policy_at(&delayed, activation).unwrap_err()),
        "LIVE_ADMISSION_REQUIRES_RUNNER_KEY"
    );
    assert_eq!(
        wire_code(&loaded_delayed.validate_at(activation).unwrap_err()),
        "LIVE_ADMISSION_REQUIRES_RUNNER_KEY"
    );
    validate_policy_at(&delayed, activation + 1_000).unwrap();
    loaded_delayed.validate_at(activation + 1_000).unwrap();

    let mut offline = fixture();
    offline.sandbox_policy.live_admission_enabled = false;
    offline.issuer_keys.remove(runner_key(&offline));
    validate_policy_at(&offline, activation).unwrap();
    accepted(&offline).validate_at(activation).unwrap();

    // A structurally invalid snapshot never reaches the instant checks.
    let mut unsafe_policy = fixture();
    unsafe_policy.route_policy.evolutionary_authority = true;
    assert_eq!(
        wire_code(&validate_policy_at(&unsafe_policy, activation).unwrap_err()),
        "UNSAFE_POLICY"
    );
}
