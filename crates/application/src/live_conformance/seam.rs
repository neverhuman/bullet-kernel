//! Test-only policy builder. Derives a v1alpha2 live-admission policy from the
//! v1alpha1 fixture for a caller-supplied operator key and loads it through
//! the production loader (`policy_snapshot::LoadedPolicy::from_bytes`).
//!
//! There is no bypass: every policy a test drives through the positive
//! live-conformance path satisfies exactly the bullet-wire rules (ADR 0012),
//! so a generation below `LIVE_ADMISSION_MIN_GENERATION`, a missing
//! provider-runner key, or any conservatism relaxation is refused here the
//! same way an operator's on-disk policy would be. It is compiled only under
//! `test` or the `test-seams` feature and is never wired into the CLI.

use crate::policy_snapshot::{LoadedPolicy, POLICY_SCHEMA_VERSION_V1ALPHA2};
use bullet_harness_core::launch_grant::{canonical_json, LaunchGrantSigningKey};
use bullet_harness_core::HarnessError;
use serde_json::json;

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/policy-v1alpha1.json");
const WIDE_EXPIRY_MS: u64 = 4_000_000_000_000;
const WIDE_RETENTION_MS: u64 = 4_000_100_000_000;

/// Build a v1alpha2 policy at `generation` that enables live admission and
/// admits `key` for the `provider-runner` audience across a wide window (so
/// the deterministic simulation clock lands inside it), then load it through
/// the production loader.
///
/// # Errors
///
/// `POLICY_INVALID` exactly as the production loader refuses it (for example
/// `LIVE_ADMISSION_REQUIRES_GENERATION` below generation 2), or when the
/// fixture cannot be decoded or encoded.
pub fn live_admission_policy(
    key: &LaunchGrantSigningKey,
    generation: u64,
) -> Result<LoadedPolicy, HarnessError> {
    let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).map_err(decode)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| decode_str("policy fixture is not an object"))?;
    object.insert(
        "schema_version".into(),
        json!(POLICY_SCHEMA_VERSION_V1ALPHA2),
    );
    object.insert("policy_generation".into(), json!(generation));
    object.insert("activation_at_unix_ms".into(), json!(0));
    object.insert("expires_at_unix_ms".into(), json!(WIDE_EXPIRY_MS));
    if let Some(sandbox) = object
        .get_mut("sandbox_policy")
        .and_then(serde_json::Value::as_object_mut)
    {
        sandbox.insert("live_admission_enabled".into(), json!(true));
    }
    let provider_key = json!({
        "schema_version": "v1alpha1",
        "issuer": key.issuer(),
        "key_id": key.key_id(),
        "key_purpose": "authority-signing",
        "algorithm": "paseto-v4.public",
        "public_key": key.public_key_hex(),
        "audiences": ["provider-runner"],
        "activates_at_unix_ms": 0,
        "expires_at_unix_ms": WIDE_EXPIRY_MS,
        "revoked_at_unix_ms": null,
        "retain_until_unix_ms": WIDE_RETENTION_MS,
    });
    object
        .get_mut("issuer_keys")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| decode_str("policy fixture lacks issuer_keys"))?
        .push(provider_key);

    let bytes = canonical_json(&value)
        .map_err(|error| decode_str(&format!("canonical encoding failed: {error}")))?;
    LoadedPolicy::from_bytes(&bytes)
}

fn decode(error: serde_json::Error) -> HarnessError {
    decode_str(&error.to_string())
}

fn decode_str(reason: &str) -> HarnessError {
    HarnessError::PolicyInvalid {
        reason: format!("TEST_FIXTURE: {reason}"),
    }
}
