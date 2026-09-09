//! Issuer-key lifecycle rules (bullet-wire `policy::keys`) over the generated
//! `IssuerKeyV1`, plus audience-aware key resolution for launch grants.

use super::invalid;
use bullet_domain::schema_bundle::{
    AuthorityAudienceV1, IssuerKeyV1, KeyAlgorithmV1, KeyPurposeV1, PolicySnapshotV1,
};
use bullet_harness_core::launch_grant::{is_lower_hex_64, LaunchGrantVerificationKey};
use bullet_harness_core::HarnessError;
use std::collections::BTreeSet;

const KEY_RETENTION_GRACE_MS: u64 = 15_000;

/// Wire label of a generated audience (`bullet-gitd`, `effect-broker`,
/// `provider-runner`).
#[must_use]
pub fn audience_label(audience: &AuthorityAudienceV1) -> String {
    serde_json::to_value(audience)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub(super) fn validate_issuer_keys(keys: &[IssuerKeyV1]) -> Result<(), HarnessError> {
    let mut identities = BTreeSet::new();
    for key in keys {
        if key.schema_version != super::POLICY_SCHEMA_VERSION {
            return Err(invalid(
                "UNSUPPORTED_POLICY_SCHEMA",
                "IssuerKeyV1 schema is unsupported",
            ));
        }
        let audiences = key
            .audiences
            .iter()
            .map(audience_label)
            .collect::<BTreeSet<_>>();
        if key.issuer.is_empty()
            || key.key_id.is_empty()
            || !identities.insert((key.issuer.as_str(), key.key_id.as_str()))
            || key.activates_at_unix_ms >= key.expires_at_unix_ms
            || key.retain_until_unix_ms
                < key
                    .expires_at_unix_ms
                    .saturating_add(KEY_RETENTION_GRACE_MS)
            || key.revoked_at_unix_ms.is_some_and(|revoked| {
                revoked < key.activates_at_unix_ms || revoked > key.retain_until_unix_ms
            })
            || audiences.len() != key.audiences.len()
        {
            return Err(invalid(
                "INVALID_ISSUER_KEY_LIFECYCLE",
                "issuer keys require unique identities and ordered activation, expiry, revocation, and retention windows",
            ));
        }
        match (&key.key_purpose, &key.algorithm) {
            (KeyPurposeV1::AuthoritySigning, KeyAlgorithmV1::PasetoV4Public) => {
                if key.audiences.is_empty() || !is_lower_hex_64(&key.public_key) {
                    return Err(invalid(
                        "INVALID_AUTHORITY_PUBLIC_KEY",
                        "authority keys require audiences and a raw 32-byte lowercase-hex public key",
                    ));
                }
                LaunchGrantVerificationKey::from_hex(&key.issuer, &key.key_id, &key.public_key)
                    .map_err(|error| invalid("INVALID_AUTHORITY_PUBLIC_KEY", &error.to_string()))?;
            }
            (KeyPurposeV1::ReleaseSigning, KeyAlgorithmV1::SshEd25519) => {
                if !key.audiences.is_empty() || !key.public_key.starts_with("ssh-ed25519 ") {
                    return Err(invalid(
                        "INVALID_RELEASE_PUBLIC_KEY",
                        "release keys require SSH Ed25519 form and no runtime audience",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "INVALID_KEY_USE",
                    "key purpose and algorithm are incompatible",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn authority_key_at(
    policy: &PolicySnapshotV1,
    issuer: &str,
    key_id: &str,
    audience: &str,
    now_unix_ms: u64,
) -> Result<LaunchGrantVerificationKey, HarnessError> {
    if now_unix_ms < policy.activation_at_unix_ms || now_unix_ms >= policy.expires_at_unix_ms {
        return Err(invalid(
            "POLICY_NOT_ACTIVE",
            &format!(
                "policy generation {} is not active at {now_unix_ms}",
                policy.policy_generation
            ),
        ));
    }
    let key = policy
        .issuer_keys
        .iter()
        .find(|key| key.issuer == issuer && key.key_id == key_id)
        .ok_or_else(|| unknown(issuer, key_id, "issuer and key id are not registered"))?;
    if key.key_purpose != KeyPurposeV1::AuthoritySigning
        || key.algorithm != KeyAlgorithmV1::PasetoV4Public
    {
        return Err(unknown(
            issuer,
            key_id,
            "selected key is not an authority-signing PASETO key",
        ));
    }
    if !key
        .audiences
        .iter()
        .any(|admitted| audience_label(admitted) == audience)
    {
        return Err(unknown(
            issuer,
            key_id,
            &format!("selected key is not admitted for audience {audience}"),
        ));
    }
    if now_unix_ms < key.activates_at_unix_ms
        || now_unix_ms >= key.expires_at_unix_ms
        || key
            .revoked_at_unix_ms
            .is_some_and(|revoked| now_unix_ms >= revoked)
    {
        return Err(unknown(
            issuer,
            key_id,
            "selected key is not active at the verification instant",
        ));
    }
    LaunchGrantVerificationKey::from_hex(&key.issuer, &key.key_id, &key.public_key)
}

fn unknown(issuer: &str, key_id: &str, reason: &str) -> HarnessError {
    HarnessError::LaunchGrantKeyUnknown {
        issuer: issuer.to_string(),
        key_id: key_id.to_string(),
        reason: reason.to_string(),
    }
}
