use super::canonical::{decode_canonical, hash_canonical, invalid};
use super::{CandidatePreparationGrantV1, SignedCandidatePreparationGrantV1};
use crate::error::HarnessError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CANDIDATE_PREPARATION_SIGNING_PURPOSE: &str = "candidate-preparation-grant-signing";
pub const CANDIDATE_PREPARATION_CLAIMS_DOMAIN: &str = "candidate-preparation.grant.v1alpha1";
pub const CANDIDATE_PREPARATION_ENVELOPE_DOMAIN: &str = "candidate-preparation.envelope.v1alpha1";
pub const CANDIDATE_PREPARATION_IMPLICIT_ASSERTION: &[u8] =
    b"bullet-farm.candidate-preparation-grant.v1alpha1";
const SCHEMA_VERSION: &str = "v1alpha1";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TOKEN_BYTES: usize = 32_768;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidatePreparationFooter {
    schema_version: String,
    issuer: String,
    key_id: String,
    purpose: String,
}

impl CandidatePreparationFooter {
    pub(super) fn new(issuer: &str, key_id: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            issuer: issuer.to_owned(),
            key_id: key_id.to_owned(),
            purpose: CANDIDATE_PREPARATION_SIGNING_PURPOSE.to_owned(),
        }
    }
}

pub fn decode_signed_candidate_preparation_grant(
    bytes: &[u8],
) -> Result<SignedCandidatePreparationGrantV1, HarnessError> {
    let signed: SignedCandidatePreparationGrantV1 = decode_canonical(bytes)?;
    validate_signed(&signed)?;
    Ok(signed)
}

pub fn candidate_preparation_envelope_digest(
    signed: &SignedCandidatePreparationGrantV1,
) -> Result<String, HarnessError> {
    validate_signed(signed)?;
    hash_canonical(CANDIDATE_PREPARATION_ENVELOPE_DOMAIN, signed)
}

pub(super) fn validate_signed(
    signed: &SignedCandidatePreparationGrantV1,
) -> Result<(), HarnessError> {
    require_exact("schema_version", &signed.schema_version, SCHEMA_VERSION)?;
    require_label("issuer", &signed.issuer)?;
    require_label("key_id", &signed.key_id)?;
    if !signed.paseto.starts_with("v4.public.") || signed.paseto.len() > MAX_TOKEN_BYTES {
        return Err(invalid("carrier is not a bounded PASETO v4.public token"));
    }
    Ok(())
}

pub fn validate_candidate_preparation_grant(
    grant: &CandidatePreparationGrantV1,
) -> Result<(), HarnessError> {
    require_exact("schema_version", &grant.schema_version, SCHEMA_VERSION)?;
    require_exact(
        "signing_purpose",
        &grant.signing_purpose,
        CANDIDATE_PREPARATION_SIGNING_PURPOSE,
    )?;
    require_exact(
        "claims_domain",
        &grant.claims_domain,
        CANDIDATE_PREPARATION_CLAIMS_DOMAIN,
    )?;
    require_exact(
        "envelope_domain",
        &grant.envelope_domain,
        CANDIDATE_PREPARATION_ENVELOPE_DOMAIN,
    )?;
    require_label("issuer", &grant.issuer)?;
    require_label("key_id", &grant.key_id)?;
    for (name, value, prefix) in [
        (
            "candidate_preparation_grant_id",
            grant.candidate_preparation_grant_id.as_str(),
            "cpg",
        ),
        ("repository_id", grant.repository_id.as_str(), "rep"),
        ("mission_id", grant.mission_id.as_str(), "mis"),
        ("plan_revision_id", grant.plan_revision_id.as_str(), "pln"),
        ("work_package_id", grant.work_package_id.as_str(), "wpk"),
        ("variant_id", grant.variant_id.as_str(), "var"),
        ("attempt_id", grant.attempt_id.as_str(), "atm"),
        ("runner_id", grant.runner_id.as_str(), "run"),
        ("workspace_id", grant.workspace_id.as_str(), "wsp"),
        ("change_id", grant.change_id.as_str(), "chg"),
        ("graph_revision_id", grant.graph_revision_id.as_str(), "grf"),
        (
            "context_capsule_id",
            grant.context_capsule_id.as_str(),
            "cnt",
        ),
        (
            "execution_envelope_id",
            grant.execution_envelope_id.as_str(),
            "exe",
        ),
    ] {
        require_id(name, value, prefix)?;
    }
    for (name, value) in [
        ("request_digest", grant.request_digest.as_str()),
        (
            "authority_token_digest",
            grant.authority_token_digest.as_str(),
        ),
        ("grant_nonce", grant.grant_nonce.as_str()),
        ("scope_grant_digest", grant.scope_grant_digest.as_str()),
        ("environment_digest", grant.environment_digest.as_str()),
        ("toolchain_digest", grant.toolchain_digest.as_str()),
    ] {
        require_hex(name, value)?;
    }
    for (name, value) in [
        ("attempt_fence", grant.attempt_fence),
        ("runner_epoch", grant.runner_epoch),
        ("scope_revision", grant.scope_revision),
        ("context_revision", grant.context_revision),
    ] {
        require_positive_safe(name, value)?;
    }
    for (name, value) in [
        ("authority_epoch", grant.authority_epoch),
        ("freeze_generation", grant.freeze_generation),
        ("issued_at_unix_ms", grant.issued_at_unix_ms),
        ("not_before_unix_ms", grant.not_before_unix_ms),
        ("expires_at_unix_ms", grant.expires_at_unix_ms),
    ] {
        require_safe(name, value)?;
    }
    if grant.issued_at_unix_ms > grant.not_before_unix_ms
        || grant.not_before_unix_ms >= grant.expires_at_unix_ms
    {
        return Err(invalid("grant time window is empty or inverted"));
    }
    if grant.parent_candidate_ids.len() > 128 {
        return Err(invalid("parent Candidate list exceeds 128"));
    }
    let mut parents = BTreeSet::new();
    for parent in &grant.parent_candidate_ids {
        require_id("parent_candidate_id", parent, "can")?;
        if !parents.insert(parent) {
            return Err(invalid("parent Candidate list contains a duplicate"));
        }
    }
    Ok(())
}

fn require_exact(name: &str, value: &str, expected: &str) -> Result<(), HarnessError> {
    if value == expected {
        Ok(())
    } else {
        Err(invalid(format!("{name} is not the frozen value")))
    }
}

fn require_label(name: &str, value: &str) -> Result<(), HarnessError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
        })
    {
        Err(invalid(format!("{name} is outside the frozen label set")))
    } else {
        Ok(())
    }
}

fn require_id(name: &str, value: &str, prefix: &str) -> Result<(), HarnessError> {
    let Some(hex) = value.strip_prefix(&format!("{prefix}_")) else {
        return Err(invalid(format!("{name} has the wrong prefix")));
    };
    require_hex(name, hex)
}

fn require_hex(name: &str, value: &str) -> Result<(), HarnessError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid(format!("{name} is not 64 lowercase hex")))
    }
}

fn require_safe(name: &str, value: u64) -> Result<(), HarnessError> {
    if value <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(invalid(format!("{name} exceeds the safe-integer ceiling")))
    }
}

fn require_positive_safe(name: &str, value: u64) -> Result<(), HarnessError> {
    require_safe(name, value)?;
    if value == 0 {
        Err(invalid(format!("{name} must be positive")))
    } else {
        Ok(())
    }
}
