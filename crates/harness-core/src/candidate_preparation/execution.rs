//! Exact execution-envelope validation shared by issuance and verification.

use super::canonical::{hash_canonical, invalid};
use super::{CandidatePreparationGrantV1, ExecutionEnvelopeV1, ExecutionToolV1};
use crate::error::HarnessError;
use std::collections::BTreeSet;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const EXECUTION_ENVELOPE_SIGNING_PURPOSE: &str = "execution-envelope-signing";
const EXECUTION_ENVELOPE_CLAIMS_DOMAIN: &str = "execution.envelope.v1alpha1";
const EXECUTION_ENVELOPE_DIGEST_DOMAIN: &str = "execution.envelope";
const EXECUTION_TOOLCHAIN_DIGEST_DOMAIN: &str = "execution.toolchain";

pub fn execution_envelope_digest(envelope: &ExecutionEnvelopeV1) -> Result<String, HarnessError> {
    validate_execution_envelope(envelope)?;
    hash_canonical(EXECUTION_ENVELOPE_DIGEST_DOMAIN, envelope)
}

pub fn execution_toolchain_digest(tools: &[ExecutionToolV1]) -> Result<String, HarnessError> {
    validate_tools(tools)?;
    hash_canonical(EXECUTION_TOOLCHAIN_DIGEST_DOMAIN, &tools.to_vec())
}

pub fn validate_execution_envelope(envelope: &ExecutionEnvelopeV1) -> Result<(), HarnessError> {
    exact("schema_version", &envelope.schema_version, "v1alpha1")?;
    exact(
        "signing_purpose",
        &envelope.signing_purpose,
        EXECUTION_ENVELOPE_SIGNING_PURPOSE,
    )?;
    exact(
        "claims_domain",
        &envelope.claims_domain,
        EXECUTION_ENVELOPE_CLAIMS_DOMAIN,
    )?;
    digest_id(
        "execution_envelope_id",
        &envelope.execution_envelope_id,
        "exe",
    )?;
    digest_id("runner_id", &envelope.runner_id, "run")?;
    digest_id("provider_profile_id", &envelope.provider_profile_id, "prf")?;
    digest_id(
        "containment_profile_id",
        &envelope.containment_profile_id,
        "ctp",
    )?;
    for (name, value) in [
        ("environment_digest", envelope.environment_digest.as_str()),
        ("toolchain_digest", envelope.toolchain_digest.as_str()),
        (
            "sandbox_image_digest",
            envelope.sandbox_image_digest.as_str(),
        ),
    ] {
        digest(name, value)?;
    }
    for (name, value) in [
        ("issuer", envelope.issuer.as_str()),
        ("key_id", envelope.key_id.as_str()),
        ("provider", envelope.provider.as_str()),
        ("model", envelope.model.as_str()),
        ("adapter", envelope.adapter.as_str()),
        ("platform", envelope.platform.as_str()),
    ] {
        label(name, value)?;
    }
    positive_safe("runner_epoch", envelope.runner_epoch)?;
    safe("authority_epoch", envelope.authority_epoch)?;
    safe("freeze_generation", envelope.freeze_generation)?;
    safe("issued_at_unix_ms", envelope.issued_at_unix_ms)?;
    safe("expires_at_unix_ms", envelope.expires_at_unix_ms)?;
    if envelope.expires_at_unix_ms <= envelope.issued_at_unix_ms {
        return Err(invalid("execution envelope time window is empty"));
    }
    validate_tools(&envelope.tools)?;
    if envelope.toolchain_digest != execution_toolchain_digest(&envelope.tools)? {
        return Err(invalid(
            "toolchain digest does not bind the ordered tool manifest",
        ));
    }
    Ok(())
}

pub fn validate_candidate_preparation_binding(
    grant: &CandidatePreparationGrantV1,
    envelope: &ExecutionEnvelopeV1,
) -> Result<(), HarnessError> {
    super::claims::validate_candidate_preparation_grant(grant)?;
    validate_execution_envelope(envelope)?;
    if grant.execution_envelope_id != envelope.execution_envelope_id
        || grant.runner_id != envelope.runner_id
        || grant.runner_epoch != envelope.runner_epoch
        || grant.environment_digest != envelope.environment_digest
        || grant.toolchain_digest != envelope.toolchain_digest
        || grant.authority_epoch != envelope.authority_epoch
        || grant.freeze_generation != envelope.freeze_generation
        || grant.issued_at_unix_ms < envelope.issued_at_unix_ms
        || grant.expires_at_unix_ms > envelope.expires_at_unix_ms
    {
        return Err(invalid(
            "Candidate grant does not bind the exact execution envelope",
        ));
    }
    Ok(())
}

fn validate_tools(tools: &[ExecutionToolV1]) -> Result<(), HarnessError> {
    if tools.is_empty() || tools.len() > 64 {
        return Err(invalid("execution tool manifest must contain 1..=64 tools"));
    }
    let mut ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for tool in tools {
        exact("tool.schema_version", &tool.schema_version, "v1alpha1")?;
        digest_id("tool_id", &tool.tool_id, "etl")?;
        digest("tool.executable_digest", &tool.executable_digest)?;
        digest("tool.descriptor_digest", &tool.descriptor_digest)?;
        label("tool.role", &tool.role)?;
        label("tool.version", &tool.version)?;
        if !ids.insert(tool.tool_id.as_str())
            || !roles.insert(tool.role.as_str())
            || !paths.insert(tool.executable_path.as_str())
            || !tool.executable_path.starts_with('/')
            || tool.executable_path.contains('\0')
        {
            return Err(invalid(
                "execution tools require unique ids, roles, and absolute non-NUL paths",
            ));
        }
    }
    Ok(())
}

fn exact(name: &str, value: &str, expected: &str) -> Result<(), HarnessError> {
    if value == expected {
        Ok(())
    } else {
        Err(invalid(format!("{name} is not the frozen value")))
    }
}

fn digest_id(name: &str, value: &str, prefix: &str) -> Result<(), HarnessError> {
    let Some(value) = value.strip_prefix(&format!("{prefix}_")) else {
        return Err(invalid(format!("{name} has the wrong prefix")));
    };
    digest(name, value)
}

fn digest(name: &str, value: &str) -> Result<(), HarnessError> {
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

fn label(name: &str, value: &str) -> Result<(), HarnessError> {
    if value.is_empty() || value.contains('\0') || value.len() > 256 {
        Err(invalid(format!(
            "{name} is empty, overlong, or contains NUL"
        )))
    } else {
        Ok(())
    }
}

fn safe(name: &str, value: u64) -> Result<(), HarnessError> {
    if value <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(invalid(format!("{name} exceeds the safe-integer ceiling")))
    }
}

fn positive_safe(name: &str, value: u64) -> Result<(), HarnessError> {
    safe(name, value)?;
    if value == 0 {
        Err(invalid(format!("{name} must be positive")))
    } else {
        Ok(())
    }
}
