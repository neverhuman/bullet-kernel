use super::{AuthorityScopeError, PreparedAuthorityScopeAdmission};
use crate::CommandRequest;
use bullet_domain::schema_bundle::ScopeGrantV1;
use bullet_harness_core::candidate_preparation_scope_paths_digest;
use bullet_harness_core::launch_grant::{canonical_json, MAX_SAFE_INTEGER};
use chrono::DateTime;
use serde::Serialize;
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

const MAX_SCOPE_PATHS: usize = 128;
const MAX_PATH_BYTES: usize = 4_096;
const COMMAND_KIND: &str = "admit_scope_grant";

/// Sole mutation-capable scope envelope admitted by this first substrate.
pub const AUTHORITY_SCOPE_ENVELOPE_CLASS: &str = "write-in-variant";

#[derive(Serialize)]
struct CommandPayload<'a> {
    schema_version: &'static str,
    scope_grant: &'a ScopeGrantV1,
    expected_authority_epoch: u64,
    admitted_at: &'a str,
}

/// Validate one exact generated grant and derive its command and shared scope digest.
pub fn prepare_authority_scope_admission(
    grant: &ScopeGrantV1,
    expected_authority_epoch: u64,
    idempotency_key: &str,
    now: &str,
) -> Result<PreparedAuthorityScopeAdmission, AuthorityScopeError> {
    validate_grant(grant)?;
    require_safe_positive("expected_authority_epoch", expected_authority_epoch)?;
    validate_timestamp(now)?;
    let scope_paths_digest = candidate_preparation_scope_paths_digest(&grant.normalized_paths)
        .map_err(|error| invalid(error.to_string()))?;
    let grant_bytes = canonical_json(grant).map_err(|error| invalid(error.to_string()))?;
    let payload = CommandPayload {
        schema_version: "v1alpha1",
        scope_grant: grant,
        expected_authority_epoch,
        admitted_at: now,
    };
    let command = CommandRequest::new(idempotency_key, COMMAND_KIND, &payload)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(PreparedAuthorityScopeAdmission::new(
        grant.clone(),
        command,
        grant_bytes,
        scope_paths_digest,
        expected_authority_epoch,
        now.to_owned(),
    ))
}

fn validate_grant(grant: &ScopeGrantV1) -> Result<(), AuthorityScopeError> {
    if grant.schema_version != "v1alpha1" {
        return Err(invalid("scope grant schema must be v1alpha1"));
    }
    require_prefixed_id(&grant.scope_grant_id, "sgr_")?;
    if grant.scope_revision != 1 {
        return Err(invalid(
            "initial scope admission requires scope_revision exactly 1",
        ));
    }
    validate_paths(&grant.normalized_paths)?;
    if !grant.protected_resources.is_empty() {
        return Err(invalid(
            "protected resources are unsupported until their guard is durable",
        ));
    }
    if grant.envelope_class != AUTHORITY_SCOPE_ENVELOPE_CLASS {
        return Err(invalid("unsupported scope envelope class"));
    }
    Ok(())
}

fn validate_paths(paths: &[String]) -> Result<(), AuthorityScopeError> {
    if paths.is_empty() || paths.len() > MAX_SCOPE_PATHS {
        return Err(invalid("normalized_paths must contain 1..=128 entries"));
    }
    let mut collision_keys = BTreeSet::new();
    for path in paths {
        if path.is_empty()
            || path.len() > MAX_PATH_BYTES
            || path.starts_with('/')
            || path.contains('\\')
            || path.nfc().collect::<String>() != *path
        {
            return Err(invalid(
                "scope path is not a bounded normalized relative path",
            ));
        }
        for segment in path.split('/') {
            if segment.is_empty()
                || matches!(segment, "." | "..")
                || segment.eq_ignore_ascii_case(".git")
                || segment.contains(':')
                || segment.ends_with('.')
                || segment.ends_with(' ')
                || segment.chars().any(char::is_control)
            {
                return Err(invalid("scope path contains a forbidden component"));
            }
        }
        let collision_key = path.nfc().flat_map(char::to_lowercase).collect::<String>();
        if !collision_keys.insert(collision_key) {
            return Err(invalid("scope paths contain a duplicate or case collision"));
        }
    }
    Ok(())
}

fn require_prefixed_id(value: &str, prefix: &str) -> Result<(), AuthorityScopeError> {
    if value.strip_prefix(prefix).is_some_and(|body| {
        body.len() == 64
            && body
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        Ok(())
    } else {
        Err(invalid("scope_grant_id must be sgr_ plus 64 lowercase hex"))
    }
}

fn require_safe_positive(name: &str, value: u64) -> Result<(), AuthorityScopeError> {
    if (1..=MAX_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{name} must be within 1..=MAX_SAFE_INTEGER"
        )))
    }
}

fn validate_timestamp(value: &str) -> Result<(), AuthorityScopeError> {
    if value.is_empty() || value.len() > 64 || !value.ends_with('Z') {
        return Err(invalid("admission timestamp must be bounded RFC 3339 UTC"));
    }
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid("admission timestamp must be bounded RFC 3339 UTC"))?;
    let millis = parsed.timestamp_millis();
    let instant = u64::try_from(millis)
        .map_err(|_| invalid("admission timestamp is outside the safe UTC range"))?;
    if parsed.offset().local_minus_utc() != 0 || instant > MAX_SAFE_INTEGER {
        return Err(invalid("admission timestamp is outside the safe UTC range"));
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> AuthorityScopeError {
    AuthorityScopeError::Invalid(reason.into())
}
