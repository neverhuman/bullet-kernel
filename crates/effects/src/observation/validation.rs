use super::{
    invalid, ObservationError, ObservationOutcomeV1, ObservationSubjectV1, ObservationV1,
    COMPONENT_CLASS, FIXTURE_TRUST, MAX_WINDOW_MS, OBSERVATION_SCHEMA,
};
use crate::EffectsError;
use bullet_harness_core::launch_grant::{
    hash_canonical, is_lower_hex_64, validate_label, MAX_SAFE_INTEGER,
};
use serde::Serialize;

pub(super) fn derive_readback(
    result: Result<Option<String>, EffectsError>,
    expected: &str,
) -> (ObservationOutcomeV1, Option<String>, Option<String>) {
    match result {
        Ok(Some(oid)) if oid == expected => (ObservationOutcomeV1::Matched, Some(oid), None),
        Ok(Some(oid)) if valid_oid(&oid) => (
            ObservationOutcomeV1::Mismatched,
            Some(oid),
            Some("TARGET_OID_MISMATCH".into()),
        ),
        Ok(Some(_)) => (
            ObservationOutcomeV1::Unknown,
            None,
            Some("TARGET_READBACK_INVALID".into()),
        ),
        Ok(None) => (
            ObservationOutcomeV1::Absent,
            None,
            Some("TARGET_ABSENT".into()),
        ),
        Err(error) => (
            ObservationOutcomeV1::Unknown,
            None,
            Some(error.reason_code().into()),
        ),
    }
}

pub(super) fn validate_subject(subject: &ObservationSubjectV1) -> Result<(), ObservationError> {
    if !typed_hex(&subject.proof_bundle_id, "prb")
        || !typed_hex(&subject.proof_root, "prf")
        || !typed_hex(&subject.integration_subject_id, "ins")
        || !valid_target(&subject.target)
        || !valid_oid(&subject.previous_oid)
        || !valid_oid(&subject.integrated_oid)
        || !valid_oid(&subject.check_sha)
        || subject.check_sha != subject.integrated_oid
        || subject.check_proof_root != subject.proof_root
        || !valid_text(&subject.check_name, 128)
    {
        return Err(invalid(
            "Candidate, proof, integration, target, or check binding is invalid",
        ));
    }
    Ok(())
}

pub(super) fn validate_record(
    record: &ObservationV1,
    issuer: &str,
    key_id: &str,
    expected: Option<(&ObservationSubjectV1, u64)>,
) -> Result<(), ObservationError> {
    validate_subject(&record.subject)?;
    if record.schema_version != OBSERVATION_SCHEMA
        || record.evidence_class != COMPONENT_CLASS
        || record.signing_trust != FIXTURE_TRUST
        || record.independent_evidence_eligible
        || record.transaction_gate_eligible
        || record.release_gate_eligible
        || record.observer_service_id != issuer
        || record.observer_key_id != key_id
        || observation_id(record)? != record.observation_id
        || !consistent_outcome(record)
    {
        return Err(invalid(
            "observation markers, identity, or derived outcome are invalid",
        ));
    }
    let window = record
        .fresh_until_unix_ms
        .checked_sub(record.observed_at_unix_ms)
        .ok_or(ObservationError::ObservationTimeInvalid)?;
    validate_window(record.observed_at_unix_ms, window)?;
    if let Some((subject, now)) = expected {
        if &record.subject != subject {
            return Err(ObservationError::SubjectMismatch);
        }
        if now > MAX_SAFE_INTEGER
            || now < record.observed_at_unix_ms
            || now >= record.fresh_until_unix_ms
        {
            return Err(ObservationError::ObservationTimeInvalid);
        }
    }
    Ok(())
}

pub(super) fn observation_id(record: &ObservationV1) -> Result<String, ObservationError> {
    hash_canonical(
        "integration.observation.id.v1",
        &Identity {
            subject: &record.subject,
            outcome: record.outcome,
            observed_oid: &record.observed_oid,
            readback_reason_code: &record.readback_reason_code,
            observed_at_unix_ms: record.observed_at_unix_ms,
            fresh_until_unix_ms: record.fresh_until_unix_ms,
            observer_service_id: &record.observer_service_id,
            observer_key_id: &record.observer_key_id,
        },
    )
    .map(|digest| format!("obs_{digest}"))
    .map_err(|error| invalid(error.to_string()))
}

pub(super) fn validate_identity(issuer: &str, key_id: &str) -> Result<(), ObservationError> {
    validate_label("issuer", issuer).map_err(|error| invalid(error.to_string()))?;
    validate_label("key_id", key_id).map_err(|error| invalid(error.to_string()))
}

pub(super) fn validate_window(observed_at: u64, window: u64) -> Result<u64, ObservationError> {
    if observed_at > MAX_SAFE_INTEGER || window == 0 || window > MAX_WINDOW_MS {
        return Err(ObservationError::ObservationTimeInvalid);
    }
    observed_at
        .checked_add(window)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or(ObservationError::ObservationTimeInvalid)
}

#[derive(Serialize)]
struct Identity<'a> {
    subject: &'a ObservationSubjectV1,
    outcome: ObservationOutcomeV1,
    observed_oid: &'a Option<String>,
    readback_reason_code: &'a Option<String>,
    observed_at_unix_ms: u64,
    fresh_until_unix_ms: u64,
    observer_service_id: &'a str,
    observer_key_id: &'a str,
}

fn consistent_outcome(record: &ObservationV1) -> bool {
    match record.outcome {
        ObservationOutcomeV1::Matched => {
            record.observed_oid.as_deref() == Some(record.subject.integrated_oid.as_str())
                && record.readback_reason_code.is_none()
                && record.integration_survived
        }
        ObservationOutcomeV1::Mismatched => {
            record
                .observed_oid
                .as_ref()
                .is_some_and(|oid| valid_oid(oid) && oid != &record.subject.integrated_oid)
                && record.readback_reason_code.as_deref() == Some("TARGET_OID_MISMATCH")
                && !record.integration_survived
        }
        ObservationOutcomeV1::Absent => {
            record.observed_oid.is_none()
                && record.readback_reason_code.as_deref() == Some("TARGET_ABSENT")
                && !record.integration_survived
        }
        ObservationOutcomeV1::Unknown => {
            record.observed_oid.is_none()
                && record
                    .readback_reason_code
                    .as_deref()
                    .is_some_and(valid_reason_code)
                && !record.integration_survived
        }
    }
}

fn typed_hex(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(is_lower_hex_64)
}

fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_target(value: &str) -> bool {
    let suffix = value.strip_prefix("refs/heads/").unwrap_or_default();
    !suffix.is_empty()
        && value.len() <= 256
        && !value.starts_with("refs/heads/bullet/candidate/")
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}
