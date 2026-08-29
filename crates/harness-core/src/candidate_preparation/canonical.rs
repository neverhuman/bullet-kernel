use crate::error::HarnessError;
use serde::{de::DeserializeOwned, Serialize};

const MAX_CANONICAL_BYTES: usize = 64 * 1024;
const FRAMED_DOMAIN_PREFIX: &[u8] = b"bullet-wire.v1\0";

pub(super) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, HarnessError> {
    canonical_candidate_preparation_json(value)
}

pub fn canonical_candidate_preparation_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, HarnessError> {
    serde_jcs::to_vec(value).map_err(|error| invalid(format!("RFC 8785 encoding failed: {error}")))
}

pub(super) fn decode_canonical<T>(bytes: &[u8]) -> Result<T, HarnessError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(invalid("canonical document is empty or exceeds 64 KiB"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| invalid(format!("document is not strict UTF-8: {error}")))?;
    if text.starts_with('\u{feff}') {
        return Err(invalid("canonical document carries a UTF-8 BOM"));
    }
    let value: T = serde_json::from_str(text)
        .map_err(|error| invalid(format!("document does not match its strict type: {error}")))?;
    if canonical_json(&value)? != bytes {
        return Err(invalid("document is not RFC 8785 canonical JSON"));
    }
    Ok(value)
}

pub(super) fn hash_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, HarnessError> {
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || b".-_0123456789".contains(&byte))
    {
        return Err(invalid("hash domain is outside the frozen ASCII set"));
    }
    let bytes = canonical_json(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(FRAMED_DOMAIN_PREFIX);
    for subject in [domain.as_bytes(), bytes.as_slice()] {
        hasher.update(
            &u64::try_from(subject.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(subject);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn invalid(reason: impl Into<String>) -> HarnessError {
    HarnessError::CandidatePreparationInvalid {
        reason: reason.into(),
    }
}
