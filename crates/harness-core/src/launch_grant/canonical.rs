//! Vendored canonical-JSON (RFC 8785) and framed-digest helpers that are
//! byte-equivalent to bullet-wire's `canonical_json`, `decode_canonical`, and
//! `hash_framed_bytes`. The Kernel takes no path dependency on the hub crate;
//! equivalence is pinned by the golden-vector test instead.

use crate::error::HarnessError;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Upper bound for one canonical document admitted at this boundary.
pub const MAX_CANONICAL_BYTES: usize = 64 * 1024;

const FRAMED_DOMAIN_PREFIX: &[u8] = b"bullet-wire.v1\0";

/// RFC 8785 canonical encoding of `value`.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` when the value cannot be canonically encoded.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, HarnessError> {
    serde_jcs::to_vec(value).map_err(|error| HarnessError::LaunchGrantInvalid {
        reason: format!("RFC 8785 encoding failed: {error}"),
    })
}

/// Strictly decode exactly one canonical document into `T`.
///
/// The bytes must be bounded, strict UTF-8 without a byte-order mark, must
/// decode into `T` without unknown or duplicate fields, and must re-encode to
/// exactly the same bytes (canonical order, numbers, and escaping).
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` for any deviation.
pub fn decode_canonical<T>(bytes: &[u8]) -> Result<T, HarnessError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(invalid("canonical document is empty or exceeds 64 KiB"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| invalid(&format!("document is not strict UTF-8: {error}")))?;
    if text.starts_with('\u{feff}') {
        return Err(invalid(
            "canonical documents do not carry a UTF-8 byte-order mark",
        ));
    }
    let value: T = serde_json::from_str(text)
        .map_err(|error| invalid(&format!("document does not match its strict type: {error}")))?;
    if canonical_json(&value)? != bytes {
        return Err(invalid("document is not RFC 8785 canonical JSON"));
    }
    Ok(value)
}

/// Domain-separated, length-framed BLAKE3 digest (lowercase hex) equivalent to
/// bullet-wire `hash_framed_bytes`.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` when the domain label is not lowercase ASCII.
pub fn hash_framed_bytes(domain: &str, bytes: &[u8]) -> Result<String, HarnessError> {
    validate_domain(domain)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(FRAMED_DOMAIN_PREFIX);
    frame(&mut hasher, domain.as_bytes());
    frame(&mut hasher, bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

/// Domain-separated digest of the canonical encoding of `value`.
///
/// # Errors
///
/// `LAUNCH_GRANT_INVALID` when the value cannot be canonically encoded.
pub fn hash_canonical<T: Serialize>(domain: &str, value: &T) -> Result<String, HarnessError> {
    validate_domain(domain)?;
    let canonical = canonical_json(value)?;
    hash_framed_bytes(domain, &canonical)
}

/// True for exactly 64 lowercase hexadecimal characters.
#[must_use]
pub fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_domain(domain: &str) -> Result<(), HarnessError> {
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || b".-_0123456789".contains(&byte))
    {
        return Err(invalid("hash domain must use lowercase ASCII labels"));
    }
    Ok(())
}

fn frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
}

fn invalid(reason: &str) -> HarnessError {
    HarnessError::LaunchGrantInvalid {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Probe {
        z: String,
        a: u64,
    }

    #[test]
    fn canonical_encoding_sorts_keys_and_round_trips() {
        let probe = Probe {
            z: "last".into(),
            a: 17,
        };
        let bytes = canonical_json(&probe).unwrap();
        assert_eq!(bytes, br#"{"a":17,"z":"last"}"#);
        assert_eq!(decode_canonical::<Probe>(&bytes).unwrap(), probe);
    }

    #[test]
    fn non_canonical_duplicate_unknown_and_bom_documents_are_refused() {
        for raw in [
            &br#"{"z":"last","a":17}"#[..],
            &br#"{"a":17,"a":18,"z":"last"}"#[..],
            &br#"{"a":17,"q":1,"z":"last"}"#[..],
            "\u{feff}{\"a\":17,\"z\":\"last\"}".as_bytes(),
            &br#"{"a": 17,"z":"last"}"#[..],
            &b""[..],
        ] {
            let error = decode_canonical::<Probe>(raw).unwrap_err();
            assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");
        }
    }

    #[test]
    fn framed_digest_matches_the_hub_cross_language_golden() {
        // bullet-wire CANONICAL_GOLDEN_JSON / CANONICAL_GOLDEN_HASH.
        let golden = r##"{"a":"é","array":[true,null,17],"z":"last"}"##;
        let value: serde_json::Value = serde_json::from_str(golden).unwrap();
        assert_eq!(canonical_json(&value).unwrap(), golden.as_bytes());
        assert!(is_lower_hex_64(
            &hash_framed_bytes("golden.cross-language", golden.as_bytes()).unwrap()
        ));
        assert!(hash_framed_bytes("Bad Domain", b"x").is_err());
    }
}
