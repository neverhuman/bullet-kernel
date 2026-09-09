//! Signed, single-use, short-lived probe grants: the authority PROBE-1b needs
//! to execute one contained `claude --version` + protocol hello under real
//! admission instead of a paperwork probe.
//!
//! Same scheme as launch grants, reused exactly: PASETO v4.public over RFC 8785
//! claims, canonical authenticated footer, implicit assertion, the same
//! `LaunchGrantSigningKey` / `LaunchGrantVerificationKey`, the same
//! `LaunchGrantNonceLedger` for single use, and the same
//! `sandbox_policy.live_admission_enabled` gate. Disjoint purpose: the footer
//! purpose, implicit assertion, claims schema, and the closed one-variant
//! `ProbePurpose` all differ from launch grants, so a launch grant can never
//! verify as a probe grant and a probe grant can never verify as a launch grant.
//! A verified grant yields `live::ProbeGrantEvidence` (defined by PROBE-1A) with
//! `grant_blake3` = domain-separated BLAKE3 over the canonical claims.

use super::canonical::{canonical_json, decode_canonical, hash_canonical, is_lower_hex_64};
use super::claims::{validate_label, MAX_LAUNCH_GRANT_TTL_MS, MAX_SAFE_INTEGER};
use super::expectation::PolicyBinding;
use super::keys::{LaunchGrantSigningKey, LaunchGrantVerificationKey};
use super::nonce::{LaunchGrantNonceLedger, NonceConsumption};
use crate::error::HarnessError;
use crate::live::{ContainmentClass, ProbeGrantEvidence};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::Public;
use serde::{Deserialize, Serialize};

/// Frozen schema label carried by the claims and the envelope.
pub const PROBE_GRANT_SCHEMA: &str = "bullet.probe-grant.v1";
/// Footer purpose binding the issuer key to probe grants only.
pub const PROBE_GRANT_KEY_PURPOSE: &str = "probe-grant-signing";
/// PASETO implicit assertion; never transmitted, always authenticated.
pub const PROBE_GRANT_IMPLICIT_ASSERTION: &[u8] = b"bullet-farm.probe-grant.v1";
/// Digest domain for `ProbeGrantEvidence.grant_blake3`.
pub const PROBE_GRANT_CLAIMS_DOMAIN: &str = "authority.probe-grant-claims.v1";
/// Hard cap on `expires_at - issued_at`; equal to the launch-grant cap (15 s).
pub const MAX_PROBE_GRANT_TTL_MS: u64 = MAX_LAUNCH_GRANT_TTL_MS;
/// Value passed in the ledger's Attempt slot: probe nonces live in their own
/// scope and can never be consumed by a launch grant (`atm_` + 64 hex) or vice
/// versa.
pub const PROBE_GRANT_NONCE_SCOPE: &str = "bullet.probe-grant.v1";
/// Upper bound on one serialized token.
pub const MAX_PROBE_TOKEN_BYTES: usize = 4_096;
const PROVIDERS: [&str; 4] = ["claude", "codex", "cursor", "agy"];

/// Closed purpose set: exactly one variant, so no probe grant can carry a
/// launch purpose at the type level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbePurpose {
    /// Execute one contained runtime probe; never a provider turn.
    Probe,
}

impl<'de> Deserialize<'de> for ProbePurpose {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = String::deserialize(deserializer)?;
        if label == "probe" {
            Ok(Self::Probe)
        } else {
            Err(serde::de::Error::custom("purpose must be probe"))
        }
    }
}

/// Signed claim set of one probe grant. Field order is irrelevant (RFC 8785).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeGrantClaims {
    /// Always `bullet.probe-grant.v1`.
    pub schema: String,
    /// Always `probe`.
    pub purpose: ProbePurpose,
    /// Issuer label; must equal the footer and the selected key.
    pub issuer: String,
    /// Key label; must equal the footer and the selected key.
    pub key_id: String,
    /// One of `claude`, `codex`, `cursor`, `agy`.
    pub provider: String,
    /// Exact executable bytes the probe may run.
    pub executable_blake3: String,
    /// Containment the probe must run under.
    pub containment: ContainmentClass,
    /// Single-use 64-hex nonce persisted by the issuer under the probe scope.
    pub nonce: String,
    /// Issue instant; also the inclusive validity start.
    pub issued_at_unix_ms: u64,
    /// Exclusive validity end; at most 15 s after `issued_at_unix_ms`.
    pub expires_at_unix_ms: u64,
}

impl ProbeGrantClaims {
    /// Validate every field exactly. Shape validity is not authority.
    ///
    /// # Errors
    ///
    /// `PROBE_GRANT_MALFORMED` naming the field, or `PROBE_GRANT_TTL_EXCEEDED`.
    pub fn validate_shape(&self) -> Result<(), ProbeGrantError> {
        if self.schema != PROBE_GRANT_SCHEMA {
            return Err(malformed("schema", "must be bullet.probe-grant.v1"));
        }
        label("issuer", &self.issuer)?;
        label("key_id", &self.key_id)?;
        if !PROVIDERS.contains(&self.provider.as_str()) {
            return Err(malformed("provider", "not in the frozen provider set"));
        }
        if !is_lower_hex_64(&self.executable_blake3) {
            return Err(malformed("executable_blake3", "must be 64 lowercase hex"));
        }
        if !is_lower_hex_64(&self.nonce) {
            return Err(malformed("nonce", "must be 64 lowercase hex"));
        }
        if self.issued_at_unix_ms == 0 || self.issued_at_unix_ms > MAX_SAFE_INTEGER {
            return Err(malformed("issued_at_unix_ms", "must be a safe integer"));
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms > MAX_SAFE_INTEGER
        {
            return Err(malformed(
                "expires_at_unix_ms",
                "must be after issued_at_unix_ms and at most MAX_SAFE_INTEGER",
            ));
        }
        let ttl_ms = self.expires_at_unix_ms - self.issued_at_unix_ms;
        if ttl_ms > MAX_PROBE_GRANT_TTL_MS {
            return Err(ProbeGrantError::TtlExceeded { ttl_ms });
        }
        Ok(())
    }

    /// Validity window `[issued_at, expires_at)`.
    #[must_use]
    pub fn window(&self) -> (u64, u64) {
        (self.issued_at_unix_ms, self.expires_at_unix_ms)
    }

    /// Domain-separated framed BLAKE3 over the canonical claims; this is the
    /// `grant_blake3` every probe observation binds to.
    ///
    /// # Errors
    ///
    /// Shape refusal or `PROBE_GRANT_INVALID` on encoding failure.
    pub fn digest(&self) -> Result<String, ProbeGrantError> {
        self.validate_shape()?;
        Ok(hash_canonical(PROBE_GRANT_CLAIMS_DOMAIN, self)?)
    }
}

/// Serialized probe grant: labels for key selection plus the PASETO token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProbeGrant {
    /// Always `bullet.probe-grant.v1`.
    pub schema: String,
    /// Issuer label the verifier selects a key by.
    pub issuer: String,
    /// Key label the verifier selects a key by.
    pub key_id: String,
    /// `v4.public.` token.
    pub paseto: String,
}

impl SignedProbeGrant {
    /// Validate the envelope shape only; carries no authority.
    ///
    /// # Errors
    ///
    /// `PROBE_GRANT_MALFORMED` naming the field.
    pub fn validate_envelope(&self) -> Result<(), ProbeGrantError> {
        if self.schema != PROBE_GRANT_SCHEMA {
            return Err(malformed("schema", "must be bullet.probe-grant.v1"));
        }
        label("issuer", &self.issuer)?;
        label("key_id", &self.key_id)?;
        if !self.paseto.starts_with("v4.public.")
            || self.paseto.len() > MAX_PROBE_TOKEN_BYTES
            || !self.paseto.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(malformed(
                "paseto",
                "must be a bounded printable v4.public token",
            ));
        }
        Ok(())
    }
}

/// What the verifier requires the grant to authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeExpectation {
    /// Provider wire name about to be probed.
    pub provider: String,
    /// Exact executable bytes about to be executed.
    pub executable_blake3: String,
    /// Containment the probe will actually run under.
    pub containment: ContainmentClass,
}

/// Typed refusals; `UNKNOWN` is never a success.
#[derive(Debug, thiserror::Error)]
pub enum ProbeGrantError {
    /// A claim or envelope field has the wrong shape.
    #[error("probe grant malformed on {field}: {reason}")]
    Malformed { field: &'static str, reason: String },
    /// Encoding, entropy, or ledger failure surfaced by a shared helper.
    #[error("probe grant invalid: {reason}")]
    Invalid { reason: String },
    /// The token was signed for another purpose (for example a launch grant).
    #[error("probe grant purpose mismatch: signed for {found}")]
    PurposeMismatch { found: String },
    /// No verification key matches the envelope labels.
    #[error("probe grant key unknown: {issuer}/{key_id}")]
    KeyUnknown { issuer: String, key_id: String },
    /// Signature, footer, or implicit assertion failed to authenticate.
    #[error("probe grant signature, footer, or implicit assertion is invalid")]
    SignatureInvalid,
    /// `expires_at - issued_at` is above the hard cap.
    #[error("probe grant ttl {ttl_ms} ms exceeds the 15000 ms cap")]
    TtlExceeded { ttl_ms: u64 },
    /// Presented before `issued_at`.
    #[error("probe grant not valid before {issued_at_unix_ms}")]
    NotYetValid { issued_at_unix_ms: u64 },
    /// Presented at or after `expires_at`, or the ledger record expired.
    #[error("probe grant expired at {expires_at_unix_ms}")]
    Expired { expires_at_unix_ms: u64 },
    /// Authenticated claim differs from the expectation.
    #[error("probe grant subject mismatch on {field}")]
    SubjectMismatch { field: &'static str },
    /// Policy keeps live admission disabled; nothing is consumed.
    #[error("policy generation {generation} keeps {field} disabled")]
    LiveAdmissionDisabled {
        generation: u64,
        field: &'static str,
    },
    /// The nonce was already spent.
    #[error("probe grant nonce {nonce} replayed")]
    Replayed { nonce: String },
    /// The nonce was never registered under the probe scope.
    #[error("probe grant nonce {nonce} was never registered under the probe scope")]
    NonceUnknown { nonce: String },
}

impl ProbeGrantError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "PROBE_GRANT_MALFORMED",
            Self::Invalid { .. } => "PROBE_GRANT_INVALID",
            Self::PurposeMismatch { .. } => "PROBE_GRANT_PURPOSE_MISMATCH",
            Self::KeyUnknown { .. } => "PROBE_GRANT_KEY_UNKNOWN",
            Self::SignatureInvalid => "PROBE_GRANT_SIGNATURE_INVALID",
            Self::TtlExceeded { .. } => "PROBE_GRANT_TTL_EXCEEDED",
            Self::NotYetValid { .. } => "PROBE_GRANT_NOT_YET_VALID",
            Self::Expired { .. } => "PROBE_GRANT_EXPIRED",
            Self::SubjectMismatch { .. } => "PROBE_GRANT_SUBJECT_MISMATCH",
            Self::LiveAdmissionDisabled { .. } => "POLICY_LIVE_ADMISSION_DISABLED",
            Self::Replayed { .. } => "PROBE_GRANT_REPLAYED",
            Self::NonceUnknown { .. } => "PROBE_GRANT_NONCE_UNKNOWN",
        }
    }

    /// The claim, envelope, or policy field the refusal names, if any.
    #[must_use]
    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::Malformed { field, .. }
            | Self::SubjectMismatch { field }
            | Self::LiveAdmissionDisabled { field, .. } => Some(field),
            Self::PurposeMismatch { .. } => Some("purpose"),
            Self::KeyUnknown { .. } => Some("key_id"),
            Self::SignatureInvalid => Some("paseto"),
            Self::TtlExceeded { .. } | Self::Expired { .. } => Some("expires_at_unix_ms"),
            Self::NotYetValid { .. } => Some("issued_at_unix_ms"),
            Self::Replayed { .. } | Self::NonceUnknown { .. } => Some("nonce"),
            Self::Invalid { .. } => None,
        }
    }
}

impl From<HarnessError> for ProbeGrantError {
    fn from(error: HarnessError) -> Self {
        Self::Invalid {
            reason: error.to_string(),
        }
    }
}

/// Canonical footer bound into every probe-grant signature; same key set as
/// the launch-grant footer so a foreign footer's purpose can be read back.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeGrantFooter {
    schema_version: String,
    issuer: String,
    key_id: String,
    purpose: String,
}

/// Canonical footer bytes for `(issuer, key_id)`.
///
/// # Errors
///
/// `PROBE_GRANT_INVALID` on encoding failure.
pub fn probe_grant_footer(issuer: &str, key_id: &str) -> Result<Vec<u8>, ProbeGrantError> {
    Ok(canonical_json(&ProbeGrantFooter {
        schema_version: PROBE_GRANT_SCHEMA.to_string(),
        issuer: issuer.to_string(),
        key_id: key_id.to_string(),
        purpose: PROBE_GRANT_KEY_PURPOSE.to_string(),
    })?)
}

/// Sign validated claims with the issuer key whose labels they name. The
/// issuer must separately register `claims.nonce` under
/// `PROBE_GRANT_NONCE_SCOPE` with `claims.expires_at_unix_ms`.
///
/// # Errors
///
/// Shape refusal, `PROBE_GRANT_TTL_EXCEEDED`, `PROBE_GRANT_MALFORMED` on a
/// label mismatch, or `PROBE_GRANT_INVALID` on a signing failure.
pub fn mint_probe_grant(
    key: &LaunchGrantSigningKey,
    claims: &ProbeGrantClaims,
) -> Result<SignedProbeGrant, ProbeGrantError> {
    claims.validate_shape()?;
    if claims.issuer != key.issuer() {
        return Err(malformed("issuer", "does not match the signing key"));
    }
    if claims.key_id != key.key_id() {
        return Err(malformed("key_id", "does not match the signing key"));
    }
    let payload = canonical_json(claims)?;
    let footer = probe_grant_footer(key.issuer(), key.key_id())?;
    let secret = AsymmetricSecretKey::<V4>::from(key.secret_bytes())
        .map_err(|_| invalid("signing key bytes are not a v4.public secret"))?;
    let paseto = PublicToken::sign(
        &secret,
        &payload,
        Some(&footer),
        Some(PROBE_GRANT_IMPLICIT_ASSERTION),
    )
    .map_err(|_| invalid("PASETO signing failed"))?;
    Ok(SignedProbeGrant {
        schema: PROBE_GRANT_SCHEMA.to_string(),
        issuer: key.issuer().to_string(),
        key_id: key.key_id().to_string(),
        paseto,
    })
}

/// Verify one probe grant fail-closed and consume its nonce exactly once.
/// Order: envelope, key selection, authentication, shape, subject, time,
/// policy, then the single side effect (nonce consumption).
///
/// # Errors
///
/// Every `ProbeGrantError` variant. Nothing is consumed unless every other
/// check passed; a disabled policy refuses without touching the ledger.
pub fn verify_probe_grant(
    token: &SignedProbeGrant,
    policy: &PolicyBinding,
    keys: &[LaunchGrantVerificationKey],
    nonces: &mut dyn LaunchGrantNonceLedger,
    now_unix_ms: u64,
    expected: &ProbeExpectation,
) -> Result<ProbeGrantEvidence, ProbeGrantError> {
    token.validate_envelope()?;
    let key = keys
        .iter()
        .find(|key| key.issuer() == token.issuer && key.key_id() == token.key_id)
        .ok_or_else(|| ProbeGrantError::KeyUnknown {
            issuer: token.issuer.clone(),
            key_id: token.key_id.clone(),
        })?;
    let claims = authenticate(key, token)?;
    if claims.provider != expected.provider {
        return Err(ProbeGrantError::SubjectMismatch { field: "provider" });
    }
    if claims.executable_blake3 != expected.executable_blake3 {
        return Err(ProbeGrantError::SubjectMismatch {
            field: "executable_blake3",
        });
    }
    if claims.containment != expected.containment {
        return Err(ProbeGrantError::SubjectMismatch {
            field: "containment",
        });
    }
    let (issued_at_unix_ms, expires_at_unix_ms) = claims.window();
    if now_unix_ms < issued_at_unix_ms {
        return Err(ProbeGrantError::NotYetValid { issued_at_unix_ms });
    }
    if now_unix_ms >= expires_at_unix_ms {
        return Err(ProbeGrantError::Expired { expires_at_unix_ms });
    }
    if !policy.live_admission_enabled {
        return Err(ProbeGrantError::LiveAdmissionDisabled {
            generation: policy.policy_generation,
            field: "sandbox_policy.live_admission_enabled",
        });
    }
    let grant_blake3 = claims.digest()?;
    match nonces.consume_nonce(&claims.nonce, PROBE_GRANT_NONCE_SCOPE, now_unix_ms)? {
        NonceConsumption::Consumed => Ok(ProbeGrantEvidence {
            grant_blake3,
            provider: claims.provider,
            executable_blake3: claims.executable_blake3,
            containment: claims.containment,
            expires_at_unix_ms,
        }),
        NonceConsumption::Replayed => Err(ProbeGrantError::Replayed {
            nonce: claims.nonce,
        }),
        NonceConsumption::Expired => Err(ProbeGrantError::Expired { expires_at_unix_ms }),
        NonceConsumption::Unknown => Err(ProbeGrantError::NonceUnknown {
            nonce: claims.nonce,
        }),
    }
}

/// Authenticate signature, footer, and implicit assertion, then strictly
/// decode and shape-check the claims. No time, subject, policy, or nonce
/// checks happen here.
fn authenticate(
    key: &LaunchGrantVerificationKey,
    token: &SignedProbeGrant,
) -> Result<ProbeGrantClaims, ProbeGrantError> {
    let footer = probe_grant_footer(key.issuer(), key.key_id())?;
    let public_bytes = hex::decode(key.public_key_hex())
        .map_err(|_| invalid("verification key hex is not decodable"))?;
    let public = AsymmetricPublicKey::<V4>::from(&public_bytes)
        .map_err(|_| invalid("verification key bytes are not a v4.public key"))?;
    let untrusted = UntrustedToken::<Public, V4>::try_from(token.paseto.as_str())
        .map_err(|_| malformed("paseto", "invalid PASETO framing"))?;
    let trusted = match PublicToken::verify(
        &public,
        &untrusted,
        Some(&footer),
        Some(PROBE_GRANT_IMPLICIT_ASSERTION),
    ) {
        Ok(trusted) => trusted,
        Err(_) => return Err(purpose_or_signature(&untrusted)),
    };
    let claims = decode_canonical::<ProbeGrantClaims>(trusted.payload().as_bytes())
        .map_err(|error| malformed("claims", &error.to_string()))?;
    claims.validate_shape()?;
    if claims.issuer != key.issuer() {
        return Err(malformed("issuer", "signed claims do not match the footer"));
    }
    if claims.key_id != key.key_id() {
        return Err(malformed("key_id", "signed claims do not match the footer"));
    }
    Ok(claims)
}

/// After authentication failed: name the foreign purpose when the untrusted
/// footer carries one, otherwise report the signature. Only ever a refusal;
/// no acceptance path reads the untrusted footer.
fn purpose_or_signature(untrusted: &UntrustedToken<Public, V4>) -> ProbeGrantError {
    match decode_canonical::<ProbeGrantFooter>(untrusted.untrusted_footer()) {
        Ok(footer) if footer.purpose != PROBE_GRANT_KEY_PURPOSE => {
            ProbeGrantError::PurposeMismatch {
                found: footer
                    .purpose
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(64)
                    .collect(),
            }
        }
        _ => ProbeGrantError::SignatureInvalid,
    }
}

fn label(field: &'static str, value: &str) -> Result<(), ProbeGrantError> {
    validate_label(field, value).map_err(|_| malformed(field, "must be a bounded label"))
}

fn malformed(field: &'static str, reason: &str) -> ProbeGrantError {
    ProbeGrantError::Malformed {
        field,
        reason: reason.to_string(),
    }
}

fn invalid(reason: &str) -> ProbeGrantError {
    ProbeGrantError::Invalid {
        reason: reason.to_string(),
    }
}
