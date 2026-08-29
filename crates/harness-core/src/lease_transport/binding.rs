//! Signed lease-transport claim set and the exact durable subject a permit
//! binds.
//!
//! Spec §26.4 keys every lease mutation on variant/attempt/fence/runner/epoch/
//! workspace nonce; §6.8 binds the Attempt incarnation to its workspace and
//! to the scope and policy generations in force. Every field below is part of
//! the canonical signed claims. Shape validity is never authority.

use crate::error::HarnessError;
use crate::launch_grant::{
    hash_canonical, is_lower_hex_64, validate_label, MAX_LAUNCH_GRANT_TTL_MS, MAX_SAFE_INTEGER,
};
use serde::{Deserialize, Serialize};

use super::{
    LEASE_TRANSPORT_AUDIENCE, LEASE_TRANSPORT_CLAIMS_DOMAIN, LEASE_TRANSPORT_SCHEMA_VERSION,
};

/// One Kernel↔Runner lease-transport operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseTransportOperation {
    /// Create or replay the writer lease for one work package.
    Acquire,
    /// Renew the active lease.
    Heartbeat,
    /// Apply one legal attempt transition.
    Advance,
    /// Close the lease.
    Release,
    /// Return the last grant for a lost acquire response.
    Readback,
    /// Return one immutable terminal outcome after response loss.
    SettlementReadback,
}

impl LeaseTransportOperation {
    /// Wire label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Heartbeat => "heartbeat",
            Self::Advance => "advance",
            Self::Release => "release",
            Self::Readback => "readback",
            Self::SettlementReadback => "settlement_readback",
        }
    }

    /// Whether the operation acts on an already granted Attempt incarnation.
    /// Grant-class operations (`acquire`, `readback`) bind the workspace the
    /// grant creates or returns; no fence exists for them to present.
    #[must_use]
    pub fn binds_incarnation(self) -> bool {
        matches!(
            self,
            Self::Heartbeat | Self::Advance | Self::Release | Self::SettlementReadback
        )
    }
}

#[path = "subject.rs"]
mod subject;

pub use subject::{LeaseIncarnationClaims, LeaseSubjectClaims};

/// Signed claim set. Shape validity is not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTransportClaims {
    /// Always `v1alpha1`.
    pub schema_version: String,
    /// Unique 64-hex permit identifier.
    pub permit_id: String,
    /// Always `lease-runner`.
    pub audience: String,
    /// One of the frozen operations.
    pub operation: LeaseTransportOperation,
    /// Issuer label.
    pub issuer: String,
    /// Key label.
    pub key_id: String,
    /// Issue instant.
    pub issued_at_unix_ms: u64,
    /// Inclusive validity start.
    pub not_before_unix_ms: u64,
    /// Exclusive validity end; at most 15 s after `not_before`.
    pub expires_at_unix_ms: u64,
    /// Single-use 64-hex nonce.
    pub permit_nonce: String,
    /// Framed digest of the exact request body this permit covers.
    pub request_digest: String,
    /// Runner that may present the permit.
    pub runner_id: String,
    /// Runner incarnation.
    pub runner_epoch: u64,
    /// Kernel authority epoch; always equal to `subject.authority_epoch`.
    pub authority_epoch: u64,
    /// Work package the operation names.
    pub work_package_id: String,
    /// Digest of the acquire idempotency key.
    pub idempotency_digest: String,
    /// Durable lease subject the operation is bound to.
    pub subject: LeaseSubjectClaims,
}

impl LeaseTransportClaims {
    /// Validate every field exactly.
    ///
    /// # Errors
    /// `LEASE_TRANSPORT_INVALID` or `LEASE_TRANSPORT_AUDIENCE_MISMATCH`.
    pub fn validate_shape(&self) -> Result<(), LeaseTransportError> {
        if self.schema_version != LEASE_TRANSPORT_SCHEMA_VERSION {
            return Err(invalid("schema_version must be v1alpha1"));
        }
        if self.audience != LEASE_TRANSPORT_AUDIENCE {
            return Err(LeaseTransportError::AudienceMismatch {
                audience: printable(&self.audience),
            });
        }
        validate_label("issuer", &self.issuer).map_err(map_harness)?;
        validate_label("key_id", &self.key_id).map_err(map_harness)?;
        hex_64("permit_id", &self.permit_id)?;
        hex_64("permit_nonce", &self.permit_nonce)?;
        hex_64("request_digest", &self.request_digest)?;
        hex_64("idempotency_digest", &self.idempotency_digest)?;
        if self.runner_id.is_empty() || self.work_package_id.is_empty() {
            return Err(invalid("runner_id and work_package_id are required"));
        }
        bounded("runner_epoch", self.runner_epoch)?;
        positive("authority_epoch", self.authority_epoch)?;
        if self.authority_epoch != self.subject.authority_epoch {
            return Err(invalid(
                "authority_epoch must equal subject.authority_epoch",
            ));
        }
        bounded("issued_at_unix_ms", self.issued_at_unix_ms)?;
        bounded("not_before_unix_ms", self.not_before_unix_ms)?;
        bounded("expires_at_unix_ms", self.expires_at_unix_ms)?;
        if self.issued_at_unix_ms > self.not_before_unix_ms
            || self.not_before_unix_ms >= self.expires_at_unix_ms
        {
            return Err(invalid(
                "window requires issued_at <= not_before < expires_at",
            ));
        }
        if self.expires_at_unix_ms - self.not_before_unix_ms > MAX_LAUNCH_GRANT_TTL_MS {
            return Err(LeaseTransportError::TtlExceeded {
                ttl_ms: self.expires_at_unix_ms - self.not_before_unix_ms,
            });
        }
        self.subject.validate_shape(self.operation)
    }

    /// Exact validity window `[not_before, expires_at)`.
    #[must_use]
    pub fn window(&self) -> (u64, u64) {
        (self.not_before_unix_ms, self.expires_at_unix_ms)
    }

    /// Framed digest of the canonical claims.
    ///
    /// # Errors
    /// Shape or encoding refusal.
    pub fn digest(&self) -> Result<String, LeaseTransportError> {
        self.validate_shape()?;
        hash_canonical(LEASE_TRANSPORT_CLAIMS_DOMAIN, self).map_err(map_harness)
    }
}

/// Expected subject for one verified permit. The issuer mints claims from
/// exactly this value, so issuance and verification cannot drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseTransportExpectation {
    /// Operation the caller is invoking now.
    pub operation: LeaseTransportOperation,
    /// Digest of the exact request body presented with the permit.
    pub request_digest: String,
    /// Runner the Kernel will execute as.
    pub runner_id: String,
    /// Runner incarnation.
    pub runner_epoch: u64,
    /// Kernel authority epoch, kept for wire compatibility. Minted claims
    /// derive it from `subject.authority_epoch`; verification refuses any
    /// expectation whose two values disagree.
    pub authority_epoch: u64,
    /// Work package named by the body.
    pub work_package_id: String,
    /// Digest of the acquire idempotency key.
    pub idempotency_digest: String,
    /// Durable lease subject the Kernel resolved for this call.
    pub subject: LeaseSubjectClaims,
    /// Verifier clock; also the issue instant of minted claims.
    pub now_unix_ms: u64,
}

impl LeaseTransportExpectation {
    /// Claims for `(issuer, key_id)` valid `[now, now + ttl_ms)`.
    #[must_use]
    pub fn claims(
        &self,
        issuer: &str,
        key_id: &str,
        permit_id: String,
        permit_nonce: String,
        ttl_ms: u64,
    ) -> LeaseTransportClaims {
        LeaseTransportClaims {
            schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
            permit_id,
            audience: LEASE_TRANSPORT_AUDIENCE.to_string(),
            operation: self.operation,
            issuer: issuer.to_string(),
            key_id: key_id.to_string(),
            issued_at_unix_ms: self.now_unix_ms,
            not_before_unix_ms: self.now_unix_ms,
            expires_at_unix_ms: self.now_unix_ms.saturating_add(ttl_ms),
            permit_nonce,
            request_digest: self.request_digest.clone(),
            runner_id: self.runner_id.clone(),
            runner_epoch: self.runner_epoch,
            authority_epoch: self.subject.authority_epoch,
            work_package_id: self.work_package_id.clone(),
            idempotency_digest: self.idempotency_digest.clone(),
            subject: self.subject.clone(),
        }
    }

    pub(super) fn check(&self, c: &LeaseTransportClaims) -> Result<(), LeaseTransportError> {
        if c.operation != self.operation {
            return Err(LeaseTransportError::OperationMismatch {
                expected: self.operation.as_str(),
                actual: c.operation.as_str(),
            });
        }
        let field = first_deviation([
            (c.request_digest != self.request_digest, "request_digest"),
            (c.runner_id != self.runner_id, "runner_id"),
            (c.runner_epoch != self.runner_epoch, "runner_epoch"),
            (c.authority_epoch != self.authority_epoch, "authority_epoch"),
            (c.work_package_id != self.work_package_id, "work_package_id"),
            (
                c.idempotency_digest != self.idempotency_digest,
                "idempotency_digest",
            ),
        ])
        .or_else(|| self.subject.first_mismatch(&c.subject));
        match field {
            Some(field) => Err(LeaseTransportError::SubjectMismatch { field }),
            None => Ok(()),
        }
    }
}

/// Binding under which a permit nonce is reserved and consumed.
#[must_use]
pub fn nonce_binding(
    operation: LeaseTransportOperation,
    runner_id: &str,
    idempotency_digest: &str,
) -> String {
    format!("{}:{runner_id}:{idempotency_digest}", operation.as_str())
}

/// Typed lease-transport refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseTransportError {
    /// Shape, framing, or encoding refusal.
    #[error("lease transport invalid: {reason}")]
    Invalid {
        /// Non-secret detail.
        reason: String,
    },
    /// Audience is not `lease-runner`.
    #[error("lease transport audience mismatch: {audience}")]
    AudienceMismatch {
        /// Presented audience.
        audience: String,
    },
    /// Operation does not match the invoked verb.
    #[error("lease transport operation mismatch: expected {expected}, got {actual}")]
    OperationMismatch {
        /// Expected verb.
        expected: &'static str,
        /// Presented verb.
        actual: &'static str,
    },
    /// One bound subject field does not match the request or the ledger.
    #[error("lease transport subject mismatch: {field}")]
    SubjectMismatch {
        /// Claim field that deviated.
        field: &'static str,
    },
    /// Verification key identity is unknown.
    #[error("lease transport key unknown: {issuer}/{key_id}")]
    KeyUnknown {
        /// Presented issuer.
        issuer: String,
        /// Presented key id.
        key_id: String,
    },
    /// Permit is not yet valid.
    #[error("lease transport not yet valid (not_before={not_before_unix_ms})")]
    NotYetValid {
        /// Inclusive start.
        not_before_unix_ms: u64,
    },
    /// Permit has expired.
    #[error("lease transport expired (expires_at={expires_at_unix_ms})")]
    Expired {
        /// Exclusive end.
        expires_at_unix_ms: u64,
    },
    /// TTL exceeds 15 s.
    #[error("lease transport ttl exceeded: {ttl_ms} ms")]
    TtlExceeded {
        /// Requested ttl.
        ttl_ms: u64,
    },
    /// Nonce was already consumed.
    #[error("lease transport replayed: {permit_id}")]
    Replayed {
        /// Replayed permit.
        permit_id: String,
    },
}

impl LeaseTransportError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "LEASE_TRANSPORT_INVALID",
            Self::AudienceMismatch { .. } => "LEASE_TRANSPORT_AUDIENCE_MISMATCH",
            Self::OperationMismatch { .. } => "LEASE_TRANSPORT_OPERATION_MISMATCH",
            Self::SubjectMismatch { .. } => "LEASE_TRANSPORT_SUBJECT_MISMATCH",
            Self::KeyUnknown { .. } => "LEASE_TRANSPORT_KEY_UNKNOWN",
            Self::NotYetValid { .. } => "LEASE_TRANSPORT_NOT_YET_VALID",
            Self::Expired { .. } => "LEASE_TRANSPORT_EXPIRED",
            Self::TtlExceeded { .. } => "LEASE_TRANSPORT_TTL_EXCEEDED",
            Self::Replayed { .. } => "LEASE_TRANSPORT_REPLAYED",
        }
    }
}

fn first_deviation<const N: usize>(checks: [(bool, &'static str); N]) -> Option<&'static str> {
    checks
        .into_iter()
        .find_map(|(deviates, field)| deviates.then_some(field))
}

fn hex_64(name: &str, value: &str) -> Result<(), LeaseTransportError> {
    if is_lower_hex_64(value) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "{name} must be 64 lowercase hex characters"
        )))
    }
}

fn positive(name: &str, value: u64) -> Result<(), LeaseTransportError> {
    if value == 0 {
        return Err(invalid(&format!("{name} must be at least 1")));
    }
    bounded(name, value)
}

fn bounded(name: &str, value: u64) -> Result<(), LeaseTransportError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(&format!(
            "{name} exceeds the interoperable integer range"
        )));
    }
    Ok(())
}

pub(super) fn invalid(reason: &str) -> LeaseTransportError {
    LeaseTransportError::Invalid {
        reason: reason.to_string(),
    }
}

pub(super) fn map_harness(error: HarnessError) -> LeaseTransportError {
    invalid(&error.to_string())
}

pub(super) fn printable(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect()
}
