//! Strict canonical request and immutable terminal outcome records.

use super::super::SignedLeaseError;
use crate::store::LedgerError;
use bullet_domain::{Attempt, AttemptId, AttemptState, RunnerId, VariantId, WorkPackageId};
use bullet_harness_core::launch_grant::{canonical_json, decode_canonical, is_lower_hex_64};
use bullet_harness_core::lease_transport::{
    request_digest, LeaseSubjectClaims, LeaseTransportOperation,
};
use serde::{Deserialize, Serialize};

/// Frozen strict settlement-row version.
pub const LEASE_SETTLEMENT_RECORD_VERSION: &str = "lease-transport-settlement.v1alpha1";

/// Full request for one replay-safe attempt transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvanceSettlementRequest {
    /// Canonical digest of the acquire body whose grant is the source.
    pub acquire_request_digest: String,
    /// Package named by the acquire.
    pub work_package_id: WorkPackageId,
    /// Original Runner identity.
    pub runner_id: RunnerId,
    /// Original Runner generation.
    pub runner_epoch: u64,
    /// Original acquire idempotency key.
    pub idempotency_key: String,
    /// Variant held by the exact source grant.
    pub variant_id: VariantId,
    /// Attempt held by the exact source grant.
    pub attempt_id: AttemptId,
    /// Permanent fence of the Attempt incarnation.
    pub attempt_fence: u64,
    /// State that must exist before applying the edge.
    pub expected_state: AttemptState,
    /// Legal next state.
    pub target_state: AttemptState,
}

/// Full request for one replay-safe lease release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSettlementRequest {
    /// Canonical digest of the acquire body whose grant is the source.
    pub acquire_request_digest: String,
    /// Package named by the acquire.
    pub work_package_id: WorkPackageId,
    /// Original Runner identity.
    pub runner_id: RunnerId,
    /// Original Runner generation.
    pub runner_epoch: u64,
    /// Original acquire idempotency key.
    pub idempotency_key: String,
    /// Variant held by the exact source grant.
    pub variant_id: VariantId,
    /// Attempt held by the exact source grant.
    pub attempt_id: AttemptId,
    /// Permanent fence of the Attempt incarnation.
    pub attempt_fence: u64,
    /// State that must exist before release.
    pub expected_state: AttemptState,
    /// Terminal state persisted by release.
    pub final_state: AttemptState,
    /// Whether the package returns to the ready queue.
    pub requeue: bool,
}

/// Exact terminal request. Its canonical digest derives the lts_ identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseSettlementRequest {
    /// One attempt transition.
    Advance(AdvanceSettlementRequest),
    /// One lease release.
    Release(ReleaseSettlementRequest),
}

impl LeaseSettlementRequest {
    /// Stable full-width typed identity derived from the exact canonical request.
    ///
    /// # Errors
    /// Canonical encoding refusal.
    pub fn settlement_id(&self) -> Result<String, SignedLeaseError> {
        Ok(format!("lts_{}", self.digest()?))
    }

    /// Canonical request digest.
    ///
    /// # Errors
    /// Canonical encoding refusal.
    pub fn digest(&self) -> Result<String, SignedLeaseError> {
        request_digest(self).map_err(SignedLeaseError::Transport)
    }

    /// Runner identity bound by the request.
    #[must_use]
    pub fn runner_id(&self) -> &RunnerId {
        match self {
            Self::Advance(body) => &body.runner_id,
            Self::Release(body) => &body.runner_id,
        }
    }

    /// Runner generation bound by the request.
    #[must_use]
    pub fn runner_epoch(&self) -> u64 {
        match self {
            Self::Advance(body) => body.runner_epoch,
            Self::Release(body) => body.runner_epoch,
        }
    }

    pub(super) fn operation(&self) -> LeaseTransportOperation {
        match self {
            Self::Advance(_) => LeaseTransportOperation::Advance,
            Self::Release(_) => LeaseTransportOperation::Release,
        }
    }

    pub(super) fn package(&self) -> &WorkPackageId {
        match self {
            Self::Advance(body) => &body.work_package_id,
            Self::Release(body) => &body.work_package_id,
        }
    }

    pub(super) fn key(&self) -> &str {
        match self {
            Self::Advance(body) => &body.idempotency_key,
            Self::Release(body) => &body.idempotency_key,
        }
    }

    pub(super) fn attempt(&self) -> &AttemptId {
        match self {
            Self::Advance(body) => &body.attempt_id,
            Self::Release(body) => &body.attempt_id,
        }
    }

    pub(super) fn variant(&self) -> &VariantId {
        match self {
            Self::Advance(body) => &body.variant_id,
            Self::Release(body) => &body.variant_id,
        }
    }

    pub(super) fn fence(&self) -> u64 {
        match self {
            Self::Advance(body) => body.attempt_fence,
            Self::Release(body) => body.attempt_fence,
        }
    }

    pub(super) fn expected_state(&self) -> AttemptState {
        match self {
            Self::Advance(body) => body.expected_state,
            Self::Release(body) => body.expected_state,
        }
    }

    pub(super) fn acquire_digest(&self) -> &str {
        match self {
            Self::Advance(body) => &body.acquire_request_digest,
            Self::Release(body) => &body.acquire_request_digest,
        }
    }
}

/// Immutable exact terminal outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseSettlementOutcome {
    /// Attempt after a legal transition.
    Advanced(Attempt),
    /// Attempt after release persisted its terminal state.
    Released(Attempt),
}

/// Strict canonical mutation/outcome record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSettlementRecord {
    /// Always LEASE_SETTLEMENT_RECORD_VERSION.
    pub version: String,
    /// lts_ plus the canonical request digest.
    pub settlement_id: String,
    /// Canonical request digest repeated for strict row agreement.
    pub request_digest: String,
    /// Exact request.
    pub request: LeaseSettlementRequest,
    /// Mutation-time signed subject, retained for historical readback.
    pub subject: LeaseSubjectClaims,
    /// Exact resulting Attempt.
    pub outcome: LeaseSettlementOutcome,
}

impl LeaseSettlementRecord {
    pub(super) fn new(
        request: LeaseSettlementRequest,
        subject: LeaseSubjectClaims,
        outcome: LeaseSettlementOutcome,
    ) -> Result<Self, SignedLeaseError> {
        let request_digest = request.digest()?;
        let record = Self {
            version: LEASE_SETTLEMENT_RECORD_VERSION.into(),
            settlement_id: format!("lts_{request_digest}"),
            request_digest,
            request,
            subject,
            outcome,
        };
        record.check()?;
        Ok(record)
    }

    /// Canonical opaque storage bytes.
    ///
    /// # Errors
    /// Encoding or internal-agreement refusal.
    pub fn encode(&self) -> Result<String, SignedLeaseError> {
        self.check()?;
        let bytes = canonical_json(self).map_err(invalid)?;
        String::from_utf8(bytes).map_err(|_| store_refusal())
    }

    /// Strict canonical decode with recursive unknown-field and row-agreement checks.
    ///
    /// # Errors
    /// Fixed store refusal for every deviation.
    pub fn decode(text: &str) -> Result<Self, SignedLeaseError> {
        let record: Self = decode_canonical(text.as_bytes()).map_err(|_| store_refusal())?;
        record.check().map_err(|_| store_refusal())?;
        Ok(record)
    }

    pub(super) fn require_request(
        &self,
        request: &LeaseSettlementRequest,
    ) -> Result<(), SignedLeaseError> {
        self.check().map_err(|_| store_refusal())?;
        if self.request == *request
            && self.request_digest == request.digest()?
            && self.settlement_id == request.settlement_id()?
        {
            return Ok(());
        }
        Err(conflict())
    }

    fn check(&self) -> Result<(), SignedLeaseError> {
        let digest = self.request.digest()?;
        let expected_id = format!("lts_{digest}");
        if self.version != LEASE_SETTLEMENT_RECORD_VERSION
            || !is_lower_hex_64(&self.request_digest)
            || self.request_digest != digest
            || self.settlement_id != expected_id
            || !is_lower_hex_64(self.request.acquire_digest())
            || self
                .subject
                .validate_shape(self.request.operation())
                .is_err()
        {
            return Err(store_refusal());
        }
        let attempt =
            match (&self.request, &self.outcome) {
                (
                    LeaseSettlementRequest::Advance(body),
                    LeaseSettlementOutcome::Advanced(attempt),
                ) if attempt.state == body.target_state => attempt,
                (
                    LeaseSettlementRequest::Release(body),
                    LeaseSettlementOutcome::Released(attempt),
                ) if attempt.state == body.final_state => attempt,
                _ => return Err(store_refusal()),
            };
        let agrees = attempt.id == *self.request.attempt()
            && attempt.variant_id == *self.request.variant()
            && attempt.work_package_id == *self.request.package()
            && attempt.runner_id == *self.request.runner_id()
            && attempt.runner_epoch == self.request.runner_epoch()
            && attempt.fence == self.request.fence();
        agrees.then_some(()).ok_or_else(store_refusal)
    }

    /// Fixed non-disclosing store refusal for every malformed settlement row.
    #[must_use]
    pub fn refused() -> LedgerError {
        LedgerError::Store("lease-transport settlement record refused".into())
    }
}

fn invalid(error: bullet_harness_core::HarnessError) -> SignedLeaseError {
    SignedLeaseError::Transport(
        bullet_harness_core::lease_transport::LeaseTransportError::Invalid {
            reason: error.to_string(),
        },
    )
}

fn conflict() -> SignedLeaseError {
    SignedLeaseError::Ledger(
        bullet_domain::DomainError::Idempotency(
            "lease settlement request differs under the same settlement id".into(),
        )
        .into(),
    )
}

fn store_refusal() -> SignedLeaseError {
    SignedLeaseError::Ledger(LeaseSettlementRecord::refused())
}
