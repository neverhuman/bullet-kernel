//! Kernel-owned signed lease-transport service. Public farmd
//! `/api/v1/leases/*` routes stay absent and the signing key never leaves
//! farmd. Every operation opens `Ledger::with_lease_transport` FIRST, then
//! resolves graph/package/variant, the authority row, the Attempt, the lease,
//! and the active-lease decision through the transaction port, mints, signs,
//! verifies and consumes the permit against exactly that transaction-local
//! truth, and only then mutates. No pre-transaction observation reaches the
//! write.

mod active_readback;
mod grant_resolution;
mod mint;
mod readback;
mod settlement;
#[cfg(any(test, feature = "test-seams"))]
mod synthetic_selection;

pub use mint::{
    expectation_for, grant_subject, incarnation_subject, lease_subject, legal_transition,
    require_current_fence, workspace_for_key, Presented, SignedLeaseError,
};
#[cfg(any(test, feature = "test-seams"))]
pub use mint::{issue_operation_permit, issue_permit};
pub use readback::{LeaseGrantRecord, LEASE_GRANT_RECORD_VERSION};
pub use settlement::{
    AdvanceSettlementRequest, LeaseSettlementOutcome, LeaseSettlementRecord,
    LeaseSettlementRequest, ReleaseSettlementRequest, LEASE_SETTLEMENT_RECORD_VERSION,
};
#[cfg(all(feature = "test-seams", debug_assertions))]
pub use synthetic_selection::SyntheticSelectedAcquireBody;

#[cfg(any(test, feature = "test-seams"))]
use crate::authority_revision::NormalizedAuthority;
use crate::records::{HeartbeatRequest, LeaseGrant, ReleaseRequest};
use crate::store::{LeaseTransportTxn, Ledger, LedgerError};
use bullet_domain::{Attempt, AttemptId, AttemptState, DomainError, RunnerId, WorkPackageId};
use bullet_harness_core::lease_transport::{
    new_hex_64, nonce_binding, verify_lease_permit, LeaseTransportExpectation,
    LeaseTransportOperation, LeaseTransportSigningKey, LeaseTransportVerificationKey,
};
#[cfg(any(test, feature = "test-seams"))]
use bullet_harness_core::lease_transport::{LeaseSubjectClaims, SignedLeasePermit};
use grant_resolution::grant_truth;
#[cfg(any(test, feature = "test-seams"))]
use mint::{graph_for_package, idempotency_digest, lease_request};
use mint::{incarnation_truth, no_mismatch, TxnNonceLedger};
use serde::{Deserialize, Serialize};

/// Permit validity after issue.
pub const PERMIT_TTL_MS: u64 = 15_000;

/// Request body covered by an `acquire` or `readback` operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAcquireBody {
    /// Package to lease.
    pub work_package_id: WorkPackageId,
    /// Runner identity.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Idempotency key; also seeds the attempt.
    pub idempotency_key: String,
    /// Requested TTL in seconds (`1..=15`).
    pub ttl_seconds: i64,
}

/// Request body covered by a heartbeat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHeartbeatBody {
    /// Package named by the permit subject.
    pub work_package_id: WorkPackageId,
    /// Acquire idempotency key.
    pub idempotency_key: String,
    /// Six-identity heartbeat.
    pub call: HeartbeatRequest,
}

/// Request body covered by a release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseBody {
    /// Package named by the permit subject.
    pub work_package_id: WorkPackageId,
    /// Runner identity.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Acquire idempotency key.
    pub idempotency_key: String,
    /// Release identity.
    pub call: ReleaseRequest,
}

/// Request body covered by an attempt advance. The presented fence is the
/// permanent fence of `attempt_id`; it must be the active lease's fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdvanceBody {
    /// Package named by the permit subject.
    pub work_package_id: WorkPackageId,
    /// Runner identity.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Acquire idempotency key.
    pub idempotency_key: String,
    /// Attempt to transition.
    pub attempt_id: AttemptId,
    /// Legal next state.
    pub state: AttemptState,
}

/// Operator-held issuer plus a separately verifying gateway.
pub struct KernelLeaseTransport {
    signing: LeaseTransportSigningKey,
    verification: LeaseTransportVerificationKey,
}

impl KernelLeaseTransport {
    /// Bind both halves of one operator-held key; the Runner never sees it.
    ///
    /// # Errors
    /// `LEASE_TRANSPORT_INVALID` when the public half cannot be derived.
    pub fn new(signing: LeaseTransportSigningKey) -> Result<Self, SignedLeaseError> {
        let verification = signing
            .verification_key()
            .map_err(SignedLeaseError::Transport)?;
        Ok(Self {
            signing,
            verification,
        })
    }

    /// Mint a fresh operator-held key pair from operating-system entropy.
    ///
    /// # Errors
    /// Entropy or key-shape refusal.
    pub fn generate() -> Result<Self, SignedLeaseError> {
        Self::new(
            LeaseTransportSigningKey::generate("kernel-local", "lease-1")
                .map_err(SignedLeaseError::Transport)?,
        )
    }

    /// Acquire or replay one writer lease from an unsigned Runner request.
    /// Graph, variant, and authority are resolved inside the transaction and
    /// the grant record is bound there before it is persisted.
    ///
    /// # Errors
    /// Typed transport or ledger refusal; `IDEMPOTENCY_CONFLICT` when the
    /// key was acquired with a different body.
    pub fn acquire<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let op = LeaseTransportOperation::Acquire;
        let prepare = |txn: &dyn LeaseTransportTxn| grant_truth(txn, op, body, now_unix_ms);
        self.admit(ledger, prepare, |txn, expected, truth| {
            let grant = txn.acquire_lease(&truth.request)?;
            let record = truth.bind(grant)?;
            txn.put_transport_grant(&expected.idempotency_digest, &record)?;
            Ok(record.grant)
        })
    }

    /// Return the recorded grant without minting a sibling. The request,
    /// its canonical digest, and the subject are reconstructed inside the
    /// transaction and must agree exactly with the recorded grant.
    ///
    /// # Errors
    /// Typed transport refusal, `UNKNOWN` when no grant was stored,
    /// `IDEMPOTENCY_CONFLICT` for a changed body, `STORE_FAILURE` for an
    /// inconsistent record.
    pub fn readback<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let op = LeaseTransportOperation::Readback;
        let prepare = |txn: &dyn LeaseTransportTxn| grant_truth(txn, op, body, now_unix_ms);
        self.admit(ledger, prepare, |txn, expected, truth| {
            let stored = txn
                .get_transport_grant(&expected.idempotency_digest)?
                .ok_or(SignedLeaseError::Unknown)?;
            Ok(truth.bind_row(stored)?.grant)
        })
    }

    /// Renew one lease. The six-identity call must name the Attempt the
    /// transaction loads, which must hold a live lease at the store's clock.
    ///
    /// # Errors
    /// Typed transport or ledger refusal.
    pub fn heartbeat<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedHeartbeatBody,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let call = &body.call;
        let presented = presented(&call.runner_id, call.runner_epoch, &body.work_package_id);
        let op = LeaseTransportOperation::Heartbeat;
        let key = &body.idempotency_key;
        let identity = |attempt: &Attempt| {
            no_mismatch([
                (call.variant_id != attempt.variant_id, "variant_id"),
                (call.fence != attempt.fence, "fence"),
                (
                    call.workspace_nonce != attempt.workspace_nonce,
                    "workspace_nonce_digest",
                ),
            ])
        };
        let prepare = |txn: &dyn LeaseTransportTxn| {
            let id = &call.attempt_id;
            let now = now_unix_ms;
            let truth = incarnation_truth(txn, op, body, presented, key, id, identity, now)?;
            Ok((truth.expected, ()))
        };
        self.admit(ledger, prepare, |txn, _, ()| Ok(txn.heartbeat(call)?))
    }

    /// Close one lease held by the Attempt the transaction loads.
    ///
    /// # Errors
    /// Typed transport or ledger refusal.
    pub fn release<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedReleaseBody,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        self.release_ephemeral(ledger, body, now_unix_ms)
    }

    /// Apply one legal attempt transition. The presented Attempt's permanent
    /// fence must be the active lease's fence (`LEASE_FENCE_STALE`), the lease
    /// must be active and unexpired at the store's authoritative time
    /// (`LEASE_NOT_ACTIVE`), and the edge must exist in the domain machine
    /// (`ATTEMPT_TRANSITION_ILLEGAL`). A refusal leaves the Attempt unchanged.
    ///
    /// # Errors
    /// Typed transport, guard, or ledger refusal.
    pub fn advance<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAdvanceBody,
        now_unix_ms: u64,
    ) -> Result<Attempt, SignedLeaseError> {
        self.advance_ephemeral(ledger, body, now_unix_ms)
    }

    /// Run one operation inside the store transaction: `prepare` resolves
    /// the expectation from transaction-local truth only, the permit is
    /// minted, signed, verified, and its nonce consumed against exactly that
    /// expectation, then `apply` mutates. Any refusal rolls everything back.
    pub(super) fn admit<L, S, R, P, F>(
        &self,
        ledger: &mut L,
        prepare: P,
        apply: F,
    ) -> Result<R, SignedLeaseError>
    where
        L: Ledger,
        P: FnOnce(
            &dyn LeaseTransportTxn,
        ) -> Result<(LeaseTransportExpectation, S), SignedLeaseError>,
        F: FnOnce(
            &mut dyn LeaseTransportTxn,
            &LeaseTransportExpectation,
            S,
        ) -> Result<R, SignedLeaseError>,
    {
        ledger.with_lease_transport(|txn| self.admit_tx(txn, prepare, apply))
    }

    pub(super) fn admit_tx<S, R, P, F>(
        &self,
        txn: &mut dyn LeaseTransportTxn,
        prepare: P,
        apply: F,
    ) -> Result<R, SignedLeaseError>
    where
        P: FnOnce(
            &dyn LeaseTransportTxn,
        ) -> Result<(LeaseTransportExpectation, S), SignedLeaseError>,
        F: FnOnce(
            &mut dyn LeaseTransportTxn,
            &LeaseTransportExpectation,
            S,
        ) -> Result<R, SignedLeaseError>,
    {
        let (expected, state) = prepare(&*txn)?;
        let nonce = new_hex_64().map_err(SignedLeaseError::Transport)?;
        let permit_id = new_hex_64().map_err(SignedLeaseError::Transport)?;
        let (issuer, key_id) = (self.signing.issuer(), self.signing.key_id());
        let claims = expected.claims(issuer, key_id, permit_id, nonce.clone(), PERMIT_TTL_MS);
        let binding = nonce_binding(
            claims.operation,
            &claims.runner_id,
            &claims.idempotency_digest,
        );
        txn.reserve_transport_nonce(&nonce, &binding, claims.expires_at_unix_ms)?;
        let signed = self
            .signing
            .sign(&claims)
            .map_err(SignedLeaseError::Transport)?;
        let mut nonces = TxnNonceLedger { txn: &mut *txn };
        let verified = verify_lease_permit(&signed, &self.verification, &expected, &mut nonces);
        drop(verified.map_err(SignedLeaseError::Transport)?);
        apply(txn, &expected, state)
    }
}

fn presented<'a>(runner_id: &'a RunnerId, epoch: u64, package: &'a WorkPackageId) -> Presented<'a> {
    (runner_id, epoch, package.as_str())
}

/// The port refuses a package no current graph owns with `STALE_AUTHORITY`;
/// the transport keeps its `LEASE_TRANSPORT_UNKNOWN` contract for it.
pub(super) fn unknown_package(error: LedgerError) -> SignedLeaseError {
    match error {
        LedgerError::Domain(DomainError::StaleAuthority(_)) => SignedLeaseError::Unknown,
        other => SignedLeaseError::Ledger(other),
    }
}

/// The port.s authoritative-clock active check refuses with `STALE_AUTHORITY`;
/// the transport reports it as `LEASE_NOT_ACTIVE`.
pub(super) fn not_active(error: LedgerError) -> SignedLeaseError {
    match error {
        LedgerError::Domain(DomainError::StaleAuthority(reason)) => {
            SignedLeaseError::NotActive { reason }
        }
        other => SignedLeaseError::Ledger(other),
    }
}

/// In-process gateway with a process-local grant index. Production farmd
/// uses [`KernelLeaseTransport`]; this type remains for test-seams clients
/// and verifies against the genesis authority row.
#[cfg(any(test, feature = "test-seams"))]
pub struct SignedLeaseService {
    verification: LeaseTransportVerificationKey,
    nonces: bullet_harness_core::launch_grant::MemoryNonceLedger,
    last_acquire: std::collections::BTreeMap<String, LeaseGrant>,
}

#[cfg(any(test, feature = "test-seams"))]
impl SignedLeaseService {
    /// Bind the service to one verification key.
    #[must_use]
    pub fn new(verification: LeaseTransportVerificationKey) -> Self {
        Self {
            verification,
            nonces: bullet_harness_core::launch_grant::MemoryNonceLedger::new(),
            last_acquire: std::collections::BTreeMap::new(),
        }
    }

    /// Register a freshly minted nonce before verification.
    pub fn register_nonce(&mut self, nonce: &str, binding: &str, expires_at_unix_ms: u64) -> bool {
        self.nonces.register(nonce, binding, expires_at_unix_ms)
    }

    /// Acquire or replay one writer lease after verifying the permit.
    ///
    /// # Errors
    /// Typed transport refusal or ledger failure.
    pub fn acquire<L: Ledger>(
        &mut self,
        ledger: &mut L,
        permit: &SignedLeasePermit,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let (graph, variant_id) = graph_for_package(ledger, &body.work_package_id)?;
        self.verify_grant(permit, LeaseTransportOperation::Acquire, body, now_unix_ms)?;
        let grant = ledger.acquire_lease(&lease_request(body, &graph.mission.id, &variant_id))?;
        self.last_acquire
            .insert(idempotency_digest(&body.idempotency_key)?, grant.clone());
        Ok(grant)
    }

    /// Return the last grant for this idempotency key without minting a sibling.
    ///
    /// # Errors
    /// Typed transport refusal, or `UNKNOWN` when no grant was stored.
    pub fn readback(
        &mut self,
        permit: &SignedLeasePermit,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        self.verify_grant(permit, LeaseTransportOperation::Readback, body, now_unix_ms)?;
        self.last_acquire
            .get(&idempotency_digest(&body.idempotency_key)?)
            .cloned()
            .ok_or(SignedLeaseError::Unknown)
    }

    /// Renew one lease.
    ///
    /// # Errors
    /// Typed transport or ledger refusal.
    pub fn heartbeat<L: Ledger>(
        &mut self,
        ledger: &mut L,
        permit: &SignedLeasePermit,
        work_package_id: &WorkPackageId,
        idempotency_key: &str,
        call: &HeartbeatRequest,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let subject = seam_incarnation_subject(ledger, &call.attempt_id)?;
        let presented = presented(&call.runner_id, call.runner_epoch, work_package_id);
        let (op, key, now) = (
            LeaseTransportOperation::Heartbeat,
            idempotency_key,
            now_unix_ms,
        );
        self.verify(permit, op, call, presented, key, subject, now)?;
        Ok(ledger.heartbeat(call)?)
    }

    /// Close one lease.
    ///
    /// # Errors
    /// Typed transport or ledger refusal.
    #[allow(clippy::too_many_arguments)]
    pub fn release<L: Ledger>(
        &mut self,
        ledger: &mut L,
        permit: &SignedLeasePermit,
        runner_id: &RunnerId,
        runner_epoch: u64,
        work_package_id: &WorkPackageId,
        idempotency_key: &str,
        call: &ReleaseRequest,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let subject = seam_incarnation_subject(ledger, &call.attempt_id)?;
        let presented = presented(runner_id, runner_epoch, work_package_id);
        let (op, key, now) = (
            LeaseTransportOperation::Release,
            idempotency_key,
            now_unix_ms,
        );
        self.verify(permit, op, call, presented, key, subject, now)?;
        Ok(ledger.release_lease(call)?)
    }

    fn verify_grant(
        &mut self,
        permit: &SignedLeasePermit,
        op: LeaseTransportOperation,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let (workspace_id, nonce) = workspace_for_key(&body.idempotency_key);
        let subject = grant_subject(&workspace_id, &nonce, &NormalizedAuthority::genesis())?;
        let presented = presented(&body.runner_id, body.runner_epoch, &body.work_package_id);
        let key = &body.idempotency_key;
        self.verify(permit, op, body, presented, key, subject, now_unix_ms)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify<T: Serialize>(
        &mut self,
        permit: &SignedLeasePermit,
        op: LeaseTransportOperation,
        body: &T,
        presented: Presented<'_>,
        key: &str,
        subject: LeaseSubjectClaims,
        now: u64,
    ) -> Result<(), SignedLeaseError> {
        let epoch = NormalizedAuthority::genesis().authority_epoch();
        let expected = expectation_for(op, body, presented, key, epoch, subject, now)?;
        verify_lease_permit(permit, &self.verification, &expected, &mut self.nonces)
            .map(|_| ())
            .map_err(SignedLeaseError::Transport)
    }
}
#[cfg(any(test, feature = "test-seams"))]
fn seam_incarnation_subject<L: Ledger>(
    ledger: &L,
    attempt_id: &AttemptId,
) -> Result<LeaseSubjectClaims, SignedLeaseError> {
    let attempt = ledger
        .get_attempt(attempt_id)?
        .ok_or(SignedLeaseError::Unknown)?;
    incarnation_subject(&attempt, &NormalizedAuthority::genesis())
}
