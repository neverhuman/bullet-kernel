//! Kernel-owned signed lease-transport service.
//!
//! Public farmd `/api/v1/leases/*` routes stay absent. The operator-held
//! signing key never leaves farmd. A Runner may present an unsigned
//! request; Kernel validates durable package truth, reserves a nonce,
//! signs, then a separate gateway verifies that permit and applies the
//! ledger mutation in the same immediate transaction.

use crate::launch_grant::GENESIS_AUTHORITY_EPOCH;
use crate::records::{HeartbeatRequest, LeaseGrant, LeaseRequest, ReleaseRequest, StoredGraph};
use crate::store::{LeaseTransportTxn, Ledger, LedgerError};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Digest, RunnerId, VariantId, WorkPackageId, WorkspaceId,
};
use bullet_harness_core::launch_grant::{LaunchGrantNonceLedger, NonceConsumption};
use bullet_harness_core::lease_transport::{
    new_hex_64, request_digest, verify_lease_permit, LeaseTransportClaims, LeaseTransportError,
    LeaseTransportExpectation, LeaseTransportOperation, LeaseTransportSigningKey,
    LeaseTransportVerificationKey, SignedLeasePermit, LEASE_TRANSPORT_AUDIENCE,
    LEASE_TRANSPORT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};

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

/// Request body covered by an attempt advance.
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
    /// Bind both halves of one operator-held key. The Runner never receives
    /// the secret.
    ///
    /// # Errors
    ///
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
    ///
    /// Entropy or key-shape refusal.
    pub fn generate() -> Result<Self, SignedLeaseError> {
        Self::new(
            LeaseTransportSigningKey::generate("kernel-local", "lease-1")
                .map_err(SignedLeaseError::Transport)?,
        )
    }

    /// Acquire or replay one writer lease from an unsigned Runner request.
    ///
    /// # Errors
    ///
    /// Typed transport or ledger refusal.
    pub fn acquire<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let (graph, variant_id) = graph_for_package(ledger, &body.work_package_id)?;
        if graph
            .variants
            .iter()
            .all(|variant| variant.work_package_id != body.work_package_id)
        {
            return Err(SignedLeaseError::Unknown);
        }
        let request = lease_request(body, &graph, &variant_id);
        let digest = idempotency_digest(&body.idempotency_key)?;
        self.admit(
            ledger,
            LeaseTransportOperation::Acquire,
            body,
            &body.runner_id,
            body.runner_epoch,
            body.work_package_id.as_str(),
            &digest,
            now_unix_ms,
            |txn| {
                let grant = txn
                    .acquire_lease(&request)
                    .map_err(SignedLeaseError::Ledger)?;
                txn.put_transport_grant(&digest, &grant)
                    .map_err(SignedLeaseError::Ledger)?;
                Ok(grant)
            },
        )
    }

    /// Return the last grant without minting a sibling.
    ///
    /// # Errors
    ///
    /// Typed transport refusal, or `UNKNOWN` when no grant was stored.
    pub fn readback<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        let digest = idempotency_digest(&body.idempotency_key)?;
        graph_for_package(ledger, &body.work_package_id)?;
        self.admit(
            ledger,
            LeaseTransportOperation::Readback,
            body,
            &body.runner_id,
            body.runner_epoch,
            body.work_package_id.as_str(),
            &digest,
            now_unix_ms,
            |txn| {
                txn.get_transport_grant(&digest)
                    .map_err(SignedLeaseError::Ledger)?
                    .ok_or(SignedLeaseError::Unknown)
            },
        )
    }

    /// Renew one lease.
    ///
    /// # Errors
    ///
    /// Typed transport or ledger refusal.
    pub fn heartbeat<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedHeartbeatBody,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let digest = idempotency_digest(&body.idempotency_key)?;
        self.admit(
            ledger,
            LeaseTransportOperation::Heartbeat,
            body,
            &body.call.runner_id,
            body.call.runner_epoch,
            body.work_package_id.as_str(),
            &digest,
            now_unix_ms,
            |txn| txn.heartbeat(&body.call).map_err(SignedLeaseError::Ledger),
        )
    }

    /// Close one lease.
    ///
    /// # Errors
    ///
    /// Typed transport or ledger refusal.
    pub fn release<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedReleaseBody,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let digest = idempotency_digest(&body.idempotency_key)?;
        self.admit(
            ledger,
            LeaseTransportOperation::Release,
            body,
            &body.runner_id,
            body.runner_epoch,
            body.work_package_id.as_str(),
            &digest,
            now_unix_ms,
            |txn| {
                txn.release_lease(&body.call)
                    .map_err(SignedLeaseError::Ledger)
            },
        )
    }

    /// Apply one legal attempt transition.
    ///
    /// # Errors
    ///
    /// Typed transport or ledger refusal.
    pub fn advance<L: Ledger>(
        &self,
        ledger: &mut L,
        body: &SignedAdvanceBody,
        now_unix_ms: u64,
    ) -> Result<Attempt, SignedLeaseError> {
        let digest = idempotency_digest(&body.idempotency_key)?;
        self.admit(
            ledger,
            LeaseTransportOperation::Advance,
            body,
            &body.runner_id,
            body.runner_epoch,
            body.work_package_id.as_str(),
            &digest,
            now_unix_ms,
            |txn| {
                let mut attempt = txn
                    .get_attempt(&body.attempt_id)
                    .map_err(SignedLeaseError::Ledger)?
                    .ok_or(SignedLeaseError::Unknown)?;
                if attempt.runner_id != body.runner_id
                    || attempt.runner_epoch != body.runner_epoch
                    || attempt.work_package_id != body.work_package_id
                {
                    return Err(SignedLeaseError::Transport(
                        LeaseTransportError::SubjectMismatch,
                    ));
                }
                attempt.state = body.state;
                txn.put_attempt(&attempt)
                    .map_err(SignedLeaseError::Ledger)?;
                Ok(attempt)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit<L, T, R, F>(
        &self,
        ledger: &mut L,
        operation: LeaseTransportOperation,
        body: &T,
        runner_id: &RunnerId,
        runner_epoch: u64,
        work_package_id: &str,
        idempotency_digest: &str,
        now_unix_ms: u64,
        after_verify: F,
    ) -> Result<R, SignedLeaseError>
    where
        L: Ledger,
        T: Serialize,
        F: FnOnce(&mut dyn LeaseTransportTxn) -> Result<R, SignedLeaseError>,
    {
        let request_digest = request_digest(body).map_err(SignedLeaseError::Transport)?;
        let authority_epoch = ledger.current_authority()?.authority_epoch();
        ledger.with_lease_transport(|txn| {
            let nonce = new_hex_64().map_err(SignedLeaseError::Transport)?;
            let permit_id = new_hex_64().map_err(SignedLeaseError::Transport)?;
            let expires_at_unix_ms = now_unix_ms.saturating_add(15_000);
            let binding = format!(
                "{}:{}:{idempotency_digest}",
                operation.as_str(),
                runner_id.as_str()
            );
            txn.reserve_transport_nonce(&nonce, &binding, expires_at_unix_ms)?;
            let claims = LeaseTransportClaims {
                schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
                permit_id,
                audience: LEASE_TRANSPORT_AUDIENCE.to_string(),
                operation,
                issuer: self.signing.issuer().to_string(),
                key_id: self.signing.key_id().to_string(),
                issued_at_unix_ms: now_unix_ms,
                not_before_unix_ms: now_unix_ms,
                expires_at_unix_ms,
                permit_nonce: nonce,
                request_digest: request_digest.clone(),
                runner_id: runner_id.as_str().to_string(),
                runner_epoch,
                authority_epoch,
                work_package_id: work_package_id.to_string(),
                idempotency_digest: idempotency_digest.to_string(),
            };
            let permit = self
                .signing
                .sign(&claims)
                .map_err(SignedLeaseError::Transport)?;
            let expectation = LeaseTransportExpectation {
                operation,
                request_digest,
                runner_id: runner_id.as_str().to_string(),
                runner_epoch,
                authority_epoch,
                work_package_id: work_package_id.to_string(),
                idempotency_digest: idempotency_digest.to_string(),
                now_unix_ms,
            };
            {
                let mut nonces = TxnNonceLedger { txn };
                let _verified =
                    verify_lease_permit(&permit, &self.verification, &expectation, &mut nonces)
                        .map_err(SignedLeaseError::Transport)?;
            }
            after_verify(txn)
        })
    }
}

struct TxnNonceLedger<'a> {
    txn: &'a mut dyn LeaseTransportTxn,
}

impl LaunchGrantNonceLedger for TxnNonceLedger<'_> {
    fn consume_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, bullet_harness_core::error::HarnessError> {
        self.txn
            .consume_transport_nonce(nonce, attempt_id, now_unix_ms)
            .map_err(
                |err| bullet_harness_core::error::HarnessError::LaunchGrantInvalid {
                    reason: err.to_string(),
                },
            )
    }
}

/// Simulator-only in-process issuer: register the nonce, then sign.
///
/// Co-locating issuance with the verifier is a test seam, never a
/// production admission path.
#[cfg(any(test, feature = "test-seams"))]
pub fn issue_permit(
    key: &LeaseTransportSigningKey,
    service: &mut SignedLeaseService,
    operation: LeaseTransportOperation,
    body: &SignedAcquireBody,
    now_unix_ms: u64,
) -> Result<SignedLeasePermit, SignedLeaseError> {
    issue_operation_permit(
        key,
        service,
        operation,
        &body.runner_id,
        body.runner_epoch,
        body.work_package_id.as_str(),
        &body.idempotency_key,
        body,
        now_unix_ms,
    )
}

/// Simulator-only issuer for any request body the permit must digest.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-seams"))]
pub fn issue_operation_permit<T: Serialize>(
    key: &LeaseTransportSigningKey,
    service: &mut SignedLeaseService,
    operation: LeaseTransportOperation,
    runner_id: &RunnerId,
    runner_epoch: u64,
    work_package_id: &str,
    idempotency_key: &str,
    body: &T,
    now_unix_ms: u64,
) -> Result<SignedLeasePermit, SignedLeaseError> {
    let digest = request_digest(body).map_err(SignedLeaseError::Transport)?;
    let idem = idempotency_digest(idempotency_key)?;
    let nonce = new_hex_64().map_err(SignedLeaseError::Transport)?;
    let permit_id = new_hex_64().map_err(SignedLeaseError::Transport)?;
    let claims = LeaseTransportClaims {
        schema_version: LEASE_TRANSPORT_SCHEMA_VERSION.to_string(),
        permit_id,
        audience: LEASE_TRANSPORT_AUDIENCE.to_string(),
        operation,
        issuer: key.issuer().to_string(),
        key_id: key.key_id().to_string(),
        issued_at_unix_ms: now_unix_ms,
        not_before_unix_ms: now_unix_ms,
        expires_at_unix_ms: now_unix_ms + 15_000,
        permit_nonce: nonce.clone(),
        request_digest: digest,
        runner_id: runner_id.as_str().to_string(),
        runner_epoch,
        authority_epoch: GENESIS_AUTHORITY_EPOCH,
        work_package_id: work_package_id.to_string(),
        idempotency_digest: idem.clone(),
    };
    let binding = format!("{}:{}:{}", operation.as_str(), claims.runner_id, idem);
    if !service.register_nonce(&nonce, &binding, claims.expires_at_unix_ms) {
        return Err(SignedLeaseError::Transport(LeaseTransportError::Invalid {
            reason: "permit nonce already registered".into(),
        }));
    }
    key.sign(&claims).map_err(SignedLeaseError::Transport)
}

/// In-process gateway with a process-local grant index. Production farmd
/// uses [`KernelLeaseTransport`]; this type remains for test-seams clients.
pub struct SignedLeaseService {
    verification: LeaseTransportVerificationKey,
    nonces: bullet_harness_core::launch_grant::MemoryNonceLedger,
    last_acquire: std::collections::BTreeMap<String, LeaseGrant>,
}

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
    ///
    /// Typed transport refusal or ledger failure.
    pub fn acquire<L: Ledger>(
        &mut self,
        ledger: &mut L,
        permit: &SignedLeasePermit,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        self.verify(
            permit,
            LeaseTransportOperation::Acquire,
            body,
            &body.runner_id,
            body.runner_epoch,
            body.work_package_id.as_str(),
            &body.idempotency_key,
            now_unix_ms,
        )?;
        let (graph, variant_id) = graph_for_package(ledger, &body.work_package_id)?;
        let request = lease_request(body, &graph, &variant_id);
        let grant = ledger
            .acquire_lease(&request)
            .map_err(SignedLeaseError::Ledger)?;
        self.last_acquire
            .insert(idempotency_digest(&body.idempotency_key)?, grant.clone());
        Ok(grant)
    }

    /// Return the last grant for this idempotency key without minting a sibling.
    ///
    /// # Errors
    ///
    /// Typed transport refusal, or `UNKNOWN` when no grant was stored.
    pub fn readback(
        &mut self,
        permit: &SignedLeasePermit,
        body: &SignedAcquireBody,
        now_unix_ms: u64,
    ) -> Result<LeaseGrant, SignedLeaseError> {
        self.verify(
            permit,
            LeaseTransportOperation::Readback,
            body,
            &body.runner_id,
            body.runner_epoch,
            body.work_package_id.as_str(),
            &body.idempotency_key,
            now_unix_ms,
        )?;
        self.last_acquire
            .get(&idempotency_digest(&body.idempotency_key)?)
            .cloned()
            .ok_or(SignedLeaseError::Unknown)
    }

    /// Renew one lease.
    ///
    /// # Errors
    ///
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
        self.verify(
            permit,
            LeaseTransportOperation::Heartbeat,
            call,
            &call.runner_id,
            call.runner_epoch,
            work_package_id.as_str(),
            idempotency_key,
            now_unix_ms,
        )?;
        ledger.heartbeat(call).map_err(SignedLeaseError::Ledger)
    }

    /// Close one lease.
    ///
    /// # Errors
    ///
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
        self.verify(
            permit,
            LeaseTransportOperation::Release,
            call,
            runner_id,
            runner_epoch,
            work_package_id.as_str(),
            idempotency_key,
            now_unix_ms,
        )?;
        ledger.release_lease(call).map_err(SignedLeaseError::Ledger)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify<T: Serialize>(
        &mut self,
        permit: &SignedLeasePermit,
        operation: LeaseTransportOperation,
        body: &T,
        runner_id: &RunnerId,
        runner_epoch: u64,
        work_package_id: &str,
        idempotency_key: &str,
        now_unix_ms: u64,
    ) -> Result<(), SignedLeaseError> {
        let digest = request_digest(body).map_err(SignedLeaseError::Transport)?;
        let expectation = LeaseTransportExpectation {
            operation,
            request_digest: digest,
            runner_id: runner_id.as_str().to_string(),
            runner_epoch,
            authority_epoch: GENESIS_AUTHORITY_EPOCH,
            work_package_id: work_package_id.to_string(),
            idempotency_digest: idempotency_digest(idempotency_key)?,
            now_unix_ms,
        };
        verify_lease_permit(permit, &self.verification, &expectation, &mut self.nonces)
            .map(|_| ())
            .map_err(SignedLeaseError::Transport)
    }
}

/// Service-level refusal.
#[derive(Debug, thiserror::Error)]
pub enum SignedLeaseError {
    /// Permit verification failed.
    #[error(transparent)]
    Transport(LeaseTransportError),
    /// Ledger refused the operation.
    #[error(transparent)]
    Ledger(LedgerError),
    /// Readback found no stored grant.
    #[error("lease transport unknown")]
    Unknown,
}

impl SignedLeaseError {
    /// Stable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Transport(error) => error.reason_code(),
            Self::Ledger(error) => error.reason_code(),
            Self::Unknown => "LEASE_TRANSPORT_UNKNOWN",
        }
    }
}

impl From<LedgerError> for SignedLeaseError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

fn idempotency_digest(key: &str) -> Result<String, SignedLeaseError> {
    request_digest(&key).map_err(SignedLeaseError::Transport)
}

fn lease_request(
    body: &SignedAcquireBody,
    graph: &StoredGraph,
    variant_id: &VariantId,
) -> LeaseRequest {
    LeaseRequest {
        idempotency_key: body.idempotency_key.clone(),
        mission_id: graph.mission.id.clone(),
        variant_id: variant_id.clone(),
        attempt_seed: body.idempotency_key.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        workspace_id: WorkspaceId::from_seed(&body.idempotency_key),
        workspace_nonce: *Digest::of(body.idempotency_key.as_bytes()).as_bytes(),
        scope_revision: 1,
        context_revision: 1,
        ttl_seconds: body.ttl_seconds,
    }
}

fn graph_for_package<L: Ledger>(
    ledger: &L,
    package: &WorkPackageId,
) -> Result<(StoredGraph, VariantId), SignedLeaseError> {
    for mission in ledger.list_missions().map_err(SignedLeaseError::Ledger)? {
        let Some(graph) = ledger
            .get_graph(&mission.id)
            .map_err(SignedLeaseError::Ledger)?
        else {
            continue;
        };
        if let Some(variant) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == *package)
        {
            let variant_id = variant.id.clone();
            return Ok((graph, variant_id));
        }
    }
    Err(SignedLeaseError::Unknown)
}
