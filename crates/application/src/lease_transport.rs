//! Kernel-side signed lease-transport service.
//!
//! Public farmd `/v1/leases/*` routes stay absent. `HttpLeaseClient` is not
//! an admission path. This service verifies a `lease-runner` permit, then
//! applies one ledger operation or returns the last grant for a lost
//! acquire response. Permit issuance is not implemented as a production
//! transport; the in-process issuer below exists only under `test-seams`.

use crate::launch_grant::KERNEL_AUTHORITY_EPOCH;
use crate::records::{HeartbeatRequest, LeaseGrant, LeaseRequest, ReleaseRequest, StoredGraph};
use crate::store::{Ledger, LedgerError};
use bullet_domain::{Digest, RunnerId, VariantId, WorkPackageId, WorkspaceId};
use bullet_harness_core::launch_grant::MemoryNonceLedger;
#[cfg(any(test, feature = "test-seams"))]
use bullet_harness_core::lease_transport::LeaseTransportSigningKey;
use bullet_harness_core::lease_transport::{
    request_digest, verify_lease_permit, LeaseTransportError, LeaseTransportExpectation,
    LeaseTransportOperation, LeaseTransportVerificationKey, SignedLeasePermit,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Request body covered by an `acquire` or `readback` permit.
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

/// One Kernel-owned signed lease-transport endpoint.
///
/// `last_acquire` is process-local. Readback after a restart is `UNKNOWN`
/// until a durable grant index exists. That is not a five-plane proof.
pub struct SignedLeaseService {
    verification: LeaseTransportVerificationKey,
    nonces: MemoryNonceLedger,
    last_acquire: BTreeMap<String, LeaseGrant>,
}

impl SignedLeaseService {
    /// Bind the service to one verification key. The matching signing key
    /// stays with the issuer, never this service.
    #[must_use]
    pub fn new(verification: LeaseTransportVerificationKey) -> Self {
        Self {
            verification,
            nonces: MemoryNonceLedger::new(),
            last_acquire: BTreeMap::new(),
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

    /// Renew one lease. The permit covers `call`, not `SignedAcquireBody`.
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

    /// Close one lease. The permit covers `call`, not `SignedAcquireBody`.
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
            authority_epoch: KERNEL_AUTHORITY_EPOCH,
            work_package_id: work_package_id.to_string(),
            idempotency_digest: idempotency_digest(idempotency_key)?,
            now_unix_ms,
        };
        verify_lease_permit(permit, &self.verification, &expectation, &mut self.nonces)
            .map(|_| ())
            .map_err(SignedLeaseError::Transport)
    }
}

/// Simulator-only in-process issuer: register the nonce, then sign.
///
/// This deliberately co-locates issuance with the verifier so tests can
/// exercise the wire contract. It is absent from default production builds.
///
/// # Errors
///
/// Signing, entropy, or nonce-registration failure.
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
///
/// It is absent from default production builds; a real transport must obtain
/// permits from a separately authenticated Kernel-owned issuer.
///
/// # Errors
///
/// Signing, entropy, or nonce-registration failure.
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
    let nonce =
        bullet_harness_core::lease_transport::new_hex_64().map_err(SignedLeaseError::Transport)?;
    let permit_id =
        bullet_harness_core::lease_transport::new_hex_64().map_err(SignedLeaseError::Transport)?;
    let claims = bullet_harness_core::lease_transport::LeaseTransportClaims {
        schema_version: bullet_harness_core::lease_transport::LEASE_TRANSPORT_SCHEMA_VERSION
            .to_string(),
        permit_id,
        audience: bullet_harness_core::lease_transport::LEASE_TRANSPORT_AUDIENCE.to_string(),
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
        authority_epoch: KERNEL_AUTHORITY_EPOCH,
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
