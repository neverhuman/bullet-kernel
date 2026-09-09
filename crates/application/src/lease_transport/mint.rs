//! Minting of lease-transport claims from durable truth, the advance guard,
//! and the simulator-only permit issuer. Durable rows reach this module only
//! through the open transaction port (`grant_truth`, `incarnation_truth`);
//! claims are minted from the very expectation the gateway verifies against.

pub(super) use super::grant_resolution::grant_truth;
use super::{not_active, unknown_package, SignedAcquireBody};
#[cfg(any(test, feature = "test-seams"))]
use super::{SignedLeaseService, PERMIT_TTL_MS};
use crate::authority_revision::NormalizedAuthority;
#[cfg(any(test, feature = "test-seams"))]
use crate::records::StoredGraph;
use crate::records::{ActiveLease, LeaseGrant, LeaseRequest};
use crate::store::LeaseTransportTxn;
#[cfg(any(test, feature = "test-seams"))]
use crate::store::{CurrentPackage, Ledger, LedgerError};
#[cfg(any(test, feature = "test-seams"))]
use bullet_domain::WorkPackageId;
use bullet_domain::{
    Attempt, AttemptId, AttemptState, Digest, MissionId, RunnerId, VariantId, WorkspaceId,
};
use bullet_harness_core::launch_grant::{
    workspace_nonce_digest, LaunchGrantNonceLedger, NonceConsumption,
};
#[cfg(any(test, feature = "test-seams"))]
use bullet_harness_core::lease_transport::{
    new_hex_64, nonce_binding, LeaseTransportSigningKey, SignedLeasePermit,
};
use bullet_harness_core::lease_transport::{
    request_digest, LeaseIncarnationClaims, LeaseSubjectClaims, LeaseTransportError,
    LeaseTransportExpectation, LeaseTransportOperation,
};
use bullet_harness_core::HarnessError;
use serde::Serialize;

mod error;

pub use error::SignedLeaseError;

/// Identity the Runner presented with a request: runner, epoch, package.
pub type Presented<'a> = (&'a RunnerId, u64, &'a str);

/// Exact expectation for one request body, the presented identity, and the
/// durable subject the Kernel loaded.
///
/// # Errors
/// Encoding refusal.
pub fn expectation_for<T: Serialize>(
    operation: LeaseTransportOperation,
    body: &T,
    presented: Presented<'_>,
    idempotency_key: &str,
    authority_epoch: u64,
    subject: LeaseSubjectClaims,
    now_unix_ms: u64,
) -> Result<LeaseTransportExpectation, SignedLeaseError> {
    Ok(LeaseTransportExpectation {
        operation,
        request_digest: request_digest(body).map_err(SignedLeaseError::Transport)?,
        runner_id: presented.0.as_str().to_string(),
        runner_epoch: presented.1,
        authority_epoch,
        work_package_id: presented.2.to_string(),
        idempotency_digest: idempotency_digest(idempotency_key)?,
        subject,
        now_unix_ms,
    })
}

/// Grant-class subject: the workspace the grant creates or returns plus the
/// authority generations in force. No fence exists yet.
///
/// # Errors
/// All-zero workspace nonce.
pub fn grant_subject(
    workspace_id: &WorkspaceId,
    workspace_nonce: &[u8; 32],
    authority: &NormalizedAuthority,
) -> Result<LeaseSubjectClaims, SignedLeaseError> {
    Ok(LeaseSubjectClaims {
        workspace_id: workspace_id.as_str().to_string(),
        workspace_generation: authority.workspace_generation(),
        workspace_nonce_digest: workspace_nonce_digest(workspace_nonce).map_err(transport)?,
        scope_digest: authority.scope_digest().to_string(),
        policy_generation: authority.policy_generation(),
        freeze_generation: authority.freeze_generation(),
        graph_revision: authority.graph_revision(),
        routing_generation: authority.routing_generation(),
        authority_epoch: authority.authority_epoch(),
        incarnation: None,
    })
}

/// Subject of one fenced Attempt incarnation plus the authority generations.
///
/// # Errors
/// All-zero workspace nonce.
pub fn incarnation_subject(
    attempt: &Attempt,
    authority: &NormalizedAuthority,
) -> Result<LeaseSubjectClaims, SignedLeaseError> {
    let mut subject = grant_subject(&attempt.workspace_id, &attempt.workspace_nonce, authority)?;
    subject.incarnation = Some(LeaseIncarnationClaims {
        variant_id: attempt.variant_id.as_str().to_string(),
        attempt_id: attempt.id.as_str().to_string(),
        fence: attempt.fence,
        scope_revision: attempt.scope_revision,
        context_revision: attempt.context_revision,
    });
    Ok(subject)
}

/// Subject minted from a lease row and its Attempt (what
/// `LeaseService::acquire` returns); the rows must agree on every column.
///
/// # Errors
/// `LEASE_TRANSPORT_SUBJECT_MISMATCH` naming the column, or nonce refusal.
pub fn lease_subject(
    grant: &LeaseGrant,
    authority: &NormalizedAuthority,
) -> Result<LeaseSubjectClaims, SignedLeaseError> {
    let (a, l) = (&grant.attempt, &grant.lease);
    no_mismatch([
        (l.variant_id != a.variant_id, "variant_id"),
        (l.attempt_id != a.id, "attempt_id"),
        (l.fence != a.fence, "fence"),
        (l.runner_id != a.runner_id, "runner_id"),
        (l.runner_epoch != a.runner_epoch, "runner_epoch"),
        (
            l.workspace_nonce != a.workspace_nonce,
            "workspace_nonce_digest",
        ),
    ])?;
    incarnation_subject(a, authority)
}

/// Require the presented Attempt's permanent fence to be the fence the
/// variant's active lease row carries now.
///
/// # Errors
/// `LEASE_NOT_ACTIVE` without a lease row; `LEASE_FENCE_STALE` when another
/// incarnation holds the lease.
pub fn require_current_fence(
    attempt: &Attempt,
    lease: Option<&ActiveLease>,
) -> Result<(), SignedLeaseError> {
    let Some(lease) = lease else {
        return Err(SignedLeaseError::NotActive {
            reason: format!("no active lease for variant {}", attempt.variant_id),
        });
    };
    if lease.fence != attempt.fence || lease.attempt_id != attempt.id {
        return Err(SignedLeaseError::FenceStale {
            attempt_fence: attempt.fence,
            lease_fence: lease.fence,
        });
    }
    Ok(())
}

/// Apply the domain machine to one requested edge.
///
/// # Errors
/// `ATTEMPT_TRANSITION_ILLEGAL` for any edge outside the machine.
pub fn legal_transition(
    attempt: &Attempt,
    to: AttemptState,
) -> Result<AttemptState, SignedLeaseError> {
    attempt
        .state
        .transition(to)
        .map_err(|_| SignedLeaseError::TransitionIllegal {
            from: attempt.state.as_str(),
            to: to.as_str(),
        })
}

pub(super) struct TxnNonceLedger<'a> {
    pub(super) txn: &'a mut dyn LeaseTransportTxn,
}

impl LaunchGrantNonceLedger for TxnNonceLedger<'_> {
    fn consume_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        now_unix_ms: u64,
    ) -> Result<NonceConsumption, HarnessError> {
        self.txn
            .consume_transport_nonce(nonce, attempt_id, now_unix_ms)
            .map_err(|err| HarnessError::LaunchGrantInvalid {
                reason: err.to_string(),
            })
    }
}

pub(super) fn no_mismatch<const N: usize>(
    checks: [(bool, &'static str); N],
) -> Result<(), SignedLeaseError> {
    let deviation = checks.into_iter().find(|(deviates, _)| *deviates);
    deviation.map_or(Ok(()), |(_, field)| {
        Err(SignedLeaseError::Transport(
            LeaseTransportError::SubjectMismatch { field },
        ))
    })
}

pub(super) fn transport(error: HarnessError) -> SignedLeaseError {
    let reason = error.to_string();
    SignedLeaseError::Transport(LeaseTransportError::Invalid { reason })
}

pub(super) fn idempotency_digest(key: &str) -> Result<String, SignedLeaseError> {
    request_digest(&key).map_err(SignedLeaseError::Transport)
}

/// Workspace identity every grant derives from the acquire idempotency key.
#[must_use]
pub fn workspace_for_key(idempotency_key: &str) -> (WorkspaceId, [u8; 32]) {
    (
        WorkspaceId::from_seed(idempotency_key),
        *Digest::of(idempotency_key.as_bytes()).as_bytes(),
    )
}

pub(super) fn lease_request(
    body: &SignedAcquireBody,
    mission_id: &MissionId,
    variant_id: &VariantId,
) -> LeaseRequest {
    let (workspace_id, workspace_nonce) = workspace_for_key(&body.idempotency_key);
    LeaseRequest {
        idempotency_key: body.idempotency_key.clone(),
        mission_id: mission_id.clone(),
        variant_id: variant_id.clone(),
        attempt_seed: body.idempotency_key.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        workspace_id,
        workspace_nonce,
        scope_revision: 1,
        context_revision: 1,
        ttl_seconds: body.ttl_seconds,
    }
}

#[cfg(any(test, feature = "test-seams"))]
pub(super) fn graph_for_package<L: Ledger>(
    ledger: &L,
    package: &WorkPackageId,
) -> Result<(StoredGraph, VariantId), SignedLeaseError> {
    let mut found = None;
    for mission in ledger.list_missions()? {
        let Some(graph) = ledger.get_graph(&mission.id)? else {
            continue;
        };
        if let Some(current) = CurrentPackage::from_graph(&graph, package)? {
            if found.is_some() {
                return Err(LedgerError::Store(format!(
                    "work package {package} is duplicated across current graphs"
                ))
                .into());
            }
            found = Some((graph, current.variant.id));
        }
    }
    found.ok_or(SignedLeaseError::Unknown)
}

/// Simulator-only in-process issuer: register the nonce, then sign. Never a
/// production admission path.
///
/// # Errors
/// Typed transport refusal.
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
/// Grant-class operations bind the workspace the key derives; incarnation
/// operations bind the grant this service stored for the same key. The seam
/// mints against the genesis authority row.
///
/// # Errors
/// `LEASE_TRANSPORT_UNKNOWN` when no grant was stored for the key.
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
    let authority = NormalizedAuthority::genesis();
    let subject = if operation.binds_incarnation() {
        let grant = service
            .last_acquire
            .get(&idempotency_digest(idempotency_key)?)
            .ok_or(SignedLeaseError::Unknown)?;
        lease_subject(grant, &authority)?
    } else {
        let (workspace_id, nonce) = workspace_for_key(idempotency_key);
        grant_subject(&workspace_id, &nonce, &authority)?
    };
    let presented = (runner_id, runner_epoch, work_package_id);
    let epoch = authority.authority_epoch();
    let expected = expectation_for(
        operation,
        body,
        presented,
        idempotency_key,
        epoch,
        subject,
        now_unix_ms,
    )?;
    let nonce = new_hex_64().map_err(SignedLeaseError::Transport)?;
    let permit_id = new_hex_64().map_err(SignedLeaseError::Transport)?;
    let claims = expected.claims(
        key.issuer(),
        key.key_id(),
        permit_id,
        nonce.clone(),
        PERMIT_TTL_MS,
    );
    let binding = nonce_binding(operation, &claims.runner_id, &claims.idempotency_digest);
    if !service.register_nonce(&nonce, &binding, claims.expires_at_unix_ms) {
        return Err(SignedLeaseError::Transport(LeaseTransportError::Invalid {
            reason: "permit nonce already registered".into(),
        }));
    }
    key.sign(&claims).map_err(SignedLeaseError::Transport)
}

/// The proven Attempt plus the expectation minted from its live lease.
pub(super) struct IncarnationTruth {
    pub(super) attempt: Attempt,
    pub(super) expected: LeaseTransportExpectation,
}

/// Inside the transaction: load the Attempt, prove exact permit↔Attempt
/// identity (`presented` plus the caller.s `identity` checks), require its live
/// lease at the current fence, run the authoritative-clock active check, and
/// mint the expectation. Refusals are typed and leave nothing behind.
#[allow(clippy::too_many_arguments)]
pub(super) fn incarnation_truth<T: Serialize>(
    txn: &dyn LeaseTransportTxn,
    op: LeaseTransportOperation,
    body: &T,
    presented: Presented<'_>,
    idempotency_key: &str,
    attempt_id: &AttemptId,
    identity: impl FnOnce(&Attempt) -> Result<(), SignedLeaseError>,
    now_unix_ms: u64,
) -> Result<IncarnationTruth, SignedLeaseError> {
    let unknown = SignedLeaseError::Unknown;
    let attempt = txn.get_attempt(attempt_id)?.ok_or(unknown)?;
    let package = attempt.work_package_id.as_str();
    let (workspace_id, workspace_nonce) = workspace_for_key(idempotency_key);
    no_mismatch([
        (attempt.runner_id != *presented.0, "runner_id"),
        (attempt.runner_epoch != presented.1, "runner_epoch"),
        (package != presented.2, "work_package_id"),
        (attempt.workspace_id != workspace_id, "workspace_id"),
        (
            attempt.workspace_nonce != workspace_nonce,
            "workspace_nonce_digest",
        ),
    ])?;
    identity(&attempt)?;
    let Some(lease) = txn.get_lease(&attempt.id)? else {
        return Err(lease_gone(txn, &attempt)?);
    };
    require_current_fence(&attempt, Some(&lease))?;
    txn.check_active_lease(&attempt.id, attempt.fence)
        .map_err(not_active)?;
    let authority = txn.current_authority()?;
    let grant = LeaseGrant {
        attempt: attempt.clone(),
        lease,
    };
    let subject = lease_subject(&grant, &authority)?;
    let epoch = authority.authority_epoch();
    let key = idempotency_key;
    let expected = expectation_for(op, body, presented, key, epoch, subject, now_unix_ms)?;
    Ok(IncarnationTruth { attempt, expected })
}

/// A later variant fence means a successor holds the lease; else it is gone.
fn lease_gone(
    txn: &dyn LeaseTransportTxn,
    attempt: &Attempt,
) -> Result<SignedLeaseError, SignedLeaseError> {
    let current = txn
        .resolve_variant(&attempt.work_package_id, &attempt.variant_id)
        .map_err(unknown_package)?
        .variant
        .fence_counter;
    if current != attempt.fence {
        return Ok(SignedLeaseError::FenceStale {
            attempt_fence: attempt.fence,
            lease_fence: current,
        });
    }
    Ok(SignedLeaseError::NotActive {
        reason: format!("no active lease for variant {}", attempt.variant_id),
    })
}
