//! Writer leases and permanent fences. Authority flows through the ledger's
//! single-transaction acquisition (spec section 26.3), never through checks
//! followed by separate writes.

use crate::records::{
    validate_lease_ttl, ExpiredLease, HeartbeatRequest, LeaseGrant, LeaseRequest, ReleaseRequest,
    StoredGraph,
};
use crate::store::{Ledger, LedgerError};
use bullet_domain::{
    observation::PreservationDecision, Attempt, AttemptState, AuthorityToken, Digest, DomainError,
    RunnerId, WorkspaceId,
};
use chrono::{DateTime, SecondsFormat, Utc};

/// Lease and fence operations.
pub struct LeaseService;

impl LeaseService {
    /// Fixed-width RFC 3339 UTC encoding used across the ledger boundary.
    #[must_use]
    pub fn rfc3339(at: DateTime<Utc>) -> String {
        at.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    /// Build the deterministic acquisition request for one variant.
    ///
    /// # Errors
    ///
    /// Returns a store error when the variant index is out of range.
    pub fn request_for(
        graph: &StoredGraph,
        variant_index: usize,
        seed: &str,
        ttl_seconds: i64,
    ) -> Result<LeaseRequest, LedgerError> {
        let variant = graph
            .variants
            .get(variant_index)
            .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
        Ok(LeaseRequest {
            idempotency_key: format!("lease:{seed}"),
            mission_id: graph.mission.id.clone(),
            variant_id: variant.id.clone(),
            attempt_seed: seed.to_string(),
            runner_id: RunnerId::from_seed(seed),
            runner_epoch: 1,
            workspace_id: WorkspaceId::from_seed(seed),
            workspace_nonce: *Digest::of(seed.as_bytes()).as_bytes(),
            scope_revision: 1,
            context_revision: 1,
            ttl_seconds,
        })
    }

    /// Acquire the writer lease for one variant in a single ledger
    /// transaction and mint the matching Authority Token.
    ///
    /// # Errors
    ///
    /// Returns typed fence/idempotency errors or a store failure.
    pub fn acquire<L: Ledger>(
        ledger: &mut L,
        graph: &StoredGraph,
        variant_index: usize,
        seed: &str,
        ttl_seconds: i64,
    ) -> Result<(Attempt, AuthorityToken, LeaseGrant), LedgerError> {
        let request = Self::request_for(graph, variant_index, seed, ttl_seconds)?;
        let grant = ledger.acquire_lease(&request)?;
        let token = Self::token_for(graph, &grant.attempt)?;
        Ok((grant.attempt.clone(), token, grant))
    }

    /// Reclaim every lease whose expiry has already passed, in one ledger
    /// transaction against the store's own clock.
    ///
    /// This is the named production entry point for expiry reclamation: the
    /// `bullet farm reap` CLI and any daemon maintenance tick call exactly this
    /// function, and it is deterministic — it reclaims what is due at the
    /// moment the store commits, and nothing else. Acquisition does not need
    /// it: [`Self::acquire`] reaches `Ledger::acquire_lease`, which reclaims the
    /// requested Variant's dead lease inside its own transaction. Running it
    /// again after it has reclaimed a lease returns an empty set.
    ///
    /// # Errors
    ///
    /// Returns a store failure; a corrupt persisted lease window fails closed
    /// without reclaiming anything.
    pub fn expire_due<L: Ledger>(ledger: &mut L) -> Result<Vec<ExpiredLease>, LedgerError> {
        ledger.expire_leases()
    }

    /// Rebuild the token an acquisition minted for `attempt`.
    ///
    /// # Errors
    ///
    /// Returns a store error when the attempt's variant is not in the graph.
    pub fn token_for(
        graph: &StoredGraph,
        attempt: &Attempt,
    ) -> Result<AuthorityToken, LedgerError> {
        let variant = graph
            .variants
            .iter()
            .find(|variant| variant.id == attempt.variant_id)
            .ok_or_else(|| LedgerError::Store("attempt variant not in graph".into()))?;
        Ok(AuthorityToken {
            organization_id: graph.mission.organization_id.clone(),
            repository_id: graph.mission.repository_id.clone(),
            mission_id: graph.mission.id.clone(),
            acceptance_contract_id: graph.mission.acceptance_contract_id.clone(),
            plan_revision_id: graph.plan.id.clone(),
            graph_sequence: 1,
            work_package_id: attempt.work_package_id.clone(),
            selection_group_id: variant.selection_group_id.clone(),
            variant_id: variant.id.clone(),
            attempt_id: attempt.id.clone(),
            attempt_fence: attempt.fence,
            runner_id: attempt.runner_id.clone(),
            runner_epoch: attempt.runner_epoch,
            workspace_id: attempt.workspace_id.clone(),
            workspace_nonce: attempt.workspace_nonce,
            scope_revision: attempt.scope_revision,
            context_revision: attempt.context_revision,
            config_snapshot_hash: Digest::of(b"cfg"),
            policy_snapshot_hash: Digest::of(b"pol"),
            routing_policy_hash: Digest::of(b"route"),
            credential_profile_id: None,
            credential_generation: None,
        })
    }

    /// Heartbeat request carrying the six identity columns of one grant.
    #[must_use]
    pub fn heartbeat_of(grant: &LeaseGrant) -> HeartbeatRequest {
        HeartbeatRequest {
            variant_id: grant.lease.variant_id.clone(),
            attempt_id: grant.lease.attempt_id.clone(),
            fence: grant.lease.fence,
            runner_id: grant.lease.runner_id.clone(),
            runner_epoch: grant.lease.runner_epoch,
            workspace_nonce: grant.lease.workspace_nonce,
            ttl_seconds: grant.lease.ttl_seconds,
        }
    }

    /// Validate one caller-provided TTL without granting authority.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_LEASE_TTL` outside the frozen Phase-1 range 1..=15 seconds.
    pub fn validate_ttl(ttl_seconds: i64) -> Result<i64, LedgerError> {
        validate_lease_ttl(ttl_seconds).map_err(Into::into)
    }

    /// Close one grant's lease.
    ///
    /// # Errors
    ///
    /// Returns `StaleAuthority` when the lease is held by another attempt.
    pub fn release<L: Ledger>(
        ledger: &mut L,
        grant: &LeaseGrant,
        final_state: AttemptState,
        requeue: bool,
    ) -> Result<(), LedgerError> {
        ledger.release_lease(&ReleaseRequest {
            variant_id: grant.lease.variant_id.clone(),
            attempt_id: grant.lease.attempt_id.clone(),
            final_state,
            requeue,
        })
    }

    /// Consume an exact preservation decision before workspace cleanup.
    ///
    /// # Errors
    ///
    /// Returns stale authority when the decision no longer matches the Attempt.
    pub fn authorize_workspace_cleanup(
        decision: PreservationDecision,
        attempt: &Attempt,
    ) -> Result<Digest, LedgerError> {
        decision
            .authorize_workspace_cleanup(attempt)
            .map_err(Into::into)
    }

    /// Refuse patch application from a stale token or non-running Attempt.
    ///
    /// # Errors
    ///
    /// Returns `StaleAuthority` when the token does not match.
    pub fn authorize_patch_application(
        token: &AuthorityToken,
        attempt: &Attempt,
    ) -> Result<(), LedgerError> {
        token.verify(&attempt.id, attempt.fence)?;
        if !attempt.state.permits_patch_application() {
            return Err(DomainError::StaleAuthority(format!(
                "{} cannot apply a patch while {:?}",
                attempt.id, attempt.state
            ))
            .into());
        }
        Ok(())
    }
}
