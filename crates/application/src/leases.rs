//! Writer leases and permanent fences.

use crate::store::{Ledger, LedgerError};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, AuthorityToken, Digest, DomainError, RunnerId, WorkspaceId,
};

/// Lease and fence operations.
pub struct LeaseService;

impl LeaseService {
    /// Open a new Attempt on a variant. The fence is never reused.
    ///
    /// # Errors
    ///
    /// Returns a domain error when a writer already exists or the fence would reuse.
    pub fn open_attempt<L: Ledger>(
        ledger: &mut L,
        graph: &crate::store::StoredGraph,
        variant_index: usize,
        seed: &str,
    ) -> Result<(Attempt, AuthorityToken), LedgerError> {
        let variant = graph
            .variants
            .get(variant_index)
            .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
        let package = graph
            .packages
            .iter()
            .find(|p| p.id == variant.work_package_id)
            .ok_or_else(|| LedgerError::Store("package missing".into()))?;
        if let Some(existing) = ledger.active_attempt(&package.id)? {
            if existing.state.may_mutate() {
                return Err(DomainError::Fence(format!(
                    "variant already has writer {}",
                    existing.id
                ))
                .into());
            }
        }
        let fence = variant.fence_counter;
        let attempt = Attempt {
            id: AttemptId::from_seed(seed),
            variant_id: variant.id.clone(),
            fence,
            workspace_id: WorkspaceId::from_seed(seed),
            state: AttemptState::Executing,
        };
        let token = Self::token_for(graph, variant_index, &attempt, seed);
        ledger.put_attempt(&attempt)?;
        Ok((attempt, token))
    }

    /// Rebuild the token that `open_attempt` would have issued.
    #[must_use]
    pub fn token_for(
        graph: &crate::store::StoredGraph,
        variant_index: usize,
        attempt: &Attempt,
        seed: &str,
    ) -> AuthorityToken {
        let variant = &graph.variants[variant_index];
        let package = graph
            .packages
            .iter()
            .find(|package| package.id == variant.work_package_id)
            .expect("package bound to variant");
        AuthorityToken {
            organization_id: graph.mission.organization_id.clone(),
            repository_id: graph.mission.repository_id.clone(),
            mission_id: graph.mission.id.clone(),
            acceptance_contract_id: graph.mission.acceptance_contract_id.clone(),
            plan_revision_id: graph.plan.id.clone(),
            graph_sequence: 1,
            work_package_id: package.id.clone(),
            selection_group_id: variant.selection_group_id.clone(),
            variant_id: variant.id.clone(),
            attempt_id: attempt.id.clone(),
            attempt_fence: attempt.fence,
            runner_id: RunnerId::from_seed(seed),
            runner_epoch: 1,
            workspace_id: attempt.workspace_id.clone(),
            workspace_nonce: Digest::of(seed.as_bytes()).as_bytes().to_owned(),
            scope_revision: 1,
            context_revision: 1,
            config_snapshot_hash: Digest::of(b"cfg"),
            policy_snapshot_hash: Digest::of(b"pol"),
            routing_policy_hash: Digest::of(b"route"),
            credential_profile_id: None,
            credential_generation: None,
        }
    }

    /// Open a successor Attempt. Fence is incremented; the previous writer is stale.
    ///
    /// # Errors
    ///
    /// Returns a domain error when the previous writer is still live or the fence
    /// would not increase.
    pub fn open_successor<L: Ledger>(
        ledger: &mut L,
        graph: &crate::store::StoredGraph,
        variant_index: usize,
        previous: &Attempt,
        seed: &str,
    ) -> Result<(Attempt, AuthorityToken, crate::store::StoredGraph), LedgerError> {
        let mut previous = previous.clone();
        if previous.state.may_mutate() {
            previous.state = previous.state.transition(AttemptState::Stale)?;
            ledger.put_attempt(&previous)?;
        }
        let variant = graph
            .variants
            .get(variant_index)
            .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
        let delta = crate::graph_delta::GraphDelta {
            parent: crate::graph_delta::graph_digest(graph),
            ops: vec![crate::graph_delta::GraphOp::BumpFence {
                variant_id: variant.id.clone(),
                from: variant.fence_counter,
                to: variant.fence_counter.saturating_add(1),
            }],
        };
        let graph = crate::graph_delta::apply_graph_delta(ledger, &graph.mission.id, &delta)?;
        let (attempt, token) = Self::open_attempt(ledger, &graph, variant_index, seed)?;
        Ok((attempt, token, graph))
    }

    /// Refuse cleanup when the observation is not a verified value.
    ///
    /// # Errors
    ///
    /// Returns stale authority when `observation` does not permit destruction.
    pub fn cleanup_if_verified<T>(
        observation: &bullet_domain::Observation<T>,
        attempt: &Attempt,
    ) -> Result<(), LedgerError> {
        if !observation.permits_destruction() {
            return Err(DomainError::StaleAuthority(format!(
                "unknown cannot destroy {}",
                attempt.id
            ))
            .into());
        }
        if !attempt.state.may_mutate() {
            return Err(DomainError::StaleAuthority(format!("{} is stale", attempt.id)).into());
        }
        Ok(())
    }

    /// Refuse a mutation from a stale token.
    ///
    /// # Errors
    ///
    /// Returns `StaleAuthority` when the token does not match.
    pub fn authorize(token: &AuthorityToken, attempt: &Attempt) -> Result<(), LedgerError> {
        token.verify(&attempt.id, attempt.fence)?;
        if !attempt.state.may_mutate() {
            return Err(DomainError::StaleAuthority(format!(
                "{} is {:?}",
                attempt.id, attempt.state
            ))
            .into());
        }
        Ok(())
    }
}
