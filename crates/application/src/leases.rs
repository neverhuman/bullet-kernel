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
        let token = AuthorityToken {
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
            attempt_fence: fence,
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
        };
        ledger.put_attempt(&attempt)?;
        Ok((attempt, token))
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
