//! Authority Token. Paths, PIDs, and provider thread IDs grant nothing.

use crate::digest::Digest;
use crate::error::DomainError;
use crate::ids::{
    AcceptanceContractId, AttemptId, MissionId, OrganizationId, PlanRevisionId, ProfileId,
    RepositoryId, RunnerId, SelectionGroupId, VariantId, WorkPackageId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

/// Complete immutable authority for one Attempt incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityToken {
    /// Organization.
    pub organization_id: OrganizationId,
    /// Repository.
    pub repository_id: RepositoryId,
    /// Mission.
    pub mission_id: MissionId,
    /// Acceptance contract bound at admission.
    pub acceptance_contract_id: AcceptanceContractId,
    /// Immutable plan revision.
    pub plan_revision_id: PlanRevisionId,
    /// Graph sequence at grant time.
    pub graph_sequence: u64,
    /// Work package.
    pub work_package_id: WorkPackageId,
    /// Selection group.
    pub selection_group_id: SelectionGroupId,
    /// Variant that owns the writer lease.
    pub variant_id: VariantId,
    /// Attempt incarnation.
    pub attempt_id: AttemptId,
    /// Permanent fence epoch. Never reused.
    pub attempt_fence: u64,
    /// Runner that holds the lease.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Private workspace.
    pub workspace_id: WorkspaceId,
    /// Workspace nonce.
    pub workspace_nonce: [u8; 32],
    /// Scope grant revision.
    pub scope_revision: u64,
    /// Context capsule revision.
    pub context_revision: u64,
    /// Config snapshot.
    pub config_snapshot_hash: Digest,
    /// Policy snapshot.
    pub policy_snapshot_hash: Digest,
    /// Routing policy snapshot.
    pub routing_policy_hash: Digest,
    /// Optional provider profile.
    pub credential_profile_id: Option<ProfileId>,
    /// Credential generation.
    pub credential_generation: Option<u64>,
}

impl AuthorityToken {
    /// Verify the token names the expected Attempt and fence.
    pub fn verify(&self, attempt: &AttemptId, fence: u64) -> Result<(), DomainError> {
        if self.attempt_id != *attempt {
            return Err(DomainError::StaleAuthority(format!(
                "token attempt {} != {}",
                self.attempt_id, attempt
            )));
        }
        if self.attempt_fence != fence {
            return Err(DomainError::StaleAuthority(format!(
                "token fence {} != {fence}",
                self.attempt_fence
            )));
        }
        Ok(())
    }

    /// Content hash used as a correlation key.
    pub fn digest(&self) -> Result<Digest, DomainError> {
        Digest::of_json(self)
    }
}
