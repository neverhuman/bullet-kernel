//! Authoritative entities. Runtime projections are not stored here.

use crate::digest::Digest;
use crate::ids::{
    AcceptanceContractId, AttemptId, CandidateId, EffectId, EvidenceId, MissionId, OrganizationId,
    PlanRevisionId, RepositoryId, RequirementId, RunnerId, SelectionGroupId, VariantId,
    WorkPackageId, WorkspaceId,
};
use crate::states::{AttemptState, MissionState, WorkPackageState};
use crate::taxonomy::TaskClass;
use serde::{Deserialize, Serialize};

/// Authorized engineering objective.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mission {
    /// Identity.
    pub id: MissionId,
    /// Owning org.
    pub organization_id: OrganizationId,
    /// Target repository.
    pub repository_id: RepositoryId,
    /// Human title.
    pub title: String,
    /// Objective text.
    pub objective: String,
    /// Frozen acceptance contract.
    pub acceptance_contract_id: AcceptanceContractId,
    /// Lifecycle.
    pub state: MissionState,
}

/// One machine-addressable acceptance requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceRequirement {
    /// Identity.
    pub id: RequirementId,
    /// Description.
    pub description: String,
    /// Kind label such as `functional` or `security`.
    pub kind: String,
}

/// Immutable, content-addressed plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRevision {
    /// Identity.
    pub id: PlanRevisionId,
    /// Mission.
    pub mission_id: MissionId,
    /// Canonical hash of the graph payload.
    pub canonical_hash: Digest,
}

/// Smallest independently contracted unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkPackage {
    /// Identity.
    pub id: WorkPackageId,
    /// Mission.
    pub mission_id: MissionId,
    /// Plan that materialized this node.
    pub plan_revision_id: PlanRevisionId,
    /// Task class used for routing.
    pub task_class: TaskClass,
    /// Title.
    pub title: String,
    /// Lifecycle. Integration is repository truth.
    pub state: WorkPackageState,
}

/// Unit of writable authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variant {
    /// Identity.
    pub id: VariantId,
    /// Selection group.
    pub selection_group_id: SelectionGroupId,
    /// Work package.
    pub work_package_id: WorkPackageId,
    /// Monotonic fence. Never reused.
    pub fence_counter: u64,
}

/// One execution incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// Identity.
    pub id: AttemptId,
    /// Variant.
    pub variant_id: VariantId,
    /// Work package the variant writes.
    pub work_package_id: WorkPackageId,
    /// Fence assigned at creation. Permanent.
    pub fence: u64,
    /// Runner that holds the lease.
    pub runner_id: RunnerId,
    /// Runner generation.
    pub runner_epoch: u64,
    /// Private workspace.
    pub workspace_id: WorkspaceId,
    /// Workspace nonce bound to the lease.
    pub workspace_nonce: [u8; 32],
    /// Scope grant revision.
    pub scope_revision: u64,
    /// Context capsule revision.
    pub context_revision: u64,
    /// Lifecycle.
    pub state: AttemptState,
}

/// Exact implementation identity. A ChangeId never authorizes integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Identity.
    pub id: CandidateId,
    /// Attempt that prepared it.
    pub attempt_id: AttemptId,
    /// Base commit SHA.
    pub base_sha: String,
    /// Head commit SHA.
    pub head_sha: String,
    /// Tree SHA.
    pub tree_sha: String,
    /// Patch digest.
    pub patch_digest: Digest,
}

/// Exact-subject evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Identity.
    pub id: EvidenceId,
    /// Candidate that was tested.
    pub candidate_id: CandidateId,
    /// Trust tier `E0`..=`E4`.
    pub tier: String,
    /// Gate name.
    pub gate: String,
    /// Only typed PASS satisfies a blocking gate.
    pub result: String,
}

/// Privileged external mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// Identity.
    pub id: EffectId,
    /// Attempt that requested it.
    pub attempt_id: AttemptId,
    /// Logical key for idempotent replay.
    pub logical_key: String,
    /// Desired remote state.
    pub desired: String,
    /// Receipt kind: `verified` or `unknown`.
    pub outcome: String,
}
