//! Atomic, content-addressed plan materialization.

use crate::commands::CommandRequest;
use crate::store::{Ledger, LedgerError, StoredGraph};
use bullet_domain::{
    Digest, Mission, MissionId, MissionState, OrganizationId, PlanRevision, PlanRevisionId,
    RepositoryId, SelectionGroupId, TaskClass, Variant, VariantId, WorkPackage, WorkPackageId,
    WorkPackageState,
};

/// Input for one plan revision.
#[derive(Clone, Debug)]
pub struct PlanInput {
    /// Mission title.
    pub title: String,
    /// Objective.
    pub objective: String,
    /// Work package titles and classes.
    pub packages: Vec<(String, TaskClass)>,
}

/// Materialize a plan. Retrying the same seed returns the same graph.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn materialize_plan<L: Ledger>(
    ledger: &mut L,
    seed: &str,
    input: &PlanInput,
) -> Result<StoredGraph, LedgerError> {
    let request = CommandRequest::new(format!("materialize:{seed}"), "materialize_plan", &seed);
    ledger.record_command(&request)?;

    let mission_id = MissionId::from_seed(seed);
    if let Some(existing) = ledger.get_graph(&mission_id)? {
        return Ok(existing);
    }

    let plan_id = PlanRevisionId::from_seed(seed);
    let canonical_hash = Digest::of(format!("{seed}:{}", input.title).as_bytes());
    let mission = Mission {
        id: mission_id,
        organization_id: OrganizationId::from_seed(seed),
        repository_id: RepositoryId::from_seed(seed),
        title: input.title.clone(),
        objective: input.objective.clone(),
        acceptance_contract_id: bullet_domain::AcceptanceContractId::from_seed(seed),
        state: MissionState::Active,
    };
    let plan = PlanRevision {
        id: plan_id.clone(),
        mission_id: mission.id.clone(),
        canonical_hash,
    };
    let mut packages = Vec::new();
    let mut variants = Vec::new();
    for (idx, (title, class)) in input.packages.iter().enumerate() {
        let pkg_seed = format!("{seed}:wp:{idx}");
        let package = WorkPackage {
            id: WorkPackageId::from_seed(&pkg_seed),
            mission_id: mission.id.clone(),
            plan_revision_id: plan_id.clone(),
            task_class: *class,
            title: title.clone(),
            state: WorkPackageState::Ready,
        };
        let variant = Variant {
            id: VariantId::from_seed(&pkg_seed),
            selection_group_id: SelectionGroupId::from_seed(&pkg_seed),
            work_package_id: package.id.clone(),
            fence_counter: 1,
        };
        packages.push(package);
        variants.push(variant);
    }
    let graph = StoredGraph {
        mission,
        plan,
        packages,
        variants,
    };
    ledger.put_graph(&graph)?;
    ledger.append_event("graph_materialized", seed)?;
    Ok(graph)
}
