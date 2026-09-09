//! Atomic, content-addressed plan materialization.

use crate::commands::CommandRequest;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{
    Digest, Mission, MissionId, MissionState, OrganizationId, PlanRevision, PlanRevisionId,
    RepositoryId, SelectionGroupId, TaskClass, Variant, VariantId, WorkPackage, WorkPackageId,
    WorkPackageState,
};
use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "test-seams"))]
mod synthetic_selection;
#[cfg(any(test, feature = "test-seams"))]
pub use synthetic_selection::materialize_synthetic_selection;

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

/// Canonical JSON shape the plan hash covers: seed, title, objective, and
/// every package. Changing any of them changes the hash.
#[derive(Serialize)]
struct CanonicalPlan<'a> {
    seed: &'a str,
    title: &'a str,
    objective: &'a str,
    packages: Vec<CanonicalPackage<'a>>,
}

#[derive(Serialize)]
struct CanonicalPackage<'a> {
    title: &'a str,
    task_class: TaskClass,
}

/// Exact durable result of an atomic Mission materialization command.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterializeCommandResult {
    /// Command, graph rows, and audit event committed together.
    Applied {
        /// Initial graph created by this command.
        graph: Box<StoredGraph>,
    },
}

impl MaterializeCommandResult {
    /// Encode the exact initial graph for durable replay.
    ///
    /// # Errors
    /// Store failure when serialization fails.
    pub fn applied(graph: &StoredGraph) -> Result<String, LedgerError> {
        serde_json::to_string(&Self::Applied {
            graph: Box::new(graph.clone()),
        })
        .map_err(|error| LedgerError::Store(error.to_string()))
    }

    /// Strictly decode a stored result. The byte-for-byte canonical roundtrip
    /// rejects ignored nested fields, alternate encodings, and corruption.
    ///
    /// # Errors
    /// Store failure for malformed or non-canonical persisted data.
    pub fn decode(value: &str) -> Result<Self, LedgerError> {
        let decoded: Self =
            serde_json::from_str(value).map_err(|error| LedgerError::Store(error.to_string()))?;
        let canonical = serde_json::to_string(&decoded)
            .map_err(|error| LedgerError::Store(error.to_string()))?;
        if canonical != value {
            return Err(LedgerError::Store(
                "materialization result is not canonical".into(),
            ));
        }
        Ok(decoded)
    }

    /// Return the stored graph only when it exactly matches the deterministic
    /// graph for this command request.
    ///
    /// # Errors
    /// Store failure when persisted result identity or content differs.
    pub fn graph_for(self, expected: &StoredGraph) -> Result<StoredGraph, LedgerError> {
        let Self::Applied { graph } = self;
        let stored =
            serde_json::to_string(&graph).map_err(|error| LedgerError::Store(error.to_string()))?;
        let expected = serde_json::to_string(expected)
            .map_err(|error| LedgerError::Store(error.to_string()))?;
        if stored != expected {
            return Err(LedgerError::Store(
                "materialization result does not match command graph".into(),
            ));
        }
        Ok(*graph)
    }
}

fn canonical<'a>(seed: &'a str, input: &'a PlanInput) -> CanonicalPlan<'a> {
    CanonicalPlan {
        seed,
        title: &input.title,
        objective: &input.objective,
        packages: input
            .packages
            .iter()
            .map(|(title, task_class)| CanonicalPackage {
                title,
                task_class: *task_class,
            })
            .collect(),
    }
}

/// Materialize a plan. Retrying the same seed returns the same graph; the
/// same seed with a different input is a typed idempotency conflict.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn materialize_plan<L: Ledger>(
    ledger: &mut L,
    seed: &str,
    input: &PlanInput,
    now: &str,
) -> Result<StoredGraph, LedgerError> {
    let plan_body = canonical(seed, input);
    let key = format!("materialize:{seed}");
    let request = CommandRequest::new(&key, "materialize_plan", &plan_body)?;
    let graph = build_graph(seed, input, Digest::of(request.payload.as_bytes()));
    ledger.materialize_plan_command(&request, &graph, now)
}

fn build_graph(seed: &str, input: &PlanInput, canonical_hash: Digest) -> StoredGraph {
    let mission_id = MissionId::from_seed(seed);
    let plan_id = PlanRevisionId::from_seed(seed);
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
            fence_counter: 0,
        };
        packages.push(package);
        variants.push(variant);
    }
    StoredGraph {
        mission,
        plan,
        packages,
        variants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryLedger;
    use crate::store::LedgerError;
    use bullet_domain::DomainError;

    fn plan() -> PlanInput {
        PlanInput {
            title: "t".into(),
            objective: "o".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        }
    }

    #[test]
    fn canonical_hash_covers_objective_and_packages() {
        let base = plan();
        let mut other_objective = plan();
        other_objective.objective = "different".into();
        let mut other_packages = plan();
        other_packages
            .packages
            .push(("two".into(), TaskClass::CodeReview));
        let h = |input: &PlanInput| {
            Digest::of_json(&canonical("s", input))
                .expect("hash")
                .to_hex()
        };
        assert_ne!(h(&base), h(&other_objective));
        assert_ne!(h(&base), h(&other_packages));
        assert_eq!(h(&base), h(&plan()));
    }

    #[test]
    fn same_seed_different_input_is_idempotency_conflict() {
        let mut ledger = MemoryLedger::new();
        materialize_plan(&mut ledger, "m", &plan(), "2026-01-01T00:00:00.000Z").expect("first");
        let mut changed = plan();
        changed.title = "changed".into();
        let err = materialize_plan(&mut ledger, "m", &changed, "2026-01-01T00:00:01.000Z")
            .expect_err("conflict");
        assert!(matches!(
            err,
            LedgerError::Domain(DomainError::Idempotency(_))
        ));
    }
}
