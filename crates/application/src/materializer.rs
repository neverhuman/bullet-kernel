//! Atomic, content-addressed plan materialization.

use crate::commands::CommandRequest;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{
    CommandPhase, Digest, Mission, MissionId, MissionState, OrganizationId, PlanRevision,
    PlanRevisionId, RepositoryId, SelectionGroupId, TaskClass, Variant, VariantId, WorkPackage,
    WorkPackageId, WorkPackageState,
};
use serde::Serialize;

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
    let record = ledger.record_command(&request)?;

    let mission_id = MissionId::from_seed(seed);
    if let Some(existing) = ledger.get_graph(&mission_id)? {
        if record.phase == CommandPhase::Pending {
            ledger.set_command_phase(
                &key,
                CommandPhase::Verified,
                Some(existing.mission.id.as_str()),
            )?;
        }
        return Ok(existing);
    }

    let graph = build_graph(seed, input, Digest::of(request.payload.as_bytes()));
    ledger.materialize_graph(&graph, now)?;
    ledger.set_command_phase(&key, CommandPhase::Applied, Some(mission_id.as_str()))?;

    if ledger.get_graph(&mission_id)?.is_some() {
        ledger.set_command_phase(&key, CommandPhase::Verified, None)?;
    } else {
        ledger.set_command_phase(&key, CommandPhase::Unknown, None)?;
        return Err(LedgerError::Store(
            "materialized graph failed read-back".into(),
        ));
    }
    Ok(graph)
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

    #[test]
    fn materialization_is_atomic_under_failpoint() {
        let mut ledger = MemoryLedger::new();
        // First write (record_command) succeeds; second (materialize_graph) fails.
        ledger.set_failpoint(1);
        let err = materialize_plan(&mut ledger, "atomic", &plan(), "2026-01-01T00:00:00.000Z")
            .expect_err("failpoint");
        assert!(matches!(err, LedgerError::Store(_)));
        let mission = MissionId::from_seed("atomic");
        assert!(ledger.get_graph(&mission).expect("read").is_none());
        assert!(ledger.ready_rows().expect("ready").is_empty());
        assert!(ledger.list_events().expect("events").is_empty());
        // Replay after the crash succeeds and is idempotent.
        let first = materialize_plan(&mut ledger, "atomic", &plan(), "2026-01-01T00:00:01.000Z")
            .expect("replay");
        let second = materialize_plan(&mut ledger, "atomic", &plan(), "2026-01-01T00:00:02.000Z")
            .expect("idempotent");
        assert_eq!(first.mission.id, second.mission.id);
        assert_eq!(first.plan.canonical_hash, second.plan.canonical_hash);
        assert_eq!(ledger.ready_rows().expect("ready").len(), 1);
    }
}
