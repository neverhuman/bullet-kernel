//! Context Capsule parity helpers for the in-memory ledger.

use super::MemoryLedger;
use crate::{
    initial_context_capsules, validate_initial_context_set, ContextCapsule, LedgerError,
    StoredGraph,
};
use bullet_domain::WorkPackageId;

impl MemoryLedger {
    pub(super) fn insert_initial_contexts(
        &mut self,
        graph: &StoredGraph,
        recorded_at: &str,
    ) -> Result<(), LedgerError> {
        let capsules = initial_context_capsules(graph, recorded_at)?;
        for capsule in capsules {
            if self
                .context_capsules
                .insert(capsule.work_package_id.to_string(), capsule)
                .is_some()
            {
                return Err(LedgerError::Store(
                    "context capsule already exists for work package".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn require_initial_contexts(&self, graph: &StoredGraph) -> Result<(), LedgerError> {
        let capsules = self.contexts_for_mission(graph.mission.id.as_str());
        validate_initial_context_set(graph, &capsules)
    }

    pub(super) fn validate_all_initial_contexts(&self) -> Result<(), LedgerError> {
        let mut expected_rows = 0usize;
        for graph in self.graphs.values() {
            self.require_initial_contexts(graph)?;
            expected_rows = expected_rows
                .checked_add(graph.packages.len())
                .ok_or_else(|| LedgerError::Store("context capsule row count overflow".into()))?;
        }
        if expected_rows != self.context_capsules.len() {
            return Err(LedgerError::Store(
                "context capsule rows exist outside a materialized graph".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn require_context_revision(
        &self,
        graph: &StoredGraph,
        package: &WorkPackageId,
        revision: u64,
    ) -> Result<(), LedgerError> {
        self.require_initial_contexts(graph)?;
        if !graph
            .packages
            .iter()
            .any(|candidate| candidate.id == *package)
        {
            return Err(bullet_domain::DomainError::StaleAuthority(format!(
                "context package {package} is not owned by graph {}",
                graph.mission.id
            ))
            .into());
        }
        if revision != 1 {
            return Err(bullet_domain::DomainError::StaleAuthority(format!(
                "context revision {revision} is not the current revision 1 for {package}"
            ))
            .into());
        }
        Ok(())
    }

    pub(super) fn contexts_for_mission(&self, mission: &str) -> Vec<ContextCapsule> {
        self.context_capsules
            .values()
            .filter(|capsule| capsule.mission_id.as_str() == mission)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ProjectionReader;
    use crate::{materialize_plan, LeaseGrant, LeaseService, Ledger, PlanInput};
    use bullet_domain::{DomainError, TaskClass};

    #[test]
    fn projection_refuses_a_missing_capsule() {
        let mut ledger = MemoryLedger::new();
        let graph = materialize_plan(
            &mut ledger,
            "missing-context",
            &PlanInput {
                title: "context".into(),
                objective: "detect row loss".into(),
                packages: vec![("package".into(), TaskClass::SecurityAnalysis)],
            },
            "2026-01-01T00:00:00.000Z",
        )
        .expect("materialize");
        ledger
            .context_capsules
            .remove(graph.packages[0].id.as_str());

        let error = ledger
            .list_context_capsules()
            .expect_err("missing capsule must fail closed");
        assert!(matches!(error, LedgerError::Store(_)));
    }

    #[test]
    fn foreign_graph_package_never_satisfies_context_or_replay() {
        let mut ledger = MemoryLedger::new();
        let first = materialize_plan(
            &mut ledger,
            "first-context",
            &PlanInput {
                title: "first".into(),
                objective: "bind first graph".into(),
                packages: vec![("first-package".into(), TaskClass::SecurityAnalysis)],
            },
            "2026-01-01T00:00:00.000Z",
        )
        .expect("first graph");
        let second = materialize_plan(
            &mut ledger,
            "second-context",
            &PlanInput {
                title: "second".into(),
                objective: "bind second graph".into(),
                packages: vec![("second-package".into(), TaskClass::SecurityAnalysis)],
            },
            "2026-01-01T00:00:00.000Z",
        )
        .expect("second graph");

        let direct = ledger
            .require_context_revision(&first, &second.packages[0].id, 1)
            .expect_err("foreign package must not satisfy first graph");
        assert!(matches!(
            direct,
            LedgerError::Domain(DomainError::StaleAuthority(_))
        ));

        let request =
            LeaseService::request_for(&first, 0, "foreign-replay", 15).expect("lease request");
        let mut grant = ledger.acquire_lease(&request).expect("first lease");
        let outbox_len = ledger.outbox_all().expect("outbox").len();
        grant.attempt.work_package_id = second.packages[0].id.clone();
        let response = serde_json::to_string::<LeaseGrant>(&grant).expect("grant json");
        ledger
            .commands
            .get_mut(&request.idempotency_key)
            .expect("stored command")
            .response = Some(response);

        let replay = ledger
            .acquire_lease(&request)
            .expect_err("foreign replay package must fail closed");
        assert!(matches!(
            replay,
            LedgerError::Domain(DomainError::StaleAuthority(_))
        ));
        assert_eq!(ledger.outbox_all().expect("outbox").len(), outbox_len);
    }
}
