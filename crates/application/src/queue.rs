//! Ready queue. A package is ready only when its push-maintained row says so.

use crate::leases::LeaseService;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{Attempt, AttemptId, AuthorityToken, MissionId, WorkPackage};
use serde::{Deserialize, Serialize};

/// One dispatchable package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyItem {
    /// Mission.
    pub mission_id: MissionId,
    /// Package.
    pub package: WorkPackage,
}

/// Packages with a live ready row, joined to their mission graphs.
///
/// # Errors
///
/// Returns a store error when a graph cannot be loaded.
pub fn ready_queue<L: Ledger>(ledger: &L) -> Result<Vec<ReadyItem>, LedgerError> {
    let rows = ledger.ready_rows()?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut graphs: Vec<StoredGraph> = Vec::new();
    for mission in ledger.list_missions()? {
        if let Some(graph) = ledger.get_graph(&mission.id)? {
            graphs.push(graph);
        }
    }
    let mut out = Vec::new();
    for row in rows {
        for graph in &graphs {
            if let Some(package) = graph
                .packages
                .iter()
                .find(|package| package.id == row.work_package_id)
            {
                out.push(ReadyItem {
                    mission_id: graph.mission.id.clone(),
                    package: package.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// Claim the first ready package through the single-transaction lease
/// acquisition. Same seed is idempotent.
///
/// # Errors
///
/// Returns a ledger or domain error.
pub fn claim_ready<L: Ledger>(
    ledger: &mut L,
    seed: &str,
) -> Result<Option<(Attempt, AuthorityToken)>, LedgerError> {
    let attempt_id = AttemptId::from_seed(seed);
    if let Some(existing) = ledger.get_attempt(&attempt_id)? {
        let token = reconstruct_token(ledger, &existing)?;
        return Ok(Some((existing, token)));
    }
    let Some(item) = ready_queue(ledger)?.into_iter().next() else {
        return Ok(None);
    };
    let graph = ledger
        .get_graph(&item.mission_id)?
        .ok_or_else(|| LedgerError::Store("graph missing".into()))?;
    let variant_index = graph
        .variants
        .iter()
        .position(|variant| variant.work_package_id == item.package.id)
        .ok_or_else(|| LedgerError::Store("variant missing".into()))?;
    let (attempt, token, _grant) = LeaseService::acquire(ledger, &graph, variant_index, seed, 15)?;
    Ok(Some((attempt, token)))
}

fn reconstruct_token<L: Ledger>(
    ledger: &L,
    attempt: &Attempt,
) -> Result<AuthorityToken, LedgerError> {
    for mission in ledger.list_missions()? {
        if let Some(graph) = ledger.get_graph(&mission.id)? {
            if graph
                .variants
                .iter()
                .any(|variant| variant.id == attempt.variant_id)
            {
                return LeaseService::token_for(&graph, attempt);
            }
        }
    }
    Err(LedgerError::Store("attempt graph missing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::{materialize_plan, PlanInput};
    use crate::memory::MemoryLedger;
    use bullet_domain::TaskClass;

    #[test]
    fn ready_then_claim_is_idempotent() {
        let mut ledger = MemoryLedger::new();
        materialize_plan(
            &mut ledger,
            "q",
            &PlanInput {
                title: "t".into(),
                objective: "o".into(),
                packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
            },
            "2026-01-01T00:00:00.000Z",
        )
        .expect("plan");
        assert_eq!(ready_queue(&ledger).expect("q").len(), 1);
        let first = claim_ready(&mut ledger, "claim-1")
            .expect("claim")
            .expect("item");
        assert!(ready_queue(&ledger).expect("q").is_empty());
        let second = claim_ready(&mut ledger, "claim-1")
            .expect("replay")
            .expect("item");
        assert_eq!(first.0.id, second.0.id);
        assert_eq!(first.0.fence, second.0.fence);
        assert_eq!(first.1.attempt_fence, second.1.attempt_fence);
    }
}
