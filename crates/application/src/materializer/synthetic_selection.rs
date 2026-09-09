//! Hard-false two-Variant materialization seam for offline dogfood mechanics.

use super::{build_graph, canonical, PlanInput};
use crate::commands::CommandRequest;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{Digest, DomainError, SelectionGroupId, Variant, VariantId};
use serde::Serialize;

const PROTOCOL: &str = "bullet.synthetic-selection.component.v1";

#[derive(Serialize)]
struct CanonicalSyntheticSelection<'a> {
    protocol: &'static str,
    seed: &'a str,
    plan: super::CanonicalPlan<'a>,
    work_package_id: bullet_domain::WorkPackageId,
    selection_group_id: SelectionGroupId,
    variant_ids: [VariantId; 2],
}

/// Materialize one package with exactly two deterministic Variants in one
/// SelectionGroup. This seam exists only in tests and `test-seams` builds.
///
/// # Errors
/// Typed graph, command, or store refusal.
pub fn materialize_synthetic_selection<L: Ledger>(
    ledger: &mut L,
    seed: &str,
    input: &PlanInput,
    now: &str,
) -> Result<StoredGraph, LedgerError> {
    if input.packages.len() != 1 {
        return Err(DomainError::Conflict(
            "synthetic selection requires exactly one work package".into(),
        )
        .into());
    }
    let mut graph = build_graph(seed, input, Digest::of(&[]));
    let package = graph.packages[0].id.clone();
    let group = SelectionGroupId::from_seed(&format!("{seed}:synthetic-selection"));
    let mut variants = [
        VariantId::from_seed(&format!("{seed}:synthetic-selection:0")),
        VariantId::from_seed(&format!("{seed}:synthetic-selection:1")),
    ];
    variants.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let body = CanonicalSyntheticSelection {
        protocol: PROTOCOL,
        seed,
        plan: canonical(seed, input),
        work_package_id: package.clone(),
        selection_group_id: group.clone(),
        variant_ids: variants.clone(),
    };
    let key = format!("materialize-synthetic-selection:{seed}");
    let request = CommandRequest::new(&key, "materialize_synthetic_selection", &body)?;
    graph.plan.canonical_hash = Digest::of(request.payload.as_bytes());
    graph.variants = variants
        .into_iter()
        .map(|id| Variant {
            id,
            selection_group_id: group.clone(),
            work_package_id: package.clone(),
            fence_counter: 0,
        })
        .collect();
    ledger.materialize_plan_command(&request, &graph, now)
}

#[cfg(test)]
mod tests;
