use super::*;
use crate::memory::MemoryLedger;
use bullet_domain::{DomainError, TaskClass};

const AT: &str = "2026-01-01T00:00:00.000Z";

fn input() -> PlanInput {
    PlanInput {
        title: "synthetic selection".into(),
        objective: "exercise two isolated component lanes".into(),
        packages: vec![("one".into(), TaskClass::BoundedBugFix)],
    }
}

#[test]
fn exact_replay_has_one_package_and_two_stable_sorted_variants() {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_synthetic_selection(&mut ledger, "pair", &input(), AT).unwrap();
    let replay = materialize_synthetic_selection(&mut ledger, "pair", &input(), AT).unwrap();
    assert_eq!(
        serde_json::to_string(&graph).unwrap(),
        serde_json::to_string(&replay).unwrap()
    );
    assert_eq!(graph.packages.len(), 1);
    assert_eq!(graph.variants.len(), 2);
    assert_ne!(graph.variants[0].id, graph.variants[1].id);
    assert!(graph.variants[0].id.as_str() < graph.variants[1].id.as_str());
    assert_eq!(
        graph.variants[0].selection_group_id,
        graph.variants[1].selection_group_id
    );
    for variant in &graph.variants {
        assert_eq!(variant.work_package_id, graph.packages[0].id);
        assert_eq!(variant.fence_counter, 0);
    }
}

#[test]
fn changed_body_conflicts_and_non_single_package_input_refuses() {
    let mut ledger = MemoryLedger::new();
    materialize_synthetic_selection(&mut ledger, "conflict", &input(), AT).unwrap();
    let mut changed = input();
    changed.objective = "changed".into();
    let error = materialize_synthetic_selection(&mut ledger, "conflict", &changed, AT)
        .expect_err("same key and changed body");
    assert!(matches!(
        error,
        LedgerError::Domain(DomainError::Idempotency(_))
    ));

    let two = vec![
        ("one".into(), TaskClass::BoundedBugFix),
        ("two".into(), TaskClass::CodeReview),
    ];
    for packages in [Vec::new(), two] {
        let mut invalid = input();
        invalid.packages = packages;
        let error =
            materialize_synthetic_selection(&mut MemoryLedger::new(), "shape", &invalid, AT)
                .expect_err("exactly one package");
        assert_eq!(error.reason_code(), "GRAPH_CONFLICT");
    }
}
