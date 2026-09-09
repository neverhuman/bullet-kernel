use bullet_application::store::ProjectionReader;
use bullet_application::{materialize_plan, LeaseService, Ledger, MemoryLedger, PlanInput};
use bullet_domain::{DomainError, TaskClass};

const AT: &str = "2026-01-01T00:00:00.000Z";

fn plan() -> PlanInput {
    PlanInput {
        title: "durable context".into(),
        objective: "bind the exact initial task context".into(),
        packages: vec![("package".into(), TaskClass::SecurityAnalysis)],
    }
}

#[test]
fn memory_materialization_persists_exact_initial_context() {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(&mut ledger, "context", &plan(), AT).expect("materialize");
    let capsules = ledger.list_context_capsules().expect("capsules");
    assert_eq!(capsules.len(), 1);
    let capsule = &capsules[0];
    assert_eq!(capsule.mission_id, graph.mission.id);
    assert_eq!(capsule.work_package_id, graph.packages[0].id);
    assert_eq!(capsule.plan_revision_id, graph.plan.id);
    assert_eq!(capsule.revision, 1);
    assert_eq!(capsule.task_class, TaskClass::SecurityAnalysis);
    assert_eq!(capsule.objective, graph.mission.objective);
    assert_eq!(capsule.package_title, graph.packages[0].title);
    capsule.validate().expect("valid capsule");

    let replay = materialize_plan(&mut ledger, "context", &plan(), AT).expect("replay");
    assert_eq!(replay.mission.id, graph.mission.id);
    assert_eq!(
        ledger.list_context_capsules().expect("replay rows"),
        capsules
    );
}

#[test]
fn memory_lease_refuses_stale_or_future_context_before_authority_writes() {
    for revision in [0, 2] {
        let mut ledger = MemoryLedger::new();
        let graph = materialize_plan(&mut ledger, &format!("revision-{revision}"), &plan(), AT)
            .expect("materialize");
        let mut request = LeaseService::request_for(&graph, 0, &format!("attempt-{revision}"), 15)
            .expect("request");
        request.context_revision = revision;
        let error = ledger
            .acquire_lease(&request)
            .expect_err("revision refused");
        assert!(matches!(
            error,
            bullet_application::LedgerError::Domain(DomainError::StaleAuthority(_))
        ));
        let stored = ledger
            .get_graph(&graph.mission.id)
            .expect("graph read")
            .expect("graph");
        assert_eq!(stored.variants[0].fence_counter, 0);
        assert!(ledger
            .get_lease(&graph.variants[0].id)
            .expect("lease")
            .is_none());
        assert!(ledger
            .get_attempt(&bullet_domain::AttemptId::from_seed(&format!(
                "attempt-{revision}"
            )))
            .expect("attempt")
            .is_none());
        assert!(ledger.outbox_all().expect("outbox").is_empty());
        assert_eq!(ledger.list_events().expect("events").len(), 1);
    }
}
