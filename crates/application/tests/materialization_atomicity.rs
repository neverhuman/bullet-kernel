use bullet_application::store::ProjectionReader;
use bullet_application::{
    materialize_plan, LeaseService, Ledger, MemoryLedger, PlanInput, StoredGraph,
};
use bullet_domain::{CommandPhase, DomainError, MissionId, TaskClass};

const AT: &str = "2026-01-01T00:00:00.000Z";

fn plan() -> PlanInput {
    PlanInput {
        title: "atomic materialization".into(),
        objective: "old or complete next".into(),
        packages: vec![("package".into(), TaskClass::BoundedBugFix)],
    }
}

fn graph_json(graph: &StoredGraph) -> String {
    serde_json::to_string(graph).expect("graph json")
}

#[test]
fn every_memory_failure_boundary_is_exactly_old_or_complete_next() {
    for fail_after in 0..=8 {
        let seed = format!("memory-materialize-{fail_after}");
        let key = format!("materialize:{seed}");
        let mission = MissionId::from_seed(&seed);
        let mut ledger = MemoryLedger::new();
        ledger.set_failpoint(fail_after);

        let error = materialize_plan(&mut ledger, &seed, &plan(), AT).expect_err("failpoint");
        assert_eq!(error.reason_code(), "STORE_FAILURE");

        if fail_after < 8 {
            assert!(ledger.get_command(&key).expect("command").is_none());
            assert!(ledger.get_graph(&mission).expect("graph").is_none());
            assert!(ledger.ready_rows().expect("ready").is_empty());
            assert!(ledger.list_events().expect("events").is_empty());
            assert!(ledger.list_context_capsules().expect("contexts").is_empty());
        } else {
            let command = ledger
                .get_command(&key)
                .expect("command")
                .expect("stored command");
            assert_eq!(command.phase, CommandPhase::Applied);
            assert!(command.response.is_some());
            assert!(ledger.get_graph(&mission).expect("graph").is_some());
            assert_eq!(ledger.ready_rows().expect("ready").len(), 1);
            assert_eq!(ledger.list_events().expect("events").len(), 1);
            assert_eq!(ledger.list_context_capsules().expect("contexts").len(), 1);
        }

        let recovered = materialize_plan(&mut ledger, &seed, &plan(), AT).expect("recover");
        let before_replay = graph_json(&recovered);
        let events_before = ledger.list_events().expect("events");
        let replay = materialize_plan(&mut ledger, &seed, &plan(), AT).expect("replay");
        assert_eq!(graph_json(&replay), before_replay);
        assert_eq!(ledger.list_events().expect("events"), events_before);

        let (attempt, _, _) = LeaseService::acquire(&mut ledger, &recovered, 0, &seed, 15)
            .expect("first lease after recovery");
        assert_eq!(attempt.fence, 1, "failpoint {fail_after} leaked a fence");
    }
}

#[test]
fn memory_conflict_and_corrupt_result_are_inert() {
    let mut ledger = MemoryLedger::new();
    let seed = "memory-materialize-corrupt";
    let key = format!("materialize:{seed}");
    let graph = materialize_plan(&mut ledger, seed, &plan(), AT).expect("materialize");
    let graph_before = graph_json(&graph);
    let events_before = ledger.list_events().expect("events");

    let mut changed = plan();
    changed.objective = "different".into();
    let conflict = materialize_plan(&mut ledger, seed, &changed, AT).expect_err("conflict");
    assert!(matches!(
        conflict,
        bullet_application::LedgerError::Domain(DomainError::Idempotency(_))
    ));
    assert_eq!(
        graph_json(
            &ledger
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored")
        ),
        graph_before
    );
    assert_eq!(ledger.list_events().expect("events"), events_before);

    let command = ledger
        .get_command(&key)
        .expect("command")
        .expect("stored command");
    let mut corrupt: serde_json::Value =
        serde_json::from_str(command.response.as_deref().expect("response")).expect("json");
    corrupt["graph"]["mission"]
        .as_object_mut()
        .expect("mission object")
        .insert("unexpected".into(), true.into());
    ledger
        .set_command_phase(
            &key,
            CommandPhase::Applied,
            Some(&serde_json::to_string(&corrupt).expect("encode")),
        )
        .expect("corrupt fixture");
    let error = materialize_plan(&mut ledger, seed, &plan(), AT).expect_err("fail closed");
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert_eq!(
        graph_json(
            &ledger
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored")
        ),
        graph_before
    );
    assert_eq!(ledger.list_events().expect("events"), events_before);
}
