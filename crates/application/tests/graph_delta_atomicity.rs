use bullet_application::graph_delta::GraphDeltaCommandResult;
use bullet_application::{
    apply_graph_delta, graph_digest, materialize_plan, CommandRequest, GraphDelta, GraphOp, Ledger,
    LedgerError, MemoryLedger, PlanInput, StoredGraph,
};
use bullet_domain::{CommandPhase, DomainError, TaskClass, WorkPackageState};
use proptest::prelude::*;

fn graph_and_delta(ledger: &mut MemoryLedger, seed: &str) -> (StoredGraph, GraphDelta) {
    let graph = materialize_plan(
        ledger,
        seed,
        &PlanInput {
            title: "d".into(),
            objective: "o".into(),
            packages: vec![("p".into(), TaskClass::BoundedBugFix)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("plan");
    let delta = GraphDelta {
        parent: graph_digest(&graph),
        ops: vec![GraphOp::SetPackageState {
            id: graph.packages[0].id.clone(),
            from: WorkPackageState::Ready,
            to: WorkPackageState::Leased,
        }],
    };
    (graph, delta)
}

#[test]
fn delta_is_atomic_and_idempotent() {
    let mut ledger = MemoryLedger::new();
    let (graph, delta) = graph_and_delta(&mut ledger, "delta-seed");
    let pkg = graph.packages[0].clone();
    let events_before = ledger.list_events().expect("events").len();
    let first = apply_graph_delta(&mut ledger, &graph.mission.id, &delta).expect("apply");
    assert_eq!(first.packages[0].state, WorkPackageState::Leased);
    let second = apply_graph_delta(&mut ledger, &graph.mission.id, &delta).expect("replay");
    assert_eq!(second.packages[0].state, WorkPackageState::Leased);
    assert_eq!(
        ledger.list_events().expect("events").len(),
        events_before + 1
    );
    let key = format!("delta:{}", delta.digest().expect("digest").to_hex());
    let command = ledger
        .get_command(&key)
        .expect("command")
        .expect("stored command");
    assert_eq!(command.phase, CommandPhase::Applied);
    assert!(matches!(
        GraphDeltaCommandResult::decode(command.response.as_deref().expect("result"))
            .expect("decode"),
        GraphDeltaCommandResult::Applied { .. }
    ));

    let stale = GraphDelta {
        parent: graph_digest(&graph),
        ops: vec![GraphOp::SetPackageState {
            id: pkg.id,
            from: WorkPackageState::Ready,
            to: WorkPackageState::Rejected,
        }],
    };
    let err = apply_graph_delta(&mut ledger, &graph.mission.id, &stale).expect_err("conflict");
    assert!(matches!(err, LedgerError::Domain(DomainError::Conflict(_))));
    let stale_key = format!("delta:{}", stale.digest().expect("digest").to_hex());
    let failed = ledger
        .get_command(&stale_key)
        .expect("command")
        .expect("failed command");
    assert_eq!(failed.phase, CommandPhase::Failed);
    assert_eq!(
        ledger.list_events().expect("events").len(),
        events_before + 1
    );
    let replay =
        apply_graph_delta(&mut ledger, &graph.mission.id, &stale).expect_err("failed replay");
    assert_eq!(replay.reason_code(), err.reason_code());
    assert_eq!(
        ledger.list_events().expect("events").len(),
        events_before + 1
    );
}

proptest! {
    #[test]
    fn every_memory_failure_boundary_is_exactly_old_or_new(fail_after in 0u32..=5) {
        let mut ledger = MemoryLedger::new();
        let (before, delta) = graph_and_delta(&mut ledger, "delta-memory-failpoint");
        let before_json = serde_json::to_string(&before).expect("graph json");
        let events_before = ledger.list_events().expect("events");
        let key = format!("delta:{}", delta.digest().expect("digest").to_hex());
        ledger.set_failpoint(fail_after);

        let error = apply_graph_delta(&mut ledger, &before.mission.id, &delta)
            .expect_err("injected failure");
        prop_assert_eq!(error.reason_code(), "STORE_FAILURE");
        let after = ledger.get_graph(&before.mission.id).expect("graph").expect("stored");
        let events_after = ledger.list_events().expect("events");
        let command = ledger.get_command(&key).expect("command");

        if fail_after < 5 {
            prop_assert_eq!(serde_json::to_string(&after).expect("graph json"), before_json);
            prop_assert_eq!(events_after, events_before.clone());
            prop_assert!(command.is_none());
        } else {
            prop_assert_eq!(after.packages[0].state, WorkPackageState::Leased);
            prop_assert_eq!(events_after.len(), events_before.len() + 1);
            prop_assert_eq!(command.expect("command").phase, CommandPhase::Applied);
        }

        let recovered = apply_graph_delta(&mut ledger, &before.mission.id, &delta)
            .expect("idempotent recovery");
        prop_assert_eq!(recovered.packages[0].state, WorkPackageState::Leased);
        prop_assert_eq!(ledger.list_events().expect("events").len(), events_before.len() + 1);
        prop_assert_eq!(
            ledger.get_command(&key).expect("command").expect("stored").phase,
            CommandPhase::Applied
        );
    }
}

#[test]
fn conflicting_request_never_reuses_an_applied_command_key() {
    let mut ledger = MemoryLedger::new();
    let (graph, delta) = graph_and_delta(&mut ledger, "delta-command-conflict");
    let request =
        CommandRequest::new("manual-delta-key", "apply_graph_delta", &delta).expect("request");
    ledger
        .apply_graph_delta_command(&request, &graph.mission.id, &delta)
        .expect("first");
    let conflicting = GraphDelta {
        parent: delta.parent,
        ops: Vec::new(),
    };
    let conflicting_request =
        CommandRequest::new("manual-delta-key", "apply_graph_delta", &conflicting)
            .expect("request");
    let events_before = ledger.list_events().expect("events");
    let graph_before = ledger
        .get_graph(&graph.mission.id)
        .expect("graph")
        .expect("stored");
    let graph_before_json = serde_json::to_string(&graph_before).expect("graph json");
    let error = ledger
        .apply_graph_delta_command(&conflicting_request, &graph.mission.id, &conflicting)
        .expect_err("idempotency conflict");
    assert!(matches!(
        error,
        LedgerError::Domain(DomainError::Idempotency(_))
    ));
    let graph_after = ledger
        .get_graph(&graph.mission.id)
        .expect("graph")
        .expect("stored");
    assert_eq!(
        serde_json::to_string(&graph_after).expect("graph json"),
        graph_before_json
    );
    assert_eq!(ledger.list_events().expect("events"), events_before);
}

#[test]
fn replay_returns_its_exact_result_without_reverting_a_successor() {
    let mut ledger = MemoryLedger::new();
    let (graph, first_delta) = graph_and_delta(&mut ledger, "delta-exact-replay");
    let first = apply_graph_delta(&mut ledger, &graph.mission.id, &first_delta).expect("first");
    let successor_delta = GraphDelta {
        parent: graph_digest(&first),
        ops: vec![GraphOp::SetPackageState {
            id: first.packages[0].id.clone(),
            from: WorkPackageState::Leased,
            to: WorkPackageState::Executing,
        }],
    };
    apply_graph_delta(&mut ledger, &graph.mission.id, &successor_delta).expect("successor");
    let events_before_replay = ledger.list_events().expect("events");

    let replay = apply_graph_delta(&mut ledger, &graph.mission.id, &first_delta).expect("replay");
    assert_eq!(replay.packages[0].state, WorkPackageState::Leased);
    assert_eq!(
        ledger
            .get_graph(&graph.mission.id)
            .expect("graph")
            .expect("stored")
            .packages[0]
            .state,
        WorkPackageState::Executing
    );
    assert_eq!(ledger.list_events().expect("events"), events_before_replay);
}

#[test]
fn stored_result_with_unknown_fields_fails_closed() {
    let nested = GraphDeltaCommandResult::decode(
        r#"{"status":"failed","error":{"kind":"conflict","message":"x","unexpected":true}}"#,
    )
    .expect_err("nested unknown field must fail closed");
    assert_eq!(nested.reason_code(), "STORE_FAILURE");

    let mut ledger = MemoryLedger::new();
    let (graph, delta) = graph_and_delta(&mut ledger, "delta-strict-result");
    apply_graph_delta(&mut ledger, &graph.mission.id, &delta).expect("apply");
    let key = format!("delta:{}", delta.digest().expect("digest").to_hex());
    let command = ledger
        .get_command(&key)
        .expect("command")
        .expect("stored command");
    let mut result: serde_json::Value =
        serde_json::from_str(command.response.as_deref().expect("result")).expect("decode");
    result
        .as_object_mut()
        .expect("object")
        .insert("unexpected".into(), serde_json::Value::Bool(true));
    let corrupt = serde_json::to_string(&result).expect("encode");
    ledger
        .set_command_phase(&key, CommandPhase::Applied, Some(&corrupt))
        .expect("corrupt fixture");
    let graph_before = graph_digest(
        &ledger
            .get_graph(&graph.mission.id)
            .expect("graph")
            .expect("stored"),
    );
    let events_before = ledger.list_events().expect("events");

    let error = apply_graph_delta(&mut ledger, &graph.mission.id, &delta)
        .expect_err("unknown field must fail closed");
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert_eq!(
        graph_digest(
            &ledger
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored")
        ),
        graph_before
    );
    assert_eq!(ledger.list_events().expect("events"), events_before);
}
