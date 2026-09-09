//! Graph Delta command, graph, event, and result form one durable transaction.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{
    graph_digest, materialize_plan, CommandRequest, GraphDelta, GraphOp, Ledger, LedgerError,
    PlanInput, StoredGraph,
};
use bullet_domain::{CommandPhase, DomainError, TaskClass, WorkPackageState};
use std::path::Path;

fn graph_and_delta(path: &Path, seed: &str) -> (SqliteLedger, StoredGraph, GraphDelta) {
    let mut ledger = SqliteLedger::open(path).expect("open");
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "atomic delta".into(),
            objective: "old or new".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("materialize");
    let delta = GraphDelta {
        parent: graph_digest(&graph),
        ops: vec![GraphOp::SetPackageState {
            id: graph.packages[0].id.clone(),
            from: WorkPackageState::Ready,
            to: WorkPackageState::Leased,
        }],
    };
    (ledger, graph, delta)
}

#[test]
fn sqlite_failure_boundaries_recover_to_exactly_old_or_new() {
    for fail_after in 0..=5 {
        let dir = support::private_tempdir();
        let path = dir.path().join("delta.sqlite");
        let (mut ledger, before, delta) = graph_and_delta(&path, "sqlite-delta-failpoint");
        let before_json = serde_json::to_string(&before).expect("graph json");
        let events_before = ledger.list_events().expect("events");
        let key = format!("delta:{}", delta.digest().expect("digest").to_hex());
        ledger.set_graph_delta_failpoint(fail_after);

        let error = bullet_application::apply_graph_delta(&mut ledger, &before.mission.id, &delta)
            .expect_err("injected failure");
        assert_eq!(error.reason_code(), "STORE_FAILURE");
        drop(ledger);

        let mut recovered = SqliteLedger::open(&path).expect("reopen");
        let after = recovered
            .get_graph(&before.mission.id)
            .expect("graph")
            .expect("stored");
        let events_after = recovered.list_events().expect("events");
        let command = recovered.get_command(&key).expect("command");
        if fail_after < 5 {
            assert_eq!(
                serde_json::to_string(&after).expect("graph json"),
                before_json
            );
            assert_eq!(events_after, events_before);
            assert!(command.is_none());
        } else {
            assert_eq!(after.packages[0].state, WorkPackageState::Leased);
            assert_eq!(events_after.len(), events_before.len() + 1);
            assert_eq!(
                command.expect("stored command").phase,
                CommandPhase::Applied
            );
        }

        let final_graph =
            bullet_application::apply_graph_delta(&mut recovered, &before.mission.id, &delta)
                .expect("replay recovery");
        assert_eq!(final_graph.packages[0].state, WorkPackageState::Leased);
        assert_eq!(
            recovered.list_events().expect("events").len(),
            events_before.len() + 1,
            "failpoint {fail_after} duplicated the graph event"
        );
        assert_eq!(
            recovered
                .get_command(&key)
                .expect("command")
                .expect("stored command")
                .phase,
            CommandPhase::Applied
        );
    }
}

#[test]
fn sqlite_refusal_and_conflicting_request_are_durable_and_inert() {
    let dir = support::private_tempdir();
    let path = dir.path().join("delta.sqlite");
    let (mut ledger, graph, delta) = graph_and_delta(&path, "sqlite-delta-conflict");
    let request =
        CommandRequest::new("manual-delta-key", "apply_graph_delta", &delta).expect("request");
    ledger
        .apply_graph_delta_command(&request, &graph.mission.id, &delta)
        .expect("first apply");
    let applied_graph = ledger
        .get_graph(&graph.mission.id)
        .expect("graph")
        .expect("stored");
    let applied_json = serde_json::to_string(&applied_graph).expect("graph json");
    let events_after_apply = ledger.list_events().expect("events");

    let conflicting = GraphDelta {
        parent: delta.parent,
        ops: Vec::new(),
    };
    let conflicting_request =
        CommandRequest::new("manual-delta-key", "apply_graph_delta", &conflicting)
            .expect("request");
    let error = ledger
        .apply_graph_delta_command(&conflicting_request, &graph.mission.id, &conflicting)
        .expect_err("idempotency conflict");
    assert!(matches!(
        error,
        LedgerError::Domain(DomainError::Idempotency(_))
    ));
    assert_eq!(ledger.list_events().expect("events"), events_after_apply);
    assert_eq!(
        serde_json::to_string(
            &ledger
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored")
        )
        .expect("graph json"),
        applied_json
    );

    let refused = GraphDelta {
        parent: graph_digest(&graph),
        ops: vec![GraphOp::SetPackageState {
            id: graph.packages[0].id.clone(),
            from: WorkPackageState::Ready,
            to: WorkPackageState::Rejected,
        }],
    };
    let refused_key = format!("delta:{}", refused.digest().expect("digest").to_hex());
    let refused_error =
        bullet_application::apply_graph_delta(&mut ledger, &graph.mission.id, &refused)
            .expect_err("stale parent");
    assert!(matches!(
        refused_error,
        LedgerError::Domain(DomainError::Conflict(_))
    ));
    let failed = ledger
        .get_command(&refused_key)
        .expect("command")
        .expect("failed command");
    assert_eq!(failed.phase, CommandPhase::Failed);
    assert!(failed.response.is_some());
    let replay_error =
        bullet_application::apply_graph_delta(&mut ledger, &graph.mission.id, &refused)
            .expect_err("failed replay");
    assert_eq!(replay_error.reason_code(), refused_error.reason_code());
    assert_eq!(ledger.list_events().expect("events"), events_after_apply);
}
