mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::store::ProjectionReader;
use bullet_application::{materialize_plan, LeaseService, Ledger, PlanInput, StoredGraph};
use bullet_domain::{CommandPhase, DomainError, MissionId, TaskClass};
use std::path::Path;

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

fn reopen(path: &Path) -> SqliteLedger {
    SqliteLedger::open(path).expect("reopen")
}

#[test]
fn sqlite_failure_boundaries_reopen_to_exactly_old_or_complete_next() {
    for fail_after in 0..=8 {
        let dir = support::private_tempdir();
        let path = dir.path().join("materialize.sqlite");
        let seed = format!("sqlite-materialize-{fail_after}");
        let key = format!("materialize:{seed}");
        let mission = MissionId::from_seed(&seed);
        let mut ledger = reopen(&path);
        ledger.set_materialization_failpoint(fail_after);

        let error = materialize_plan(&mut ledger, &seed, &plan(), AT).expect_err("failpoint");
        assert_eq!(error.reason_code(), "STORE_FAILURE");
        drop(ledger);

        let mut recovered = reopen(&path);
        if fail_after < 8 {
            assert!(recovered.get_command(&key).expect("command").is_none());
            assert!(recovered.get_graph(&mission).expect("graph").is_none());
            assert!(recovered.ready_rows().expect("ready").is_empty());
            assert!(recovered.list_events().expect("events").is_empty());
            assert!(recovered
                .list_context_capsules()
                .expect("contexts")
                .is_empty());
        } else {
            let command = recovered
                .get_command(&key)
                .expect("command")
                .expect("stored command");
            assert_eq!(command.phase, CommandPhase::Applied);
            assert!(command.response.is_some());
            assert!(recovered.get_graph(&mission).expect("graph").is_some());
            assert_eq!(recovered.ready_rows().expect("ready").len(), 1);
            assert_eq!(recovered.list_events().expect("events").len(), 1);
            assert_eq!(
                recovered.list_context_capsules().expect("contexts").len(),
                1
            );
        }

        let graph = materialize_plan(&mut recovered, &seed, &plan(), AT).expect("recover");
        let before_replay = graph_json(&graph);
        let events_before = recovered.list_events().expect("events");
        drop(recovered);

        let mut replayed = reopen(&path);
        let replay = materialize_plan(&mut replayed, &seed, &plan(), AT).expect("replay");
        assert_eq!(graph_json(&replay), before_replay);
        assert_eq!(replayed.list_events().expect("events"), events_before);

        let (attempt, _, _) = LeaseService::acquire(&mut replayed, &graph, 0, &seed, 15)
            .expect("first lease after recovery");
        assert_eq!(attempt.fence, 1, "failpoint {fail_after} leaked a fence");
    }
}

#[test]
fn sqlite_conflict_and_corrupt_result_survive_reopen_inertly() {
    let dir = support::private_tempdir();
    let path = dir.path().join("materialize.sqlite");
    let seed = "sqlite-materialize-corrupt";
    let key = format!("materialize:{seed}");
    let mut ledger = reopen(&path);
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
    drop(ledger);

    let mut reopened = reopen(&path);
    let error = materialize_plan(&mut reopened, seed, &plan(), AT).expect_err("fail closed");
    assert_eq!(error.reason_code(), "STORE_FAILURE");
    assert_eq!(
        graph_json(
            &reopened
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored")
        ),
        graph_before
    );
    assert_eq!(reopened.list_events().expect("events"), events_before);
}
