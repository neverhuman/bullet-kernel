mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::store::ProjectionReader;
use bullet_application::{materialize_plan, LeaseService, Ledger, PlanInput};
use bullet_domain::{AttemptId, DomainError, TaskClass};
use rusqlite::{params, Connection};

const AT: &str = "2026-01-01T00:00:00.000Z";

fn plan(packages: usize) -> PlanInput {
    PlanInput {
        title: "durable context".into(),
        objective: "bind exact initial context before a writer fence".into(),
        packages: (0..packages)
            .map(|index| (format!("package-{index}"), TaskClass::FeatureImplementation))
            .collect(),
    }
}

#[test]
fn sqlite_context_revision_is_authority_before_fence_allocation() {
    for revision in [0, 2] {
        let directory = support::private_tempdir();
        let path = directory.path().join("context.sqlite3");
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let seed = format!("revision-{revision}");
        let graph = materialize_plan(&mut ledger, &seed, &plan(1), AT).expect("materialize");
        let capsules = ledger.list_context_capsules().expect("capsules");
        assert_eq!(capsules.len(), 1);
        capsules[0].validate().expect("valid capsule");

        let attempt_seed = format!("attempt-{revision}");
        let mut request = LeaseService::request_for(&graph, 0, &attempt_seed, 15).expect("request");
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
            .expect("graph")
            .expect("stored");
        assert_eq!(stored.variants[0].fence_counter, 0);
        assert!(ledger
            .get_lease(&graph.variants[0].id)
            .expect("lease")
            .is_none());
        assert!(ledger
            .get_attempt(&AttemptId::from_seed(&attempt_seed))
            .expect("attempt")
            .is_none());
        assert!(ledger.outbox_all().expect("outbox").is_empty());
        assert_eq!(ledger.list_events().expect("events").len(), 1);
    }
}

#[test]
fn missing_corrupt_and_cross_package_capsules_fail_closed_without_repair() {
    for mutation in ["missing", "digest", "cross-package"] {
        let directory = support::private_tempdir();
        let path = directory.path().join("hostile-context.sqlite3");
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let graph = materialize_plan(&mut ledger, mutation, &plan(2), AT).expect("materialize");
        drop(ledger);

        let raw = Connection::open(&path).expect("raw open");
        match mutation {
            "missing" => {
                raw.execute(
                    "DELETE FROM context_capsules WHERE work_package_id = ?1",
                    params![graph.packages[0].id.as_str()],
                )
                .expect("delete capsule");
            }
            "digest" => {
                raw.execute(
                    "UPDATE context_capsules SET content_digest = ?1 WHERE work_package_id = ?2",
                    params!["a".repeat(64), graph.packages[0].id.as_str()],
                )
                .expect("mutate digest");
            }
            "cross-package" => {
                raw.execute(
                    "DELETE FROM context_capsules WHERE work_package_id = ?1",
                    params![graph.packages[1].id.as_str()],
                )
                .expect("remove target row");
                raw.execute(
                    "UPDATE context_capsules SET work_package_id = ?1 WHERE work_package_id = ?2",
                    params![graph.packages[1].id.as_str(), graph.packages[0].id.as_str()],
                )
                .expect("cross-package row");
            }
            _ => unreachable!(),
        }
        drop(raw);

        let mut reopened = SqliteLedger::open(&path).expect("schema remains recognizable");
        assert!(reopened.list_context_capsules().is_err());
        let request = LeaseService::request_for(&graph, 0, "hostile-attempt", 15).expect("request");
        assert!(reopened.acquire_lease(&request).is_err());
        assert_eq!(
            reopened
                .get_graph(&graph.mission.id)
                .expect("graph")
                .expect("stored")
                .variants[0]
                .fence_counter,
            0
        );
        assert!(reopened.outbox_all().expect("outbox").is_empty());
        assert_eq!(reopened.list_events().expect("events").len(), 1);

        let replay = materialize_plan(&mut reopened, mutation, &plan(2), AT);
        assert!(
            replay.is_err(),
            "replay must not silently repair {mutation}"
        );
    }
}

#[test]
fn exact_lease_replay_rechecks_immutable_context_truth() {
    let directory = support::private_tempdir();
    let path = directory.path().join("replay-context.sqlite3");
    let (graph, request) = {
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let graph = materialize_plan(&mut ledger, "replay", &plan(1), AT).expect("materialize");
        let request = LeaseService::request_for(&graph, 0, "replay-attempt", 15).expect("request");
        ledger.acquire_lease(&request).expect("first lease");
        (graph, request)
    };
    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE context_capsules SET objective = 'substituted' WHERE work_package_id = ?1",
            params![graph.packages[0].id.as_str()],
        )
        .expect("substitute context");
    let mut reopened = SqliteLedger::open(&path).expect("schema remains recognizable");
    assert!(reopened.acquire_lease(&request).is_err());
    assert_eq!(reopened.outbox_all().expect("outbox").len(), 1);
}

#[test]
fn replay_refuses_a_valid_capsule_from_another_graph() {
    let directory = support::private_tempdir();
    let path = directory.path().join("foreign-replay.sqlite3");
    let (first, second, request, mut grant, outbox_len) = {
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let first =
            materialize_plan(&mut ledger, "first-replay", &plan(1), AT).expect("first graph");
        let second =
            materialize_plan(&mut ledger, "second-replay", &plan(1), AT).expect("second graph");
        let request = LeaseService::request_for(&first, 0, "foreign-package", 15).expect("request");
        let grant = ledger.acquire_lease(&request).expect("first lease");
        let outbox_len = ledger.outbox_all().expect("outbox").len();
        (first, second, request, grant, outbox_len)
    };
    grant.attempt.work_package_id = second.packages[0].id.clone();
    let response = serde_json::to_string(&grant).expect("grant json");
    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE commands SET response_json = ?1 WHERE idempotency_key = ?2",
            params![response, request.idempotency_key],
        )
        .expect("substitute replay subject");

    let mut reopened = SqliteLedger::open(&path).expect("reopen");
    let replay = reopened
        .acquire_lease(&request)
        .expect_err("foreign replay package must fail closed");
    assert!(matches!(
        replay,
        bullet_application::LedgerError::Domain(DomainError::StaleAuthority(_))
    ));
    assert_eq!(reopened.outbox_all().expect("outbox").len(), outbox_len);
    assert_eq!(
        reopened
            .get_graph(&first.mission.id)
            .expect("graph")
            .expect("first")
            .variants[0]
            .fence_counter,
        1
    );
    assert_eq!(
        reopened
            .get_graph(&second.mission.id)
            .expect("graph")
            .expect("second")
            .variants[0]
            .fence_counter,
        0
    );
}
