//! Shared ledger conformance and the cross-connection lease race.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::conformance::check_all;
use bullet_application::{materialize_plan, LeaseService, Ledger, PlanInput};
use bullet_domain::TaskClass;
use chrono::{DateTime, Duration, Utc};
use std::sync::{Arc, Barrier};
use std::thread;

fn t(offset: i64) -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_795_000_000 + offset)
}

#[test]
fn sqlite_ledger_passes_shared_conformance() {
    let dir = support::private_tempdir();
    let mut n = 0u32;
    check_all(|| {
        n += 1;
        SqliteLedger::open(dir.path().join(format!("conf-{n}.sqlite"))).expect("open")
    })
    .expect("sqlite ledger conformance");
}

#[test]
fn two_connections_racing_one_variant_grant_exactly_once() {
    let dir = support::private_tempdir();
    let path = dir.path().join("race.sqlite");
    let graph = {
        let mut ledger = SqliteLedger::open(&path).expect("open");
        materialize_plan(
            &mut ledger,
            "race",
            &PlanInput {
                title: "race".into(),
                objective: "one writer".into(),
                packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
            },
            &LeaseService::rfc3339(t(0)),
        )
        .expect("plan")
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for seed in ["race-a", "race-b"] {
        let path = path.clone();
        let graph = graph.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut ledger = SqliteLedger::open(&path).expect("open");
            barrier.wait();
            LeaseService::acquire(&mut ledger, &graph, 0, seed, 15)
                .map(|(attempt, _token, _grant)| attempt.fence)
                .map_err(|err| err.to_string())
        }));
    }
    let results: Vec<Result<u64, String>> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    let winners: Vec<&u64> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one connection must win the lease; got {results:?}"
    );
    assert_eq!(*winners[0], 1);
    let ledger = SqliteLedger::open(&path).expect("verify");
    let attempts = ledger.list_attempts(&graph.mission.id).expect("attempts");
    assert_eq!(attempts.len(), 1, "loser must not create an attempt row");
    assert_eq!(attempts[0].fence, 1);
    let lease = ledger
        .get_lease(&graph.variants[0].id)
        .expect("lease read")
        .expect("lease");
    assert_eq!(lease.attempt_id, attempts[0].id);
}
