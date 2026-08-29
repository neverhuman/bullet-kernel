//! The expiry reaper has a production caller. A runner that dies without
//! releasing leaves a holder row, and `acquire_lease` refuses every successor
//! while that row exists; these tests prove the crashed incarnation is reclaimed
//! exactly once, on the acquisition path itself and through the named
//! `LeaseService::expire_due` entry point, and that a live lease is untouched.
//!
//! Raw SQL places an exact expired window without sleeping, exactly as
//! `chaos.rs` and `lease_clock.rs` already do.

use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, ExpiredLease, LeaseGrant, LeaseService, Ledger, PlanInput, StoredGraph,
};
use bullet_domain::{AttemptState, TaskClass};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

mod support;

const MATERIALIZED_AT: &str = "2026-01-01T00:00:00.000Z";
const TTL_SECONDS: i64 = 5;

fn plan() -> PlanInput {
    PlanInput {
        title: "reaper".into(),
        objective: "reclaim a dead writer".into(),
        packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
    }
}

/// One materialized graph plus one lease held by a runner that is about to die.
fn crashed_writer(path: &Path, seed: &str) -> (StoredGraph, LeaseGrant) {
    let mut ledger = SqliteLedger::open(path).expect("open");
    let graph = materialize_plan(&mut ledger, seed, &plan(), MATERIALIZED_AT).expect("plan");
    let (_attempt, _token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, seed, TTL_SECONDS).expect("lease");
    (graph, grant)
    // The connection drops here without releasing: a killed process.
}

/// Place the persisted window entirely in the past. The stored TTL is unchanged,
/// so the window still satisfies the adapter's exact `expiry - heartbeat == ttl`
/// validation and nothing is being weakened.
fn force_expired(path: &Path) {
    Connection::open(path)
        .expect("raw open")
        .execute(
            "UPDATE active_leases
             SET heartbeat_at = '2000-01-01T00:00:00.000Z',
                 expires_at = '2000-01-01T00:00:05.000Z'",
            [],
        )
        .expect("set exact expired test window");
}

fn count_kind(ledger: &SqliteLedger, kind: &str) -> usize {
    ledger
        .list_events()
        .expect("events")
        .iter()
        .filter(|event| event.kind == kind)
        .count()
}

fn reclaim_outbox(ledger: &SqliteLedger) -> Vec<ExpiredLease> {
    ledger
        .outbox_all()
        .expect("outbox")
        .iter()
        .filter(|item| item.kind == "lease_reclaimed")
        .map(|item| serde_json::from_str(&item.payload).expect("reclaim payload"))
        .collect()
}

#[test]
fn two_concurrent_acquirers_reclaim_a_dead_lease_exactly_once() {
    let dir = support::private_tempdir();
    let path = dir.path().join("race.sqlite");
    let (graph, grant) = crashed_writer(&path, "race");
    let dead = grant.attempt.clone();
    force_expired(&path);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for seed in ["successor-a", "successor-b"] {
        let path = path.clone();
        let graph = graph.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut ledger = SqliteLedger::open(path).expect("open");
            barrier.wait();
            LeaseService::acquire(&mut ledger, &graph, 0, seed, 15).map(|(attempt, _, _)| attempt)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("join"))
        .collect();

    let winners: Vec<_> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one acquirer may hold the variant"
    );
    let refusals: Vec<_> = results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .collect();
    assert_eq!(refusals.len(), 1);
    // The live successor left the package `Leased`, so the loser is refused by
    // the package-state gate that runs before the holder check — never by a
    // store failure and never by reclaiming a lease that is now live.
    assert_eq!(
        refusals[0].reason_code(),
        "GRAPH_CONFLICT",
        "the loser is refused by live authority, not by a store failure"
    );

    let ledger = SqliteLedger::open(&path).expect("verify");
    assert_eq!(
        count_kind(&ledger, "lease_expired"),
        1,
        "the dead lease is reclaimed exactly once under two concurrent acquirers"
    );
    let reclaimed = reclaim_outbox(&ledger);
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempt_id, dead.id);
    assert_eq!(reclaimed[0].fence, dead.fence);
    assert_eq!(reclaimed[0].work_package_id, dead.work_package_id);
    assert_eq!(
        winners[0].fence,
        dead.fence + 1,
        "the successor's fence is strictly greater and the dead fence is never reused"
    );
}

#[test]
fn the_dead_attempt_reaches_its_terminal_state_and_the_event_is_persisted() {
    let dir = support::private_tempdir();
    let path = dir.path().join("terminal.sqlite");
    let (graph, grant) = crashed_writer(&path, "terminal");
    let dead = grant.attempt.clone();
    force_expired(&path);

    let mut ledger = SqliteLedger::open(&path).expect("recover");
    let (successor, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "terminal-b", 15).expect("successor");

    let crashed = ledger
        .get_attempt(&dead.id)
        .expect("read")
        .expect("dead attempt");
    assert_eq!(crashed.state, AttemptState::Crashed);
    assert!(successor.fence > dead.fence);
    let event = ledger
        .list_events()
        .expect("events")
        .into_iter()
        .find(|event| event.kind == "lease_expired")
        .expect("durable lease_expired event");
    assert_eq!(event.body, dead.id.as_str());
    assert_eq!(event.stream_id, Some(dead.variant_id.to_string()));
    assert_eq!(reclaim_outbox(&ledger).len(), 1);
    // The dead incarnation's heartbeat stays refused forever.
    assert_eq!(
        ledger
            .heartbeat(&LeaseService::heartbeat_of(&grant))
            .expect_err("no revival")
            .reason_code(),
        "STALE_AUTHORITY"
    );
}

#[test]
fn an_unexpired_lease_is_never_reclaimed() {
    let dir = support::private_tempdir();
    let path = dir.path().join("live.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(&mut ledger, "live", &plan(), MATERIALIZED_AT).expect("plan");
    let (holder, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "live-a", 15).expect("lease");

    // The named sweep must not touch it.
    assert!(LeaseService::expire_due(&mut ledger)
        .expect("sweep")
        .is_empty());
    // Neither may an acquisition attempt use reclamation to steal it. The
    // package is `Leased` while the holder lives, so that gate refuses first.
    assert_eq!(
        LeaseService::acquire(&mut ledger, &graph, 0, "live-b", 15)
            .expect_err("live lease is not stealable")
            .reason_code(),
        "GRAPH_CONFLICT"
    );

    assert_eq!(count_kind(&ledger, "lease_expired"), 0);
    assert!(reclaim_outbox(&ledger).is_empty());
    assert_eq!(
        ledger
            .get_attempt(&holder.id)
            .expect("read")
            .expect("attempt")
            .state,
        AttemptState::Starting
    );
    assert_eq!(
        ledger
            .get_lease(&holder.variant_id)
            .expect("read")
            .expect("lease")
            .attempt_id,
        holder.id
    );
}

#[test]
fn expire_due_is_the_named_entry_point_and_is_idempotent() {
    let dir = support::private_tempdir();
    let path = dir.path().join("idempotent.sqlite");
    let (graph, grant) = crashed_writer(&path, "idem");
    let dead = grant.attempt.clone();
    force_expired(&path);

    let mut ledger = SqliteLedger::open(&path).expect("recover");
    let first = LeaseService::expire_due(&mut ledger).expect("first sweep");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].attempt_id, dead.id);
    assert_eq!(first[0].fence, dead.fence);
    assert!(ledger
        .ready_rows()
        .expect("ready")
        .iter()
        .any(|row| row.work_package_id == dead.work_package_id));

    let second = LeaseService::expire_due(&mut ledger).expect("second sweep");
    assert!(second.is_empty(), "reclamation is idempotent");
    assert_eq!(count_kind(&ledger, "lease_expired"), 1);
    assert_eq!(reclaim_outbox(&ledger).len(), 1);
    assert_eq!(
        ledger
            .get_attempt(&dead.id)
            .expect("read")
            .expect("attempt")
            .state,
        AttemptState::Crashed
    );

    let (successor, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "idem-b", 15).expect("successor");
    assert_eq!(successor.fence, dead.fence + 1);
}
