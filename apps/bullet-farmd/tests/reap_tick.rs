//! Farmd's writer-lease maintenance tick has a production caller and a durable
//! effect. These tests prove it reclaims a dead incarnation exactly once even
//! while an acquirer contends for the same lease, never touches a live one, is
//! silent when nothing is due, reports itself on `/health` only additively, and
//! that `/api/v1/fleet` drops the lease it reclaimed.
//!
//! Raw SQL places an exact expired window without sleeping, exactly as the
//! adapter's own `lease_reaper.rs` already does.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::records::MAX_LEASE_TTL_SECONDS;
use bullet_application::{
    materialize_plan, ExpiredLease, LeaseGrant, LeaseService, Ledger, PlanInput, StoredGraph,
};
use bullet_domain::{AttemptState, TaskClass};
use bullet_farmd::reaper;
use rusqlite::Connection;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const MATERIALIZED_AT: &str = "2026-01-01T00:00:00.000Z";
const TTL_SECONDS: i64 = 5;
const LOCAL_ORIGIN: &str = "http://127.0.0.1:7420";

fn plan() -> PlanInput {
    PlanInput {
        title: "farmd tick".into(),
        objective: "reclaim a dead writer without an operator".into(),
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

fn attempt_state(ledger: &SqliteLedger, grant: &LeaseGrant) -> AttemptState {
    ledger
        .get_attempt(&grant.attempt.id)
        .expect("read attempt")
        .expect("attempt row")
        .state
}

async fn serve(app: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    addr
}

async fn get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .expect("response timeout")
        .expect("read");
    let response = String::from_utf8_lossy(&bytes).to_string();
    assert!(response.starts_with("HTTP/1.1 200"), "{path}: {response}");
    let body = response.split_once("\r\n\r\n").expect("body").1;
    if serde_json::from_str::<Value>(body).is_ok() {
        return body.to_string();
    }
    // Connection: close responses may arrive chunked; strip the framing.
    body.lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect()
}

#[test]
fn tick_and_acquirer_contend_for_one_expired_lease_and_reclaim_it_exactly_once() {
    let directory = support::private_tempdir();

    // Round one. The acquirer holds the write lock, reclaims inside its own
    // transaction and then fails after the reclaim, so its reclamation is rolled
    // back and the only reclamation that can survive is the tick's. That makes
    // this round contend for the same expired lease *and* pin the tick's own
    // reclaim call: without it nothing is reclaimed at all.
    let path = directory.path().join("rollback.sqlite");
    let (graph, grant) = crashed_writer(&path, "rollback");
    let dead = grant.attempt.clone();
    force_expired(&path);

    let barrier = Arc::new(Barrier::new(2));
    let acquirer = {
        let path = path.clone();
        let graph = graph.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut ledger = SqliteLedger::open(&path).expect("open");
            ledger.set_lease_acquisition_failpoint(1);
            barrier.wait();
            LeaseService::acquire(&mut ledger, &graph, 0, "rolled-back", TTL_SECONDS)
                .expect_err("the injected failure must roll this acquisition back")
        })
    };
    let ticker = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut ledger = SqliteLedger::open(&path).expect("open");
            barrier.wait();
            reaper::sweep(&mut ledger).expect("tick sweep")
        })
    };
    let refusal = acquirer.join().expect("join acquirer");
    let reclaimed = ticker.join().expect("join tick");

    assert!(
        refusal
            .to_string()
            .contains("injected lease acquisition failpoint"),
        "the acquirer must fail after its own reclaim, not before it: {refusal}"
    );
    assert_eq!(
        reclaimed.len(),
        1,
        "the tick, not the rolled-back acquirer, reclaims the dead lease"
    );
    assert_eq!(reclaimed[0].attempt_id, dead.id);
    assert_eq!(reclaimed[0].fence, dead.fence);
    assert_eq!(reclaimed[0].work_package_id, dead.work_package_id);

    let mut ledger = SqliteLedger::open(&path).expect("verify");
    assert_eq!(
        count_kind(&ledger, "lease_expired"),
        1,
        "exactly one reclamation event is persisted"
    );
    assert_eq!(
        reclaim_outbox(&ledger),
        reclaimed,
        "one lease_reclaimed row, and it is the tick's own reclamation"
    );
    assert_eq!(attempt_state(&ledger, &grant), AttemptState::Crashed);
    let (successor, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "successor", TTL_SECONDS)
            .expect("successor acquires the freed variant");
    assert_eq!(
        successor.fence,
        dead.fence + 1,
        "the successor's fence is N+1 and the dead fence is never reused"
    );
    assert_eq!(count_kind(&ledger, "lease_expired"), 1);
    assert_eq!(reclaim_outbox(&ledger).len(), 1, "no second outbox row");

    // Round two. Both actors are healthy and race for the same expired lease.
    // Whichever transaction commits first, the durable truth is one reclamation:
    // both reach the same single-transaction `reclaim_expired_variant`.
    let path = directory.path().join("race.sqlite");
    let (graph, grant) = crashed_writer(&path, "race");
    let dead = grant.attempt.clone();
    force_expired(&path);

    let barrier = Arc::new(Barrier::new(2));
    let acquirer = {
        let path = path.clone();
        let graph = graph.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut ledger = SqliteLedger::open(&path).expect("open");
            barrier.wait();
            LeaseService::acquire(&mut ledger, &graph, 0, "racing-successor", TTL_SECONDS)
                .map(|(attempt, _token, _grant)| attempt)
        })
    };
    let ticker = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut ledger = SqliteLedger::open(&path).expect("open");
            barrier.wait();
            reaper::sweep(&mut ledger).expect("tick sweep")
        })
    };
    let acquired = acquirer.join().expect("join acquirer");
    let by_tick = ticker.join().expect("join tick");

    let successor = acquired.expect("the freed variant is acquirable under either ordering");
    assert_eq!(
        successor.fence,
        dead.fence + 1,
        "the successor's fence is N+1"
    );
    let ledger = SqliteLedger::open(&path).expect("verify");
    assert_eq!(
        count_kind(&ledger, "lease_expired"),
        1,
        "exactly one reclamation event is persisted under contention"
    );
    let outbox = reclaim_outbox(&ledger);
    assert_eq!(outbox.len(), 1, "no second lease_reclaimed row appears");
    assert_eq!(outbox[0].attempt_id, dead.id);
    assert_eq!(outbox[0].fence, dead.fence);
    assert!(
        by_tick.len() <= 1,
        "the tick can win at most one reclamation"
    );
    if let Some(reclaimed) = by_tick.first() {
        assert_eq!(
            *reclaimed, outbox[0],
            "when the tick wins the race it is the same durable reclamation"
        );
    }
    assert_eq!(attempt_state(&ledger, &grant), AttemptState::Crashed);
}

#[test]
fn the_tick_never_touches_a_live_lease_and_is_silent_when_nothing_is_due() {
    let directory = support::private_tempdir();
    let path = directory.path().join("live.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");

    assert!(
        reaper::sweep(&mut ledger).expect("empty sweep").is_empty(),
        "a tick over an empty ledger reclaims nothing"
    );
    assert!(
        ledger.outbox_all().expect("outbox").is_empty(),
        "a tick with nothing to do is silent in the outbox"
    );
    assert!(ledger.list_events().expect("events").is_empty());

    let graph = materialize_plan(&mut ledger, "live", &plan(), MATERIALIZED_AT).expect("plan");
    let (holder, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "live-holder", MAX_LEASE_TTL_SECONDS)
            .expect("lease");
    let outbox_before = ledger.outbox_all().expect("outbox");
    let events_before = ledger.list_events().expect("events").len();

    for round in 0..3 {
        assert!(
            reaper::sweep(&mut ledger).expect("sweep").is_empty(),
            "round {round}: a live lease is never reclaimed"
        );
    }

    assert_eq!(
        count_kind(&ledger, "lease_expired"),
        0,
        "a tick that fires with a live lease present persists zero events"
    );
    assert!(reclaim_outbox(&ledger).is_empty());
    assert_eq!(
        ledger.outbox_all().expect("outbox"),
        outbox_before,
        "the outbox is byte-identical after three no-op ticks"
    );
    assert_eq!(ledger.list_events().expect("events").len(), events_before);
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

#[tokio::test]
async fn health_reports_the_tick_only_after_it_has_run() {
    let directory = support::private_tempdir();
    let path = directory.path().join("health.sqlite");
    let (app, state) =
        bullet_farmd::api::daemon(&path, None, LOCAL_ORIGIN.to_string(), None).expect("daemon");
    let addr = serve(app).await;

    let before = get(addr, "/health").await;
    assert!(
        !before.contains("reap"),
        "a daemon whose tick has never fired answers exactly what it always did: {before}"
    );
    #[cfg(not(feature = "embedded-portal"))]
    assert_eq!(
        before, r#"{"status":"ok"}"#,
        "the default body is unchanged"
    );

    assert!(reaper::run_once(&state)
        .await
        .expect("idle tick")
        .is_empty());
    let idle: Value = serde_json::from_str(&get(addr, "/health").await).expect("health json");
    assert_eq!(idle["status"], "ok");
    assert_eq!(idle["reap"]["reclaimed"], 0);
    chrono::DateTime::parse_from_rfc3339(idle["reap"]["last_run_at"].as_str().expect("last run"))
        .expect("RFC 3339 last run");

    let (_graph, grant) = crashed_writer(&path, "health");
    force_expired(&path);
    assert_eq!(
        reaper::run_once(&state).await.expect("tick").len(),
        1,
        "the tick reclaims the dead lease against the daemon's own ledger"
    );
    let after: Value = serde_json::from_str(&get(addr, "/health").await).expect("health json");
    assert_eq!(after["status"], "ok");
    assert_eq!(
        after["reap"]["reclaimed"], 1,
        "the reclaim count is cumulative"
    );
    assert!(
        after["reap"]["last_run_at"] != idle["reap"]["last_run_at"]
            || after["reap"]["reclaimed"] != idle["reap"]["reclaimed"],
        "the reported run advanced"
    );
    let ledger = SqliteLedger::open(&path).expect("verify");
    assert_eq!(attempt_state(&ledger, &grant), AttemptState::Crashed);
}

#[tokio::test]
async fn fleet_drops_the_lease_the_tick_reclaimed_and_shows_the_work_ready() {
    let directory = support::private_tempdir();
    let path = directory.path().join("fleet.sqlite");
    let (_graph, grant) = crashed_writer(&path, "fleet");
    force_expired(&path);
    let (app, state) =
        bullet_farmd::api::daemon(&path, None, LOCAL_ORIGIN.to_string(), None).expect("daemon");
    let addr = serve(app).await;

    let before: Value =
        serde_json::from_str(&get(addr, "/api/v1/fleet").await).expect("fleet json");
    let leases = before["data"]["leases"].as_array().expect("leases");
    assert_eq!(leases.len(), 1, "the dead holder row is still there");
    assert_eq!(leases[0]["liveness"], "expired");
    assert_eq!(leases[0]["attempt_id"], grant.attempt.id.to_string());
    assert_eq!(leases[0]["attempt_state"], AttemptState::Starting.as_str());
    assert!(
        before["data"]["ready_queue"]
            .as_array()
            .expect("ready queue")
            .is_empty(),
        "the work is not ready while the dead lease holds it"
    );

    assert_eq!(reaper::run_once(&state).await.expect("tick").len(), 1);

    let after: Value = serde_json::from_str(&get(addr, "/api/v1/fleet").await).expect("fleet json");
    assert!(
        after["data"]["leases"]
            .as_array()
            .expect("leases")
            .is_empty(),
        "a reclaimed lease disappears from the fleet projection"
    );
    let ready = after["data"]["ready_queue"]
        .as_array()
        .expect("ready queue");
    assert_eq!(
        ready.len(),
        1,
        "the freed package is back on the ready queue"
    );
    assert_eq!(
        ready[0]["work_package_id"],
        grant.attempt.work_package_id.to_string()
    );
    let ledger = SqliteLedger::open(&path).expect("verify");
    assert_eq!(
        attempt_state(&ledger, &grant),
        AttemptState::Crashed,
        "the Attempt shows its terminal state"
    );
}
