//! Adversarial database-clock lease authority tests. Raw SQL is used only to
//! place canonical persisted windows at exact boundaries without sleeping.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, LeaseGrant, LeaseService, Ledger, PlanInput, StoredGraph,
};
use bullet_domain::{AttemptState, TaskClass};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

const MATERIALIZED_AT: &str = "2026-01-01T00:00:00.000Z";

fn sqlite_fixture(path: &Path) -> Connection {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(path).expect("create private SQLite fixture"));
    Connection::open(path).expect("open SQLite fixture")
}

fn setup(path: &Path, seed: &str, ttl_seconds: i64) -> (StoredGraph, LeaseGrant) {
    let mut ledger = SqliteLedger::open(path).expect("open");
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "database clock".into(),
            objective: "lease authority".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        MATERIALIZED_AT,
    )
    .expect("plan");
    let (_, _, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, seed, ttl_seconds).expect("acquire");
    (graph, grant)
}

fn set_window(path: &Path, heartbeat_at: &str, expires_at: &str) {
    Connection::open(path)
        .expect("raw open")
        .execute(
            "UPDATE active_leases SET heartbeat_at = ?1, expires_at = ?2",
            [heartbeat_at, expires_at],
        )
        .expect("set test window");
}

fn stored_window(path: &Path) -> (String, String, i64) {
    Connection::open(path)
        .expect("raw open")
        .query_row(
            "SELECT heartbeat_at, expires_at, ttl_seconds FROM active_leases",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("stored window")
}

#[test]
fn database_owns_grant_window_and_exact_replay_never_renews() {
    let dir = support::private_tempdir();
    let path = dir.path().join("clock.sqlite");
    let before: String = sqlite_fixture(&path)
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .expect("database before");
    let (graph, grant) = setup(&path, "db-owned", 5);
    let after: String = Connection::open(&path)
        .expect("raw open")
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .expect("database after");
    assert!(before <= grant.lease.heartbeat_at && grant.lease.heartbeat_at <= after);
    assert_eq!(grant.lease.ttl_seconds, 5);

    let request = LeaseService::request_for(&graph, 0, "db-owned", 5).expect("request");
    let mut ledger = SqliteLedger::open(&path).expect("reopen");
    let replay = ledger.acquire_lease(&request).expect("replay");
    assert_eq!(
        serde_json::to_vec(&replay).expect("bytes"),
        serde_json::to_vec(&grant).expect("bytes")
    );
    assert_eq!(
        stored_window(&path),
        (
            grant.lease.heartbeat_at.clone(),
            grant.lease.expires_at.clone(),
            5,
        )
    );

    let changed = LeaseService::request_for(&graph, 0, "db-owned", 6).expect("request");
    assert_eq!(
        ledger
            .acquire_lease(&changed)
            .expect_err("changed TTL conflict")
            .reason_code(),
        "IDEMPOTENCY_CONFLICT"
    );
}

#[test]
fn invalid_ttl_never_consumes_a_fence_and_exact_expiry_advances_once() {
    let dir = support::private_tempdir();
    let path = dir.path().join("expiry.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(
        &mut ledger,
        "expiry",
        &PlanInput {
            title: "expiry".into(),
            objective: "boundary".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        MATERIALIZED_AT,
    )
    .expect("plan");
    for ttl in [0, 16] {
        assert_eq!(
            LeaseService::acquire(&mut ledger, &graph, 0, "invalid", ttl)
                .expect_err("invalid")
                .reason_code(),
            "INVALID_LEASE_TTL"
        );
    }
    let (_, _, first) = LeaseService::acquire(&mut ledger, &graph, 0, "first", 5).expect("first");
    assert_eq!(first.attempt.fence, 1);
    drop(ledger);

    set_window(
        &path,
        "2000-01-01T00:00:00.000Z",
        "2000-01-01T00:00:05.000Z",
    );
    let mut ledger = SqliteLedger::open(&path).expect("restart");
    assert_eq!(ledger.expire_leases().expect("expire").len(), 1);
    assert_eq!(
        ledger
            .heartbeat(&LeaseService::heartbeat_of(&first))
            .expect_err("no revival")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    let (second, _, _) =
        LeaseService::acquire(&mut ledger, &graph, 0, "second", 5).expect("successor");
    assert_eq!(second.fence, 2);
}

#[test]
fn changed_ttl_and_stale_identity_leave_the_window_unchanged() {
    let dir = support::private_tempdir();
    let path = dir.path().join("heartbeat.sqlite");
    let (_, grant) = setup(&path, "heartbeat", 15);
    let original = stored_window(&path);
    let mut ledger = SqliteLedger::open(&path).expect("reopen");

    let mut changed = LeaseService::heartbeat_of(&grant);
    changed.ttl_seconds = 14;
    assert_eq!(
        ledger
            .heartbeat(&changed)
            .expect_err("changed TTL")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    let mut stale = LeaseService::heartbeat_of(&grant);
    stale.runner_epoch += 1;
    assert_eq!(
        ledger
            .heartbeat(&stale)
            .expect_err("stale identity")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    assert_eq!(stored_window(&path), original);
}

#[test]
fn corrupt_or_inexact_persisted_windows_fail_closed_without_mutation() {
    for (name, heartbeat_at, expires_at) in [
        ("malformed", "aaa", "zzz"),
        (
            "oversized",
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:02:00.000Z",
        ),
        (
            "inverted",
            "2000-01-01T00:01:00.000Z",
            "2000-01-01T00:00:00.000Z",
        ),
    ] {
        let dir = support::private_tempdir();
        let path = dir.path().join(format!("{name}.sqlite"));
        let (_, grant) = setup(&path, name, 15);
        set_window(&path, heartbeat_at, expires_at);
        let original = stored_window(&path);
        let mut ledger = SqliteLedger::open(&path).expect("reopen");
        assert_eq!(
            ledger
                .heartbeat(&LeaseService::heartbeat_of(&grant))
                .expect_err("corrupt heartbeat")
                .reason_code(),
            "STORE_FAILURE"
        );
        assert_eq!(
            ledger
                .expire_leases()
                .expect_err("corrupt expiry")
                .reason_code(),
            "STORE_FAILURE"
        );
        assert_eq!(stored_window(&path), original);
    }
}

#[test]
fn corrupt_persisted_ttl_is_store_failure_not_request_error() {
    let dir = support::private_tempdir();
    let path = dir.path().join("ttl-corrupt.sqlite");
    let (graph, _) = setup(&path, "ttl-corrupt", 15);
    let conn = Connection::open(&path).expect("raw open");
    conn.pragma_update(None, "ignore_check_constraints", "ON")
        .expect("test bypass");
    conn.execute("UPDATE active_leases SET ttl_seconds = 0", [])
        .expect("corrupt persisted TTL");
    let ledger = SqliteLedger::open(&path).expect("reopen");
    assert_eq!(
        ledger
            .get_lease(&graph.variants[0].id)
            .expect_err("persisted corruption")
            .reason_code(),
        "STORE_FAILURE"
    );
}

#[test]
fn concurrent_heartbeat_cannot_revive_an_expiring_lease() {
    let dir = support::private_tempdir();
    let path = dir.path().join("race.sqlite");
    let (_, grant) = setup(&path, "race-expiry", 15);
    set_window(
        &path,
        "2000-01-01T00:00:00.000Z",
        "2000-01-01T00:00:15.000Z",
    );
    let barrier = Arc::new(Barrier::new(2));
    let heartbeat_path = path.clone();
    let heartbeat_barrier = Arc::clone(&barrier);
    let heartbeat_grant = grant.clone();
    let heartbeat = thread::spawn(move || {
        let mut ledger = SqliteLedger::open(heartbeat_path).expect("heartbeat open");
        heartbeat_barrier.wait();
        ledger.heartbeat(&LeaseService::heartbeat_of(&heartbeat_grant))
    });
    let expiry_path = path.clone();
    let expiry = thread::spawn(move || {
        let mut ledger = SqliteLedger::open(expiry_path).expect("expiry open");
        barrier.wait();
        ledger.expire_leases()
    });
    assert_eq!(
        heartbeat
            .join()
            .expect("heartbeat join")
            .expect_err("expired heartbeat")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    assert_eq!(
        expiry.join().expect("expiry join").expect("expiry").len(),
        1
    );
    let ledger = SqliteLedger::open(&path).expect("verify");
    assert!(ledger
        .get_lease(&grant.lease.variant_id)
        .expect("read")
        .is_none());
    assert_eq!(
        ledger
            .get_attempt(&grant.attempt.id)
            .expect("attempt read")
            .expect("attempt")
            .state,
        AttemptState::Crashed
    );
}
