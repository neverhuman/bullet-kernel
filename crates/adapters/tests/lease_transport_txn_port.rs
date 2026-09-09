//! Transaction-local `LeaseTransportTxn` port on both ledgers: package,
//! authority, lease, and active-lease truth are read from the one open store
//! transaction at the store's own clock, and SQLite's `BEGIN IMMEDIATE`
//! excludes every other writer until that transaction closes.

use bullet_adapters::SqliteLedger;
use bullet_application::store::{CurrentPackage, LeaseTransportTxn};
use bullet_application::{
    materialize_plan, LeaseGrant, LeaseRequest, LeaseService, Ledger, LedgerError, MemoryLedger,
    PlanInput, ReleaseRequest, StoredGraph,
};
use bullet_domain::{
    AttemptId, AttemptState, TaskClass, Variant, VariantId, WorkPackageId, WorkPackageState,
};
use rusqlite::Connection;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

const AT: &str = "2026-01-01T00:00:00.000Z";
const TTL: i64 = 5;
const STALE: &str = "STALE_AUTHORITY";

fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure tempdir mode");
    }
    directory
}

fn plan<L: Ledger>(ledger: &mut L, seed: &str) -> (StoredGraph, LeaseRequest) {
    let graph = materialize_plan(
        ledger,
        seed,
        &PlanInput {
            title: "transaction-local port".into(),
            objective: "read every truth inside one transaction".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        AT,
    )
    .expect("materialize");
    let request =
        LeaseService::request_for(&graph, 0, &format!("{seed}-lease"), TTL).expect("request");
    (graph, request)
}

fn in_txn<L: Ledger, T>(ledger: &mut L, f: impl FnOnce(&mut dyn LeaseTransportTxn) -> T) -> T {
    ledger
        .with_lease_transport(|txn| Ok::<T, LedgerError>(f(txn)))
        .expect("transaction commits")
}

fn release<L: Ledger>(ledger: &mut L, grant: &LeaseGrant) {
    LeaseService::release(ledger, grant, AttemptState::Cancelled, false).expect("release");
}

fn package_lookup<L: Ledger>(ledger: &mut L, seed: &str) {
    let (graph, request) = plan(ledger, seed);
    let package_id = graph.packages[0].id.clone();
    let unknown = WorkPackageId::from_seed("no-such-package");
    let (materialized, refused) = in_txn(ledger, |txn| {
        (
            txn.resolve_package(&package_id).expect("current package"),
            txn.resolve_package(&unknown).expect_err("unknown package"),
        )
    });
    assert_eq!(
        materialized,
        CurrentPackage {
            mission: graph.mission.clone(),
            plan: graph.plan.clone(),
            package: graph.packages[0].clone(),
            variant: graph.variants[0].clone(),
        }
    );
    assert_eq!(materialized.package.state, WorkPackageState::Ready);
    assert_eq!(materialized.variant.fence_counter, 0);
    assert_eq!(refused.reason_code(), STALE);

    let grant = ledger.acquire_lease(&request).expect("acquire");
    let current = in_txn(ledger, |txn| {
        txn.resolve_package(&package_id).expect("current package")
    });
    assert_eq!(current.package.state, WorkPackageState::Leased);
    assert_eq!(current.variant.fence_counter, grant.lease.fence);
    assert_eq!(current.variant.id, grant.lease.variant_id);
    assert_eq!(current.mission, graph.mission);
    assert_eq!(current.plan, graph.plan);
}

#[test]
fn memory_package_lookup_reads_current_graph_and_refuses_unknown() {
    package_lookup(&mut MemoryLedger::new(), "memory-package");
}

#[test]
fn sqlite_package_lookup_reads_current_graph_and_refuses_unknown() {
    let directory = secure_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("package.sqlite3")).expect("open");
    package_lookup(&mut ledger, "sqlite-package");
}

#[test]
fn memory_current_authority_reads_the_store_row() {
    let mut ledger = MemoryLedger::new();
    plan(&mut ledger, "memory-authority");
    let expected = Ledger::current_authority(&ledger).expect("store authority");
    let seen = in_txn(&mut ledger, |txn| {
        txn.current_authority().expect("authority")
    });
    assert_eq!(seen, expected);
}

#[test]
fn sqlite_current_authority_reads_the_store_row() {
    let directory = secure_tempdir();
    let path = directory.path().join("authority.sqlite3");
    plan(
        &mut SqliteLedger::open(&path).expect("open"),
        "sqlite-authority",
    );
    let genesis = Ledger::current_authority(&SqliteLedger::open(&path).expect("reopen"))
        .expect("genesis row");
    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE authority_revisions SET graph_revision = 7, authority_epoch = 3
             WHERE singleton = 1",
            [],
        )
        .expect("advance authority row");
    let mut ledger = SqliteLedger::open(&path).expect("reopen");
    let expected = Ledger::current_authority(&ledger).expect("store authority");
    let seen = in_txn(&mut ledger, |txn| {
        txn.current_authority().expect("authority")
    });
    assert_eq!(seen, expected);
    assert_ne!(seen, genesis);
    assert_eq!(seen.graph_revision(), 7);
    assert_eq!(seen.authority_epoch(), 3);
}

fn lease_lifecycle<L: Ledger>(ledger: &mut L, seed: &str) {
    let (_graph, request) = plan(ledger, seed);
    let attempt_id = AttemptId::from_seed(&request.attempt_seed);
    let before = in_txn(ledger, |txn| {
        (
            txn.get_lease(&attempt_id).expect("lease read"),
            txn.get_attempt(&attempt_id).expect("attempt read"),
        )
    });
    assert_eq!(before, (None, None));

    let grant = ledger.acquire_lease(&request).expect("acquire");
    assert_eq!(grant.attempt.id, attempt_id);
    let (lease, attempt) = in_txn(ledger, |txn| {
        (
            txn.get_lease(&attempt_id).expect("lease read"),
            txn.get_attempt(&attempt_id).expect("attempt read"),
        )
    });
    assert_eq!(lease, Some(grant.lease.clone()));
    assert_eq!(attempt, Some(grant.attempt.clone()));

    release(ledger, &grant);
    let (lease, attempt) = in_txn(ledger, |txn| {
        (
            txn.get_lease(&attempt_id).expect("lease read"),
            txn.get_attempt(&attempt_id).expect("attempt read"),
        )
    });
    assert_eq!(lease, None);
    assert_eq!(
        attempt.map(|attempt| attempt.state),
        Some(AttemptState::Cancelled)
    );
}

#[test]
fn memory_get_lease_tracks_acquire_and_release() {
    lease_lifecycle(&mut MemoryLedger::new(), "memory-lease");
}

#[test]
fn sqlite_get_lease_tracks_acquire_and_release() {
    let directory = secure_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("lease.sqlite3")).expect("open");
    lease_lifecycle(&mut ledger, "sqlite-lease");
}

/// Live check, stale fence, unknown Attempt, and a release performed inside
/// the same transaction; `expire` places the lease past the store's clock.
fn active_lease_checks<L: Ledger>(ledger: &mut L, seed: &str, expire: impl FnOnce(&mut L)) {
    let (_graph, request) = plan(ledger, seed);
    let grant = ledger.acquire_lease(&request).expect("acquire");
    let attempt_id = grant.attempt.id.clone();
    let fence = grant.lease.fence;
    let unknown = AttemptId::from_seed("no-such-attempt");
    let (live, stale_fence, no_attempt) = in_txn(ledger, |txn| {
        (
            txn.check_active_lease(&attempt_id, fence),
            txn.check_active_lease(&attempt_id, fence + 1)
                .expect_err("stale fence"),
            txn.check_active_lease(&unknown, fence)
                .expect_err("unknown attempt"),
        )
    });
    live.expect("live lease at the store clock");
    assert_eq!(stale_fence.reason_code(), STALE);
    assert_eq!(no_attempt.reason_code(), STALE);

    expire(ledger);
    let (lease, expired) = in_txn(ledger, |txn| {
        (
            txn.get_lease(&attempt_id).expect("lease read"),
            txn.check_active_lease(&attempt_id, fence)
                .expect_err("expired at the store clock"),
        )
    });
    assert!(
        lease.is_some(),
        "expiry is decided by the clock, not by reclaim"
    );
    assert_eq!(expired.reason_code(), STALE);

    let (_graph, request) = plan(ledger, &format!("{seed}-released"));
    let grant = ledger.acquire_lease(&request).expect("acquire");
    let attempt_id = grant.attempt.id.clone();
    let fence = grant.lease.fence;
    let (before, after, lease) = in_txn(ledger, |txn| {
        let before = txn.check_active_lease(&attempt_id, fence);
        txn.release_lease(&ReleaseRequest {
            variant_id: grant.lease.variant_id.clone(),
            attempt_id: attempt_id.clone(),
            final_state: AttemptState::Cancelled,
            requeue: false,
        })
        .expect("release inside the transaction");
        (
            before,
            txn.check_active_lease(&attempt_id, fence)
                .expect_err("released inside the same transaction"),
            txn.get_lease(&attempt_id).expect("lease read"),
        )
    });
    before.expect("live before the release");
    assert_eq!(after.reason_code(), STALE);
    assert_eq!(lease, None);
}

#[test]
fn memory_check_active_lease_refuses_stale_fence_expiry_and_release() {
    active_lease_checks(&mut MemoryLedger::new(), "memory-check", |ledger| {
        ledger
            .advance_simulation_time(u64::try_from(TTL).expect("ttl") + 1)
            .expect("advance clock");
    });
}

#[test]
fn sqlite_check_active_lease_refuses_stale_fence_expiry_and_release() {
    let directory = secure_tempdir();
    let path = directory.path().join("check.sqlite3");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    active_lease_checks(&mut ledger, "sqlite-check", |_ledger| {
        Connection::open(&path)
            .expect("raw open")
            .execute(
                "UPDATE active_leases SET heartbeat_at = ?1, expires_at = ?2",
                ["2026-01-01T00:00:00.000Z", "2026-01-01T00:00:05.000Z"],
            )
            .expect("place the window in the past");
    });
}

#[test]
fn sqlite_open_transaction_excludes_concurrent_release_and_reacquire() {
    let directory = secure_tempdir();
    let path = directory.path().join("isolation.sqlite3");
    let mut first = SqliteLedger::open(&path).expect("open");
    let (graph, request) = plan(&mut first, "sqlite-isolation");
    let grant = first.acquire_lease(&request).expect("acquire");
    let old_attempt = grant.attempt.id.clone();
    let package_id = graph.packages[0].id.clone();
    let successor = LeaseService::request_for(&graph, 0, "sqlite-isolation-successor", TTL)
        .expect("successor request");

    let mut second = SqliteLedger::open(&path).expect("second connection");
    let started = Arc::new(Barrier::new(2));
    let writer = {
        let started = Arc::clone(&started);
        let grant = grant.clone();
        let successor = successor.clone();
        thread::spawn(move || {
            started.wait();
            LeaseService::release(&mut second, &grant, AttemptState::Cancelled, true)
                .expect("release and requeue");
            second.acquire_lease(&successor).expect("re-acquire")
        })
    };

    let raw = Connection::open(&path).expect("raw open");
    raw.busy_timeout(Duration::ZERO).expect("no busy wait");
    let (lease, current, blocked) = in_txn(&mut first, |txn| {
        started.wait();
        let blocked = raw
            .execute_batch("BEGIN IMMEDIATE")
            .expect_err("a second writer cannot begin while the transaction is open");
        txn.check_active_lease(&old_attempt, grant.lease.fence)
            .expect("still live inside the open transaction");
        (
            txn.get_lease(&old_attempt).expect("lease read"),
            txn.resolve_package(&package_id).expect("current package"),
            blocked,
        )
    });
    assert_eq!(lease, Some(grant.lease.clone()));
    assert_eq!(current.variant.fence_counter, grant.lease.fence);
    assert!(
        matches!(
            blocked,
            rusqlite::Error::SqliteFailure(ref failure, _)
                if failure.code == rusqlite::ErrorCode::DatabaseBusy
        ),
        "expected SQLITE_BUSY, got {blocked:?}"
    );

    let new_grant = writer.join().expect("writer thread");
    assert_eq!(new_grant.lease.fence, grant.lease.fence + 1);
    let (old, new, current, stale) = in_txn(&mut first, |txn| {
        (
            txn.get_lease(&old_attempt).expect("old lease read"),
            txn.get_lease(&new_grant.attempt.id)
                .expect("new lease read"),
            txn.resolve_package(&package_id).expect("current package"),
            txn.check_active_lease(&old_attempt, grant.lease.fence)
                .expect_err("old incarnation is gone"),
        )
    });
    assert_eq!(old, None);
    assert_eq!(new, Some(new_grant.lease.clone()));
    assert_eq!(current.variant.fence_counter, new_grant.lease.fence);
    assert_eq!(stale.reason_code(), STALE);
}

/// Snapshot of every row a refused lookup must leave untouched.
fn untouched<L: Ledger>(ledger: &L, graph: &StoredGraph) -> (usize, usize, usize) {
    (
        ledger
            .list_attempts(&graph.mission.id)
            .expect("attempts")
            .len(),
        ledger.list_events().expect("events").len(),
        ledger.ready_rows().expect("ready rows").len(),
    )
}

/// Corrupt the stored graph with `corrupt`, then prove the package lookup
/// fails closed as `STORE_FAILURE` inside the transaction, no grant is
/// produced, and no lease, Attempt, event, ready, or transport-grant row
/// changes on either side of the rolled-back transaction.
fn corrupt_variants<L: Ledger>(ledger: &mut L, seed: &str, corrupt: impl FnOnce(&mut StoredGraph)) {
    let (graph, request) = plan(ledger, seed);
    let package_id = graph.packages[0].id.clone();
    let attempt_id = AttemptId::from_seed(&request.attempt_seed);
    let mut corrupted = graph.clone();
    corrupt(&mut corrupted);
    ledger
        .put_graph(&corrupted)
        .expect("store the corrupted graph body");
    let before = untouched(ledger, &graph);

    let refused = ledger
        .with_lease_transport(|txn| {
            txn.resolve_package(&package_id)?;
            txn.acquire_lease(&request)
        })
        .expect_err("corrupt variant set must never yield a grant");
    assert_eq!(refused.reason_code(), "STORE_FAILURE");

    let (lease, attempt, grant) = in_txn(ledger, |txn| {
        (
            txn.get_lease(&attempt_id).expect("lease read"),
            txn.get_attempt(&attempt_id).expect("attempt read"),
            txn.get_transport_grant(&request.idempotency_key)
                .expect("grant read"),
        )
    });
    assert_eq!((lease, attempt, grant), (None, None, None));
    assert_eq!(
        ledger.get_lease(&graph.variants[0].id).expect("lease"),
        None
    );
    assert_eq!(untouched(ledger, &graph), before);
    assert_eq!(before.0, 0);
}

fn drop_every_variant(graph: &mut StoredGraph) {
    graph.variants.clear();
}

fn duplicate_variant(graph: &mut StoredGraph) {
    let mut twin: Variant = graph.variants[0].clone();
    twin.id = VariantId::from_seed("second-variant-for-one-package");
    graph.variants.push(twin);
}

#[test]
fn memory_zero_variant_package_fails_closed_without_a_grant() {
    corrupt_variants(&mut MemoryLedger::new(), "memory-zero", drop_every_variant);
}

#[test]
fn sqlite_zero_variant_package_fails_closed_without_a_grant() {
    let directory = secure_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("zero.sqlite3")).expect("open");
    corrupt_variants(&mut ledger, "sqlite-zero", drop_every_variant);
}

#[test]
fn memory_two_variant_package_fails_closed_without_a_grant() {
    corrupt_variants(&mut MemoryLedger::new(), "memory-two", duplicate_variant);
}

#[test]
fn sqlite_two_variant_package_fails_closed_without_a_grant() {
    let directory = secure_tempdir();
    let mut ledger = SqliteLedger::open(directory.path().join("two.sqlite3")).expect("open");
    corrupt_variants(&mut ledger, "sqlite-two", duplicate_variant);
}
