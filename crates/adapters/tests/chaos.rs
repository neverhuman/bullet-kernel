//! Kill/retry suite against the durable ledger. Replay is the recovery path.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, run_demo, LeaseService, Ledger, PlanInput};
use bullet_domain::observation::{
    PreservationDecision, PreservationOperation, PreservationOutcome, PreservationRecord,
};
use bullet_domain::{AttemptState, Digest, DomainError, Observation, TaskClass};
use chrono::{DateTime, Duration, Utc};
use rusqlite::Connection;

fn t(offset: i64) -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_790_000_000 + offset)
}

fn ts(offset: i64) -> String {
    LeaseService::rfc3339(t(offset))
}

fn plan() -> PlanInput {
    PlanInput {
        title: "chaos".into(),
        objective: "replay".into(),
        packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
    }
}

fn force_expired(path: &std::path::Path) {
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

#[test]
fn sqlite_demo_roundtrip_shows_both_fences() {
    let dir = support::private_tempdir();
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let receipt = run_demo(&mut ledger).expect("demo");
    assert!(receipt.stale_refused);
    assert!(receipt.materialize_idempotent);
    assert_eq!(receipt.fence_first, 1);
    assert_eq!(receipt.fence_second, 2);
    assert_eq!(receipt.candidate_head, "NOT_PRODUCED");
    assert_eq!(receipt.evidence_result, "NOT_RUN");
    assert_eq!(receipt.effect_outcome, "NOT_DISPATCHED");
    assert_eq!(receipt.effect_unknown_outcome, "NOT_DISPATCHED");
    drop(ledger);
    let mut again = SqliteLedger::open(&path).expect("reopen");
    let second = run_demo(&mut again).expect("idempotent demo");
    assert_eq!(receipt, second);
}

#[test]
fn killed_writer_is_reclaimed_and_successor_gets_next_fence() {
    let dir = support::private_tempdir();
    let path = dir.path().join("ledger.sqlite");
    let first_grant = {
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let graph = materialize_plan(&mut ledger, "kill", &plan(), &ts(0)).expect("plan");
        let (_attempt, _token, grant) =
            LeaseService::acquire(&mut ledger, &graph, 0, "kill-a", 5).expect("lease");
        grant
        // The connection drops here without releasing: a killed process.
    };
    let mut ledger = SqliteLedger::open(&path).expect("recover");
    let graph = materialize_plan(&mut ledger, "kill", &plan(), &ts(0)).expect("replay");
    force_expired(&path);
    let expired = ledger.expire_leases().expect("expire");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].attempt_id, first_grant.attempt.id);
    let crashed = ledger
        .get_attempt(&first_grant.attempt.id)
        .expect("read")
        .expect("attempt");
    assert_eq!(crashed.state, AttemptState::Crashed);
    let (successor, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "kill-b", 15).expect("successor");
    assert_eq!(successor.fence, first_grant.attempt.fence + 1);
    // The dead incarnation's heartbeat stays refused forever.
    let err = ledger
        .heartbeat(&LeaseService::heartbeat_of(&first_grant))
        .expect_err("stale");
    assert!(matches!(
        err,
        bullet_application::LedgerError::Domain(DomainError::StaleAuthority(_))
    ));
}

#[test]
fn stale_delta_cannot_rewind_successor_fence() {
    let dir = support::private_tempdir();
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(&mut ledger, "rewind", &plan(), &ts(0)).expect("plan");
    let (first, _token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "rw-a", 15).expect("first");
    LeaseService::release(&mut ledger, &grant, AttemptState::Cancelled, true).expect("release");
    let (second, _token2, _grant2) =
        LeaseService::acquire(&mut ledger, &graph, 0, "rw-b", 15).expect("second");
    assert!(second.fence > first.fence);
    let current = ledger
        .get_graph(&graph.mission.id)
        .expect("graph")
        .expect("stored");
    let rewind = bullet_application::GraphDelta {
        parent: bullet_application::graph_digest(&current),
        ops: vec![bullet_application::GraphOp::BumpFence {
            variant_id: current.variants[0].id.clone(),
            from: first.fence,
            to: first.fence,
        }],
    };
    let err = bullet_application::apply_graph_delta(&mut ledger, &graph.mission.id, &rewind)
        .expect_err("no rewind");
    assert!(matches!(
        err,
        bullet_application::LedgerError::Domain(DomainError::Fence(_))
    ));
}

#[test]
fn exact_preservation_decision_is_consumed_before_cleanup() {
    let dir = support::private_tempdir();
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(&mut ledger, "unknown", &plan(), &ts(0)).expect("plan");
    let (attempt, _token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "unk-a", 15).expect("lease");

    let mut running = attempt.clone();
    running.state = running
        .state
        .transition(AttemptState::Running)
        .expect("start writer");
    ledger.put_attempt(&running).expect("persist running");
    let live_record = PreservationRecord::for_attempt(
        &running,
        PreservationOperation::CleanupWorkspace,
        Digest::of(b"live-preservation-receipt"),
        PreservationOutcome::Preserved,
    );
    assert!(PreservationDecision::for_workspace_cleanup(
        &Observation::value(live_record),
        &running,
    )
    .is_err());

    LeaseService::release(&mut ledger, &grant, AttemptState::Superseded, true)
        .expect("terminalize before cleanup");
    let terminal = ledger
        .get_attempt(&attempt.id)
        .expect("read terminal")
        .expect("terminal Attempt");
    assert_eq!(terminal.state, AttemptState::Superseded);
    let unknown: Observation<PreservationRecord> = Observation::Unknown {
        source: "liveness".into(),
        reason: "probe timeout".into(),
    };
    let err = PreservationDecision::for_workspace_cleanup(&unknown, &terminal)
        .expect_err("unknown cannot construct cleanup authority");
    assert!(matches!(err, DomainError::StaleAuthority(_)));
    let record = PreservationRecord::for_attempt(
        &terminal,
        PreservationOperation::CleanupWorkspace,
        Digest::of(b"preservation-receipt"),
        PreservationOutcome::Preserved,
    );
    let decision =
        PreservationDecision::for_workspace_cleanup(&Observation::value(record), &terminal)
            .expect("exact preservation constructs decision");
    let digest = LeaseService::authorize_workspace_cleanup(decision, &terminal)
        .expect("superseded salvage authorizes exact cleanup");
    assert_eq!(digest, Digest::of(b"preservation-receipt"));
}

#[test]
fn corrupt_or_superseded_active_lease_fails_closed() {
    let dir = support::private_tempdir();
    let path = dir.path().join("corrupt-active.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(&mut ledger, "corrupt-active", &plan(), &ts(0)).expect("plan");
    let (_attempt, _token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "corrupt-active-a", 5).expect("lease");
    drop(ledger);

    Connection::open(&path)
        .expect("raw open")
        .execute(
            "UPDATE attempts SET state = 'superseded' WHERE id = ?1",
            [grant.attempt.id.as_str()],
        )
        .expect("inject terminal holder");

    let mut ledger = SqliteLedger::open(&path).expect("reopen");
    assert_eq!(
        ledger
            .heartbeat(&LeaseService::heartbeat_of(&grant))
            .expect_err("superseded cannot heartbeat")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    drop(ledger);
    force_expired(&path);
    let mut ledger = SqliteLedger::open(&path).expect("reopen expired");
    assert_eq!(
        ledger
            .expire_leases()
            .expect_err("terminal holder is corrupt lease truth")
            .reason_code(),
        "STORE_FAILURE"
    );
    assert!(ledger
        .get_lease(&grant.lease.variant_id)
        .expect("read lease")
        .is_some());
}
