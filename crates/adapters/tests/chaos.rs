//! Kill/retry suite against the durable ledger. Replay is the recovery path.

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, run_demo, LeaseService, Ledger, PlanInput};
use bullet_domain::{AttemptState, DomainError, TaskClass};
use chrono::{DateTime, Duration, Utc};

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

#[test]
fn sqlite_demo_roundtrip_shows_both_fences() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let receipt = run_demo(&mut ledger).expect("demo");
    assert!(receipt.stale_refused);
    assert!(receipt.materialize_idempotent);
    assert_eq!(receipt.fence, 1);
    assert_eq!(receipt.fence_second, 2);
    assert_eq!(receipt.effect_outcome, "verified");
    assert_eq!(receipt.effect_unknown_outcome, "unknown");
    drop(ledger);
    let mut again = SqliteLedger::open(&path).expect("reopen");
    let second = run_demo(&mut again).expect("idempotent demo");
    assert_eq!(receipt, second);
}

#[test]
fn killed_writer_is_reclaimed_and_successor_gets_next_fence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ledger.sqlite");
    let first_grant = {
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let graph = materialize_plan(&mut ledger, "kill", &plan(), &ts(0)).expect("plan");
        let (_attempt, _token, grant) =
            LeaseService::acquire(&mut ledger, &graph, 0, "kill-a", t(0), 5).expect("lease");
        grant
        // The connection drops here without releasing: a killed process.
    };
    let mut ledger = SqliteLedger::open(&path).expect("recover");
    let graph = materialize_plan(&mut ledger, "kill", &plan(), &ts(0)).expect("replay");
    let expired = ledger.expire_leases(&ts(60)).expect("expire");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].attempt_id, first_grant.attempt.id);
    let crashed = ledger
        .get_attempt(&first_grant.attempt.id)
        .expect("read")
        .expect("attempt");
    assert_eq!(crashed.state, AttemptState::Crashed);
    let (successor, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "kill-b", t(120), 60).expect("successor");
    assert_eq!(successor.fence, first_grant.attempt.fence + 1);
    // The dead incarnation's heartbeat stays refused forever.
    let err = ledger
        .heartbeat(&LeaseService::heartbeat_of(&first_grant, t(130), 60))
        .expect_err("stale");
    assert!(matches!(
        err,
        bullet_application::LedgerError::Domain(DomainError::StaleAuthority(_))
    ));
}

#[test]
fn stale_delta_cannot_rewind_successor_fence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(&mut ledger, "rewind", &plan(), &ts(0)).expect("plan");
    let (first, _token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "rw-a", t(0), 60).expect("first");
    LeaseService::release(&mut ledger, &grant, AttemptState::Cancelled, true, t(10))
        .expect("release");
    let (second, _token2, _grant2) =
        LeaseService::acquire(&mut ledger, &graph, 0, "rw-b", t(20), 60).expect("second");
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
fn unknown_liveness_cannot_destroy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(&mut ledger, "unknown", &plan(), &ts(0)).expect("plan");
    let (attempt, _token, _grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "unk-a", t(0), 60).expect("lease");
    let unknown: bullet_domain::Observation<()> = bullet_domain::Observation::Unknown {
        source: "liveness".into(),
        reason: "probe timeout".into(),
    };
    let err = LeaseService::cleanup_if_verified(&unknown, &attempt).expect_err("blocked");
    assert!(matches!(
        err,
        bullet_application::LedgerError::Domain(DomainError::StaleAuthority(_))
    ));
    let verified = bullet_domain::Observation::value(());
    LeaseService::cleanup_if_verified(&verified, &attempt).expect("verified may clean");
}
