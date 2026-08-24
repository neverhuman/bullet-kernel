//! Property tests over open/close/expire sequences (spec section 33.1):
//! never two writers, never a reused fence, replay-safe grants.

use bullet_application::{
    materialize_plan, LeaseGrant, LeaseService, Ledger, MemoryLedger, PlanInput,
};
use bullet_domain::AttemptState;
use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;

fn t(offset: i64) -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(1_780_000_000 + offset)
}

fn ts(offset: i64) -> String {
    LeaseService::rfc3339(t(offset))
}

fn plan() -> PlanInput {
    PlanInput {
        title: "prop".into(),
        objective: "fence properties".into(),
        packages: vec![("pkg".into(), bullet_domain::TaskClass::BoundedBugFix)],
    }
}

fn drive(ops: &[u8]) -> Result<(), TestCaseError> {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(&mut ledger, "prop", &plan(), &ts(0))
        .map_err(|err| TestCaseError::fail(format!("materialize: {err}")))?;
    let mut counter = 0u64;
    let mut granted: Vec<u64> = Vec::new();
    let mut live: Option<LeaseGrant> = None;
    for op in ops {
        match op % 3 {
            0 => {
                counter += 1;
                let seed = format!("prop-{counter}");
                match LeaseService::acquire(&mut ledger, &graph, 0, &seed, 15) {
                    Ok((attempt, _token, grant)) => {
                        prop_assert!(live.is_none(), "second writer granted while one was live");
                        prop_assert!(
                            granted.iter().all(|fence| *fence < attempt.fence),
                            "fence {} reused or decreased (granted: {granted:?})",
                            attempt.fence
                        );
                        granted.push(attempt.fence);
                        live = Some(grant);
                    }
                    Err(_) => {
                        prop_assert!(live.is_some(), "acquire refused with no live writer");
                    }
                }
            }
            1 => {
                if let Some(grant) = live.take() {
                    LeaseService::release(&mut ledger, &grant, AttemptState::Cancelled, true)
                        .map_err(|err| TestCaseError::fail(format!("release: {err}")))?;
                }
            }
            _ => {
                ledger
                    .advance_simulation_time(40)
                    .map_err(|err| TestCaseError::fail(format!("clock: {err}")))?;
                let expired = ledger
                    .expire_leases()
                    .map_err(|err| TestCaseError::fail(format!("expire: {err}")))?;
                if !expired.is_empty() {
                    live = None;
                }
            }
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn fences_are_unique_and_single_writer_holds(ops in proptest::collection::vec(any::<u8>(), 1..24)) {
        drive(&ops)?;
    }
}

#[test]
fn memory_clock_expiry_replay_and_successor_fence_are_exact() {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(&mut ledger, "clock-exact", &plan(), &ts(0)).expect("plan");
    let request = LeaseService::request_for(&graph, 0, "clock-first", 5).expect("request");
    let first = ledger.acquire_lease(&request).expect("first");
    let original = serde_json::to_vec(&first).expect("grant bytes");

    ledger.advance_simulation_time(4).expect("advance");
    let replay = ledger.acquire_lease(&request).expect("exact replay");
    assert_eq!(serde_json::to_vec(&replay).expect("grant bytes"), original);
    ledger.advance_simulation_time(1).expect("exact expiry");
    let expired = ledger.expire_leases().expect("expire");
    assert_eq!(expired.len(), 1, "replay must not renew the lease");
    assert_eq!(expired[0].attempt_id, first.attempt.id);
    assert_eq!(
        ledger
            .heartbeat(&LeaseService::heartbeat_of(&first))
            .expect_err("expired lease cannot revive")
            .reason_code(),
        "STALE_AUTHORITY"
    );

    let (successor, _, _) =
        LeaseService::acquire(&mut ledger, &graph, 0, "clock-second", 5).expect("successor");
    assert_eq!(successor.fence, 2);
}

#[test]
fn invalid_or_changed_memory_ttl_is_inert() {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(&mut ledger, "clock-invalid", &plan(), &ts(0)).expect("plan");
    for ttl in [0, 16] {
        let error =
            LeaseService::acquire(&mut ledger, &graph, 0, "invalid", ttl).expect_err("invalid TTL");
        assert_eq!(error.reason_code(), "INVALID_LEASE_TTL");
    }
    let (_attempt, _, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, "valid", 5).expect("fence one");
    assert_eq!(grant.lease.fence, 1);
    let mut changed = LeaseService::heartbeat_of(&grant);
    changed.ttl_seconds = 6;
    assert_eq!(
        ledger
            .heartbeat(&changed)
            .expect_err("changed TTL")
            .reason_code(),
        "STALE_AUTHORITY"
    );
    ledger.advance_simulation_time(5).expect("advance");
    assert_eq!(ledger.expire_leases().expect("expire").len(), 1);
}
