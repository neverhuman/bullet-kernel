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
    let mut clock = 0i64;
    for op in ops {
        clock += 10;
        match op % 3 {
            0 => {
                counter += 1;
                let seed = format!("prop-{counter}");
                match LeaseService::acquire(&mut ledger, &graph, 0, &seed, t(clock), 30) {
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
                    LeaseService::release(
                        &mut ledger,
                        &grant,
                        AttemptState::Cancelled,
                        true,
                        t(clock),
                    )
                    .map_err(|err| TestCaseError::fail(format!("release: {err}")))?;
                }
            }
            _ => {
                let expired = ledger
                    .expire_leases(&ts(clock + 40))
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
