//! Spec section 25.5 Fleet: every active lease row with its liveness judged
//! against the store's own clock, joined to its attempt and mission, plus the
//! push-maintained ready queue. One atomic read; nothing is inferred.
//!
//! Reclamation is visible here without this projection knowing about it. A dead
//! lease shows as `expired` with its Attempt's live state for at most one
//! maintenance tick (`crate::reaper`); the reclaiming transaction then deletes
//! the `active_leases` row, moves the Attempt to its terminal `Crashed` state
//! and pushes the freed package back onto `ready_queue`, so the next snapshot
//! drops the lease and shows the work as ready. `expired` is therefore a
//! transient the operator may observe, never a resting state.

use super::package_missions;
use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::store::ProjectionReader;
use bullet_application::{ActiveLease, Ledger, LedgerError, ReadyRow};
use bullet_domain::Attempt;
use chrono::DateTime;
use serde::Serialize;
use std::collections::BTreeMap;

/// One active lease row and what the ledger links it to.
#[derive(Serialize)]
pub(crate) struct FleetLease {
    variant_id: String,
    attempt_id: String,
    fence: u64,
    runner_id: String,
    runner_epoch: u64,
    heartbeat_at: String,
    expires_at: String,
    ttl_seconds: i64,
    /// `live`, `expired` (past expiry, not yet reclaimed), or `unknown`
    /// when either timestamp cannot be compared.
    pub(crate) liveness: &'static str,
    /// State of the linked attempt row; `None` is a linkage contradiction.
    pub(crate) attempt_state: Option<String>,
    work_package_id: Option<String>,
    mission_id: Option<String>,
}

/// Fleet projection body.
#[derive(Serialize)]
pub(crate) struct FleetView {
    /// Store clock inside the snapshot; liveness is judged against it.
    pub(crate) authority_time: String,
    pub(crate) leases: Vec<FleetLease>,
    pub(crate) ready_queue: Vec<ReadyRow>,
}

pub(crate) fn liveness(expires_at: &str, authority_time: &str) -> &'static str {
    match (
        DateTime::parse_from_rfc3339(expires_at),
        DateTime::parse_from_rfc3339(authority_time),
    ) {
        (Ok(expiry), Ok(now)) if expiry <= now => "expired",
        (Ok(_), Ok(_)) => "live",
        _ => "unknown",
    }
}

pub(crate) fn build(
    authority_time: String,
    leases: Vec<ActiveLease>,
    attempts: &[Attempt],
    missions: &BTreeMap<String, String>,
    ready_queue: Vec<ReadyRow>,
) -> FleetView {
    let by_attempt: BTreeMap<&str, &Attempt> = attempts
        .iter()
        .map(|attempt| (attempt.id.as_str(), attempt))
        .collect();
    let leases = leases
        .into_iter()
        .map(|lease| {
            let attempt = by_attempt.get(lease.attempt_id.as_str()).copied();
            let work_package_id = attempt.map(|attempt| attempt.work_package_id.to_string());
            FleetLease {
                liveness: liveness(&lease.expires_at, &authority_time),
                attempt_state: attempt.map(|attempt| attempt.state.as_str().to_string()),
                mission_id: work_package_id
                    .as_deref()
                    .and_then(|package| missions.get(package).cloned()),
                work_package_id,
                variant_id: lease.variant_id.to_string(),
                attempt_id: lease.attempt_id.to_string(),
                fence: lease.fence,
                runner_id: lease.runner_id.to_string(),
                runner_epoch: lease.runner_epoch,
                heartbeat_at: lease.heartbeat_at,
                expires_at: lease.expires_at,
                ttl_seconds: lease.ttl_seconds,
            }
        })
        .collect();
    FleetView {
        authority_time,
        leases,
        ready_queue,
    }
}

pub(crate) fn read<L: Ledger + ProjectionReader>(ledger: &L) -> Result<FleetView, LedgerError> {
    let authority_time = ledger.authority_time()?;
    let leases = ledger.list_leases()?;
    let attempts = ledger.list_all_attempts()?;
    let missions = package_missions(ledger)?;
    let ready_queue = ledger.ready_rows()?;
    Ok(build(
        authority_time,
        leases,
        &attempts,
        &missions,
        ready_queue,
    ))
}

pub(crate) async fn fleet(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, as_of_sequence) = ledger.read_snapshot(read)?;
    snapshot_response(view, as_of_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_is_judged_against_the_store_clock_only() {
        assert_eq!(
            liveness("2026-08-25T00:00:15.000Z", "2026-08-25T00:00:14.999Z"),
            "live"
        );
        assert_eq!(
            liveness("2026-08-25T00:00:15.000Z", "2026-08-25T00:00:15.000Z"),
            "expired"
        );
        assert_eq!(
            liveness("2026-08-25T00:00:15.000Z", "2026-08-25T00:00:16.000Z"),
            "expired"
        );
        assert_eq!(liveness("garbage", "2026-08-25T00:00:16.000Z"), "unknown");
        assert_eq!(liveness("2026-08-25T00:00:15.000Z", ""), "unknown");
    }
}
