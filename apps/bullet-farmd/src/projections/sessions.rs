//! Spec section 25.7 Session Supervisor: every attempt row grouped by state,
//! whether it currently holds the writer lease, and the lease events the
//! audit log durably recorded for it. Attempt rows carry no timestamps; the
//! only times shown come from durable events, never from a guess.

use super::{count_labels, package_missions, LabelCount};
use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::store::ProjectionReader;
use bullet_application::{ActiveLease, LeaseGrant, Ledger, LedgerError, LedgerEvent};
use bullet_domain::{Attempt, AttemptState};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const STATES: [AttemptState; 12] = [
    AttemptState::Created,
    AttemptState::Starting,
    AttemptState::Running,
    AttemptState::Paused,
    AttemptState::Checkpointing,
    AttemptState::Preparing,
    AttemptState::Succeeded,
    AttemptState::Superseded,
    AttemptState::Failed,
    AttemptState::Crashed,
    AttemptState::Cancelled,
    AttemptState::Quarantined,
];

/// One durable lease event that names an attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LeaseEventRef {
    seq: u64,
    at: String,
    kind: String,
}

#[derive(Serialize)]
pub(crate) struct AttemptRow {
    id: String,
    variant_id: String,
    work_package_id: String,
    mission_id: Option<String>,
    fence: u64,
    runner_id: String,
    runner_epoch: u64,
    workspace_id: String,
    scope_revision: u64,
    context_revision: u64,
    state: String,
    /// `held` when an active lease row names this attempt, else `none`.
    lease: &'static str,
    /// Time of the durable `attempt_leased` event, when one exists.
    leased_at: Option<String>,
    /// Newest durable lease event naming this attempt, when one exists.
    last_lease_event: Option<LeaseEventRef>,
}

/// Session Supervisor projection body.
#[derive(Serialize)]
pub(crate) struct SessionSupervisorView {
    attempts: Vec<AttemptRow>,
    state_counts: Vec<LabelCount>,
}

#[derive(Default)]
pub(crate) struct LeaseHistory {
    leased_at: Option<String>,
    last: Option<LeaseEventRef>,
}

/// Index lease events by attempt id. `attempt_leased` bodies are the stored
/// grant; expiry and release bodies are the attempt id.
fn lease_history(events: &[LedgerEvent]) -> Result<BTreeMap<String, LeaseHistory>, LedgerError> {
    let mut out: BTreeMap<String, LeaseHistory> = BTreeMap::new();
    for event in events {
        let attempt_id = match event.kind.as_str() {
            "attempt_leased" => {
                let grant: LeaseGrant = serde_json::from_str(&event.body).map_err(|err| {
                    LedgerError::Store(format!(
                        "attempt_leased event {} body is not a lease grant: {err}",
                        event.seq
                    ))
                })?;
                grant.attempt.id.to_string()
            }
            "lease_expired" | "lease_released" => event.body.clone(),
            _ => continue,
        };
        let history = out.entry(attempt_id).or_default();
        if event.kind == "attempt_leased" {
            history.leased_at = Some(event.at.clone());
        }
        if history
            .last
            .as_ref()
            .is_none_or(|last| last.seq < event.seq)
        {
            history.last = Some(LeaseEventRef {
                seq: event.seq,
                at: event.at.clone(),
                kind: event.kind.clone(),
            });
        }
    }
    Ok(out)
}

pub(crate) fn build(
    attempts: Vec<Attempt>,
    leases: &[ActiveLease],
    missions: &BTreeMap<String, String>,
    history: &BTreeMap<String, LeaseHistory>,
) -> SessionSupervisorView {
    let held: BTreeSet<&str> = leases
        .iter()
        .map(|lease| lease.attempt_id.as_str())
        .collect();
    let state_counts = count_labels(
        STATES.iter().map(|state| state.as_str()),
        attempts.iter().map(|attempt| attempt.state.as_str()),
    );
    let rows = attempts
        .into_iter()
        .map(|attempt| {
            let history = history.get(attempt.id.as_str());
            AttemptRow {
                lease: if held.contains(attempt.id.as_str()) {
                    "held"
                } else {
                    "none"
                },
                leased_at: history.and_then(|history| history.leased_at.clone()),
                last_lease_event: history.and_then(|history| history.last.clone()),
                mission_id: missions.get(attempt.work_package_id.as_str()).cloned(),
                id: attempt.id.to_string(),
                variant_id: attempt.variant_id.to_string(),
                work_package_id: attempt.work_package_id.to_string(),
                fence: attempt.fence,
                runner_id: attempt.runner_id.to_string(),
                runner_epoch: attempt.runner_epoch,
                workspace_id: attempt.workspace_id.to_string(),
                scope_revision: attempt.scope_revision,
                context_revision: attempt.context_revision,
                state: attempt.state.as_str().to_string(),
            }
        })
        .collect();
    SessionSupervisorView {
        attempts: rows,
        state_counts,
    }
}

pub(crate) fn read<L: Ledger + ProjectionReader>(
    ledger: &L,
) -> Result<SessionSupervisorView, LedgerError> {
    let attempts = ledger.list_all_attempts()?;
    let leases = ledger.list_leases()?;
    let missions = package_missions(ledger)?;
    let history = lease_history(&ledger.list_events()?)?;
    Ok(build(attempts, &leases, &missions, &history))
}

pub(crate) async fn sessions(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, as_of_sequence) = ledger.read_snapshot(read)?;
    snapshot_response(view, as_of_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::{materialize_plan, LeaseService, MemoryLedger, PlanInput};
    use bullet_domain::TaskClass;

    #[test]
    fn memory_ledger_projects_held_then_released_lease_from_durable_events() {
        let mut ledger = MemoryLedger::new();
        let graph = materialize_plan(
            &mut ledger,
            "sessions-seed",
            &PlanInput {
                title: "sessions".into(),
                objective: "project attempts".into(),
                packages: vec![("pkg".into(), TaskClass::BoundedBugFix)],
            },
            "2026-08-25T00:00:00.000Z",
        )
        .expect("materialize");
        let empty = read(&ledger).expect("empty read");
        assert!(empty.attempts.is_empty());
        assert_eq!(empty.state_counts.len(), 12);
        assert!(empty.state_counts.iter().all(|row| row.count == 0));

        let (attempt, _token, grant) =
            LeaseService::acquire(&mut ledger, &graph, 0, "sessions-a", 15).expect("acquire");
        let view = read(&ledger).expect("read");
        let row = &view.attempts[0];
        assert_eq!(row.id, attempt.id.to_string());
        assert_eq!((row.lease, row.state.as_str()), ("held", "starting"));
        assert_eq!(row.mission_id.as_deref(), Some(graph.mission.id.as_str()));
        assert_eq!(
            row.leased_at.as_deref(),
            Some(grant.lease.heartbeat_at.as_str())
        );
        assert_eq!(
            row.last_lease_event
                .as_ref()
                .map(|event| event.kind.as_str()),
            Some("attempt_leased")
        );
        let fleet = super::super::fleet::read(&ledger).expect("fleet");
        assert_eq!(fleet.leases.len(), 1);
        assert_eq!(fleet.leases[0].liveness, "live");
        assert_eq!(fleet.leases[0].attempt_state.as_deref(), Some("starting"));
        assert!(fleet.ready_queue.is_empty());

        LeaseService::release(&mut ledger, &grant, AttemptState::Cancelled, true).expect("release");
        let view = read(&ledger).expect("read after release");
        let row = &view.attempts[0];
        assert_eq!((row.lease, row.state.as_str()), ("none", "cancelled"));
        assert_eq!(
            row.last_lease_event
                .as_ref()
                .map(|event| event.kind.as_str()),
            Some("lease_released")
        );
        let cancelled = view
            .state_counts
            .iter()
            .find(|row| row.label == "cancelled")
            .expect("catalog row");
        assert_eq!(cancelled.count, 1);
        let fleet = super::super::fleet::read(&ledger).expect("fleet");
        assert!(fleet.leases.is_empty());
        assert_eq!(fleet.ready_queue.len(), 1);
    }

    #[test]
    fn corrupt_attempt_leased_body_is_a_store_failure_not_a_missing_row() {
        let event = LedgerEvent {
            seq: 1,
            at: "2026-08-25T00:00:00.000Z".into(),
            kind: "attempt_leased".into(),
            body: "not a grant".into(),
            event_id: None,
            stream_id: None,
            sequence: None,
            causation_id: None,
            correlation_id: None,
            authority_token_hash: None,
        };
        assert!(lease_history(&[event]).is_err());
    }
}
