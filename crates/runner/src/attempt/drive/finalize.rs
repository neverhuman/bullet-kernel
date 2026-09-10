//! Preserved-attempt finalization. No failure here may requeue a second release.

use super::{check_freeze, AttemptOutcome, WorkspaceSession};
use crate::error::RunnerError;
use crate::heartbeat::HeartbeatHandle;
use crate::journal::{require_journal, JournalSink};
use crate::lease::{LeaseClient, ReleaseCall};
use bullet_domain::AttemptState;
use bullet_harness_core::{HarnessAdapter, SessionHandle};

pub(super) async fn finish(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
    outcome: AttemptOutcome,
) -> Result<AttemptOutcome, RunnerError> {
    // A typed refusal from terminate is not evidence of process termination.
    // Keep the Candidate and avoid release/deletion until the adapter acks.
    let acknowledgement = adapter.terminate(session).await.map_err(|error| {
        unresolved(
            &outcome,
            journal,
            "provider_termination",
            RunnerError::from(error),
        )
    })?;
    if !acknowledgement.acknowledged {
        return Err(unresolved(
            &outcome,
            journal,
            "provider_termination",
            RunnerError::Protocol("provider termination was not acknowledged".into()),
        ));
    }
    let facts = serde_json::json!({
        "attempt_id": outcome.attempt_id,
        "candidate_id": outcome.candidate.id,
        "receipt_digest": outcome.preservation.receipt.digest,
        "destination": outcome.preservation.receipt.destination,
    })
    .to_string();
    require_journal(journal, "candidate_preserved", &facts)
        .map_err(|error| unresolved(&outcome, journal, "preservation_journal", error))?;
    require_journal(journal, "terminated", "success")
        .map_err(|error| unresolved(&outcome, journal, "termination_journal", error))?;
    check_freeze(heartbeat)
        .map_err(|error| unresolved(&outcome, journal, "pre_release_authority", error))?;

    // Terminal release precedes receipt-gated deletion. A response loss can
    // follow either mutation, so preserve the exact recovery subject on error.
    client
        .release(&ReleaseCall {
            attempt_id: outcome.attempt_id.clone(),
            outcome: AttemptState::Succeeded,
            requeue: false,
        })
        .await
        .map_err(|error| unresolved(&outcome, journal, "release", error))?;
    require_journal(journal, "released", "succeeded")
        .map_err(|error| unresolved(&outcome, journal, "release_journal", error))?;
    gitd.cleanup(
        &outcome.preservation.receipt,
        &outcome.candidate.prepared_at,
    )
    .await
    .map_err(|error| unresolved(&outcome, journal, "workspace_cleanup", error))?;
    require_journal(journal, "workspace_cleaned", &outcome.candidate.id)
        .map_err(|error| unresolved(&outcome, journal, "cleanup_journal", error))?;
    Ok(outcome)
}

fn unresolved(
    outcome: &AttemptOutcome,
    journal: &dyn JournalSink,
    stage: &'static str,
    primary: RunnerError,
) -> RunnerError {
    // Record references, never the receipt's cleanup bearer token. Neither a
    // refusal nor this record proves the artifact still exists or is intact.
    let detail = serde_json::json!({
        "stage": stage, "reason": primary.reason_code(),
        "attempt_id": outcome.attempt_id, "candidate_id": outcome.candidate.id,
        "receipt_digest": outcome.preservation.receipt.digest,
        "destination": outcome.preservation.receipt.destination,
    })
    .to_string();
    let recovery_journal_error = journal
        .try_record("finalization_unresolved", &detail)
        .err()
        .map(String::into_boxed_str);
    RunnerError::FinalizationUnresolved {
        stage,
        attempt_id: outcome.attempt_id.to_string().into_boxed_str(),
        candidate_id: outcome.candidate.id.clone().into_boxed_str(),
        receipt_digest: outcome.preservation.receipt.digest.clone().into_boxed_str(),
        destination: outcome
            .preservation
            .receipt
            .destination
            .clone()
            .into_boxed_path(),
        primary: Box::new(primary),
        recovery_journal_error,
    }
}
