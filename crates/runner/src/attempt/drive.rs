//! Attempt startup, state transition, and successful finish orchestration.

mod candidate;

use super::cleanup::cleanup_failure;
use super::session::session_loop;
use super::workspace::WorkspaceSession;
use super::{check_freeze, start_request, AttemptConfig, AttemptOutcome, CandidatePreservation};
use crate::error::RunnerError;
use crate::gitd::{WorkspaceGenerationGuard, WorkspaceInfo};
use crate::heartbeat::HeartbeatHandle;
use crate::journal::JournalSink;
use crate::lease::{AcquireGrant, LeaseClient, ReleaseCall};
use bullet_domain::AttemptState;
use bullet_harness_core::{HarnessAdapter, SessionHandle};
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_cloned_attempt_guarded(
    client: Arc<dyn LeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<dyn JournalSink>,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    gitd: &mut dyn WorkspaceSession,
    ws: &mut WorkspaceInfo,
    generation_guard: &mut WorkspaceGenerationGuard,
    heartbeat: HeartbeatHandle,
) -> Result<AttemptOutcome, RunnerError> {
    config.preservation_destination()?;
    if let Err(error) = check_freeze(&heartbeat) {
        heartbeat.abort();
        cleanup_before_session(
            client.as_ref(),
            grant,
            journal.as_ref(),
            "pre_session_frozen",
            &error,
        )
        .await;
        return Err(error);
    }
    let session = match adapter.start(start_request(grant, ws, config)).await {
        Ok(session) => session,
        Err(error) => {
            heartbeat.abort();
            let error = RunnerError::from(error);
            cleanup_before_session(
                client.as_ref(),
                grant,
                journal.as_ref(),
                "session_start_refused",
                &error,
            )
            .await;
            return Err(error);
        }
    };
    if let Err(error) = client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
    {
        heartbeat.abort();
        cleanup_failure(
            client.as_ref(),
            adapter.as_ref(),
            gitd,
            grant,
            config,
            journal.as_ref(),
            &session,
            &error,
        )
        .await;
        return Err(error);
    }
    match drive_and_finish(
        client.as_ref(),
        adapter.as_ref(),
        gitd,
        ws,
        grant,
        config,
        journal.as_ref(),
        &heartbeat,
        &session,
        generation_guard,
    )
    .await
    {
        Ok(outcome) => {
            heartbeat.abort();
            let _ = adapter.terminate(&session).await;
            journal.record("terminated", "success");
            Ok(outcome)
        }
        Err(err) => {
            heartbeat.abort();
            cleanup_failure(
                client.as_ref(),
                adapter.as_ref(),
                gitd,
                grant,
                config,
                journal.as_ref(),
                &session,
                &err,
            )
            .await;
            Err(err)
        }
    }
}

pub(super) async fn cleanup_before_session(
    client: &dyn LeaseClient,
    grant: &AcquireGrant,
    journal: &dyn JournalSink,
    stage: &'static str,
    error: &RunnerError,
) {
    journal.record(stage, error.reason_code());
    let released = client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Failed,
            requeue: true,
        })
        .await;
    journal.record(
        "released",
        &format!("failed requeue=true ok={}", released.is_ok()),
    );
}

#[allow(clippy::too_many_arguments)]
async fn drive_and_finish(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    ws: &mut WorkspaceInfo,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    heartbeat: &HeartbeatHandle,
    session: &SessionHandle,
    generation_guard: &mut WorkspaceGenerationGuard,
) -> Result<AttemptOutcome, RunnerError> {
    let capsule = config.capsule(grant, ws);
    let (gates, rounds) = session_loop(
        adapter,
        gitd,
        ws,
        &grant.authority_token,
        &capsule,
        config,
        journal,
        heartbeat,
        session,
        generation_guard,
    )
    .await?;
    check_freeze(heartbeat)?;
    client
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await?;
    let checkpoint = candidate::current_checkpoint(ws);
    let request = candidate::prepare_request(client, grant, config, ws, &checkpoint).await?;
    check_freeze(heartbeat)?;
    journal.record(
        "candidate_grant_authenticated",
        request.provenance.producing_attempt_id.as_str(),
    );
    let candidate = gitd.prepare_candidate(&request).await?;
    journal.record("candidate_prepared", &candidate.id);
    let destination = config.preservation_destination()?.to_path_buf();
    let receipt = gitd.preserve(&destination).await?;
    let preservation = CandidatePreservation::bind(&candidate, grant, &destination, receipt)?;
    journal.record(
        "candidate_preserved",
        &format!(
            "{} {} {}",
            preservation.candidate_id,
            preservation.receipt.digest,
            preservation.receipt.destination.display()
        ),
    );
    check_freeze(heartbeat)?;
    gitd.cleanup(&preservation.receipt, &candidate.prepared_at)
        .await?;
    journal.record("workspace_cleaned", &candidate.id);
    check_freeze(heartbeat)?;
    client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Succeeded,
            requeue: false,
        })
        .await?;
    journal.record("released", "succeeded");
    Ok(AttemptOutcome {
        attempt_id: grant.attempt.id.clone(),
        fence: grant.attempt.fence,
        candidate,
        preservation,
        repair_rounds: rounds,
        gates,
    })
}
