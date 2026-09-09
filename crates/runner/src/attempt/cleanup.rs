//! Failure cleanup and frozen-attempt salvage.

use super::workspace::WorkspaceSession;
use super::AttemptConfig;
use crate::error::RunnerError;
use crate::gitd::SuccessorResume;
use crate::journal::JournalSink;
use crate::lease::{AcquireGrant, LeaseClient, ReleaseCall};
use bullet_domain::AttemptState;
use bullet_harness_core::{HarnessAdapter, SessionHandle};

async fn salvage_workspace(
    gitd: &mut dyn WorkspaceSession,
    grant: &AcquireGrant,
    config: &AttemptConfig,
) -> Result<SuccessorResume, RunnerError> {
    let checkpoint = gitd.checkpoint().await?;
    let destination = config
        .workspace_root
        .join("salvage")
        .join(grant.attempt.id.as_str());
    if destination.exists() {
        return Err(RunnerError::Protocol(format!(
            "salvage destination already exists: {}",
            destination.display()
        )));
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| RunnerError::Io {
            context: "create salvage parent".into(),
            reason: error.to_string(),
        })?;
    }
    let preservation = gitd.preserve(&destination).await?;
    Ok(SuccessorResume {
        checkpoint,
        preservation,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn cleanup_failure(
    client: &dyn LeaseClient,
    adapter: &dyn HarnessAdapter,
    gitd: &mut dyn WorkspaceSession,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    journal: &dyn JournalSink,
    session: &SessionHandle,
    err: &RunnerError,
) {
    if err.is_frozen() {
        journal.record("frozen", err.reason_code());
        match salvage_workspace(gitd, grant, config).await {
            Ok(resume) => {
                journal.record(
                    "salvage_checkpoint",
                    &format!("{} {}", resume.checkpoint.id, resume.checkpoint.digest),
                );
                journal.record(
                    "salvage_preserved",
                    &format!(
                        "{} {}",
                        resume.preservation.digest,
                        resume.preservation.destination.display()
                    ),
                );
            }
            Err(salvage_err) => journal.record("salvage_failed", &salvage_err.to_string()),
        }
        let _ = adapter.terminate(session).await;
        journal.record("terminated", err.reason_code());
        return;
    }
    let _ = adapter.terminate(session).await;
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
    journal.record("terminated", err.reason_code());
}
