use super::super::AttemptConfig;
use crate::error::RunnerError;
use crate::gitd::{CheckpointBinding, PrepareCandidateRequest, WorkspaceInfo};
use crate::lease::{AcquireGrant, LeaseClient};

pub(super) fn current_checkpoint(workspace: &WorkspaceInfo) -> CheckpointBinding {
    CheckpointBinding {
        id: workspace.active_generation.checkpoint.id.clone(),
        digest: workspace.active_generation.checkpoint.digest.clone(),
    }
}

pub(super) async fn prepare_request(
    client: &dyn LeaseClient,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    workspace: &WorkspaceInfo,
    checkpoint: &CheckpointBinding,
) -> Result<PrepareCandidateRequest, RunnerError> {
    let admission = config.candidate_preparation()?;
    let rpc = client.candidate_preparation_rpc().ok_or_else(|| {
        RunnerError::Protocol(
            "lease client has no peer-authenticated Candidate-preparation RPC".into(),
        )
    })?;
    let prepared = rpc
        .candidate_prepare(&grant.attempt.id, admission.request_digest())
        .await?;
    let readback = rpc.candidate_readback(&prepared).await?;
    if readback != prepared {
        return Err(RunnerError::Protocol(
            "Candidate-preparation readback differs from the prepared grant".into(),
        ));
    }
    let verified = admission.verify(&readback, grant, &config.scope_prefixes)?;
    PrepareCandidateRequest::from_verified_grant(
        grant,
        workspace,
        checkpoint,
        &config.scope_prefixes,
        &verified,
    )
}

#[cfg(test)]
mod tests;
