use super::runner_probe::register_candidate_source;
use super::support::{fail, DurableFarmd};
use bullet_domain::Attempt;
use bullet_harness_core::{
    authenticate_candidate_preparation_grant, CandidatePreparationGrantV1,
    SignedCandidatePreparationGrantV1,
};
use bullet_runner_core::{CandidatePreparationRpcClient, SignedLeaseRpcClient};
use std::path::Path;
use std::sync::Arc;

pub(super) async fn authorized_candidate_grant(
    farmd: &DurableFarmd,
    client: &Arc<SignedLeaseRpcClient>,
    _database: &Path,
    attempt: &Attempt,
) -> Result<
    (
        CandidatePreparationGrantV1,
        SignedCandidatePreparationGrantV1,
    ),
    String,
> {
    let request_digest = register_candidate_source(client, attempt).await?;
    let grant = client
        .candidate_prepare(&attempt.id, &request_digest)
        .await
        .map_err(|error| fail(format!("prepare direct Candidate grant: {error}")))?;
    client
        .candidate_readback(&grant)
        .await
        .map_err(|error| fail(format!("read back direct Candidate grant: {error}")))?;
    let claims = authenticate_candidate_preparation_grant(
        grant.signed_grant(),
        &farmd.candidate_verification_key_material,
    )
    .map_err(|error| fail(format!("authenticate direct Candidate grant: {error}")))?;
    Ok((claims, grant.signed_grant().clone()))
}
