use bullet_domain::AuthorityToken;
use bullet_harness_core::{
    authenticate_candidate_preparation_grant, candidate_preparation_scope_paths_digest,
    CandidatePreparationGrantV1, CandidatePreparationVerificationKey,
    SignedCandidatePreparationGrantV1,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareCandidateRequest {
    change: ChangeRequest,
    provenance: CandidateProvenanceRequest,
    candidate_preparation_grant: SignedCandidatePreparationGrantV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeRequest {
    id: String,
    mission: String,
    acceptance_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateProvenanceRequest {
    schema_version: u32,
    repository_id: String,
    producing_attempt_id: String,
    attempt_fence: u64,
    work_package_id: String,
    variant_id: String,
    plan_revision_id: String,
    graph_revision_id: String,
    base_checkpoint_id: String,
    base_commit: String,
    parent_candidate_ids: Vec<String>,
    granted_scope: Vec<String>,
    context_capsule_id: String,
    configuration_snapshot_id: String,
    policy_snapshot_id: String,
    routing_snapshot_id: String,
    environment_digest: String,
    toolchain_digest: String,
}

pub(crate) struct AuthenticatedCandidatePreparation {
    pub(crate) claims: CandidatePreparationGrantV1,
    pub(crate) signed: SignedCandidatePreparationGrantV1,
}

pub(super) fn authenticate(
    params: &Value,
    authority: &Value,
    key: &CandidatePreparationVerificationKey,
) -> Result<AuthenticatedCandidatePreparation, (String, String)> {
    let request: PrepareCandidateRequest = serde_json::from_value(params.clone())
        .map_err(|error| refused(format!("strict prepare-candidate request: {error}")))?;
    let token: AuthorityToken = serde_json::from_value(authority.clone())
        .map_err(|error| refused(format!("strict authority token: {error}")))?;
    let claims =
        authenticate_candidate_preparation_grant(&request.candidate_preparation_grant, key)
            .map_err(|error| (error.reason_code().to_owned(), error.to_string()))?;
    require_request_binding(&request, &claims, &token)?;
    Ok(AuthenticatedCandidatePreparation {
        claims,
        signed: request.candidate_preparation_grant,
    })
}

fn require_request_binding(
    request: &PrepareCandidateRequest,
    claims: &CandidatePreparationGrantV1,
    token: &AuthorityToken,
) -> Result<(), (String, String)> {
    let provenance = &request.provenance;
    let authority_token_digest = token
        .digest()
        .map_err(|error| refused(format!("authority token digest: {error}")))?
        .to_hex();
    let scope_digest = candidate_preparation_scope_paths_digest(&provenance.granted_scope)
        .map_err(|error| refused(format!("granted scope digest: {error}")))?;
    let acceptance_root = token
        .acceptance_contract_id
        .as_str()
        .strip_prefix("acc_")
        .ok_or_else(|| refused("authority token acceptance contract has the wrong prefix"))?;
    let coherent = request.change.id == claims.change_id
        && request.change.mission == claims.mission_id
        && request.change.acceptance_root == acceptance_root
        && claims.authority_token_digest == authority_token_digest
        && provenance.schema_version == 1
        && provenance.repository_id == claims.repository_id
        && provenance.repository_id == token.repository_id.as_str()
        && provenance.producing_attempt_id == claims.attempt_id
        && provenance.producing_attempt_id == token.attempt_id.as_str()
        && provenance.attempt_fence == claims.attempt_fence
        && provenance.attempt_fence == token.attempt_fence
        && provenance.work_package_id == claims.work_package_id
        && provenance.work_package_id == token.work_package_id.as_str()
        && provenance.variant_id == claims.variant_id
        && provenance.variant_id == token.variant_id.as_str()
        && provenance.plan_revision_id == claims.plan_revision_id
        && provenance.plan_revision_id == token.plan_revision_id.as_str()
        && provenance.graph_revision_id == claims.graph_revision_id
        && !provenance.base_checkpoint_id.is_empty()
        && !provenance.base_commit.is_empty()
        && provenance.parent_candidate_ids == claims.parent_candidate_ids
        && scope_digest == claims.scope_grant_digest
        && provenance.context_capsule_id == claims.context_capsule_id
        && provenance.configuration_snapshot_id
            == format!("cnt_{}", token.config_snapshot_hash.to_hex())
        && provenance.policy_snapshot_id == format!("cnt_{}", token.policy_snapshot_hash.to_hex())
        && provenance.routing_snapshot_id == format!("cnt_{}", token.routing_policy_hash.to_hex())
        && provenance.environment_digest == claims.environment_digest
        && provenance.toolchain_digest == claims.toolchain_digest;
    if coherent {
        Ok(())
    } else {
        Err(refused(
            "prepare-candidate request differs from authenticated Candidate authority",
        ))
    }
}

fn refused(message: impl Into<String>) -> (String, String) {
    ("CANDIDATE_PREPARATION_REFUSED".to_owned(), message.into())
}
