use super::{CallResult, RpcRequest};
use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    CandidatePreparationAuthoritySnapshot, CandidatePreparationSigningKey,
    CandidatePreparationSource, CandidatePreparationStore, LedgerCandidatePreparationIssuer,
    StoredCandidatePreparationGrant,
};
use bullet_domain::{AttemptId, RunnerId};
use serde::{Deserialize, Serialize};

const INVALID: &str = "CANDIDATE_PREPARATION_REQUEST_INVALID";
const NOT_FOUND: &str = "CANDIDATE_PREPARATION_GRANT_NOT_FOUND";

pub(super) fn is_method(method: &str) -> bool {
    matches!(
        method,
        "candidate_authority" | "candidate_register" | "candidate_prepare" | "candidate_readback"
    )
}

pub(super) fn call(
    ledger: &mut SqliteLedger,
    key: &CandidatePreparationSigningKey,
    hello_runner: &RunnerId,
    hello_epoch: u64,
    request: &RpcRequest,
) -> CallResult {
    match request.method.as_str() {
        "candidate_authority" => {
            let params: CandidateAuthorityRequest = parse_params(request)?;
            let attempt_id = parse_attempt(&params.attempt_id)?;
            let authority = authority(ledger, &attempt_id, hello_runner, hello_epoch)?;
            serde_json::to_value(CandidateAuthorityResponse::from(authority))
                .map_err(|error| ("ENCODING", error.to_string()))
        }
        "candidate_register" => {
            let params: CandidateRegisterRequest = parse_params(request)?;
            let attempt_id = params.source.attempt_id.clone();
            let authority = authority(ledger, &attempt_id, hello_runner, hello_epoch)?;
            require_current_source(&params.source, &authority, hello_runner, hello_epoch)?;
            let registered = ledger
                .register_candidate_preparation_source(&params.source)
                .map_err(|error| (error.reason_code(), error.to_string()))?;
            serde_json::to_value(CandidateRegisterResponse {
                schema_version: "v1alpha1",
                attempt_id: attempt_id.to_string(),
                request_digest: registered.request_digest,
            })
            .map_err(|error| ("ENCODING", error.to_string()))
        }
        "candidate_prepare" => {
            let params: CandidateRequest = parse_params(request)?;
            let attempt_id = parse_attempt(&params.attempt_id)?;
            require_digest(&params.request_digest)?;
            let record = LedgerCandidatePreparationIssuer::new(ledger, key)
                .mint_for_workload(
                    &params.request_digest,
                    &attempt_id,
                    hello_runner,
                    hello_epoch,
                )
                .map_err(|error| (error.reason_code(), error.to_string()))?;
            response(record)
        }
        "candidate_readback" => {
            let params: CandidateRequest = parse_params(request)?;
            let attempt_id = parse_attempt(&params.attempt_id)?;
            require_digest(&params.request_digest)?;
            let source = ledger
                .get_candidate_preparation_source(&params.request_digest)
                .map_err(|error| (error.reason_code(), error.to_string()))?
                .ok_or((
                    "CANDIDATE_PREPARATION_SOURCE_MISSING",
                    "Candidate-preparation source is absent".to_owned(),
                ))?;
            if source.source.attempt_id != attempt_id {
                return Err(subject_mismatch());
            }
            if ledger
                .get_candidate_preparation_grant(&params.request_digest)
                .map_err(|error| (error.reason_code(), error.to_string()))?
                .is_none()
            {
                return Err((
                    NOT_FOUND,
                    "Candidate-preparation grant is absent".to_owned(),
                ));
            }
            let record = LedgerCandidatePreparationIssuer::new(ledger, key)
                .mint_for_workload(
                    &params.request_digest,
                    &attempt_id,
                    hello_runner,
                    hello_epoch,
                )
                .map_err(|error| (error.reason_code(), error.to_string()))?;
            response(record)
        }
        _ => unreachable!("candidate call is routed only for candidate methods"),
    }
}

fn authority(
    ledger: &mut SqliteLedger,
    attempt_id: &AttemptId,
    hello_runner: &RunnerId,
    hello_epoch: u64,
) -> Result<CandidatePreparationAuthoritySnapshot, (&'static str, String)> {
    let snapshot = ledger
        .with_candidate_preparation(|transaction| transaction.authority_snapshot(attempt_id))
        .map_err(|error| (error.reason_code(), error.to_string()))?;
    if snapshot.runner_id != hello_runner.as_str() || snapshot.runner_epoch != hello_epoch {
        return Err(subject_mismatch());
    }
    Ok(snapshot)
}

fn require_current_source(
    source: &CandidatePreparationSource,
    authority: &CandidatePreparationAuthoritySnapshot,
    hello_runner: &RunnerId,
    hello_epoch: u64,
) -> Result<(), (&'static str, String)> {
    source
        .validate()
        .map_err(|error| (error.reason_code(), error.to_string()))?;
    let envelope = &source.execution_envelope;
    let exact = source.attempt_id.as_str() == authority.attempt_id
        && envelope.runner_id == hello_runner.as_str()
        && envelope.runner_epoch == hello_epoch
        && envelope.authority_epoch == authority.authority_epoch
        && envelope.freeze_generation == authority.freeze_generation
        && envelope.issued_at_unix_ms <= authority.now_unix_ms
        && envelope.expires_at_unix_ms > authority.now_unix_ms;
    exact.then_some(()).ok_or_else(subject_mismatch)
}

fn parse_attempt(raw: &str) -> Result<AttemptId, (&'static str, String)> {
    AttemptId::parse(raw).map_err(|error| (INVALID, format!("invalid attempt_id: {error}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRequest {
    attempt_id: String,
    request_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateAuthorityRequest {
    attempt_id: String,
}

#[derive(Serialize)]
struct CandidateAuthorityResponse {
    schema_version: &'static str,
    attempt_id: String,
    authority_epoch: u64,
    freeze_generation: u64,
    now_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
}

impl From<CandidatePreparationAuthoritySnapshot> for CandidateAuthorityResponse {
    fn from(snapshot: CandidatePreparationAuthoritySnapshot) -> Self {
        Self {
            schema_version: "v1alpha1",
            attempt_id: snapshot.attempt_id,
            authority_epoch: snapshot.authority_epoch,
            freeze_generation: snapshot.freeze_generation,
            now_unix_ms: snapshot.now_unix_ms,
            lease_expires_at_unix_ms: snapshot.lease_expires_at_unix_ms,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRegisterRequest {
    source: CandidatePreparationSource,
}

#[derive(Serialize)]
struct CandidateRegisterResponse {
    schema_version: &'static str,
    attempt_id: String,
    request_digest: String,
}

#[derive(Serialize)]
struct CandidateResponse {
    schema_version: &'static str,
    request_digest: String,
    attempt_id: String,
    candidate_preparation_grant_id: String,
    signed_grant_canonical_json: String,
    envelope_digest: String,
}

fn parse_params<T: for<'de> Deserialize<'de>>(
    request: &RpcRequest,
) -> Result<T, (&'static str, String)> {
    serde_json::from_value(request.params.clone())
        .map_err(|error| (INVALID, format!("strict Candidate request: {error}")))
}

fn response(record: StoredCandidatePreparationGrant) -> CallResult {
    let signed_grant_canonical_json = String::from_utf8(record.signed_bytes)
        .map_err(|_| ("ENCODING", "stored signed grant is not UTF-8".to_owned()))?;
    serde_json::to_value(CandidateResponse {
        schema_version: "v1alpha1",
        request_digest: record.grant.request_digest,
        attempt_id: record.grant.attempt_id,
        candidate_preparation_grant_id: record.grant.candidate_preparation_grant_id,
        signed_grant_canonical_json,
        envelope_digest: record.envelope_digest,
    })
    .map_err(|error| ("ENCODING", error.to_string()))
}

fn require_digest(value: &str) -> Result<(), (&'static str, String)> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err((INVALID, "request_digest is not 64 lowercase hex".to_owned()))
    }
}

fn subject_mismatch() -> (&'static str, String) {
    (
        "CANDIDATE_PREPARATION_REFUSED",
        "authenticated workload differs from the durable Attempt incarnation".to_owned(),
    )
}
