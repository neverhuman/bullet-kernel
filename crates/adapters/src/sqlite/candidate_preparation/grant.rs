use super::{candidate_store, source, step};
use crate::sqlite::{events, outbox};
use bullet_application::candidate_preparation::{
    CandidatePreparationError, CandidatePreparationGrantV1, SignedCandidatePreparationGrantV1,
    StoredCandidatePreparationGrant,
};
use rusqlite::{params, Connection, OptionalExtension};

struct RawGrant {
    grant_id: String,
    nonce: String,
    attempt_id: String,
    variant_id: String,
    fence: i64,
    runner_id: String,
    runner_epoch: i64,
    workspace_id: String,
    scope_revision: i64,
    context_revision: i64,
    authority_epoch: i64,
    freeze_generation: i64,
    graph_revision_id: String,
    scope_digest: String,
    execution_envelope_id: String,
    environment_digest: String,
    toolchain_digest: String,
    issued_at: i64,
    expires_at: i64,
    claims_bytes: Vec<u8>,
    signed_bytes: Vec<u8>,
    envelope_digest: String,
}

const COLUMNS: &str = "candidate_preparation_grant_id, grant_nonce, attempt_id, variant_id, \
    attempt_fence, runner_id, runner_epoch, workspace_id, scope_revision, context_revision, \
    authority_epoch, freeze_generation, graph_revision_id, scope_grant_digest, \
    execution_envelope_id, environment_digest, toolchain_digest, issued_at_unix_ms, \
    expires_at_unix_ms, claims_bytes, signed_bytes, envelope_digest";

pub(super) fn get(
    conn: &Connection,
    request_digest: &str,
) -> Result<Option<StoredCandidatePreparationGrant>, CandidatePreparationError> {
    let raw = conn
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM candidate_preparation_grants WHERE request_digest = ?1"
            ),
            [request_digest],
            |row| {
                Ok(RawGrant {
                    grant_id: row.get(0)?,
                    nonce: row.get(1)?,
                    attempt_id: row.get(2)?,
                    variant_id: row.get(3)?,
                    fence: row.get(4)?,
                    runner_id: row.get(5)?,
                    runner_epoch: row.get(6)?,
                    workspace_id: row.get(7)?,
                    scope_revision: row.get(8)?,
                    context_revision: row.get(9)?,
                    authority_epoch: row.get(10)?,
                    freeze_generation: row.get(11)?,
                    graph_revision_id: row.get(12)?,
                    scope_digest: row.get(13)?,
                    execution_envelope_id: row.get(14)?,
                    environment_digest: row.get(15)?,
                    toolchain_digest: row.get(16)?,
                    issued_at: row.get(17)?,
                    expires_at: row.get(18)?,
                    claims_bytes: row.get(19)?,
                    signed_bytes: row.get(20)?,
                    envelope_digest: row.get(21)?,
                })
            },
        )
        .optional()
        .map_err(candidate_store)?;
    raw.map(|raw| decode(conn, request_digest, raw)).transpose()
}

fn decode(
    conn: &Connection,
    request_digest: &str,
    raw: RawGrant,
) -> Result<StoredCandidatePreparationGrant, CandidatePreparationError> {
    let registered = source::get(conn, request_digest)?
        .ok_or_else(|| candidate_store("grant has no registered source"))?;
    let grant: CandidatePreparationGrantV1 = serde_json::from_slice(&raw.claims_bytes)
        .map_err(|error| candidate_store(format!("stored Candidate grant decode: {error}")))?;
    let signed: SignedCandidatePreparationGrantV1 = serde_json::from_slice(&raw.signed_bytes)
        .map_err(|error| {
            candidate_store(format!("stored signed Candidate grant decode: {error}"))
        })?;
    let record = StoredCandidatePreparationGrant {
        grant,
        signed,
        claims_bytes: raw.claims_bytes,
        signed_bytes: raw.signed_bytes,
        envelope_digest: raw.envelope_digest.clone(),
    };
    record.validate(&registered.source.execution_envelope)?;
    let claim = &record.grant;
    if claim.request_digest != request_digest
        || claim.candidate_preparation_grant_id != raw.grant_id
        || claim.grant_nonce != raw.nonce
        || claim.attempt_id != raw.attempt_id
        || claim.variant_id != raw.variant_id
        || claim.attempt_fence != to_u64(raw.fence)?
        || claim.runner_id != raw.runner_id
        || claim.runner_epoch != to_u64(raw.runner_epoch)?
        || claim.workspace_id != raw.workspace_id
        || claim.scope_revision != to_u64(raw.scope_revision)?
        || claim.context_revision != to_u64(raw.context_revision)?
        || claim.authority_epoch != to_u64(raw.authority_epoch)?
        || claim.freeze_generation != to_u64(raw.freeze_generation)?
        || claim.graph_revision_id != raw.graph_revision_id
        || claim.scope_grant_digest != raw.scope_digest
        || claim.execution_envelope_id != raw.execution_envelope_id
        || claim.environment_digest != raw.environment_digest
        || claim.toolchain_digest != raw.toolchain_digest
        || claim.issued_at_unix_ms != to_u64(raw.issued_at)?
        || claim.expires_at_unix_ms != to_u64(raw.expires_at)?
        || record.envelope_digest != raw.envelope_digest
    {
        return Err(candidate_store(
            "normalized Candidate-preparation grant columns are corrupt",
        ));
    }
    Ok(record)
}

pub(super) fn put(
    conn: &Connection,
    fail_after: &mut Option<u8>,
    record: &StoredCandidatePreparationGrant,
) -> Result<(), CandidatePreparationError> {
    let claim = &record.grant;
    let registered = source::get(conn, &claim.request_digest)?
        .ok_or(CandidatePreparationError::SourceMissing)?;
    record.validate(&registered.source.execution_envelope)?;
    conn.execute(
        "INSERT INTO candidate_preparation_grants (
           request_digest, candidate_preparation_grant_id, grant_nonce, attempt_id, variant_id,
           attempt_fence, runner_id, runner_epoch, workspace_id, scope_revision, context_revision,
           authority_epoch, freeze_generation, graph_revision_id, scope_grant_digest,
           execution_envelope_id, environment_digest, toolchain_digest, issued_at_unix_ms,
           expires_at_unix_ms, claims_bytes, signed_bytes, envelope_digest
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
           ?18, ?19, ?20, ?21, ?22, ?23
         )",
        params![
            claim.request_digest,
            claim.candidate_preparation_grant_id,
            claim.grant_nonce,
            claim.attempt_id,
            claim.variant_id,
            to_i64(claim.attempt_fence)?,
            claim.runner_id,
            to_i64(claim.runner_epoch)?,
            claim.workspace_id,
            to_i64(claim.scope_revision)?,
            to_i64(claim.context_revision)?,
            to_i64(claim.authority_epoch)?,
            to_i64(claim.freeze_generation)?,
            claim.graph_revision_id,
            claim.scope_grant_digest,
            claim.execution_envelope_id,
            claim.environment_digest,
            claim.toolchain_digest,
            to_i64(claim.issued_at_unix_ms)?,
            to_i64(claim.expires_at_unix_ms)?,
            record.claims_bytes,
            record.signed_bytes,
            record.envelope_digest,
        ],
    )
    .map_err(candidate_store)?;
    step(fail_after)?;
    events::insert_event(
        conn,
        "candidate_preparation_grant_issued",
        &claim.candidate_preparation_grant_id,
        Some(&claim.attempt_id),
        Some(&claim.request_digest),
        Some(&claim.authority_token_digest),
    )?;
    step(fail_after)?;
    let payload = std::str::from_utf8(&record.signed_bytes)
        .map_err(|_| candidate_store("signed Candidate grant is not UTF-8"))?;
    outbox::enqueue(conn, None, "candidate_verification_requested", payload)?;
    step(fail_after)?;
    Ok(())
}

fn to_i64(value: u64) -> Result<i64, CandidatePreparationError> {
    i64::try_from(value).map_err(candidate_store)
}

fn to_u64(value: i64) -> Result<u64, CandidatePreparationError> {
    u64::try_from(value).map_err(candidate_store)
}
