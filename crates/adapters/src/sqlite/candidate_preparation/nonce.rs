use super::{candidate_store, grant, snapshot};
use crate::sqlite::{events, lease_time};
use bullet_application::candidate_preparation::{
    canonical_candidate_preparation_json, CandidateNonceConsumption, CandidatePreparationError,
    CandidatePreparationGrantV1, SignedCandidatePreparationGrantV1,
    StoredCandidatePreparationGrant,
};
use bullet_domain::{AttemptId, DomainError};
use chrono::DateTime;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub(super) fn consume(
    conn: &mut Connection,
    nonce: &str,
    attempt_id: &str,
) -> Result<CandidateNonceConsumption, CandidatePreparationError> {
    if !lower_hex(nonce) {
        return Ok(CandidateNonceConsumption::Unknown);
    }
    let attempt_id = match AttemptId::parse(attempt_id) {
        Ok(value) => value,
        Err(_) => return Ok(CandidateNonceConsumption::Unknown),
    };
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(candidate_store)?;
    let request_digest: Option<String> = tx
        .query_row(
            "SELECT request_digest FROM candidate_preparation_grants WHERE grant_nonce = ?1",
            [nonce],
            |row| row.get(0),
        )
        .optional()
        .map_err(candidate_store)?;
    let Some(request_digest) = request_digest else {
        tx.commit().map_err(candidate_store)?;
        return Ok(CandidateNonceConsumption::Unknown);
    };
    let record = grant::get(&tx, &request_digest)?
        .ok_or_else(|| candidate_store("Candidate nonce has no grant"))?;
    let result = consume_record(&tx, &record, &attempt_id)?;
    tx.commit().map_err(candidate_store)?;
    Ok(result)
}

pub(super) fn final_check(
    conn: &mut Connection,
    claims: &CandidatePreparationGrantV1,
    signed: &SignedCandidatePreparationGrantV1,
    attempt_id: &AttemptId,
) -> Result<CandidateNonceConsumption, CandidatePreparationError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(candidate_store)?;
    let record = grant::get(&tx, &claims.request_digest)?.ok_or_else(|| {
        CandidatePreparationError::Refused(
            "authenticated Candidate grant is absent from durable truth".to_owned(),
        )
    })?;
    let signed_bytes = canonical_candidate_preparation_json(signed)?;
    if record.grant != *claims
        || record.signed != *signed
        || record.signed_bytes != signed_bytes
        || record.grant.attempt_id != attempt_id.as_str()
    {
        return Err(CandidatePreparationError::Refused(
            "authenticated Candidate grant differs from durable truth".to_owned(),
        ));
    }
    let result = consume_record(&tx, &record, attempt_id)?;
    tx.commit().map_err(candidate_store)?;
    Ok(result)
}

fn consume_record(
    tx: &rusqlite::Transaction<'_>,
    record: &StoredCandidatePreparationGrant,
    attempt_id: &AttemptId,
) -> Result<CandidateNonceConsumption, CandidatePreparationError> {
    let nonce = &record.grant.grant_nonce;
    let consumed: bool = tx
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM candidate_preparation_nonce_consumptions WHERE grant_nonce = ?1
             )",
            [nonce],
            |row| row.get(0),
        )
        .map_err(candidate_store)?;
    if consumed {
        return Ok(CandidateNonceConsumption::Replayed);
    }
    if record.grant.attempt_id != attempt_id.as_str() {
        return Ok(CandidateNonceConsumption::Unknown);
    }
    let now = lease_time::database_time(tx)?;
    if unix_ms(&now)? >= record.grant.expires_at_unix_ms {
        return Ok(CandidateNonceConsumption::Expired);
    }
    let current = match snapshot::authority(tx, attempt_id) {
        Ok(value) => value,
        Err(CandidatePreparationError::Ledger(bullet_application::LedgerError::Domain(
            DomainError::StaleAuthority(_),
        ))) => {
            return Ok(CandidateNonceConsumption::Unknown);
        }
        Err(error) => return Err(error),
    };
    if !same_authority(&record.grant, &current) {
        return Ok(CandidateNonceConsumption::Unknown);
    }
    tx.execute(
        "INSERT INTO candidate_preparation_nonce_consumptions (
           grant_nonce, attempt_id, consumed_at
         ) VALUES (?1, ?2, ?3)",
        params![nonce, attempt_id.as_str(), now],
    )
    .map_err(candidate_store)?;
    events::insert_event(
        tx,
        "candidate_preparation_grant_consumed",
        &record.grant.candidate_preparation_grant_id,
        Some(attempt_id.as_str()),
        Some(&record.grant.request_digest),
        Some(&record.grant.authority_token_digest),
    )?;
    Ok(CandidateNonceConsumption::Consumed)
}

fn same_authority(
    grant: &CandidatePreparationGrantV1,
    current: &bullet_application::candidate_preparation::CandidatePreparationAuthoritySnapshot,
) -> bool {
    grant.repository_id == current.repository_id
        && grant.mission_id == current.mission_id
        && grant.plan_revision_id == current.plan_revision_id
        && grant.work_package_id == current.work_package_id
        && grant.variant_id == current.variant_id
        && grant.attempt_id == current.attempt_id
        && grant.attempt_fence == current.attempt_fence
        && grant.runner_id == current.runner_id
        && grant.runner_epoch == current.runner_epoch
        && grant.workspace_id == current.workspace_id
        && grant.scope_grant_digest == current.scope_grant_digest
        && grant.scope_revision == current.scope_revision
        && grant.context_revision == current.context_revision
        && grant.graph_revision_id == current.graph_revision_id
        && grant.context_capsule_id == current.context_capsule_id
        && grant.authority_token_digest == current.authority_token_digest
        && grant.authority_epoch == current.authority_epoch
        && grant.freeze_generation == current.freeze_generation
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unix_ms(value: &str) -> Result<u64, CandidatePreparationError> {
    let value = DateTime::parse_from_rfc3339(value)
        .map_err(|_| candidate_store("Candidate nonce time is not RFC 3339"))?
        .timestamp_millis();
    u64::try_from(value).map_err(candidate_store)
}
