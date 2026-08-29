use super::candidate_store;
use crate::sqlite::{events, lease_time};
use bullet_application::candidate_preparation::{
    CandidatePreparationError, CandidatePreparationSource, RegisteredCandidatePreparationSource,
};
use chrono::DateTime;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub(super) fn register(
    conn: &mut Connection,
    source: &CandidatePreparationSource,
) -> Result<RegisteredCandidatePreparationSource, CandidatePreparationError> {
    source.validate()?;
    let request_digest = source.request_digest()?;
    let source_bytes = source.canonical_bytes()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(candidate_store)?;
    if let Some(existing) = get(&tx, &request_digest)? {
        if existing.source == *source {
            tx.commit().map_err(candidate_store)?;
            return Ok(existing);
        }
        return Err(CandidatePreparationError::Conflict(
            "request digest is bound to different source bytes".to_owned(),
        ));
    }
    let other: Option<String> = tx
        .query_row(
            "SELECT request_digest FROM candidate_preparation_sources WHERE change_id = ?1",
            [source.change_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(candidate_store)?;
    if other.is_some() {
        return Err(CandidatePreparationError::Conflict(
            "Change identity is already preregistered".to_owned(),
        ));
    }
    let registered_at = lease_time::database_time(&tx).map_err(CandidatePreparationError::from)?;
    tx.execute(
        "INSERT INTO candidate_preparation_sources (
           request_digest, source_bytes, attempt_id, change_id, root_change,
           execution_envelope_id, registered_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            request_digest,
            source_bytes,
            source.attempt_id.as_str(),
            source.change_id,
            i64::from(source.root_change),
            source.execution_envelope.execution_envelope_id,
            registered_at,
        ],
    )
    .map_err(candidate_store)?;
    events::insert_event(
        &tx,
        "candidate_preparation_source_registered",
        &request_digest,
        Some(source.attempt_id.as_str()),
        Some(&request_digest),
        None,
    )
    .map_err(CandidatePreparationError::from)?;
    tx.commit().map_err(candidate_store)?;
    Ok(RegisteredCandidatePreparationSource {
        request_digest,
        source: source.clone(),
        registered_at,
    })
}

pub(super) fn get(
    conn: &Connection,
    request_digest: &str,
) -> Result<Option<RegisteredCandidatePreparationSource>, CandidatePreparationError> {
    let raw = conn
        .query_row(
            "SELECT source_bytes, attempt_id, change_id, root_change,
                    execution_envelope_id, registered_at
             FROM candidate_preparation_sources WHERE request_digest = ?1",
            [request_digest],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(candidate_store)?;
    let Some((bytes, attempt_id, change_id, root_change, envelope_id, registered_at)) = raw else {
        return Ok(None);
    };
    let source = CandidatePreparationSource::decode_canonical(&bytes)?;
    if source.request_digest()? != request_digest
        || source.attempt_id.as_str() != attempt_id
        || source.change_id != change_id
        || i64::from(source.root_change) != root_change
        || source.execution_envelope.execution_envelope_id != envelope_id
        || DateTime::parse_from_rfc3339(&registered_at).is_err()
    {
        return Err(candidate_store(
            "persisted Candidate-preparation source binding is corrupt",
        ));
    }
    Ok(Some(RegisteredCandidatePreparationSource {
        request_digest: request_digest.to_owned(),
        source,
        registered_at,
    }))
}
