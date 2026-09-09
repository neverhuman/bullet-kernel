//! Atomic schema-19 Candidate-preparation persistence.

mod grant;
mod nonce;
mod ports;
mod snapshot;
mod source;

use super::store;
use bullet_application::candidate_preparation::{
    CandidatePreparationError, CandidatePreparationSource, CandidatePreparationTransaction,
    PreparedCandidatePreparationGrant, RegisteredCandidatePreparationSource,
    StoredCandidatePreparationGrant,
};
use bullet_domain::AttemptId;
use rusqlite::{Connection, Transaction, TransactionBehavior};

pub(super) struct Session<'connection, 'failpoint> {
    tx: Transaction<'connection>,
    fail_after: &'failpoint mut Option<u8>,
}

impl CandidatePreparationTransaction for Session<'_, '_> {
    fn get_source(
        &self,
        request_digest: &str,
    ) -> Result<Option<RegisteredCandidatePreparationSource>, CandidatePreparationError> {
        source::get(&self.tx, request_digest)
    }

    fn get_issued(
        &self,
        request_digest: &str,
    ) -> Result<Option<StoredCandidatePreparationGrant>, CandidatePreparationError> {
        grant::get(&self.tx, request_digest)
    }

    fn authority_snapshot(
        &self,
        attempt_id: &AttemptId,
    ) -> Result<
        bullet_application::candidate_preparation::CandidatePreparationAuthoritySnapshot,
        CandidatePreparationError,
    > {
        snapshot::authority(&self.tx, attempt_id)
    }

    fn require_parent_candidates(
        &self,
        source: &CandidatePreparationSource,
    ) -> Result<(), CandidatePreparationError> {
        snapshot::require_parents(&self.tx, source)
    }

    fn put_issued(
        &mut self,
        record: &PreparedCandidatePreparationGrant,
    ) -> Result<(), CandidatePreparationError> {
        grant::put(&self.tx, self.fail_after, record.record())
    }
}

pub(super) fn with_transaction<T, F>(
    conn: &mut Connection,
    fail_after: &mut Option<u8>,
    operation: F,
) -> Result<T, CandidatePreparationError>
where
    F: FnOnce(&mut dyn CandidatePreparationTransaction) -> Result<T, CandidatePreparationError>,
{
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(candidate_store)?;
    let mut session = Session { tx, fail_after };
    let result = operation(&mut session)?;
    session.tx.commit().map_err(candidate_store)?;
    Ok(result)
}

pub(super) fn candidate_store(error: impl ToString) -> CandidatePreparationError {
    CandidatePreparationError::Ledger(store(error))
}

pub(super) fn register_source(
    conn: &mut Connection,
    source: &CandidatePreparationSource,
) -> Result<RegisteredCandidatePreparationSource, CandidatePreparationError> {
    source::register(conn, source)
}

pub(super) fn get_source(
    conn: &Connection,
    request_digest: &str,
) -> Result<Option<RegisteredCandidatePreparationSource>, CandidatePreparationError> {
    source::get(conn, request_digest)
}

pub(super) fn get_grant(
    conn: &Connection,
    request_digest: &str,
) -> Result<Option<StoredCandidatePreparationGrant>, CandidatePreparationError> {
    grant::get(conn, request_digest)
}

pub(super) fn consume_nonce(
    conn: &mut Connection,
    nonce: &str,
    attempt_id: &str,
) -> Result<
    bullet_application::candidate_preparation::CandidateNonceConsumption,
    CandidatePreparationError,
> {
    nonce::consume(conn, nonce, attempt_id)
}

pub(super) fn step(fail_after: &mut Option<u8>) -> Result<(), CandidatePreparationError> {
    match fail_after {
        Some(0) => {
            *fail_after = None;
            Err(candidate_store("injected Candidate-preparation failure"))
        }
        Some(remaining) => {
            *remaining -= 1;
            Ok(())
        }
        None => Ok(()),
    }
}
