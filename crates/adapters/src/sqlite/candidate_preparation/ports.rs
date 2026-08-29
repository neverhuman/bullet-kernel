use super::super::SqliteLedger;
use super::{consume_nonce, get_grant, get_source, register_source, with_transaction};
use bullet_application::candidate_preparation::{
    CandidateNonceConsumption, CandidatePreparationError, CandidatePreparationFinalCheckStore,
    CandidatePreparationGrantV1, CandidatePreparationNonceStore, CandidatePreparationSource,
    CandidatePreparationStore, CandidatePreparationTransaction,
    RegisteredCandidatePreparationSource, SignedCandidatePreparationGrantV1,
    StoredCandidatePreparationGrant,
};
use bullet_domain::AttemptId;

impl SqliteLedger {
    /// Inject a one-shot Candidate-preparation issuance failure after
    /// `allowed` durable boundaries. Used only by crash-atomicity tests.
    pub fn set_candidate_preparation_failpoint(&mut self, allowed: u8) {
        self.candidate_preparation_fail_after = Some(allowed);
    }
}

impl CandidatePreparationStore for SqliteLedger {
    fn register_candidate_preparation_source(
        &mut self,
        source: &CandidatePreparationSource,
    ) -> Result<RegisteredCandidatePreparationSource, CandidatePreparationError> {
        register_source(&mut self.conn, source)
    }

    fn get_candidate_preparation_source(
        &self,
        request_digest: &str,
    ) -> Result<Option<RegisteredCandidatePreparationSource>, CandidatePreparationError> {
        get_source(&self.conn, request_digest)
    }

    fn get_candidate_preparation_grant(
        &self,
        request_digest: &str,
    ) -> Result<Option<StoredCandidatePreparationGrant>, CandidatePreparationError> {
        get_grant(&self.conn, request_digest)
    }

    fn with_candidate_preparation<T, F>(
        &mut self,
        operation: F,
    ) -> Result<T, CandidatePreparationError>
    where
        Self: Sized,
        F: FnOnce(&mut dyn CandidatePreparationTransaction) -> Result<T, CandidatePreparationError>,
    {
        with_transaction(
            &mut self.conn,
            &mut self.candidate_preparation_fail_after,
            operation,
        )
    }
}

impl CandidatePreparationNonceStore for SqliteLedger {
    fn consume_candidate_preparation_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
    ) -> Result<CandidateNonceConsumption, CandidatePreparationError> {
        consume_nonce(&mut self.conn, nonce, attempt_id)
    }
}

impl CandidatePreparationFinalCheckStore for SqliteLedger {
    fn final_check_candidate_preparation_grant(
        &mut self,
        claims: &CandidatePreparationGrantV1,
        signed: &SignedCandidatePreparationGrantV1,
        attempt_id: &AttemptId,
    ) -> Result<CandidateNonceConsumption, CandidatePreparationError> {
        super::nonce::final_check(&mut self.conn, claims, signed, attempt_id)
    }
}
