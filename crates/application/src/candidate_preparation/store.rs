use super::{
    CandidatePreparationAuthoritySnapshot, CandidatePreparationError, CandidatePreparationSource,
    PreparedCandidatePreparationGrant, RegisteredCandidatePreparationSource,
    StoredCandidatePreparationGrant,
};
use bullet_domain::AttemptId;

pub trait CandidatePreparationTransaction {
    fn get_source(
        &self,
        request_digest: &str,
    ) -> Result<Option<RegisteredCandidatePreparationSource>, CandidatePreparationError>;

    fn get_issued(
        &self,
        request_digest: &str,
    ) -> Result<Option<StoredCandidatePreparationGrant>, CandidatePreparationError>;

    fn authority_snapshot(
        &self,
        attempt_id: &AttemptId,
    ) -> Result<CandidatePreparationAuthoritySnapshot, CandidatePreparationError>;

    fn require_parent_candidates(
        &self,
        source: &CandidatePreparationSource,
    ) -> Result<(), CandidatePreparationError>;

    fn put_issued(
        &mut self,
        record: &PreparedCandidatePreparationGrant,
    ) -> Result<(), CandidatePreparationError>;
}

pub trait CandidatePreparationStore {
    fn register_candidate_preparation_source(
        &mut self,
        source: &CandidatePreparationSource,
    ) -> Result<RegisteredCandidatePreparationSource, CandidatePreparationError>;

    fn get_candidate_preparation_source(
        &self,
        request_digest: &str,
    ) -> Result<Option<RegisteredCandidatePreparationSource>, CandidatePreparationError>;

    fn get_candidate_preparation_grant(
        &self,
        request_digest: &str,
    ) -> Result<Option<StoredCandidatePreparationGrant>, CandidatePreparationError>;

    fn with_candidate_preparation<T, F>(
        &mut self,
        operation: F,
    ) -> Result<T, CandidatePreparationError>
    where
        Self: Sized,
        F: FnOnce(&mut dyn CandidatePreparationTransaction) -> Result<T, CandidatePreparationError>;
}
