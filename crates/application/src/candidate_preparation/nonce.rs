use super::{
    CandidatePreparationError, CandidatePreparationGrantV1, SignedCandidatePreparationGrantV1,
};
use bullet_domain::AttemptId;
use bullet_harness_core::candidate_preparation::{
    CandidateNonceConsumption, CandidatePreparationNonceLedger,
};
use bullet_harness_core::HarnessError;

pub trait CandidatePreparationNonceStore {
    fn consume_candidate_preparation_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
    ) -> Result<CandidateNonceConsumption, CandidatePreparationError>;
}

/// Durable final-check port for one authenticated Candidate grant.
///
/// Implementations compare the complete claims and canonical signed carrier
/// to stored truth before consuming the nonce in the same transaction.
pub trait CandidatePreparationFinalCheckStore {
    fn final_check_candidate_preparation_grant(
        &mut self,
        claims: &CandidatePreparationGrantV1,
        signed: &SignedCandidatePreparationGrantV1,
        attempt_id: &AttemptId,
    ) -> Result<CandidateNonceConsumption, CandidatePreparationError>;
}

pub struct StoreCandidatePreparationNonceLedger<'a, S: CandidatePreparationNonceStore>(
    pub &'a mut S,
);

impl<S: CandidatePreparationNonceStore> CandidatePreparationNonceLedger
    for StoreCandidatePreparationNonceLedger<'_, S>
{
    fn consume_candidate_preparation_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        _now_unix_ms: u64,
    ) -> Result<CandidateNonceConsumption, HarnessError> {
        self.0
            .consume_candidate_preparation_nonce(nonce, attempt_id)
            .map_err(|error| HarnessError::Io {
                context: "Candidate-preparation nonce store".to_owned(),
                reason: error.to_string(),
            })
    }
}
