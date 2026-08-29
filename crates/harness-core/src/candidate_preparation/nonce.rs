use crate::error::HarnessError;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateNonceConsumption {
    Consumed,
    Replayed,
    Unknown,
    Expired,
}

pub trait CandidatePreparationNonceLedger {
    fn consume_candidate_preparation_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        now_unix_ms: u64,
    ) -> Result<CandidateNonceConsumption, HarnessError>;
}

#[derive(Clone, Debug)]
struct Record {
    attempt_id: String,
    expires_at_unix_ms: u64,
    consumed: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryCandidatePreparationNonceLedger {
    records: BTreeMap<String, Record>,
}

impl MemoryCandidatePreparationNonceLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, nonce: &str, attempt_id: &str, expires_at_unix_ms: u64) -> bool {
        if self.records.contains_key(nonce) {
            return false;
        }
        self.records.insert(
            nonce.to_owned(),
            Record {
                attempt_id: attempt_id.to_owned(),
                expires_at_unix_ms,
                consumed: false,
            },
        );
        true
    }

    #[must_use]
    pub fn is_consumed(&self, nonce: &str) -> bool {
        self.records
            .get(nonce)
            .is_some_and(|record| record.consumed)
    }
}

impl CandidatePreparationNonceLedger for MemoryCandidatePreparationNonceLedger {
    fn consume_candidate_preparation_nonce(
        &mut self,
        nonce: &str,
        attempt_id: &str,
        now_unix_ms: u64,
    ) -> Result<CandidateNonceConsumption, HarnessError> {
        let Some(record) = self.records.get_mut(nonce) else {
            return Ok(CandidateNonceConsumption::Unknown);
        };
        if record.attempt_id != attempt_id {
            return Ok(CandidateNonceConsumption::Unknown);
        }
        if record.consumed {
            return Ok(CandidateNonceConsumption::Replayed);
        }
        if now_unix_ms >= record.expires_at_unix_ms {
            return Ok(CandidateNonceConsumption::Expired);
        }
        record.consumed = true;
        Ok(CandidateNonceConsumption::Consumed)
    }
}
