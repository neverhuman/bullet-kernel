//! Strict admission of the product Runner's one-line successful outcome.

use super::super::support::{fail, strip_oid};
use bullet_domain::{AttemptId, Digest, REPOSITORY_GATE_ID};
use bullet_runner_core::{AcquireGrant, CandidatePreservation, CandidateReceipt, GateReport};
use serde::Deserialize;
use std::path::Path;

const MAX_RUNNER_OUTCOME_BYTES: usize = 1_048_576;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductRunnerOutcome {
    pub(super) attempt_id: AttemptId,
    pub(super) fence: u64,
    pub(super) repair_rounds: u32,
    pub(super) gate_passed: bool,
    pub(super) gates: Vec<GateReport>,
    pub(super) candidate: CandidateReceipt,
    pub(super) preservation: CandidatePreservation,
}

impl ProductRunnerOutcome {
    pub(super) fn decode_and_admit(
        bytes: &[u8],
        grant: &AcquireGrant,
        expected_base: &str,
        expected_destination: &Path,
    ) -> Result<Self, String> {
        if bytes.is_empty()
            || bytes.len() > MAX_RUNNER_OUTCOME_BYTES
            || bytes.last() != Some(&b'\n')
            || bytes[..bytes.len() - 1].contains(&b'\n')
        {
            return Err(fail(
                "PRODUCT_RUNNER_OUTCOME_INVALID: expected one bounded LF-terminated record",
            ));
        }
        let value = bullet_harness_core::strict_json::decode_strict_json(
            std::str::from_utf8(&bytes[..bytes.len() - 1])
                .map_err(|_| fail("PRODUCT_RUNNER_OUTCOME_INVALID: non-UTF-8 output"))?,
        )
        .map_err(|error| fail(format!("PRODUCT_RUNNER_OUTCOME_INVALID: {error}")))?;
        let outcome: Self = serde_json::from_value(value)
            .map_err(|error| fail(format!("PRODUCT_RUNNER_OUTCOME_INVALID: {error}")))?;
        outcome.validate(grant, expected_base, expected_destination)?;
        Ok(outcome)
    }

    fn validate(
        &self,
        grant: &AcquireGrant,
        expected_base: &str,
        expected_destination: &Path,
    ) -> Result<(), String> {
        self.preservation
            .validate_against(&self.candidate, &self.attempt_id, self.fence)
            .map_err(|error| fail(format!("PRODUCT_RUNNER_PRESERVATION_INVALID: {error}")))?;
        let expected_base = strip_oid(expected_base);
        let gate_exact = self.gates.len() == 1
            && self.gates[0].gate_id == REPOSITORY_GATE_ID
            && self.gates[0].passed();
        let fixed = self.attempt_id == grant.attempt.id
            && self.fence == grant.attempt.fence
            && self.repair_rounds == 0
            && self.gate_passed
            && gate_exact
            && self.candidate.base_commit == format!("sha1:{expected_base}")
            && full_id(&self.candidate.id, "can")
            && full_id(&self.candidate.content_id, "cnt")
            && tagged_sha1(&self.candidate.head_commit)
            && tagged_sha1(&self.candidate.tree_hash)
            && lower_hex(&self.candidate.patch_hash, 64)
            && self.candidate.actual_scope == ["PONG.txt"]
            && !self.candidate.prepared_at.is_empty()
            && self.preservation.receipt.destination == expected_destination
            && self.preservation.receipt.destination.is_dir()
            && self.preservation.receipt.digest
                == Digest::of(self.preservation.receipt.token.as_bytes()).to_hex()
            && lower_hex(&self.preservation.receipt.artifact_digest, 64);
        fixed.then_some(()).ok_or_else(|| {
            fail("PRODUCT_RUNNER_OUTCOME_INVALID: Candidate, gate, or preservation subject drifted")
        })
    }
}

fn full_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(|body| lower_hex(body, 64))
}

fn tagged_sha1(value: &str) -> bool {
    value
        .strip_prefix("sha1:")
        .is_some_and(|hex| lower_hex(hex, 40))
}

fn lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
