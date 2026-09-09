//! Labeled coding-harness observation. Not COMPONENT_PROOF and not Evidence.

use super::artifacts;
use super::{AdmittedReceipt, WorkerError};
use crate::child::coding::{CodingObservation, CODING_EVIDENCE_CLASS, CODING_OBSERVATION_SCHEMA};
use crate::error::WorkerContext;
use bullet_application::{CommandDispatchClaim, RUN_CODING_KIND};
use bullet_domain::Digest;
use std::path::Path;

pub(crate) fn admit_coding_observation(
    path: &Path,
    run_root: &Path,
    claim: &CommandDispatchClaim,
    expected: Option<(&str, Digest)>,
) -> Result<AdmittedReceipt, WorkerError> {
    claim
        .validate()
        .worker("COMMAND_RECEIPT_INVALID", "validate expected command claim")?;
    if claim.request.kind != RUN_CODING_KIND {
        return Err(WorkerError::input(
            "COMMAND_RECEIPT_INVALID",
            "coding observation admits only run_coding claims",
        ));
    }
    let bytes = artifacts::read_receipt(path, run_root)?;
    let admitted = AdmittedReceipt::from_bytes(&bytes);
    if expected.is_some_and(|(raw, digest)| {
        raw != admitted.raw_sha256 || digest != admitted.receipt_digest
    }) {
        return Err(WorkerError::input(
            "COMMAND_RECEIPT_INVALID",
            "retained coding observation hashes differ from durable custody",
        ));
    }
    let observation: CodingObservation = serde_json::from_slice(&bytes).worker(
        "COMMAND_RECEIPT_INVALID",
        "decode coding harness observation",
    )?;
    if observation.schema_version != CODING_OBSERVATION_SCHEMA
        || observation.evidence_class != CODING_EVIDENCE_CLASS
        || observation.transaction_gate_eligible
        || observation.independent_evidence_eligible
        || observation.kind != RUN_CODING_KIND
        || observation.command_id != claim.command_id.as_str()
        || observation.cost != "UNPRICED"
    {
        return Err(WorkerError::input(
            "COMMAND_RECEIPT_INVALID",
            "coding observation is not the labeled harness class",
        ));
    }
    Ok(admitted)
}
