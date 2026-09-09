//! Exact outer binding and retained-path validation.

use super::{
    artifacts, invalid, ArtifactCustody, Children, CommandDispatchClaim, ComponentReceipt,
    DispatchBinding, LocalForgeReceipt, ObservationSubjectV1, RetainedPaths, TARGET,
};
use bullet_domain::CandidateId;
use bullet_harness_core::launch_grant::canonical_json;
use std::path::Path;

impl Children {
    pub(super) fn exact(&self) -> bool {
        self.farmd == "bullet-farmd"
            && self.runner == "bullet-runner"
            && self.gitd == "bullet-gitd"
            && self.verifier == "bullet-verifier-fixture"
    }
}

impl DispatchBinding {
    pub(super) fn validate_for(
        &self,
        claim: &CommandDispatchClaim,
        manifest: &str,
    ) -> Result<(), super::WorkerError> {
        let canonical = canonical_json(claim).map_err(invalid)?;
        let exact = self.source == "SEALED_CLAIM"
            && self.claim_id.as_deref() == Some(claim.claim_id.as_str())
            && self.command_id.as_deref() == Some(claim.command_id.as_str())
            && self.request_digest.as_deref() == Some(claim.request_digest.to_hex().as_str())
            && self.runner_id.as_deref() == Some(claim.runner_id.as_str())
            && self.runner_epoch == Some(claim.runner_epoch)
            && self.canonical_claim_blake3.as_deref()
                == Some(artifacts::blake3_label(&canonical).as_str())
            && self.binary_manifest_sha256.as_deref() == Some(manifest)
            && artifacts::lower_hex(manifest, 64)
            && !self.transaction_gate_eligible
            && !self.independent_evidence_eligible;
        if exact {
            Ok(())
        } else {
            Err(invalid(
                "nested public command dispatch does not match retained claim",
            ))
        }
    }
}

impl ArtifactCustody {
    pub(super) fn paths(
        &self,
        run_root: &Path,
        receipt: &ComponentReceipt,
        candidate_id: CandidateId,
    ) -> Result<RetainedPaths, super::WorkerError> {
        let exact = self.retained
            && self.artifact_root_relative == "artifacts"
            && self.source_repository_relative == "artifacts/source"
            && self.candidate_repository_relative == "artifacts/preserve/generation/repo"
            && self.local_forge_relative == "artifacts/effects/target.git"
            && self.ledger_relative == "data/ledger.sqlite"
            && self.candidate_id == receipt.candidate_id
            && self.base_oid == receipt.base_oid
            && self.head_oid == receipt.head_oid
            && self.tree_oid == receipt.tree_oid
            && self.target_ref == TARGET
            && self.target_oid == receipt.head_oid;
        if !exact {
            return Err(invalid(
                "retained artifact custody differs from outer subjects",
            ));
        }
        artifacts::require_private_dir(run_root)?;
        artifacts::require_private_dir(&run_root.join("artifacts"))?;
        artifacts::require_private_dir(&run_root.join("data"))?;
        Ok(RetainedPaths {
            source: artifacts::canonical_dir(&run_root.join(&self.source_repository_relative))?,
            candidate: artifacts::canonical_dir(
                &run_root.join(&self.candidate_repository_relative),
            )?,
            forge: artifacts::canonical_dir(&run_root.join(&self.local_forge_relative))?,
            ledger: run_root.join(&self.ledger_relative),
            candidate_id,
        })
    }
}

impl LocalForgeReceipt {
    pub(super) fn matches(
        &self,
        receipt: &ComponentReceipt,
        subject: &ObservationSubjectV1,
    ) -> bool {
        self.delivered_oid == receipt.head_oid
            && self.effect_candidate_bound
            && self.proof_root == subject.proof_root
            && self.check_name == subject.check_name
            && self.check_sha == receipt.head_oid
            && self.check_readback_matches
            && self.integration_subject_id == subject.integration_subject_id
            && self.integration_previous_oid == receipt.base_oid
            && self.integration_oid == receipt.head_oid
            && self.observation_target_oid == receipt.head_oid
            && self.restart_readback_matches
            && subject.target == TARGET
            && subject.previous_oid == receipt.base_oid
            && subject.integrated_oid == receipt.head_oid
            && subject.check_sha == receipt.head_oid
            && subject.check_proof_root == self.proof_root
    }
}
