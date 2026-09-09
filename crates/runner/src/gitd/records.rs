//! Strict records for the Runner-to-BulletGit protocol.

use super::ActiveGenerationBinding;
use bullet_harness_core::SignedCandidatePreparationGrantV1;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Private clone location returned by `clone`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceInfo {
    /// The private clone directory.
    pub repo_dir: PathBuf,
    /// Runtime dir holding manifest and tombstone.
    pub runtime_dir: PathBuf,
    /// Private branch `bullet/<variant>/<attempt>`.
    pub branch: String,
    /// Exact base commit.
    pub base_sha: String,
    /// Daemon-issued checkpoint identity for the exact initial generation.
    pub base_checkpoint_id: String,
    /// Full BLAKE3 digest of the exact initial checkpoint.
    pub base_checkpoint_digest: String,
    /// Exact initial generation manifest, pointer, and checkpoint identity.
    pub active_generation: ActiveGenerationBinding,
}

/// Exact checkpoint binding returned after a successful proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointBinding {
    /// Full-width checkpoint identity.
    pub id: String,
    /// Full BLAKE3 checkpoint digest.
    pub digest: String,
}

/// Receipt for one versioned proposal application.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyProposalReceipt {
    /// Echo of the admitted proposal identity.
    pub proposal_id: String,
    /// Number of operations applied atomically.
    pub applied: u64,
    /// Exact post-apply checkpoint used by the next proposal.
    pub checkpoint: CheckpointBinding,
    /// Exact active generation repository after the atomic switch.
    pub repo_dir: PathBuf,
    /// Exact post-switch generation manifest, pointer, and checkpoint identity.
    pub active_generation: ActiveGenerationBinding,
}

/// Exact candidate receipt from `prepare_candidate`.
///
/// Production gitd returns a nested Candidate (`id` + `manifest`). The
/// flattened fields are copied from that manifest; they are never accepted
/// as a legacy top-level `{change_seed,mission}` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReceipt {
    /// Provenance-bound candidate id (`can_` + 64 hex).
    pub id: String,
    /// Reusable content id (`cnt_` + 64 hex).
    pub content_id: String,
    /// Algorithm-tagged base commit.
    pub base_commit: String,
    /// Algorithm-tagged head commit.
    pub head_commit: String,
    /// Algorithm-tagged tree of the head commit.
    pub tree_hash: String,
    /// BLAKE3 of the `git diff base..head` bytes (hex).
    pub patch_hash: String,
    /// Paths actually written, sorted.
    #[serde(default)]
    pub actual_scope: Vec<String>,
    /// Preparation timestamp.
    #[serde(default)]
    pub prepared_at: String,
}

/// Logical Change sent to gitd. Narrative only; not Candidate identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRequest {
    /// `chg_` + 64 lowercase hex.
    pub id: String,
    /// Mission seed or id already bound on the grant.
    pub mission: String,
    /// 64-hex acceptance digest taken from the grant contract body.
    pub acceptance_root: String,
}

/// Kernel-owned provenance. Repository-derived fields are absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProvenanceRequest {
    /// Must be `1`.
    pub schema_version: u32,
    /// `rep_` subject from the grant.
    pub repository_id: String,
    /// `atm_` subject from the grant.
    pub producing_attempt_id: String,
    /// Permanent fence from the grant.
    pub attempt_fence: u64,
    /// `wpk_` subject from the grant.
    pub work_package_id: String,
    /// `var_` subject from the grant.
    pub variant_id: String,
    /// `pln_` subject from the grant.
    pub plan_revision_id: String,
    /// `grf_` subject supplied by the caller (token has only a sequence).
    pub graph_revision_id: String,
    /// Active daemon checkpoint.
    pub base_checkpoint_id: String,
    /// Algorithm-tagged base commit.
    pub base_commit: String,
    /// Predecessor Candidates.
    pub parent_candidate_ids: Vec<String>,
    /// Scope granted to this Attempt.
    pub granted_scope: Vec<String>,
    /// `cnt_` context capsule.
    pub context_capsule_id: String,
    /// `cnt_` configuration snapshot.
    pub configuration_snapshot_id: String,
    /// `cnt_` policy snapshot.
    pub policy_snapshot_id: String,
    /// `cnt_` routing snapshot.
    pub routing_snapshot_id: String,
    /// 64-hex environment digest.
    pub environment_digest: String,
    /// 64-hex toolchain digest.
    pub toolchain_digest: String,
}

/// Exact `prepare_candidate` params gitd admits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareCandidateRequest {
    /// Logical Change.
    pub change: ChangeRequest,
    /// Kernel-owned provenance.
    pub provenance: CandidateProvenanceRequest,
    /// Exact authenticated carrier; BulletGit forwards it for Kernel final check.
    pub candidate_preparation_grant: SignedCandidatePreparationGrantV1,
}

/// Sealed preserve receipt required before cleanup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservationReceipt {
    /// Opaque token returned by `preserve`.
    pub token: String,
    /// Digest of the sealed token.
    pub digest: String,
    /// Digest of the preserved artifact.
    pub artifact_digest: String,
    /// External destination that must already exist.
    pub destination: PathBuf,
}

/// Byte-resume binding after freeze salvage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorResume {
    /// Daemon checkpoint at freeze.
    pub checkpoint: CheckpointBinding,
    /// External preservation that cleanup must present.
    pub preservation: PreservationReceipt,
}
