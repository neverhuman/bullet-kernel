//! Candidate request construction and strict response validation.

use super::{
    CandidateProvenanceRequest, CandidateReceipt, ChangeRequest, CheckpointBinding,
    PrepareCandidateRequest, PreservationReceipt, WorkspaceInfo,
};
use crate::candidate_authority::VerifiedCandidatePreparation;
use crate::error::RunnerError;
use crate::lease::AcquireGrant;
use bullet_domain::Digest;
use bullet_harness_core::PatchProposal;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

impl PrepareCandidateRequest {
    /// Build the gitd request from authenticated claims and repository facts.
    ///
    /// Snapshot hashes already on the token become `cnt_<hex>` content ids.
    /// Change, graph, context, environment, toolchain, and predecessor subjects
    /// come only from the authenticated Candidate-preparation grant.
    ///
    /// # Errors
    ///
    /// Missing or malformed subjects.
    pub(crate) fn from_verified_grant(
        grant: &AcquireGrant,
        workspace: &WorkspaceInfo,
        checkpoint: &CheckpointBinding,
        granted_scope: &[String],
        verified: &VerifiedCandidatePreparation,
    ) -> Result<Self, RunnerError> {
        let token = &grant.authority_token;
        let claims = verified.claims();
        let change = ChangeRequest {
            id: require_prefixed("change_id", "chg", &claims.change_id)?,
            mission: claims.mission_id.clone(),
            acceptance_root: hex_body(
                "acceptance_contract_id",
                "acc",
                token.acceptance_contract_id.as_str(),
            )?,
        };
        let provenance = CandidateProvenanceRequest {
            schema_version: 1,
            repository_id: claims.repository_id.clone(),
            producing_attempt_id: claims.attempt_id.clone(),
            attempt_fence: claims.attempt_fence,
            work_package_id: claims.work_package_id.clone(),
            variant_id: claims.variant_id.clone(),
            plan_revision_id: claims.plan_revision_id.clone(),
            graph_revision_id: require_prefixed(
                "graph_revision_id",
                "grf",
                &claims.graph_revision_id,
            )?,
            base_checkpoint_id: checkpoint.id.clone(),
            base_commit: tagged_git_oid(&workspace.base_sha)?,
            parent_candidate_ids: claims
                .parent_candidate_ids
                .iter()
                .map(|id| require_prefixed("parent_candidate_id", "can", id))
                .collect::<Result<Vec<_>, _>>()?,
            granted_scope: granted_scope.to_vec(),
            context_capsule_id: require_prefixed(
                "context_capsule_id",
                "cnt",
                &claims.context_capsule_id,
            )?,
            configuration_snapshot_id: content_id_from_digest(token.config_snapshot_hash),
            policy_snapshot_id: content_id_from_digest(token.policy_snapshot_hash),
            routing_snapshot_id: content_id_from_digest(token.routing_policy_hash),
            environment_digest: require_hex("environment_digest", &claims.environment_digest)?,
            toolchain_digest: require_hex("toolchain_digest", &claims.toolchain_digest)?,
        };
        if provenance.attempt_fence == 0 {
            return Err(RunnerError::Protocol(
                "attempt_fence must be nonzero".into(),
            ));
        }
        Ok(Self {
            change,
            provenance,
            candidate_preparation_grant: verified.signed().clone(),
        })
    }
}

pub(super) fn apply_proposal_params(proposal: &PatchProposal) -> Result<Value, RunnerError> {
    let authoritative = proposal.authoritative_value()?;
    Ok(json!({ "proposal": authoritative }))
}

pub(super) fn prepare_candidate_params(
    request: &PrepareCandidateRequest,
) -> Result<Value, RunnerError> {
    serde_json::to_value(request)
        .map_err(|err| RunnerError::Protocol(format!("encode prepare_candidate: {err}")))
}

pub(super) fn parse_candidate_receipt(ok: Value) -> Result<CandidateReceipt, RunnerError> {
    if ok.get("change_seed").is_some()
        || ok.get("mission").is_some() && ok.get("manifest").is_none()
    {
        return Err(RunnerError::Protocol(
            "prepare_candidate returned a legacy flattened receipt".into(),
        ));
    }
    let nested: NestedCandidate = serde_json::from_value(ok)
        .map_err(|err| RunnerError::Protocol(format!("prepare_candidate result: {err}")))?;
    require_prefixed("candidate.id", "can", &nested.id)?;
    require_prefixed("candidate.content_id", "cnt", &nested.content_id)?;
    Ok(CandidateReceipt {
        id: nested.id,
        content_id: nested.content_id,
        base_commit: nested.manifest.base_commit,
        head_commit: nested.manifest.head_commit,
        tree_hash: nested.manifest.tree_oid,
        patch_hash: nested.manifest.patch_digest,
        actual_scope: nested.manifest.actual_scope,
        prepared_at: nested.prepared_at,
    })
}

#[derive(Debug, Deserialize)]
struct NestedCandidate {
    id: String,
    content_id: String,
    #[serde(default)]
    prepared_at: String,
    manifest: NestedManifest,
}

#[derive(Debug, Deserialize)]
struct NestedManifest {
    base_commit: String,
    head_commit: String,
    tree_oid: String,
    patch_digest: String,
    #[serde(default)]
    actual_scope: Vec<String>,
}

pub(super) fn parse_checkpoint_binding(ok: &Value) -> Result<CheckpointBinding, RunnerError> {
    let id = ok
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| RunnerError::Protocol("checkpoint missing id".into()))?;
    let digest = ok
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| RunnerError::Protocol("checkpoint missing digest".into()))?;
    validate_checkpoint_binding(id, digest)?;
    Ok(CheckpointBinding {
        id: id.to_string(),
        digest: digest.to_string(),
    })
}

pub(super) fn parse_preservation_receipt(
    ok: Value,
    requested: &Path,
) -> Result<PreservationReceipt, RunnerError> {
    if ok.get("bundle_path").is_some() {
        return Err(RunnerError::Protocol(
            "preserve returned a legacy bundle_path".into(),
        ));
    }
    let token = ok
        .get("preservation_receipt")
        .and_then(Value::as_str)
        .ok_or_else(|| RunnerError::Protocol("preserve missing preservation_receipt".into()))?;
    if token.is_empty() {
        return Err(RunnerError::Protocol(
            "preservation_receipt is empty".into(),
        ));
    }
    let digest = ok
        .get("preservation_receipt_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RunnerError::Protocol("preserve missing preservation_receipt_digest".into())
        })?;
    let artifact = ok
        .get("artifact_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| RunnerError::Protocol("preserve missing artifact_digest".into()))?;
    require_hex("preservation_receipt_digest", digest)?;
    require_hex("artifact_digest", artifact)?;
    let destination = ok
        .get("destination")
        .and_then(Value::as_str)
        .map_or_else(|| requested.to_path_buf(), PathBuf::from);
    Ok(PreservationReceipt {
        token: token.to_string(),
        digest: digest.to_string(),
        artifact_digest: artifact.to_string(),
        destination,
    })
}

fn content_id_from_digest(digest: Digest) -> String {
    format!("cnt_{}", digest.to_hex())
}

pub(super) fn tagged_git_oid(raw: &str) -> Result<String, RunnerError> {
    if let Some(hex) = raw.strip_prefix("sha1:") {
        if is_lower_hex(hex, 40) {
            return Ok(raw.to_string());
        }
    }
    if let Some(hex) = raw.strip_prefix("sha256:") {
        if is_lower_hex(hex, 64) {
            return Ok(raw.to_string());
        }
    }
    if is_lower_hex(raw, 40) {
        return Ok(format!("sha1:{raw}"));
    }
    Err(RunnerError::Protocol(format!(
        "base commit must be sha1:<40 hex>, sha256:<64 hex>, or raw 40-hex: {raw}"
    )))
}

pub(super) fn require_prefixed(
    field: &str,
    prefix: &str,
    value: &str,
) -> Result<String, RunnerError> {
    let expected = format!("{prefix}_");
    let Some(body) = value.strip_prefix(&expected) else {
        return Err(RunnerError::Protocol(format!(
            "{field} must be {prefix}_<64 hex>"
        )));
    };
    require_hex(field, body)?;
    Ok(value.to_string())
}

fn hex_body(field: &str, prefix: &str, value: &str) -> Result<String, RunnerError> {
    let id = require_prefixed(field, prefix, value)?;
    Ok(id[prefix.len() + 1..].to_string())
}

fn require_hex(field: &str, value: &str) -> Result<String, RunnerError> {
    if !is_lower_hex(value, 64) {
        return Err(RunnerError::Protocol(format!(
            "{field} must be 64 lowercase hex"
        )));
    }
    Ok(value.to_string())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_checkpoint_binding(id: &str, digest: &str) -> Result<(), RunnerError> {
    let id_body = id.strip_prefix("ckp_");
    let lower_hex = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !id_body.is_some_and(lower_hex) || !lower_hex(digest) {
        return Err(RunnerError::Protocol(
            "checkpoint binding must use ckp_<64 lowercase hex> and a 64-lowercase-hex digest"
                .into(),
        ));
    }
    Ok(())
}
