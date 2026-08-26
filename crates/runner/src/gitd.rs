//! Client for the `bullet-gitd` workspace daemon (line-delimited JSON over
//! stdio; protocol in bullet-git/docs/architecture.md). The daemon is the
//! sole writer of the private clone; it pins attempt/fence/nonce from the
//! initial clone token and refuses every stale call.

use crate::error::RunnerError;
use crate::lease::AcquireGrant;
use bullet_domain::{AuthorityToken, Digest};
use bullet_harness_core::PatchProposal;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const CALL_TIMEOUT: Duration = Duration::from_secs(60);

mod binary;
pub use binary::{gitd_binary, gitd_fixture_binary, AdmittedGitdBinary};

/// Private clone location returned by `clone`.
#[derive(Clone, Debug, Deserialize)]
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
}

/// Exact checkpoint binding returned after a successful proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBinding {
    /// Full-width checkpoint identity.
    pub id: String,
    /// Full BLAKE3 checkpoint digest.
    pub digest: String,
}

/// Receipt for one versioned proposal application.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyProposalReceipt {
    /// Echo of the admitted proposal identity.
    pub proposal_id: String,
    /// Number of operations applied atomically.
    pub applied: u64,
    /// Exact post-apply checkpoint used by the next proposal.
    pub checkpoint: CheckpointBinding,
}

/// Exact candidate receipt from `prepare_candidate`.
///
/// Production gitd returns a nested Candidate (`id` + `manifest`). The
/// flattened fields are copied from that manifest; they are never accepted
/// as a legacy top-level `{change_seed,mission}` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareCandidateRequest {
    /// Logical Change.
    pub change: ChangeRequest,
    /// Kernel-owned provenance.
    pub provenance: CandidateProvenanceRequest,
}

/// Subjects the grant does not carry in gitd wire shape.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CandidateBindings {
    /// `chg_` + 64 hex.
    pub change_id: String,
    /// `grf_` + 64 hex.
    pub graph_revision_id: String,
    /// `cnt_` + 64 hex.
    pub context_capsule_id: String,
    /// 64 hex.
    pub environment_digest: String,
    /// 64 hex.
    pub toolchain_digest: String,
    /// `can_` predecessors.
    pub parent_candidate_ids: Vec<String>,
}

/// Sealed preserve receipt required before cleanup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// One spawned daemon serving one workspace session.
pub struct GitdSession {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    token: Value,
}

fn io_err(context: &str, reason: impl std::fmt::Display) -> RunnerError {
    RunnerError::Io {
        context: context.to_string(),
        reason: reason.to_string(),
    }
}

fn next_request_id(current: u64) -> Result<u64, RunnerError> {
    current
        .checked_add(1)
        .ok_or_else(|| RunnerError::Protocol("gitd request id exhausted".into()))
}

fn validate_response_envelope(
    value: &Value,
    expected_id: u64,
    method: &str,
) -> Result<(), RunnerError> {
    if value.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Err(RunnerError::Protocol(format!(
            "gitd {method}: response id does not match request {expected_id}"
        )));
    }
    if value.get("ok").is_some() == value.get("err").is_some() {
        return Err(RunnerError::Protocol(format!(
            "gitd {method}: response must contain exactly one of ok or err"
        )));
    }
    Ok(())
}

impl GitdSession {
    /// Spawn the daemon with the incarnation's authority token.
    ///
    /// # Errors
    ///
    /// Returns `GITD_BINARY_UNPROVISIONED` or
    /// `GITD_BINARY_ADMISSION_REFUSED` before spawning when the exact binary
    /// subject is absent or invalid. Encoding and post-admission process I/O
    /// failures return `IO_FAILED`.
    pub async fn spawn(token: &AuthorityToken) -> Result<Self, RunnerError> {
        let token =
            serde_json::to_value(token).map_err(|err| io_err("encode authority token", err))?;
        Self::spawn_with(gitd_binary()?, std::iter::empty::<&str>(), token).await
    }

    /// Spawn an already admitted binary, including the debug-only fixture.
    ///
    /// # Errors
    ///
    /// Returns `IO_FAILED` when the binary cannot be started.
    pub async fn spawn_with(
        binary: AdmittedGitdBinary,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
        token: Value,
    ) -> Result<Self, RunnerError> {
        let spawn_path = binary.spawn_path()?;
        let display_path = binary.path().display().to_string();
        let mut child = Command::new(&spawn_path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| io_err(&format!("spawn {display_path}"), err))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io_err("gitd stdin", "pipe missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io_err("gitd stdout", "pipe missing"))?;
        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 0,
            token,
        })
    }

    /// One request/response using the session token.
    ///
    /// # Errors
    ///
    /// Daemon refusals and IO failures.
    pub async fn invoke(&mut self, method: &str, params: Value) -> Result<Value, RunnerError> {
        self.call(method, params).await
    }

    /// Stop the child and wait so it is not left as a zombie.
    ///
    /// # Errors
    ///
    /// Wait failure after kill.
    pub async fn kill(&mut self) -> Result<(), RunnerError> {
        let _ = self._child.start_kill();
        self._child
            .wait()
            .await
            .map(|_| ())
            .map_err(|err| io_err("gitd wait", err))
    }

    /// Preserve the workspace to a destination that must not already exist.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure.
    pub async fn preserve(
        &mut self,
        destination: &Path,
    ) -> Result<PreservationReceipt, RunnerError> {
        let ok = self
            .call(
                "preserve",
                json!({ "destination": destination.display().to_string() }),
            )
            .await?;
        parse_preservation_receipt(ok, destination)
    }

    /// One request/response round trip with an explicit token. Exposed so
    /// tests can prove a stale token is refused after the clone pins the
    /// expected fence.
    ///
    /// # Errors
    ///
    /// Daemon refusals preserve `STALE_AUTHORITY` and
    /// `AUTHORITY_CONTRACT_UNAVAILABLE`; all others become `GITD_REFUSED`.
    pub async fn call_with(
        &mut self,
        token: &Value,
        method: &str,
        params: Value,
    ) -> Result<Value, RunnerError> {
        let request_id = next_request_id(self.next_id)?;
        self.next_id = request_id;
        let line = json!({ "id": request_id, "method": method, "token": token, "params": params })
            .to_string();
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|err| io_err(&format!("gitd write {method}"), err))?;
        self.stdin
            .flush()
            .await
            .map_err(|err| io_err(&format!("gitd flush {method}"), err))?;
        let mut response = String::new();
        let read = tokio::time::timeout(CALL_TIMEOUT, self.stdout.read_line(&mut response))
            .await
            .map_err(|_| io_err(&format!("gitd read {method}"), "timeout"))?
            .map_err(|err| io_err(&format!("gitd read {method}"), err))?;
        if read == 0 {
            return Err(io_err(
                &format!("gitd read {method}"),
                "daemon closed stdout",
            ));
        }
        let value: Value = serde_json::from_str(response.trim())
            .map_err(|err| RunnerError::Protocol(format!("gitd {method} response: {err}")))?;
        validate_response_envelope(&value, request_id, method)?;
        if let Some(err) = value.get("err") {
            let code = err
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN")
                .to_string();
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if code == "STALE_AUTHORITY" {
                return Err(RunnerError::StaleAuthority(format!(
                    "gitd {method}: {message}"
                )));
            }
            if code == "AUTHORITY_CONTRACT_UNAVAILABLE" {
                return Err(RunnerError::AuthorityContractUnavailable {
                    method: method.to_string(),
                    message,
                });
            }
            return Err(RunnerError::Gitd {
                method: method.to_string(),
                code,
                message,
            });
        }
        value
            .get("ok")
            .cloned()
            .ok_or_else(|| RunnerError::Protocol(format!("gitd {method}: response without ok/err")))
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Value, RunnerError> {
        let token = self.token.clone();
        self.call_with(&token, method, params).await
    }

    /// Create the private clone (spec section 20.2). Must be the first call;
    /// the daemon pins attempt/fence/nonce from this token.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure.
    pub async fn clone_workspace(
        &mut self,
        source_repo: &Path,
        base_sha: &str,
        root: &Path,
        allowed_prefixes: &[String],
    ) -> Result<WorkspaceInfo, RunnerError> {
        let now = chrono::Utc::now();
        let params = json!({
            "source_repo": source_repo.display().to_string(),
            "base_sha": base_sha,
            "root": root.display().to_string(),
            "created_at": now.to_rfc3339(),
            "allowed_prefixes": allowed_prefixes,
            "commit_date": now.to_rfc3339(),
        });
        let ok = self.call("clone", params).await?;
        let workspace: WorkspaceInfo = serde_json::from_value(ok)
            .map_err(|err| RunnerError::Protocol(format!("clone result: {err}")))?;
        validate_checkpoint_binding(
            &workspace.base_checkpoint_id,
            &workspace.base_checkpoint_digest,
        )?;
        Ok(workspace)
    }

    /// Tracked paths of the clone.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure.
    pub async fn read_tree(&mut self) -> Result<Vec<String>, RunnerError> {
        let ok = self.call("read_tree", json!({})).await?;
        serde_json::from_value(ok.get("files").cloned().unwrap_or(Value::Null))
            .map_err(|err| RunnerError::Protocol(format!("read_tree result: {err}")))
    }

    /// Apply one exact versioned provider proposal without flattening it into
    /// legacy daemon patches.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure. Provider proposals never reach the
    /// legacy `apply_change` method.
    pub async fn apply_proposal(
        &mut self,
        proposal: &PatchProposal,
    ) -> Result<ApplyProposalReceipt, RunnerError> {
        let params = apply_proposal_params(proposal)?;
        let ok = self.call("apply_proposal", params).await?;
        let receipt: ApplyProposalReceipt = serde_json::from_value(ok)
            .map_err(|error| RunnerError::Protocol(format!("apply_proposal result: {error}")))?;
        if receipt.proposal_id != proposal.proposal_id {
            return Err(RunnerError::Protocol(format!(
                "apply_proposal echoed proposal {} for {}",
                receipt.proposal_id, proposal.proposal_id
            )));
        }
        let expected = u64::try_from(proposal.operations.len())
            .map_err(|error| RunnerError::Protocol(error.to_string()))?;
        if receipt.applied != expected {
            return Err(RunnerError::Protocol(format!(
                "apply_proposal reported {} operations; expected {expected}",
                receipt.applied
            )));
        }
        validate_checkpoint_binding(&receipt.checkpoint.id, &receipt.checkpoint.digest)?;
        Ok(receipt)
    }

    /// Durable salvage checkpoint (never touches the live index).
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure.
    pub async fn checkpoint(&mut self) -> Result<CheckpointBinding, RunnerError> {
        let ok = self.call("checkpoint", json!({})).await?;
        parse_checkpoint_binding(&ok)
    }

    /// Prepare the exact candidate from Kernel-owned change + provenance.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure. Legacy `{change_seed,mission}`
    /// is never encoded.
    pub async fn prepare_candidate(
        &mut self,
        request: &PrepareCandidateRequest,
    ) -> Result<CandidateReceipt, RunnerError> {
        let ok = self
            .call("prepare_candidate", prepare_candidate_params(request)?)
            .await?;
        parse_candidate_receipt(ok)
    }

    /// Delete the workspace only after presenting the sealed preserve token.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure. A `bundle_path` is never sent.
    pub async fn cleanup(
        &mut self,
        receipt: &PreservationReceipt,
        deleted_at: &str,
    ) -> Result<Value, RunnerError> {
        if receipt.token.is_empty() {
            return Err(RunnerError::Protocol(
                "cleanup requires a sealed preservation_receipt".into(),
            ));
        }
        self.call(
            "cleanup",
            json!({
                "preservation_receipt": receipt.token,
                "deleted_at": deleted_at,
            }),
        )
        .await
    }
}

impl PrepareCandidateRequest {
    /// Build the gitd request from grant, workspace, and caller bindings.
    ///
    /// Snapshot hashes already on the token become `cnt_<hex>` content ids.
    /// Graph revision, change id, context capsule, environment, and toolchain
    /// are refused unless the caller supplies valid subjects. No seed string
    /// is hashed into a missing field.
    ///
    /// # Errors
    ///
    /// Missing or malformed subjects.
    pub fn from_grant(
        grant: &AcquireGrant,
        workspace: &WorkspaceInfo,
        checkpoint: &CheckpointBinding,
        granted_scope: &[String],
        bindings: &CandidateBindings,
    ) -> Result<Self, RunnerError> {
        let token = &grant.authority_token;
        let change = ChangeRequest {
            id: require_prefixed("change_id", "chg", &bindings.change_id)?,
            mission: token.mission_id.to_string(),
            acceptance_root: hex_body(
                "acceptance_contract_id",
                "acc",
                token.acceptance_contract_id.as_str(),
            )?,
        };
        let provenance = CandidateProvenanceRequest {
            schema_version: 1,
            repository_id: token.repository_id.to_string(),
            producing_attempt_id: token.attempt_id.to_string(),
            attempt_fence: token.attempt_fence,
            work_package_id: token.work_package_id.to_string(),
            variant_id: token.variant_id.to_string(),
            plan_revision_id: token.plan_revision_id.to_string(),
            graph_revision_id: require_prefixed(
                "graph_revision_id",
                "grf",
                &bindings.graph_revision_id,
            )?,
            base_checkpoint_id: checkpoint.id.clone(),
            base_commit: tagged_git_oid(&workspace.base_sha)?,
            parent_candidate_ids: bindings
                .parent_candidate_ids
                .iter()
                .map(|id| require_prefixed("parent_candidate_id", "can", id))
                .collect::<Result<Vec<_>, _>>()?,
            granted_scope: granted_scope.to_vec(),
            context_capsule_id: require_prefixed(
                "context_capsule_id",
                "cnt",
                &bindings.context_capsule_id,
            )?,
            configuration_snapshot_id: content_id_from_digest(token.config_snapshot_hash),
            policy_snapshot_id: content_id_from_digest(token.policy_snapshot_hash),
            routing_snapshot_id: content_id_from_digest(token.routing_policy_hash),
            environment_digest: require_hex("environment_digest", &bindings.environment_digest)?,
            toolchain_digest: require_hex("toolchain_digest", &bindings.toolchain_digest)?,
        };
        if provenance.attempt_fence == 0 {
            return Err(RunnerError::Protocol(
                "attempt_fence must be nonzero".into(),
            ));
        }
        Ok(Self { change, provenance })
    }
}

fn apply_proposal_params(proposal: &PatchProposal) -> Result<Value, RunnerError> {
    let authoritative = proposal.authoritative_value()?;
    Ok(json!({ "proposal": authoritative }))
}

fn prepare_candidate_params(request: &PrepareCandidateRequest) -> Result<Value, RunnerError> {
    serde_json::to_value(request)
        .map_err(|err| RunnerError::Protocol(format!("encode prepare_candidate: {err}")))
}

fn parse_candidate_receipt(ok: Value) -> Result<CandidateReceipt, RunnerError> {
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

fn parse_checkpoint_binding(ok: &Value) -> Result<CheckpointBinding, RunnerError> {
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

fn parse_preservation_receipt(
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

fn tagged_git_oid(raw: &str) -> Result<String, RunnerError> {
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

fn require_prefixed(field: &str, prefix: &str, value: &str) -> Result<String, RunnerError> {
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

fn validate_checkpoint_binding(id: &str, digest: &str) -> Result<(), RunnerError> {
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

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use bullet_harness_core::{PatchMutation, PatchOperation, Preimage};

    #[test]
    fn provider_proposal_is_nested_exactly_once_without_legacy_flattening() {
        let proposal = PatchProposal {
            schema_version: 1,
            proposal_id: format!("cnt_{}", "1".repeat(64)),
            producing_attempt_id: format!("atm_{}", "2".repeat(64)),
            base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
            base_checkpoint_digest: "4".repeat(64),
            operations: vec![PatchOperation {
                path: "PONG.txt".into(),
                preimage: Preimage::Absent,
                mutation: PatchMutation::Write {
                    content_utf8: "PONG\n".into(),
                },
            }],
            gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
            intent_summary: "model narrative".into(),
            claims: vec!["not evidence".into()],
            uncertainties: vec![],
            done: true,
        };
        let params = apply_proposal_params(&proposal).unwrap();
        assert_eq!(params.as_object().unwrap().len(), 1);
        let wire = &params["proposal"];
        assert_eq!(wire["operations"][0]["mutation"]["kind"], "write");
        for forbidden in [
            "patches",
            "changes",
            "contents_hex",
            "intent_summary",
            "claims",
            "uncertainties",
            "done",
        ] {
            assert!(params.get(forbidden).is_none());
            assert!(wire.get(forbidden).is_none());
        }
    }

    #[test]
    fn malformed_daemon_checkpoint_bindings_fail_closed() {
        assert!(
            validate_checkpoint_binding(&format!("ckp_{}", "a".repeat(64)), &"b".repeat(64))
                .is_ok()
        );
        for (id, digest) in [
            (format!("ckp_{}", "A".repeat(64)), "b".repeat(64)),
            (format!("ckp_{}", "a".repeat(63)), "b".repeat(64)),
            (format!("bad_{}", "a".repeat(64)), "b".repeat(64)),
            (format!("ckp_{}", "a".repeat(64)), "b".repeat(63)),
        ] {
            assert!(validate_checkpoint_binding(&id, &digest).is_err());
        }

        assert!(validate_response_envelope(&json!({"id": 1, "ok": {}}), 1, "clone").is_ok());
        for malformed in [
            json!({"ok": {}}),
            json!({"id": 2, "ok": {}}),
            json!({"id": "1", "ok": {}}),
            json!({"id": 1}),
            json!({"id": 1, "ok": {}, "err": {"code": "X"}}),
        ] {
            assert!(validate_response_envelope(&malformed, 1, "clone").is_err());
        }
        assert_eq!(next_request_id(0).unwrap(), 1);
        assert!(next_request_id(u64::MAX).is_err());
    }

    #[test]
    fn prepare_candidate_encodes_change_and_provenance_never_legacy_seeds() {
        let request = PrepareCandidateRequest {
            change: ChangeRequest {
                id: format!("chg_{}", "1".repeat(64)),
                mission: format!("mis_{}", "2".repeat(64)),
                acceptance_root: "3".repeat(64),
            },
            provenance: CandidateProvenanceRequest {
                schema_version: 1,
                repository_id: format!("rep_{}", "4".repeat(64)),
                producing_attempt_id: format!("atm_{}", "5".repeat(64)),
                attempt_fence: 1,
                work_package_id: format!("wpk_{}", "6".repeat(64)),
                variant_id: format!("var_{}", "7".repeat(64)),
                plan_revision_id: format!("pln_{}", "8".repeat(64)),
                graph_revision_id: format!("grf_{}", "9".repeat(64)),
                base_checkpoint_id: format!("ckp_{}", "a".repeat(64)),
                base_commit: format!("sha1:{}", "b".repeat(40)),
                parent_candidate_ids: vec![],
                granted_scope: vec!["src".into()],
                context_capsule_id: format!("cnt_{}", "c".repeat(64)),
                configuration_snapshot_id: format!("cnt_{}", "d".repeat(64)),
                policy_snapshot_id: format!("cnt_{}", "e".repeat(64)),
                routing_snapshot_id: format!("cnt_{}", "f".repeat(64)),
                environment_digest: "1".repeat(64),
                toolchain_digest: "2".repeat(64),
            },
        };
        let params = prepare_candidate_params(&request).expect("encode");
        assert!(params.get("change_seed").is_none());
        assert!(params.get("mission").is_none());
        assert_eq!(params["change"]["id"], request.change.id);
        assert_eq!(
            params["provenance"]["producing_attempt_id"],
            request.provenance.producing_attempt_id
        );
        assert_eq!(params.as_object().map(|object| object.len()), Some(2));
    }

    #[test]
    fn nested_candidate_receipt_is_required_and_legacy_flat_shape_is_refused() {
        let ok = json!({
            "id": format!("can_{}", "1".repeat(64)),
            "content_id": format!("cnt_{}", "2".repeat(64)),
            "prepared_at": "2026-08-25T00:00:00Z",
            "manifest": {
                "base_commit": format!("sha1:{}", "a".repeat(40)),
                "head_commit": format!("sha1:{}", "b".repeat(40)),
                "tree_oid": format!("sha1:{}", "c".repeat(40)),
                "patch_digest": "d".repeat(64),
                "actual_scope": ["src/lib.rs"]
            }
        });
        let receipt = parse_candidate_receipt(ok).expect("nested");
        assert_eq!(receipt.tree_hash, format!("sha1:{}", "c".repeat(40)));
        assert_eq!(receipt.actual_scope, vec!["src/lib.rs"]);

        let legacy = json!({
            "id": format!("can_{}", "1".repeat(64)),
            "base_commit": "a".repeat(40),
            "head_commit": "b".repeat(40),
            "tree_hash": "c".repeat(40),
            "patch_hash": "d".repeat(64),
            "change_seed": "atm_x",
            "mission": "synthetic"
        });
        assert!(parse_candidate_receipt(legacy).is_err());
    }

    #[test]
    fn cleanup_and_preserve_refuse_bundle_path_and_require_sealed_token() {
        let preserve = json!({
            "preservation_receipt": "sealed-token",
            "preservation_receipt_digest": "a".repeat(64),
            "artifact_digest": "b".repeat(64),
            "destination": "/tmp/preserve"
        });
        let receipt = parse_preservation_receipt(preserve, Path::new("/tmp/preserve")).expect("ok");
        assert_eq!(receipt.token, "sealed-token");

        let legacy = json!({"bundle_path": "/tmp/bundle"});
        assert!(parse_preservation_receipt(legacy, Path::new("/tmp/x")).is_err());
    }

    #[test]
    fn missing_candidate_bindings_are_refused_instead_of_synthesized() {
        let empty = CandidateBindings::default();
        assert!(require_prefixed("change_id", "chg", &empty.change_id).is_err());
        assert!(require_prefixed("graph_revision_id", "grf", &empty.graph_revision_id).is_err());
        assert_eq!(
            tagged_git_oid(&"a".repeat(40)).unwrap(),
            format!("sha1:{}", "a".repeat(40))
        );
    }
}
