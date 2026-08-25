//! Client for the `bullet-gitd` workspace daemon (line-delimited JSON over
//! stdio; protocol in bullet-git/docs/architecture.md). The daemon is the
//! sole writer of the private clone; it pins attempt/fence/nonce from the
//! initial clone token and refuses every stale call.

use crate::error::RunnerError;
use bullet_domain::AuthorityToken;
use bullet_harness_core::PatchProposal;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const CALL_TIMEOUT: Duration = Duration::from_secs(60);
const FAMILY_BINARY: &str = "../../../bullet-git/target/debug/bullet-gitd";

/// Resolve the daemon binary: `BULLET_GITD_BIN` or the family default path.
#[must_use]
pub fn gitd_binary() -> PathBuf {
    std::env::var_os("BULLET_GITD_BIN").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join(FAMILY_BINARY),
        PathBuf::from,
    )
}

/// True when the daemon binary exists.
#[must_use]
pub fn gitd_available() -> bool {
    gitd_binary().is_file()
}

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
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Exact candidate receipt from `prepare_candidate` (subset of the
/// BulletGit Candidate; unknown fields are ignored).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateReceipt {
    /// Content-derived candidate id.
    pub id: String,
    /// Base commit SHA.
    pub base_commit: String,
    /// Head commit SHA on the private branch.
    pub head_commit: String,
    /// Tree SHA of the head commit.
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

impl GitdSession {
    /// Spawn the daemon with the incarnation's authority token.
    ///
    /// # Errors
    ///
    /// Returns `IO_FAILED` when the binary cannot be started (set
    /// `BULLET_GITD_BIN` or build bullet-gitd) or the token fails to encode.
    pub async fn spawn(token: &AuthorityToken) -> Result<Self, RunnerError> {
        let binary = gitd_binary();
        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| io_err(&format!("spawn {}", binary.display()), err))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io_err("gitd stdin", "pipe missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io_err("gitd stdout", "pipe missing"))?;
        let token =
            serde_json::to_value(token).map_err(|err| io_err("encode authority token", err))?;
        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 0,
            token,
        })
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
        self.next_id += 1;
        let line =
            json!({ "id": self.next_id, "method": method, "token": token, "params": params })
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
    pub async fn checkpoint(&mut self) -> Result<Value, RunnerError> {
        self.call("checkpoint", json!({})).await
    }

    /// Prepare the exact candidate: real SHAs plus the BLAKE3 patch digest.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure.
    pub async fn prepare_candidate(
        &mut self,
        change_seed: &str,
        mission: &str,
    ) -> Result<CandidateReceipt, RunnerError> {
        let ok = self
            .call(
                "prepare_candidate",
                json!({ "change_seed": change_seed, "mission": mission }),
            )
            .await?;
        serde_json::from_value(ok)
            .map_err(|err| RunnerError::Protocol(format!("prepare_candidate result: {err}")))
    }

    /// Preserve a bundle receipt and delete the workspace.
    ///
    /// # Errors
    ///
    /// Typed daemon refusal or IO failure.
    pub async fn cleanup(
        &mut self,
        bundle_path: &Path,
        deleted_at: &str,
    ) -> Result<Value, RunnerError> {
        self.call(
            "cleanup",
            json!({
                "bundle_path": bundle_path.display().to_string(),
                "deleted_at": deleted_at,
            }),
        )
        .await
    }
}

fn apply_proposal_params(proposal: &PatchProposal) -> Result<Value, RunnerError> {
    let authoritative = proposal.authoritative_value()?;
    Ok(json!({ "proposal": authoritative }))
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
    }
}
