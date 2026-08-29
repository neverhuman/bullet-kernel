//! One bounded line-delimited JSON session with BulletGit.

use super::candidate::{
    apply_proposal_params, parse_candidate_receipt, parse_checkpoint_binding,
    parse_preservation_receipt, prepare_candidate_params, validate_checkpoint_binding,
};
use super::{
    gitd_binary, AdmittedGitdBinary, ApplyProposalReceipt, CandidateReceipt, CheckpointBinding,
    PrepareCandidateRequest, PreservationReceipt, WorkspaceInfo,
};
use crate::error::RunnerError;
use bullet_domain::AuthorityToken;
use bullet_harness_core::PatchProposal;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const CALL_TIMEOUT: Duration = Duration::from_secs(60);

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

pub(super) fn next_request_id(current: u64) -> Result<u64, RunnerError> {
    current
        .checked_add(1)
        .ok_or_else(|| RunnerError::Protocol("gitd request id exhausted".into()))
}

pub(super) fn validate_response_envelope(
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
        let token = crate::kernel_authority::admit_token(method, &self.token, &params)?;
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
