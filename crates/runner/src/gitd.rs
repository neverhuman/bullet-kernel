//! Client for the `bullet-gitd` workspace daemon (line-delimited JSON over
//! stdio; protocol in bullet-git/docs/architecture.md). The daemon is the
//! sole writer of the private clone; it pins attempt/fence/nonce from the
//! initial clone token and refuses every stale call.

use crate::error::RunnerError;
use bullet_domain::AuthorityToken;
use bullet_harness_core::{ChangeOp, FileChange};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const CALL_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_BINARY: &str = "/home/ubuntu/bullet/bullet-git/target/debug/bullet-gitd";

/// Resolve the daemon binary: `BULLET_GITD_BIN` or the family default path.
#[must_use]
pub fn gitd_binary() -> PathBuf {
    std::env::var_os("BULLET_GITD_BIN").map_or_else(|| PathBuf::from(DEFAULT_BINARY), PathBuf::from)
}

/// True when the daemon binary exists. Tests skip gitd-dependent cases with
/// a clear reason when it is absent.
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
    /// Daemon refusals become typed `STALE_AUTHORITY` or `GITD_REFUSED`.
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
        serde_json::from_value(ok)
            .map_err(|err| RunnerError::Protocol(format!("clone result: {err}")))
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

    /// Apply whole-file changes all-or-nothing. Deletes are not supported by
    /// the daemon protocol; callers feed them back to the model instead.
    ///
    /// # Errors
    ///
    /// `PROTOCOL_ERROR` for a delete op; typed daemon refusal otherwise.
    pub async fn apply_change(&mut self, changes: &[FileChange]) -> Result<u64, RunnerError> {
        let mut patches = Vec::with_capacity(changes.len());
        for change in changes {
            if change.op == ChangeOp::Delete {
                return Err(RunnerError::Protocol(format!(
                    "delete of {} is not supported by bullet-gitd v1",
                    change.path
                )));
            }
            let contents = change.contents.as_deref().unwrap_or_default();
            patches.push(json!({
                "path": change.path,
                "contents_hex": hex::encode(contents.as_bytes()),
            }));
        }
        let ok = self
            .call("apply_change", json!({ "patches": patches }))
            .await?;
        Ok(ok
            .get("applied")
            .and_then(Value::as_u64)
            .unwrap_or_default())
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
