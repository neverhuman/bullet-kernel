//! Test-only workspace port used by Runner loop simulations.

use super::super::workspace::WorkspaceSession;
use crate::gitd::{
    ActiveGenerationBinding, ApplyProposalReceipt, CandidateReceipt, CheckpointBinding,
    PrepareCandidateRequest, PreservationReceipt, WorkspaceInfo,
};
use crate::RunnerError;
use bullet_domain::{AttemptId, AuthorityToken, Digest};
use bullet_harness_core::{PatchMutation, PatchProposal, Preimage};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) struct SimWorkspace {
    attempt_id: AttemptId,
    repo_dir: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    base_sha: String,
    checkpoint_id: String,
    checkpoint_digest: String,
    generation: u64,
    authority: AuthorityToken,
    active_generation: Option<ActiveGenerationBinding>,
    preserve_failure: Option<String>,
}

impl SimWorkspace {
    pub(super) fn new(authority: AuthorityToken) -> Self {
        Self {
            attempt_id: authority.attempt_id.clone(),
            repo_dir: None,
            runtime_dir: None,
            base_sha: String::new(),
            checkpoint_id: String::new(),
            checkpoint_digest: String::new(),
            generation: 0,
            authority,
            active_generation: None,
            preserve_failure: None,
        }
    }

    pub(super) fn fail_preserve(&mut self, reason: impl Into<String>) {
        self.preserve_failure = Some(reason.into());
    }

    fn repo(&self) -> Result<&Path, RunnerError> {
        self.repo_dir
            .as_deref()
            .ok_or_else(|| RunnerError::Protocol("test simulator has no clone".into()))
    }

    fn git(&self, args: &[&str]) -> Result<Vec<u8>, RunnerError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.repo()?)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .map_err(|error| RunnerError::Io {
                context: "test simulator git".into(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(RunnerError::Io {
                context: format!("test simulator git {args:?}"),
                reason: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(output.stdout)
    }

    pub(super) async fn clone_workspace(
        &mut self,
        source_repo: &Path,
        base_sha: &str,
        root: &Path,
        _allowed_prefixes: &[String],
    ) -> Result<WorkspaceInfo, RunnerError> {
        let workspace = root
            .join("work")
            .join(self.attempt_id.as_str())
            .join("generations")
            .join("generation-00000000000000000000");
        let repo = workspace.join("repo");
        let runtime = root.join("runtime").join(self.attempt_id.as_str());
        std::fs::create_dir_all(&workspace).map_err(|error| RunnerError::Io {
            context: "test simulator workspace".into(),
            reason: error.to_string(),
        })?;
        std::fs::create_dir_all(&runtime).map_err(|error| RunnerError::Io {
            context: "test simulator runtime".into(),
            reason: error.to_string(),
        })?;
        let output = Command::new("git")
            .args(["clone", "-q", "--no-hardlinks"])
            .arg(source_repo)
            .arg(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .map_err(|error| RunnerError::Io {
                context: "test simulator clone".into(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(RunnerError::Io {
                context: "test simulator clone".into(),
                reason: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        self.repo_dir = Some(repo.clone());
        self.runtime_dir = Some(runtime.clone());
        self.base_sha = base_sha.to_string();
        self.git(&["checkout", "-q", "--detach", base_sha])?;
        let git_tree = String::from_utf8_lossy(&self.git(&["write-tree"])?)
            .trim()
            .to_string();
        let active_generation = ActiveGenerationBinding::test_only(
            &self.authority,
            0,
            None,
            &format!("{base_sha}:0"),
            &format!("sha1:{git_tree}"),
        );
        let checkpoint = active_generation.checkpoint_binding();
        self.checkpoint_id.clone_from(&checkpoint.id);
        self.checkpoint_digest.clone_from(&checkpoint.digest);
        self.active_generation = Some(active_generation.clone());
        Ok(WorkspaceInfo {
            repo_dir: repo,
            runtime_dir: runtime,
            branch: "test-only/simulator".into(),
            base_sha: base_sha.to_string(),
            base_checkpoint_id: self.checkpoint_id.clone(),
            base_checkpoint_digest: self.checkpoint_digest.clone(),
            active_generation,
        })
    }
}

#[async_trait::async_trait]
impl WorkspaceSession for SimWorkspace {
    async fn apply_proposal(
        &mut self,
        proposal: &PatchProposal,
    ) -> Result<ApplyProposalReceipt, RunnerError> {
        if proposal.producing_attempt_id != self.attempt_id.as_str()
            || proposal.base_checkpoint_id != self.checkpoint_id
            || proposal.base_checkpoint_digest != self.checkpoint_digest
        {
            return Err(RunnerError::Gitd {
                method: "apply_proposal".into(),
                code: "STALE_CHECKPOINT".into(),
                message: "TEST_ONLY simulator binding mismatch".into(),
            });
        }
        let repo = self.repo()?.to_path_buf();
        for operation in &proposal.operations {
            let path = repo.join(&operation.path);
            match &operation.preimage {
                Preimage::Absent if path.exists() => {
                    return Err(RunnerError::Gitd {
                        method: "apply_proposal".into(),
                        code: "PREIMAGE_MISMATCH".into(),
                        message: format!("expected absent path: {}", operation.path),
                    });
                }
                Preimage::Digest { digest } => {
                    if !path.is_file() {
                        return Err(RunnerError::Gitd {
                            method: "apply_proposal".into(),
                            code: "PATH_ABSENT".into(),
                            message: format!("no regular file at: {}", operation.path),
                        });
                    }
                    let bytes = std::fs::read(&path).map_err(|error| RunnerError::Io {
                        context: "test simulator preimage".into(),
                        reason: error.to_string(),
                    })?;
                    if Digest::of(&bytes).to_hex() != *digest {
                        return Err(RunnerError::Gitd {
                            method: "apply_proposal".into(),
                            code: "PREIMAGE_MISMATCH".into(),
                            message: format!("stale preimage: {}", operation.path),
                        });
                    }
                }
                Preimage::Absent => {}
            }
        }
        for operation in &proposal.operations {
            let path = repo.join(&operation.path);
            if matches!(operation.mutation, PatchMutation::Delete) {
                if !path.is_file() {
                    return Err(RunnerError::Gitd {
                        method: "apply_proposal".into(),
                        code: "PATH_ABSENT".into(),
                        message: format!("no regular file to delete at: {}", operation.path),
                    });
                }
                std::fs::remove_file(&path).map_err(|error| RunnerError::Io {
                    context: "test simulator delete".into(),
                    reason: error.to_string(),
                })?;
                continue;
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| RunnerError::Io {
                    context: "test simulator parent".into(),
                    reason: error.to_string(),
                })?;
            }
            let PatchMutation::Write { content_utf8 } = &operation.mutation else {
                unreachable!("delete handled above")
            };
            std::fs::write(&path, content_utf8).map_err(|error| RunnerError::Io {
                context: "test simulator write".into(),
                reason: error.to_string(),
            })?;
        }
        self.generation += 1;
        let prior = self
            .active_generation
            .as_ref()
            .expect("test active generation")
            .clone();
        self.git(&["add", "-A"])?;
        let git_tree = String::from_utf8_lossy(&self.git(&["write-tree"])?)
            .trim()
            .to_string();
        let active_generation = ActiveGenerationBinding::test_only(
            &self.authority,
            self.generation,
            Some(&prior),
            &format!(
                "{}:{}:{}",
                self.base_sha, self.generation, proposal.proposal_id
            ),
            &format!("sha1:{git_tree}"),
        );
        let checkpoint = active_generation.checkpoint_binding();
        self.checkpoint_id.clone_from(&checkpoint.id);
        self.checkpoint_digest.clone_from(&checkpoint.digest);
        let current_generation = repo
            .parent()
            .expect("test repository generation")
            .to_path_buf();
        let next_generation = current_generation
            .parent()
            .expect("test generations root")
            .join(format!("generation-{:020}", self.generation));
        std::fs::rename(&current_generation, &next_generation).map_err(|error| {
            RunnerError::Io {
                context: "test simulator generation switch".into(),
                reason: error.to_string(),
            }
        })?;
        let repo_dir = next_generation.join("repo");
        self.repo_dir = Some(repo_dir.clone());
        self.active_generation = Some(active_generation.clone());
        Ok(ApplyProposalReceipt {
            proposal_id: proposal.proposal_id.clone(),
            applied: u64::try_from(proposal.operations.len())
                .map_err(|error| RunnerError::Protocol(error.to_string()))?,
            checkpoint,
            repo_dir,
            active_generation,
        })
    }

    async fn checkpoint(&mut self) -> Result<CheckpointBinding, RunnerError> {
        let receipt = serde_json::json!({
            "classification": "TEST_ONLY_SIMULATOR",
            "attempt_id": self.attempt_id.as_str(),
            "id": self.checkpoint_id,
            "digest": self.checkpoint_digest,
        });
        let runtime = self
            .runtime_dir
            .as_ref()
            .ok_or_else(|| RunnerError::Protocol("test simulator has no runtime".into()))?;
        std::fs::write(runtime.join("checkpoint.json"), receipt.to_string()).map_err(|error| {
            RunnerError::Io {
                context: "test simulator checkpoint".into(),
                reason: error.to_string(),
            }
        })?;
        Ok(CheckpointBinding {
            id: self.checkpoint_id.clone(),
            digest: self.checkpoint_digest.clone(),
        })
    }

    async fn prepare_candidate(
        &mut self,
        request: &PrepareCandidateRequest,
    ) -> Result<CandidateReceipt, RunnerError> {
        let change_seed = request.provenance.producing_attempt_id.as_str();
        self.git(&["add", "-A"])?;
        self.git(&[
            "-c",
            "user.name=Bullet Test Simulator",
            "-c",
            "user.email=simulator@invalid",
            "commit",
            "-q",
            "-m",
            "test-only candidate",
        ])?;
        let head = String::from_utf8_lossy(&self.git(&["rev-parse", "HEAD"])?)
            .trim()
            .to_string();
        let tree = String::from_utf8_lossy(&self.git(&["rev-parse", "HEAD^{tree}"])?)
            .trim()
            .to_string();
        let patch = self.git(&["diff", "--binary", &format!("{}..HEAD", self.base_sha)])?;
        let paths = String::from_utf8_lossy(&self.git(&[
            "diff",
            "--name-only",
            &format!("{}..HEAD", self.base_sha),
        ])?)
        .lines()
        .map(str::to_string)
        .collect();
        let digest = Digest::of(&patch).to_hex();
        Ok(CandidateReceipt {
            id: format!("can_{}", Digest::of(change_seed.as_bytes()).to_hex()),
            content_id: format!("cnt_{}", Digest::of(change_seed.as_bytes()).to_hex()),
            base_commit: self.base_sha.clone(),
            head_commit: head,
            tree_hash: tree,
            patch_hash: digest,
            actual_scope: paths,
            prepared_at: "TEST_ONLY_SIMULATOR".into(),
        })
    }

    async fn preserve(&mut self, destination: &Path) -> Result<PreservationReceipt, RunnerError> {
        if let Some(reason) = self.preserve_failure.take() {
            return Err(RunnerError::Io {
                context: "test simulator preserve".into(),
                reason,
            });
        }
        if destination.exists() {
            return Err(RunnerError::Protocol(
                "test simulator preserve destination exists".into(),
            ));
        }
        std::fs::create_dir_all(destination).map_err(|error| RunnerError::Io {
            context: "test simulator preserve".into(),
            reason: error.to_string(),
        })?;
        let retained_repo = destination.join("generation/repo");
        std::fs::create_dir_all(
            retained_repo
                .parent()
                .expect("test retained repository parent"),
        )
        .map_err(|error| RunnerError::Io {
            context: "test simulator preserve generation".into(),
            reason: error.to_string(),
        })?;
        let output = Command::new("git")
            .args(["clone", "-q", "--no-hardlinks"])
            .arg(self.repo()?)
            .arg(&retained_repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .map_err(|error| RunnerError::Io {
                context: "test simulator preserve repository".into(),
                reason: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(RunnerError::Io {
                context: "test simulator preserve repository".into(),
                reason: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let token = format!("TEST_ONLY_PRESERVE:{}", self.attempt_id);
        let digest = Digest::of(token.as_bytes()).to_hex();
        let artifact = Digest::of(destination.display().to_string().as_bytes()).to_hex();
        std::fs::write(destination.join("preservation.json"), token.as_bytes()).map_err(
            |error| RunnerError::Io {
                context: "test simulator preserve receipt".into(),
                reason: error.to_string(),
            },
        )?;
        Ok(PreservationReceipt {
            token,
            digest,
            artifact_digest: artifact,
            destination: destination.to_path_buf(),
        })
    }

    async fn cleanup(
        &mut self,
        receipt: &PreservationReceipt,
        deleted_at: &str,
    ) -> Result<(), RunnerError> {
        if receipt.token.is_empty() || deleted_at.is_empty() {
            return Err(RunnerError::Protocol(
                "test simulator cleanup lacks its preservation binding".into(),
            ));
        }
        let repo = self.repo()?.to_path_buf();
        let work = repo
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| RunnerError::Protocol("test simulator work root is absent".into()))?;
        std::fs::remove_dir_all(work).map_err(|error| RunnerError::Io {
            context: "test simulator cleanup".into(),
            reason: error.to_string(),
        })?;
        let runtime = self
            .runtime_dir
            .as_deref()
            .ok_or_else(|| RunnerError::Protocol("test simulator runtime is absent".into()))?;
        std::fs::write(runtime.join("tombstone.json"), receipt.digest.as_bytes()).map_err(
            |error| RunnerError::Io {
                context: "test simulator cleanup tombstone".into(),
                reason: error.to_string(),
            },
        )?;
        self.repo_dir = None;
        Ok(())
    }
}
