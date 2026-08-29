//! The Attempt loop (ADR 0001): acquire → private clone → read-only provider
//! session → scope-checked apply → deterministic gate → bounded repair →
//! exact candidate → release. A freeze (stale authority or self-kill) stops
//! all applying, checkpoints salvage, and terminates the provider.

#[cfg(test)]
mod binding_tests;
mod cleanup;
mod drive;
mod session;
#[cfg(test)]
mod simulation_tests;
mod workspace;

use crate::candidate_authority::CandidatePreparationAdmission;
use crate::capsule::Capsule;
use crate::clock::Clock;
use crate::error::RunnerError;
use crate::gate::{GateRegistry, GateReport};
use crate::gitd::{
    CandidateReceipt, GitdSession, PreservationReceipt, WorkspaceInfo, WorkspaceRootGuard,
};
use crate::heartbeat::{start_heartbeat, HeartbeatConfig, HeartbeatHandle};
use crate::journal::JournalSink;
use crate::lease::{AcquireGrant, AcquireRequest, HeartbeatCall, LeaseClient};
use bullet_domain::AttemptId;
use bullet_harness_core::{AgentSessionId, HarnessAdapter, StartSession};
use drive::{cleanup_before_session, run_cloned_attempt_guarded};
#[cfg(test)]
use session::pre_apply_refusal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use workspace::WorkspaceSession;

/// Everything one attempt run needs beyond the lease request.
#[derive(Clone, Debug)]
pub struct AttemptConfig {
    /// Source repository (the mirror bullet-gitd clones from).
    pub source_repo: PathBuf,
    /// Exact base commit SHA.
    pub base_sha: String,
    /// Root under which `work/` and `runtime/` live.
    pub workspace_root: PathBuf,
    /// Mission objective for the prompt capsule.
    pub objective: String,
    /// Granted change-intent path prefixes.
    pub scope_prefixes: Vec<String>,
    /// Ordered gate identifiers admitted by policy for this Attempt.
    pub admitted_gate_ids: Vec<String>,
    /// Bounded repair rounds after the initial turn (ADR 0001: 2).
    pub max_repair_rounds: u32,
    /// Wall-clock bound for one provider invocation.
    pub turn_timeout: Duration,
    /// Heartbeat cadence and lease TTL.
    pub heartbeat: HeartbeatConfig,
    /// Independently pinned Candidate-preparation authority. Missing refuses.
    candidate_preparation: Option<CandidatePreparationAdmission>,
    /// Exact new external directory where the successful Candidate is retained.
    preservation_destination: Option<PathBuf>,
}

impl AttemptConfig {
    /// Config with ADR 0001 defaults for the bounded loop.
    #[must_use]
    pub fn new(
        source_repo: PathBuf,
        base_sha: String,
        workspace_root: PathBuf,
        objective: String,
        scope_prefixes: Vec<String>,
        admitted_gate_ids: Vec<String>,
    ) -> Self {
        Self {
            source_repo,
            base_sha,
            workspace_root,
            objective,
            scope_prefixes,
            admitted_gate_ids,
            max_repair_rounds: 2,
            turn_timeout: Duration::from_secs(600),
            heartbeat: HeartbeatConfig::default(),
            candidate_preparation: None,
            preservation_destination: None,
        }
    }

    /// Require one exact Candidate source and independently pinned public key.
    #[must_use]
    pub fn with_candidate_preparation(mut self, admission: CandidatePreparationAdmission) -> Self {
        self.candidate_preparation = Some(admission);
        self
    }

    /// Bind the exact new external directory for successful preservation.
    #[must_use]
    pub fn with_preservation_destination(mut self, destination: PathBuf) -> Self {
        self.preservation_destination = Some(destination);
        self
    }

    pub(super) fn candidate_preparation(
        &self,
    ) -> Result<&CandidatePreparationAdmission, RunnerError> {
        self.candidate_preparation.as_ref().ok_or_else(|| {
            RunnerError::Protocol(
                "Candidate-preparation digest and verification key are not admitted".into(),
            )
        })
    }

    pub(super) fn preservation_destination(&self) -> Result<&std::path::Path, RunnerError> {
        let destination = self.preservation_destination.as_deref().ok_or_else(|| {
            RunnerError::Protocol("successful Candidate preservation is not admitted".into())
        })?;
        if !destination.is_absolute() || destination.file_name().is_none() {
            return Err(RunnerError::Protocol(
                "preservation destination must be an absolute new directory".into(),
            ));
        }
        if destination.exists() {
            return Err(RunnerError::Protocol(format!(
                "preservation destination already exists: {}",
                destination.display()
            )));
        }
        let parent = destination.parent().ok_or_else(|| {
            RunnerError::Protocol("preservation destination has no parent".into())
        })?;
        let canonical = std::fs::canonicalize(parent).map_err(|error| RunnerError::Io {
            context: "canonicalize preservation parent".into(),
            reason: error.to_string(),
        })?;
        if canonical != parent {
            return Err(RunnerError::Protocol(
                "preservation parent contains a symlink or non-canonical component".into(),
            ));
        }
        Ok(destination)
    }

    fn capsule(&self, grant: &AcquireGrant, workspace: &WorkspaceInfo) -> Capsule {
        Capsule {
            objective: self.objective.clone(),
            scope_prefixes: self.scope_prefixes.clone(),
            base_sha: self.base_sha.clone(),
            producing_attempt_id: grant.attempt.id.to_string(),
            base_checkpoint_id: workspace.base_checkpoint_id.clone(),
            base_checkpoint_digest: workspace.base_checkpoint_digest.clone(),
            admitted_gate_ids: self.admitted_gate_ids.clone(),
        }
    }
}

/// Successful attempt result.
#[derive(Clone, Debug)]
pub struct AttemptOutcome {
    /// The fenced attempt.
    pub attempt_id: AttemptId,
    /// Permanent fence epoch.
    pub fence: u64,
    /// Exact candidate receipt with real SHAs.
    pub candidate: CandidateReceipt,
    /// Candidate-bound preservation and cleanup authority.
    pub preservation: CandidatePreservation,
    /// Repair rounds consumed.
    pub repair_rounds: u32,
    /// Passing reports for every admitted gate, in policy order.
    pub gates: Vec<GateReport>,
}

/// Strict binding between one successful Candidate and its sealed preservation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePreservation {
    /// Exact Candidate identity.
    pub candidate_id: String,
    /// Exact Candidate base commit.
    pub base_commit: String,
    /// Exact Candidate head commit.
    pub head_commit: String,
    /// Exact Candidate tree.
    pub tree_hash: String,
    /// Exact Candidate patch digest.
    pub patch_hash: String,
    /// Producing Attempt identity.
    pub attempt_id: AttemptId,
    /// Permanent producing fence.
    pub fence: u64,
    /// Sealed BulletGit preservation receipt.
    pub receipt: PreservationReceipt,
}

impl CandidatePreservation {
    pub(super) fn bind(
        candidate: &CandidateReceipt,
        grant: &AcquireGrant,
        expected_destination: &std::path::Path,
        receipt: PreservationReceipt,
    ) -> Result<Self, RunnerError> {
        if receipt.destination != expected_destination || !receipt.destination.is_dir() {
            return Err(RunnerError::Protocol(
                "preservation receipt destination differs from the admitted directory".into(),
            ));
        }
        if receipt.token.is_empty()
            || !is_lower_hex(&receipt.digest, 64)
            || !is_lower_hex(&receipt.artifact_digest, 64)
        {
            return Err(RunnerError::Protocol(
                "preservation receipt is empty or has a malformed digest".into(),
            ));
        }
        if candidate.prepared_at.is_empty() {
            return Err(RunnerError::Protocol(
                "Candidate preparation time is absent; cleanup cannot be audited".into(),
            ));
        }
        let binding = Self {
            candidate_id: candidate.id.clone(),
            base_commit: candidate.base_commit.clone(),
            head_commit: candidate.head_commit.clone(),
            tree_hash: candidate.tree_hash.clone(),
            patch_hash: candidate.patch_hash.clone(),
            attempt_id: grant.attempt.id.clone(),
            fence: grant.attempt.fence,
            receipt,
        };
        binding.validate_against(candidate, &grant.attempt.id, grant.attempt.fence)?;
        Ok(binding)
    }

    /// Require this record to name one exact Candidate and producing Attempt.
    pub fn validate_against(
        &self,
        candidate: &CandidateReceipt,
        attempt_id: &AttemptId,
        fence: u64,
    ) -> Result<(), RunnerError> {
        if self.candidate_id != candidate.id
            || self.base_commit != candidate.base_commit
            || self.head_commit != candidate.head_commit
            || self.tree_hash != candidate.tree_hash
            || self.patch_hash != candidate.patch_hash
            || &self.attempt_id != attempt_id
            || self.fence != fence
        {
            return Err(RunnerError::Protocol(
                "Candidate preservation binding does not match the successful outcome".into(),
            ));
        }
        if self.receipt.token.is_empty()
            || !is_lower_hex(&self.receipt.digest, 64)
            || !is_lower_hex(&self.receipt.artifact_digest, 64)
            || !self.receipt.destination.is_absolute()
            || !self.receipt.destination.is_dir()
        {
            return Err(RunnerError::Protocol(
                "Candidate preservation contains an invalid sealed receipt".into(),
            ));
        }
        Ok(())
    }
}

fn is_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn check_freeze(heartbeat: &HeartbeatHandle) -> Result<(), RunnerError> {
    match heartbeat.frozen() {
        Some(reason) => Err(reason.to_error()),
        None => Ok(()),
    }
}

fn begin_attempt_heartbeat(
    client: Arc<dyn LeaseClient>,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    clock: Arc<dyn Clock>,
) -> Result<HeartbeatHandle, RunnerError> {
    let call = HeartbeatCall::for_grant(grant)?;
    start_heartbeat(client, call, config.heartbeat.clone(), clock)
}

pub(super) fn start_request(
    grant: &AcquireGrant,
    ws: &WorkspaceInfo,
    config: &AttemptConfig,
) -> StartSession {
    StartSession {
        session_id: AgentSessionId::new(grant.attempt.id.as_str()),
        workdir: ws.repo_dir.clone(),
        artifact_dir: config
            .workspace_root
            .join("artifacts")
            .join(grant.attempt.id.as_str()),
        model: None,
        structured_schema: serde_json::from_str(bullet_harness_core::proposal::schema_source())
            .ok(),
        max_budget_usd: None,
        wall_timeout: config.turn_timeout,
    }
}

/// Run one complete attempt.
///
/// # Errors
///
/// Typed runner failure; a freeze surfaces as `STALE_AUTHORITY` or
/// `SELF_KILL_DEADLINE` after salvage and provider termination.
pub async fn run_attempt(
    client: Arc<dyn LeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<dyn JournalSink>,
    clock: Arc<dyn Clock>,
    request: &AcquireRequest,
    config: &AttemptConfig,
) -> Result<AttemptOutcome, RunnerError> {
    GateRegistry::v1().validate_selection(&config.admitted_gate_ids)?;
    config.preservation_destination()?;
    let root_guard = WorkspaceRootGuard::open(&config.workspace_root)?;
    let grant = client.acquire(request).await?;
    journal.record(
        "lease_acquired",
        &format!("attempt {} fence {}", grant.attempt.id, grant.attempt.fence),
    );
    let heartbeat = match begin_attempt_heartbeat(client.clone(), &grant, config, clock) {
        Ok(heartbeat) => heartbeat,
        Err(error) => {
            cleanup_before_session(
                client.as_ref(),
                &grant,
                journal.as_ref(),
                "heartbeat_start_refused",
                &error,
            )
            .await;
            return Err(error);
        }
    };
    let mut gitd = match GitdSession::spawn(&grant.authority_token).await {
        Ok(gitd) => gitd,
        Err(error) => {
            heartbeat.abort();
            cleanup_before_session(
                client.as_ref(),
                &grant,
                journal.as_ref(),
                "workspace_refused",
                &error,
            )
            .await;
            return Err(error);
        }
    };
    let mut ws = match gitd
        .clone_workspace(
            &config.source_repo,
            &config.base_sha,
            &config.workspace_root,
            &config.scope_prefixes,
        )
        .await
    {
        Ok(workspace) => workspace,
        Err(error) => {
            heartbeat.abort();
            cleanup_before_session(
                client.as_ref(),
                &grant,
                journal.as_ref(),
                "workspace_refused",
                &error,
            )
            .await;
            return Err(error);
        }
    };
    if let Err(error) = ws.validate_initial(
        &config.workspace_root,
        &config.base_sha,
        &grant.authority_token,
    ) {
        heartbeat.abort();
        cleanup_before_session(
            client.as_ref(),
            &grant,
            journal.as_ref(),
            "workspace_identity_refused",
            &error,
        )
        .await;
        return Err(error);
    }
    journal.record("workspace_cloned", &ws.repo_dir.display().to_string());
    let mut generation_guard =
        match root_guard.bind(&grant.authority_token, ws.active_generation.generation) {
            Ok(guard) => guard,
            Err(error) => {
                heartbeat.abort();
                cleanup_before_session(
                    client.as_ref(),
                    &grant,
                    journal.as_ref(),
                    "workspace_descriptor_refused",
                    &error,
                )
                .await;
                return Err(error);
            }
        };
    run_cloned_attempt_guarded(
        client,
        adapter,
        journal,
        &grant,
        config,
        &mut gitd,
        &mut ws,
        &mut generation_guard,
        heartbeat,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
async fn run_cloned_attempt(
    client: Arc<dyn LeaseClient>,
    adapter: Arc<dyn HarnessAdapter>,
    journal: Arc<dyn JournalSink>,
    clock: Arc<dyn Clock>,
    grant: &AcquireGrant,
    config: &AttemptConfig,
    gitd: &mut dyn WorkspaceSession,
    ws: &mut WorkspaceInfo,
) -> Result<AttemptOutcome, RunnerError> {
    let root_guard = WorkspaceRootGuard::open(&config.workspace_root)?;
    let mut generation_guard =
        root_guard.bind(&grant.authority_token, ws.active_generation.generation)?;
    let heartbeat = begin_attempt_heartbeat(client.clone(), grant, config, clock)?;
    run_cloned_attempt_guarded(
        client,
        adapter,
        journal,
        grant,
        config,
        gitd,
        ws,
        &mut generation_guard,
        heartbeat,
    )
    .await
}
