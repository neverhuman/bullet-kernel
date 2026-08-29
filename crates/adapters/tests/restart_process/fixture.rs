use crate::model::{CrashAfter, WorkerAction, WorkerManifest, WorkerManifestInput};
use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, EffectRecoveryAuthority, EffectState, LeaseGrant, LeaseService, Ledger,
    PlanInput, ReleaseRequest, StoredGraph, ZERO_OID,
};
use bullet_domain::{AttemptState, AuthorityToken, CandidateId, EffectId, TaskClass};
use bullet_effects_core::{
    authorize, dispatch, propose, ForgeEffects, IntentInput, LocalBareForge, LossMode,
    LostResponseForge,
};
use chrono::Utc;
use std::fs::{OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct Fixture {
    _temp: tempfile::TempDir,
    pub(crate) root: PathBuf,
    pub(crate) database: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) bare: PathBuf,
    pub(crate) forge_log: PathBuf,
    pub(crate) graph: StoredGraph,
    pub(crate) intent_id: EffectId,
    pub(crate) target_ref: String,
    pub(crate) base_oid: String,
    pub(crate) desired_oid: String,
    pub(crate) token: AuthorityToken,
    pub(crate) grant: LeaseGrant,
    pub(crate) authority: EffectRecoveryAuthority,
    sequence: u64,
}

impl Fixture {
    pub(crate) fn new(seed: &str) -> Result<Self, String> {
        let temp = tempfile::Builder::new()
            .prefix("bullet-restart-")
            .tempdir()
            .map_err(|error| error.to_string())?;
        std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let root = temp
            .path()
            .canonicalize()
            .map_err(|error| error.to_string())?;
        let workspace = root.join("workspace");
        let bare = root.join("target.git");
        let database = root.join("ledger.sqlite3");
        let forge_log = root.join("forge.log");
        std::fs::create_dir(&workspace).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&workspace, Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        init_workspace(&workspace)?;
        let base_oid = git_output(&workspace, &["rev-parse", "HEAD~1"])?;
        let desired_oid = git_output(&workspace, &["rev-parse", "HEAD"])?;
        LocalBareForge::init(&bare).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&bare, Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&forge_log)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;

        let mut ledger = SqliteLedger::open(&database).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&database, Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        let graph = materialize_plan(
            &mut ledger,
            seed,
            &PlanInput {
                title: "restart recovery".into(),
                objective: "prove process death and exact readback".into(),
                packages: vec![("package".into(), TaskClass::BoundedBugFix)],
            },
            &now(),
        )
        .map_err(|error| error.to_string())?;
        let (_, original_token, original_grant) =
            LeaseService::acquire(&mut ledger, &graph, 0, &format!("{seed}-original"), 15)
                .map_err(|error| error.to_string())?;
        let candidate = CandidateId::from_seed(&format!("{seed}-candidate"));
        let target_ref = format!("refs/heads/bullet/candidate/{candidate}");
        let input = IntentInput {
            provider: "local-bare".into(),
            logical_effect_key: format!("restart:{seed}:{candidate}"),
            target_ref: target_ref.clone(),
            new_oid: desired_oid.clone(),
            expected_old_oid: ZERO_OID.into(),
            attempt_id: original_token.attempt_id.clone(),
            fence: original_token.attempt_fence,
            policy_version: "policy-v1".into(),
            provider_idempotency_key: None,
        };
        let (intent, created) =
            propose(&mut ledger, &input, &now()).map_err(|error| error.to_string())?;
        if !created {
            return Err("fixture intent replayed unexpectedly".into());
        }
        let (_, outbox) = authorize(&mut ledger, &intent.id, &original_token, &now())
            .map_err(|error| error.to_string())?;
        let mut lost =
            LostResponseForge::new(LocalBareForge::open(&bare).map_err(|error| error.to_string())?);
        lost.lose_next(LossMode::BeforePush);
        let state = dispatch(
            &mut ledger,
            &mut lost,
            &intent.id,
            &workspace,
            Some(outbox),
            &now(),
        )
        .map_err(|error| error.to_string())?;
        if state != EffectState::OutcomeUnknown {
            return Err(format!("fixture effect ended as {state:?}"));
        }
        ledger
            .release_lease(&ReleaseRequest {
                variant_id: original_grant.attempt.variant_id,
                attempt_id: original_grant.attempt.id,
                final_state: AttemptState::Crashed,
                requeue: true,
            })
            .map_err(|error| error.to_string())?;
        let (_, token, grant) =
            LeaseService::acquire(&mut ledger, &graph, 0, &format!("{seed}-recovery-a"), 15)
                .map_err(|error| error.to_string())?;
        let authority = recovery_authority(&ledger, &token)?;
        let graph = ledger
            .get_graph(&graph.mission.id)
            .map_err(|error| error.to_string())?
            .ok_or("durable fixture graph absent")?;
        drop(ledger);
        Ok(Self {
            _temp: temp,
            root,
            database,
            workspace,
            bare,
            forge_log,
            graph,
            intent_id: intent.id,
            target_ref,
            base_oid,
            desired_oid,
            token,
            grant,
            authority,
            sequence: 0,
        })
    }

    pub(crate) fn manifest(
        &mut self,
        action: WorkerAction,
        crash_after: CrashAfter,
        authority: EffectRecoveryAuthority,
        token: AuthorityToken,
        grant: LeaseGrant,
    ) -> Result<WorkerManifest, String> {
        self.sequence += 1;
        WorkerManifest::new(WorkerManifestInput {
            root: self.root.clone(),
            database: self.database.clone(),
            workspace: self.workspace.clone(),
            bare: self.bare.clone(),
            forge_log: self.forge_log.clone(),
            result: self.root.join(format!("result-{}.txt", self.sequence)),
            intent_id: self.intent_id.clone(),
            authority,
            token,
            graph: self.graph.clone(),
            grant,
            expected_ref: self.target_ref.clone(),
            expected_old_oid: ZERO_OID.into(),
            expected_new_oid: self.desired_oid.clone(),
            action,
            crash_after,
        })
    }

    pub(crate) fn current_manifest(
        &mut self,
        action: WorkerAction,
        crash_after: CrashAfter,
    ) -> Result<WorkerManifest, String> {
        self.manifest(
            action,
            crash_after,
            self.authority.clone(),
            self.token.clone(),
            self.grant.clone(),
        )
    }

    pub(crate) fn acquire_successor(&mut self, seed: &str) -> Result<(), String> {
        let mut ledger = SqliteLedger::open(&self.database).map_err(|error| error.to_string())?;
        ledger
            .release_lease(&ReleaseRequest {
                variant_id: self.grant.attempt.variant_id.clone(),
                attempt_id: self.grant.attempt.id.clone(),
                final_state: AttemptState::Crashed,
                requeue: true,
            })
            .map_err(|error| error.to_string())?;
        let (_, token, grant) = LeaseService::acquire(&mut ledger, &self.graph, 0, seed, 15)
            .map_err(|error| error.to_string())?;
        self.authority = recovery_authority(&ledger, &token)?;
        self.graph = ledger
            .get_graph(&self.graph.mission.id)
            .map_err(|error| error.to_string())?
            .ok_or("durable successor graph absent")?;
        self.token = token;
        self.grant = grant;
        Ok(())
    }

    pub(crate) fn preseed_third_oid(&self) -> Result<String, String> {
        std::fs::write(self.workspace.join("third"), b"third\n")
            .map_err(|error| error.to_string())?;
        git_status(&self.workspace, &["add", "third"])?;
        git_status(&self.workspace, &["commit", "-qm", "third"])?;
        let third = git_output(&self.workspace, &["rev-parse", "HEAD"])?;
        let refspec = format!("{third}:{}", self.target_ref);
        git_status(
            &self.workspace,
            &["push", "-q", &self.bare.display().to_string(), &refspec],
        )?;
        Ok(third)
    }

    pub(crate) fn remote_ref(&self) -> Result<Option<String>, String> {
        LocalBareForge::open(&self.bare)
            .map_err(|error| error.to_string())?
            .read_ref(&self.target_ref)
            .map_err(|error| error.to_string())
    }
}

fn recovery_authority(
    ledger: &SqliteLedger,
    token: &AuthorityToken,
) -> Result<EffectRecoveryAuthority, String> {
    let current = ledger
        .current_authority()
        .map_err(|error| error.to_string())?;
    EffectRecoveryAuthority::from_token(
        token,
        current.authority_epoch(),
        current.freeze_generation(),
        0,
    )
    .map_err(|error| error.to_string())
}

fn init_workspace(path: &Path) -> Result<(), String> {
    git_status(path, &["init", "-q", "-b", "main", "."])?;
    git_status(path, &["config", "user.name", "bullet"])?;
    git_status(path, &["config", "user.email", "bullet@test"])?;
    std::fs::write(path.join("file.txt"), b"base\n").map_err(|error| error.to_string())?;
    git_status(path, &["add", "file.txt"])?;
    git_status(path, &["commit", "-qm", "base"])?;
    std::fs::write(path.join("file.txt"), b"head\n").map_err(|error| error.to_string())?;
    git_status(path, &["add", "file.txt"])?;
    git_status(path, &["commit", "-qm", "head"])
}

fn git_status(path: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn git_output(path: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn now() -> String {
    LeaseService::rfc3339(Utc::now())
}
