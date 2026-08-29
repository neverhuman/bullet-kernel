use crate::model::{self, CrashAfter, WorkerAction, WorkerManifest};
use bullet_adapters::SqliteLedger;
use bullet_application::{
    EffectRecoveryAuthority, EffectRecoveryClaim, EffectRecoveryDisposition, EffectRecoveryError,
    EffectRecoveryStore, EffectRecoveryTransition, Ledger,
};
use bullet_domain::{Attempt, AttemptState, EffectId};
use bullet_effects_core::{
    reconcile_local_bare_restart, EffectsError, ForgeDescriptor, ForgeEffects, LocalBareForge,
    PushRequest, RestartReconcileOutcome,
};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CRASH_EXIT: i32 = 86;

pub(crate) fn run_from_private_channel() -> Result<(), String> {
    let Some(manifest) = model::load_from_environment()? else {
        return Ok(());
    };
    validate_durable_subjects(&manifest)?;
    let mut store = CrashStore {
        inner: SqliteLedger::open(&manifest.database).map_err(|error| error.to_string())?,
        crash_after: manifest.crash_after,
    };
    match manifest.action {
        WorkerAction::StaleReadbackProbe => stale_probe(&mut store, &manifest),
        WorkerAction::Reconcile => reconcile(&mut store, &manifest),
        WorkerAction::SpawnDescendant => spawn_descendant(&manifest),
    }
}

fn validate_durable_subjects(manifest: &WorkerManifest) -> Result<(), String> {
    let ledger = SqliteLedger::open(&manifest.database).map_err(|error| error.to_string())?;
    let graph = ledger
        .get_graph(&manifest.token.mission_id)
        .map_err(|error| error.to_string())?
        .ok_or("durable graph absent")?;
    if serde_json::to_vec(&graph).map_err(|error| error.to_string())?
        != serde_json::to_vec(&manifest.graph).map_err(|error| error.to_string())?
    {
        return Err("durable graph differs from manifest".into());
    }
    let attempt = ledger
        .get_attempt(&manifest.grant.attempt.id)
        .map_err(|error| error.to_string())?
        .ok_or("durable recovery attempt absent")?;
    let current_lease = ledger
        .get_lease(&manifest.grant.attempt.variant_id)
        .map_err(|error| error.to_string())?
        .ok_or("durable recovery lease absent")?;
    match manifest.action {
        WorkerAction::Reconcile | WorkerAction::SpawnDescendant
            if attempt != manifest.grant.attempt || current_lease != manifest.grant.lease =>
        {
            return Err("durable grant differs from manifest".into());
        }
        WorkerAction::StaleReadbackProbe
            if !same_historical_attempt(&attempt, &manifest.grant.attempt)
                || attempt.state != AttemptState::Crashed
                || current_lease == manifest.grant.lease
                || current_lease.attempt_id == manifest.grant.attempt.id =>
        {
            return Err("stale probe has no distinct successor lease".into());
        }
        WorkerAction::Reconcile
        | WorkerAction::StaleReadbackProbe
        | WorkerAction::SpawnDescendant => {}
    }
    let intent = ledger
        .get_effect_intent_by_id(&manifest.intent_id)
        .map_err(|error| error.to_string())?
        .ok_or("durable intent absent")?;
    if intent.target_identity != manifest.expected_ref
        || intent.expected_old_oid != manifest.expected_old_oid
        || intent.desired_state_hash != manifest.expected_new_oid
        || intent.attempt_id == manifest.grant.attempt.id
        || intent.fence >= manifest.grant.attempt.fence
    {
        return Err("durable effect subject differs from manifest".into());
    }
    manifest
        .authority
        .validate_token(&manifest.token)
        .map_err(|error| error.to_string())
}

fn spawn_descendant(manifest: &WorkerManifest) -> Result<(), String> {
    let child = Command::new("/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn cleanup hostile: {error}"))?;
    let pid = child.id();
    drop(child);
    model::write_result(&manifest.result, &pid.to_string())
}

fn same_historical_attempt(durable: &Attempt, granted: &Attempt) -> bool {
    durable.id == granted.id
        && durable.variant_id == granted.variant_id
        && durable.work_package_id == granted.work_package_id
        && durable.fence == granted.fence
        && durable.runner_id == granted.runner_id
        && durable.runner_epoch == granted.runner_epoch
        && durable.workspace_id == granted.workspace_id
        && durable.workspace_nonce == granted.workspace_nonce
        && durable.scope_revision == granted.scope_revision
        && durable.context_revision == granted.context_revision
}

fn stale_probe(store: &mut CrashStore, manifest: &WorkerManifest) -> Result<(), String> {
    let mut forge = LoggedForge::lazy(&manifest.bare, &manifest.forge_log, false);
    match reconcile_local_bare_restart(
        store,
        &mut forge,
        &manifest.intent_id,
        &manifest.authority,
        &manifest.workspace,
    ) {
        Err(error) if error.reason_code() == "EFFECT_RECOVERY_AUTHORITY_STALE" => {
            model::write_result(&manifest.result, "STALE_AUTHORITY")
        }
        Err(error) => Err(format!("unexpected stale probe refusal: {error}")),
        Ok(value) => Err(format!("stale probe unexpectedly admitted: {value:?}")),
    }
}

fn reconcile(store: &mut CrashStore, manifest: &WorkerManifest) -> Result<(), String> {
    let mut forge = LoggedForge::lazy(
        &manifest.bare,
        &manifest.forge_log,
        manifest.crash_after == CrashAfter::Push,
    );
    let outcome = reconcile_local_bare_restart(
        store,
        &mut forge,
        &manifest.intent_id,
        &manifest.authority,
        &manifest.workspace,
    )
    .map_err(|error| format!("reconcile: {}: {error}", error.reason_code()))?;
    let label = match outcome {
        RestartReconcileOutcome::NoWork => "NO_WORK",
        RestartReconcileOutcome::Adopted => "ADOPTED",
        RestartReconcileOutcome::OrphanedRemote => "ORPHANED_REMOTE",
        RestartReconcileOutcome::ReadbackUnknown => "READBACK_UNKNOWN",
        RestartReconcileOutcome::Quarantined => "QUARANTINED",
    };
    model::write_result(&manifest.result, label)
}

struct CrashStore {
    inner: SqliteLedger,
    crash_after: CrashAfter,
}

impl EffectRecoveryStore for CrashStore {
    fn claim_effect_recovery(
        &mut self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
        let result = self.inner.claim_effect_recovery(intent_id, authority)?;
        if self.crash_after == CrashAfter::Claim && result.is_some() {
            std::process::exit(CRASH_EXIT);
        }
        Ok(result)
    }

    fn readback_effect_recovery(
        &self,
        intent_id: &EffectId,
        authority: &EffectRecoveryAuthority,
    ) -> Result<Option<EffectRecoveryClaim>, EffectRecoveryError> {
        self.inner.readback_effect_recovery(intent_id, authority)
    }

    fn apply_effect_recovery(
        &mut self,
        request: &EffectRecoveryTransition,
        authority: &EffectRecoveryAuthority,
    ) -> Result<EffectRecoveryClaim, EffectRecoveryError> {
        let result = self.inner.apply_effect_recovery(request, authority)?;
        if (self.crash_after == CrashAfter::RetryReserved
            && request.to == EffectRecoveryDisposition::RetryReserved)
            || (self.crash_after == CrashAfter::Adopted
                && request.to == EffectRecoveryDisposition::Adopted)
        {
            std::process::exit(CRASH_EXIT);
        }
        Ok(result)
    }
}

struct LoggedForge {
    inner: RefCell<Option<LocalBareForge>>,
    bare: PathBuf,
    log: PathBuf,
    crash_after_push: bool,
}

impl LoggedForge {
    fn lazy(bare: &Path, log: &Path, crash_after_push: bool) -> Self {
        Self {
            inner: RefCell::new(None),
            bare: bare.to_path_buf(),
            log: log.to_path_buf(),
            crash_after_push,
        }
    }

    fn append(&self, event: &str) -> Result<(), EffectsError> {
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.log)
            .map_err(|error| EffectsError::Io(format!("open forge log: {error}")))?;
        file.write_all(event.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| EffectsError::Io(format!("sync forge log: {error}")))
    }

    fn with_inner<T>(
        &self,
        operation: impl FnOnce(&mut LocalBareForge) -> Result<T, EffectsError>,
    ) -> Result<T, EffectsError> {
        let mut slot = self
            .inner
            .try_borrow_mut()
            .map_err(|error| EffectsError::Io(format!("borrow local forge: {error}")))?;
        if slot.is_none() {
            self.append("OPEN")?;
            *slot = Some(LocalBareForge::open(&self.bare)?);
        }
        operation(
            slot.as_mut()
                .ok_or_else(|| EffectsError::Io("lazy local forge remained unavailable".into()))?,
        )
    }
}

impl ForgeEffects for LoggedForge {
    fn descriptor(&self) -> ForgeDescriptor {
        self.with_inner(|inner| {
            self.append("DESCRIPTOR")?;
            Ok(inner.descriptor())
        })
        .unwrap_or_else(|error| ForgeDescriptor {
            provider: "local-bare-unavailable".into(),
            authenticated: false,
            can_push_candidate_ref: false,
            notes: format!("lazy local forge unavailable: {error}"),
        })
    }

    fn push_candidate_ref(&mut self, request: &PushRequest) -> Result<(), EffectsError> {
        self.with_inner(|inner| {
            self.append("PUSH_BEGIN")?;
            inner.push_candidate_ref(request)
        })?;
        self.append("PUSH_OK")?;
        if self.crash_after_push {
            std::process::exit(CRASH_EXIT);
        }
        Ok(())
    }

    fn read_ref(&self, ref_name: &str) -> Result<Option<String>, EffectsError> {
        self.with_inner(|inner| {
            self.append("READ")?;
            inner.read_ref(ref_name)
        })
    }
}
