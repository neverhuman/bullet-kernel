//! Strict single-process acquire-intent custody.

use super::support::{io_err, rpc_err};
use crate::lease::AcquireGrant;
use crate::RunnerError;
use bullet_application::lease_transport::{
    LeaseSettlementRecord, LeaseSettlementRequest, SignedAcquireBody,
};
use bullet_application::LeaseService;
use bullet_domain::{AttemptId, Digest, RunnerId, WorkspaceId};
use bullet_harness_core::launch_grant::canonical_json;
use bullet_harness_core::lease_transport::request_digest;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VERSION: &str = "lease-recovery.v1alpha3";
pub(super) const MAX_INTENTS: usize = 128;
const MAX_SETTLEMENTS: usize = 128;
const MAX_KEY_BYTES: usize = 256;
const MAX_JOURNAL_BYTES: usize = 65_536;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

mod acquire;
mod settlement;

pub(super) use acquire::AcquireIntent;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcquireMeta {
    pub(super) body: SignedAcquireBody,
    pub(super) request_digest: String,
    pub(super) intent: AcquireIntent,
    intent_digest: String,
    pub(super) grant: Option<AcquireGrant>,
    pub(super) current_attempt: Option<bullet_domain::Attempt>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryJournal {
    schema_version: String,
    sequence: u64,
    runner_id: RunnerId,
    runner_epoch: u64,
    intents: BTreeMap<String, AcquireMeta>,
    settlements: BTreeMap<String, LeaseSettlementRequest>,
    completed: BTreeMap<String, LeaseSettlementRecord>,
}

impl RecoveryJournal {
    pub(super) fn new(runner_id: RunnerId, runner_epoch: u64) -> Self {
        Self {
            schema_version: VERSION.into(),
            sequence: 0,
            runner_id,
            runner_epoch,
            intents: BTreeMap::new(),
            settlements: BTreeMap::new(),
            completed: BTreeMap::new(),
        }
    }

    pub(super) fn intent_for(&self, attempt: &AttemptId) -> Option<AcquireMeta> {
        self.intents.get(attempt.as_str()).cloned()
    }

    #[cfg(test)]
    pub(super) fn reserve(&mut self, body: SignedAcquireBody) -> Result<bool, RunnerError> {
        self.reserve_intent(AcquireIntent::ordinary(body))
    }

    pub(super) fn reserve_intent(&mut self, intent: AcquireIntent) -> Result<bool, RunnerError> {
        intent.validate(&self.runner_id, self.runner_epoch)?;
        let body = intent.body().clone();
        let attempt = AttemptId::from_seed(&body.idempotency_key).to_string();
        let request_digest = request_digest(&body)
            .map_err(|error| RunnerError::Protocol(format!("acquire digest: {error}")))?;
        let intent_digest = intent.digest()?;
        if self.completed.contains_key(&attempt) {
            return Err(rpc_err(
                "IDEMPOTENCY_CONFLICT",
                "completed attempt identity cannot be acquired again",
            ));
        }
        if let Some(existing) = self.intents.get(&attempt) {
            if existing.request_digest != request_digest
                || existing.body != body
                || existing.intent_digest != intent_digest
                || existing.intent != intent
            {
                return Err(rpc_err(
                    "IDEMPOTENCY_CONFLICT",
                    "acquire intent differs under the same idempotency key",
                ));
            }
            return Ok(false);
        }
        if self.intents.len() >= MAX_INTENTS {
            return Err(rpc_err(
                "LEASE_RECOVERY_CAPACITY",
                "acquire recovery intent capacity is exhausted",
            ));
        }
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            rpc_err(
                "LEASE_RECOVERY_SEQUENCE",
                "acquire recovery sequence is exhausted",
            )
        })?;
        self.intents.insert(
            attempt,
            AcquireMeta {
                body,
                request_digest,
                intent,
                intent_digest,
                grant: None,
                current_attempt: None,
            },
        );
        Ok(true)
    }

    pub(super) fn record_grant(
        &mut self,
        body: &SignedAcquireBody,
        grant: AcquireGrant,
    ) -> Result<(), RunnerError> {
        let attempt = AttemptId::from_seed(&body.idempotency_key).to_string();
        let meta = self.intents.get_mut(&attempt).ok_or_else(corrupt)?;
        validate_grant(meta, &grant)?;
        if let Some(existing) = &meta.grant {
            if canonical_json(existing).map_err(|_| corrupt())?
                != canonical_json(&grant).map_err(|_| corrupt())?
            {
                return Err(rpc_err(
                    "IDEMPOTENCY_CONFLICT",
                    "validated acquire grant changed under one durable intent",
                ));
            }
            if meta.current_attempt.is_none() {
                return Err(corrupt());
            }
            return Ok(());
        }
        meta.current_attempt = Some(grant.attempt.clone());
        meta.grant = Some(grant);
        self.bump_sequence()?;
        Ok(())
    }

    fn bump_sequence(&mut self) -> Result<(), RunnerError> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            rpc_err(
                "LEASE_RECOVERY_SEQUENCE",
                "lease recovery sequence is exhausted",
            )
        })?;
        Ok(())
    }

    pub(super) fn forget(&mut self, body: &SignedAcquireBody) -> Result<(), RunnerError> {
        let attempt = AttemptId::from_seed(&body.idempotency_key).to_string();
        if self.intents.remove(&attempt).is_some() {
            self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
                rpc_err(
                    "LEASE_RECOVERY_SEQUENCE",
                    "acquire recovery sequence is exhausted",
                )
            })?;
        }
        Ok(())
    }

    fn validate(&self, runner: &RunnerId, epoch: u64) -> Result<(), RunnerError> {
        if self.schema_version != VERSION
            || self.runner_id != *runner
            || self.runner_epoch != epoch
            || self.intents.len() > MAX_INTENTS
            || self.settlements.len() > MAX_SETTLEMENTS
            || self.completed.len() > MAX_SETTLEMENTS
        {
            return Err(corrupt());
        }
        for (attempt, meta) in &self.intents {
            meta.intent.validate(runner, epoch)?;
            if meta.intent.body() != &meta.body || meta.intent.digest()? != meta.intent_digest {
                return Err(corrupt());
            }
            validate_body(&meta.body, runner, epoch)?;
            if AttemptId::from_seed(&meta.body.idempotency_key).as_str() != attempt {
                return Err(corrupt());
            }
            let digest = request_digest(&meta.body).map_err(|_| corrupt())?;
            if digest != meta.request_digest {
                return Err(corrupt());
            }
            if let Some(grant) = &meta.grant {
                validate_grant(meta, grant).map_err(|_| corrupt())?;
                let current = meta.current_attempt.as_ref().ok_or_else(corrupt)?;
                if !same_incarnation(&grant.attempt, current) {
                    return Err(corrupt());
                }
                let expected = self
                    .completed
                    .get(attempt)
                    .map(|record| settlement::outcome_attempt(&record.outcome))
                    .unwrap_or(&grant.attempt);
                if current != expected {
                    return Err(corrupt());
                }
            } else if meta.current_attempt.is_some() {
                return Err(corrupt());
            }
        }
        for (slot, request) in &self.settlements {
            if *slot != settlement::request_attempt(request).as_str()
                || settlement::validate_source(&self.intents, request).is_err()
            {
                return Err(corrupt());
            }
        }
        for (slot, record) in &self.completed {
            if settlement::validate_completed(slot, record, runner, epoch).is_err() {
                return Err(corrupt());
            }
        }
        Ok(())
    }
}

pub(super) fn load_recovery(
    path: &Path,
    runner: &RunnerId,
    epoch: u64,
) -> Result<RecoveryJournal, RunnerError> {
    validate_parent(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_record(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecoveryJournal::new(runner.clone(), epoch));
        }
        Err(error) => return Err(io_err("lease recovery record", &error.to_string())),
    }
    let bytes =
        std::fs::read(path).map_err(|error| io_err("lease recovery read", &error.to_string()))?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(corrupt());
    }
    #[derive(serde::Deserialize)]
    struct VersionProbe {
        schema_version: String,
    }
    let version: VersionProbe = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    if version.schema_version != VERSION {
        return Err(rpc_err(
            "LEASE_RECOVERY_VERSION_UNSUPPORTED",
            "lease recovery schema requires explicit export and re-admission",
        ));
    }
    let journal: RecoveryJournal = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    journal.validate(runner, epoch)?;
    let canonical = canonical_json(&journal).map_err(|_| corrupt())?;
    if canonical != bytes {
        return Err(corrupt());
    }
    Ok(journal)
}

pub(super) fn persist_recovery(path: &Path, journal: &RecoveryJournal) -> Result<(), RunnerError> {
    let parent_identity = validate_parent(path)?;
    journal.validate(&journal.runner_id, journal.runner_epoch)?;
    let bytes = canonical_json(journal).map_err(|_| corrupt())?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(rpc_err(
            "LEASE_RECOVERY_CAPACITY",
            "canonical lease recovery journal exceeds its restart-safe byte ceiling",
        ));
    }
    let temporary = temporary_path(path)?;
    let result = publish(&temporary, path, &bytes, parent_identity);
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(super) fn validate_grant(meta: &AcquireMeta, grant: &AcquireGrant) -> Result<(), RunnerError> {
    let (body, attempt, lease, token) = (
        &meta.body,
        &grant.attempt,
        &grant.lease,
        &grant.authority_token,
    );
    let expected_attempt = AttemptId::from_seed(&body.idempotency_key);
    let expected_workspace = WorkspaceId::from_seed(&body.idempotency_key);
    let expected_nonce = *Digest::of(body.idempotency_key.as_bytes()).as_bytes();
    let selected = meta.intent.expected_variant();
    let coherent = attempt.id == expected_attempt
        && attempt.work_package_id == body.work_package_id
        && attempt.runner_id == body.runner_id
        && attempt.runner_epoch == body.runner_epoch
        && attempt.workspace_id == expected_workspace
        && attempt.workspace_nonce == expected_nonce
        && lease.attempt_id == attempt.id
        && lease.variant_id == attempt.variant_id
        && lease.fence == attempt.fence
        && lease.runner_id == attempt.runner_id
        && lease.runner_epoch == attempt.runner_epoch
        && lease.workspace_nonce == attempt.workspace_nonce
        && lease.ttl_seconds == body.ttl_seconds
        && token.work_package_id == attempt.work_package_id
        && token.variant_id == attempt.variant_id
        && token.attempt_id == attempt.id
        && token.attempt_fence == attempt.fence
        && token.runner_id == attempt.runner_id
        && token.runner_epoch == attempt.runner_epoch
        && token.workspace_id == attempt.workspace_id
        && token.workspace_nonce == attempt.workspace_nonce
        && token.scope_revision == attempt.scope_revision
        && token.context_revision == attempt.context_revision
        && selected.is_none_or(|expected| {
            attempt.variant_id == *expected
                && lease.variant_id == *expected
                && token.variant_id == *expected
        });
    if coherent {
        Ok(())
    } else {
        Err(RunnerError::Protocol(
            "acquire grant differs from the durable intent".into(),
        ))
    }
}

fn same_incarnation(left: &bullet_domain::Attempt, right: &bullet_domain::Attempt) -> bool {
    let mut expected = left.clone();
    expected.state = right.state;
    expected == *right
}

fn validate_body(
    body: &SignedAcquireBody,
    runner: &RunnerId,
    epoch: u64,
) -> Result<(), RunnerError> {
    let key = body.idempotency_key.as_bytes();
    if body.runner_id != *runner
        || body.runner_epoch != epoch
        || key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || key.iter().any(u8::is_ascii_control)
        || LeaseService::validate_ttl(body.ttl_seconds).is_err()
    {
        return Err(rpc_err(
            "LEASE_RECOVERY_SUBJECT_MISMATCH",
            "acquire body is not admitted for this recovery principal",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ParentIdentity {
    dev: u64,
    ino: u64,
}

fn validate_parent(path: &Path) -> Result<ParentIdentity, RunnerError> {
    let parent = path.parent().ok_or_else(corrupt)?;
    let canonical = std::fs::canonicalize(parent)
        .map_err(|error| io_err("lease recovery parent", &error.to_string()))?;
    if canonical != parent {
        return Err(rpc_err(
            "LEASE_RECOVERY_PARENT",
            "recovery parent must be an absolute canonical directory",
        ));
    }
    let meta = std::fs::symlink_metadata(parent)
        .map_err(|error| io_err("lease recovery parent", &error.to_string()))?;
    let euid = std::fs::metadata("/proc/self")
        .map_err(|error| io_err("lease recovery identity", &error.to_string()))?
        .uid();
    if !meta.is_dir() || meta.uid() != euid || meta.permissions().mode() & 0o777 != 0o700 {
        return Err(rpc_err(
            "LEASE_RECOVERY_PARENT",
            "recovery parent must be euid-owned mode 0700",
        ));
    }
    Ok(ParentIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

fn validate_record(path: &Path) -> Result<(), RunnerError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| io_err("lease recovery record", &error.to_string()))?;
    let euid = std::fs::metadata("/proc/self")
        .map_err(|error| io_err("lease recovery identity", &error.to_string()))?
        .uid();
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != euid
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o777 != 0o600
    {
        return Err(rpc_err(
            "LEASE_RECOVERY_RECORD",
            "recovery record must be euid-owned single-link mode-0600 regular file",
        ));
    }
    Ok(())
}

fn temporary_path(path: &Path) -> Result<PathBuf, RunnerError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(corrupt)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence)))
}

fn publish(
    temporary: &Path,
    destination: &Path,
    bytes: &[u8],
    parent_identity: ParentIdentity,
) -> Result<(), RunnerError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)
        .map_err(|error| io_err("lease recovery temporary", &error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| io_err("lease recovery write", &error.to_string()))?;
    file.sync_all()
        .map_err(|error| io_err("lease recovery file sync", &error.to_string()))?;
    if destination.exists() {
        validate_record(destination)?;
    }
    std::fs::rename(temporary, destination)
        .map_err(|error| io_err("lease recovery publish", &error.to_string()))?;
    let parent = destination.parent().ok_or_else(corrupt)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_err("lease recovery directory sync", &error.to_string()))?;
    if validate_parent(destination)? != parent_identity {
        return Err(rpc_err(
            "LEASE_RECOVERY_PARENT_DRIFT",
            "recovery parent identity changed during publication",
        ));
    }
    validate_record(destination)?;
    let observed = std::fs::read(destination)
        .map_err(|error| io_err("lease recovery readback", &error.to_string()))?;
    if observed != bytes {
        return Err(rpc_err(
            "LEASE_RECOVERY_READBACK",
            "published recovery bytes differ from the intended journal",
        ));
    }
    Ok(())
}

fn corrupt() -> RunnerError {
    rpc_err(
        "LEASE_RECOVERY_CORRUPT",
        "acquire recovery journal is not the exact admitted format",
    )
}
