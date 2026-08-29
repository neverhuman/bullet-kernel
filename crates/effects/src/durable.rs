//! Bounded on-disk effect queue for the broker daemon.
//!
//! A lost response is stored as `OUTCOME_UNKNOWN` until identity-exact
//! reconciliation or explicit quarantine. Records are create-new, fsynced,
//! and directory-synced. Ambiguous or corrupt state fails closed.

use crate::error::EffectsError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

mod storage;

use storage::{
    ensure_directory, invalid, io_error, read_record_if_present, remove_record, require_state,
    sync_directory, validate_id, validate_job, write_new_record, WriteOutcome,
};

const MAX_RECORDS_PER_PHASE: usize = 4096;
const PHASES: [&str; 3] = ["pending", "unknown", "settled"];

/// One durable job. `state` is a wire name from [`crate::EffectState`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJob {
    /// Stable job identity (provider + logical key).
    pub id: String,
    /// Provider label.
    pub provider: String,
    /// Idempotency key, unique per provider.
    pub logical_effect_key: String,
    /// Target candidate ref.
    pub target_ref: String,
    /// Desired OID.
    pub new_oid: String,
    /// Expected current remote OID.
    pub expected_old_oid: String,
    /// Queue state (`PENDING`, `OUTCOME_UNKNOWN`, or a settled disposition).
    pub state: String,
}

/// Directory-backed queue: `pending/`, `unknown/`, `settled/`.
#[derive(Clone, Debug)]
pub struct DurableQueue {
    root: PathBuf,
}

impl DurableQueue {
    /// Open or create the queue root and its three phase directories.
    /// Existing symlinks and non-directories are refused.
    ///
    /// # Errors
    ///
    /// Filesystem failure or unsafe queue topology.
    pub fn open(root: &Path) -> Result<Self, EffectsError> {
        let root_created = ensure_directory(root)?;
        if root_created {
            let parent = root
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            sync_directory(parent)?;
        }
        for phase in PHASES {
            ensure_directory(&root.join(phase))?;
        }
        sync_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Persist a new pending job. An identical replay is a no-op; a conflicting
    /// replay or an identity already present in multiple phases is refused.
    ///
    /// # Errors
    ///
    /// Filesystem, validation, conflict, or durability failure.
    pub fn enqueue(&self, job: &DurableJob) -> Result<bool, EffectsError> {
        validate_job(job)?;
        require_state(job, "PENDING")?;
        match self.locate(&job.id)?.as_slice() {
            [] => {}
            [(_, existing)] if existing == job => return Ok(false),
            [(_, _)] => return Err(invalid(format!("conflicting replay for {}", job.id))),
            _ => return Err(invalid(format!("job {} exists in multiple phases", job.id))),
        }
        match write_new_record(&self.path("pending", &job.id), job)? {
            WriteOutcome::Created => Ok(true),
            WriteOutcome::Existing(existing) if existing == *job => Ok(false),
            WriteOutcome::Existing(_) => Err(invalid(format!(
                "conflicting concurrent replay for {}",
                job.id
            ))),
        }
    }

    /// Read the first pending job, if any. This does not claim or dispatch it.
    ///
    /// # Errors
    ///
    /// Filesystem, decode, state, or cross-phase ambiguity failure.
    pub fn take_pending(&self) -> Result<Option<DurableJob>, EffectsError> {
        self.take_first("pending", "PENDING")
    }

    /// Read the first unknown job that must be reconciled before retry.
    ///
    /// # Errors
    ///
    /// Filesystem, decode, state, or cross-phase ambiguity failure.
    pub fn take_unknown(&self) -> Result<Option<DurableJob>, EffectsError> {
        self.take_first("unknown", "OUTCOME_UNKNOWN")
    }

    /// Durably move a pending job to `unknown/` after a lost response.
    ///
    /// # Errors
    ///
    /// Filesystem, state, conflict, or durability failure.
    pub fn mark_unknown(&self, mut job: DurableJob) -> Result<(), EffectsError> {
        require_state(&job, "PENDING")?;
        let source = job.clone();
        job.state = "OUTCOME_UNKNOWN".into();
        self.transition("pending", &source, "unknown", &job)
    }

    /// Durably quarantine an unknown job. This component path deliberately
    /// cannot manufacture `VERIFIED`, `COMMITTED`, or `PASS`.
    ///
    /// # Errors
    ///
    /// Filesystem, state, conflict, or durability failure.
    pub fn mark_settled(&self, mut job: DurableJob, state: &str) -> Result<(), EffectsError> {
        require_state(&job, "OUTCOME_UNKNOWN")?;
        if state != "QUARANTINED" {
            return Err(invalid(format!(
                "unsupported local disposition {state}; only QUARANTINED is admitted"
            )));
        }
        let source = job.clone();
        job.state = state.to_owned();
        self.transition("unknown", &source, "settled", &job)
    }

    fn path(&self, phase: &str, id: &str) -> PathBuf {
        self.root.join(phase).join(format!("{id}.json"))
    }

    fn locate(&self, id: &str) -> Result<Vec<(&'static str, DurableJob)>, EffectsError> {
        validate_id(id)?;
        let mut found = Vec::new();
        for phase in PHASES {
            let path = self.path(phase, id);
            if let Some(job) = read_record_if_present(&path)? {
                let expected_state = match phase {
                    "pending" => "PENDING",
                    "unknown" => "OUTCOME_UNKNOWN",
                    "settled" => "QUARANTINED",
                    _ => return Err(invalid(format!("unknown queue phase {phase}"))),
                };
                require_state(&job, expected_state)?;
                found.push((phase, job));
            }
        }
        Ok(found)
    }

    fn take_first(
        &self,
        phase: &'static str,
        expected_state: &str,
    ) -> Result<Option<DurableJob>, EffectsError> {
        let dir = self.root.join(phase);
        let mut entries = fs::read_dir(&dir)
            .map_err(|err| io_error("read queue phase", err))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| io_error("read queue entry", err))?;
        if entries.len() > MAX_RECORDS_PER_PHASE {
            return Err(invalid(format!(
                "{phase} contains more than {MAX_RECORDS_PER_PHASE} records"
            )));
        }
        entries.sort_by_key(|entry| entry.file_name());
        let Some(entry) = entries.into_iter().next() else {
            return Ok(None);
        };
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid(format!("non-UTF-8 entry in {phase}")))?;
        let id = file_name
            .strip_suffix(".json")
            .ok_or_else(|| invalid(format!("unexpected queue entry {phase}/{file_name}")))?;
        validate_id(id)?;
        let found = self.locate(id)?;
        if found.len() != 1 || found[0].0 != phase {
            return Err(invalid(format!("job {id} has ambiguous phase state")));
        }
        let job = found
            .into_iter()
            .next()
            .ok_or_else(|| invalid(format!("job {id} disappeared during read")))?
            .1;
        require_state(&job, expected_state)?;
        Ok(Some(job))
    }

    fn transition(
        &self,
        from: &'static str,
        expected_source: &DurableJob,
        to: &'static str,
        destination: &DurableJob,
    ) -> Result<(), EffectsError> {
        validate_job(expected_source)?;
        validate_job(destination)?;
        if expected_source.id != destination.id {
            return Err(invalid("transition changed durable job identity"));
        }
        let source_path = self.path(from, &expected_source.id);
        let destination_path = self.path(to, &destination.id);
        for phase in PHASES {
            if phase == from || phase == to {
                continue;
            }
            if read_record_if_present(&self.path(phase, &expected_source.id))?.is_some() {
                return Err(invalid(format!(
                    "job {} already exists in {phase}",
                    expected_source.id
                )));
            }
        }
        match read_record_if_present(&source_path)? {
            Some(found) if found == *expected_source => {}
            Some(_) => return Err(invalid(format!("source drift for {}", expected_source.id))),
            None => match read_record_if_present(&destination_path)? {
                Some(found) if found == *destination => return Ok(()),
                _ => {
                    return Err(invalid(format!(
                        "source missing for {}",
                        expected_source.id
                    )));
                }
            },
        }
        match write_new_record(&destination_path, destination)? {
            WriteOutcome::Created => {}
            WriteOutcome::Existing(found) if found == *destination => {}
            WriteOutcome::Existing(_) => {
                return Err(invalid(format!("destination drift for {}", destination.id)));
            }
        }
        remove_record(&source_path)?;
        sync_directory(&self.root.join(from))?;
        sync_directory(&self.root.join(to))?;
        Ok(())
    }
}
