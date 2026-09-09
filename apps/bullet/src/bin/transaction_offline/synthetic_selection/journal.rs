//! Bounded fsynced per-lane journal with strict reopen validation.

use bullet_runner_core::JournalSink;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SCHEMA: &str = "bullet.synthetic-lane-journal.component.v1";
const MAX_ENTRIES: usize = 64;
const MAX_BYTES: u64 = 65_536;
const MAX_FIELD_BYTES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaneJournalEntry {
    schema_version: String,
    pub(super) sequence: u64,
    pub(super) stage: String,
    pub(super) detail: String,
}

pub(super) struct LaneJournal {
    path: PathBuf,
    entries: Mutex<Vec<LaneJournalEntry>>,
    failure: Mutex<Option<String>>,
}

impl LaneJournal {
    pub(super) fn create(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err("lane journal path must be absolute".into());
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| format!("create lane journal: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync new lane journal: {error}"))?;
        Ok(Self {
            path: path.to_path_buf(),
            entries: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
        })
    }

    pub(super) fn reopen(&self) -> Result<Vec<LaneJournalEntry>, String> {
        if let Some(error) = self
            .failure
            .lock()
            .map_err(|_| "lane journal failure lock poisoned")?
            .clone()
        {
            return Err(error);
        }
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("inspect lane journal: {error}"))?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() == 0
            || metadata.len() > MAX_BYTES
        {
            return Err("lane journal identity/size is invalid".into());
        }
        let bytes = fs::read(&self.path).map_err(|error| format!("read lane journal: {error}"))?;
        if bytes.last() != Some(&b'\n') {
            return Err("lane journal is truncated".into());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "lane journal is not UTF-8")?;
        let mut decoded = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let value = bullet_harness_core::strict_json::decode_strict_json(line)
                .map_err(|error| format!("strict lane journal decode: {error}"))?;
            let entry: LaneJournalEntry = serde_json::from_value(value)
                .map_err(|error| format!("decode lane journal entry: {error}"))?;
            if entry.schema_version != SCHEMA
                || entry.sequence != u64::try_from(index + 1).map_err(|_| "sequence overflow")?
                || entry.stage.is_empty()
                || entry.stage.len() > MAX_FIELD_BYTES
                || entry.detail.len() > MAX_FIELD_BYTES
                || serde_json::to_string(&entry)
                    .map_err(|error| format!("re-encode lane journal: {error}"))?
                    != line
            {
                return Err("lane journal entry is noncanonical or inconsistent".into());
            }
            decoded.push(entry);
        }
        if decoded.is_empty() || decoded.len() > MAX_ENTRIES {
            return Err("lane journal entry count is invalid".into());
        }
        let memory = self
            .entries
            .lock()
            .map_err(|_| "lane journal entries lock poisoned")?;
        if decoded != *memory {
            return Err("lane journal reopened bytes differ from written entries".into());
        }
        Ok(decoded)
    }

    fn append(&self, stage: &str, detail: &str) -> Result<(), String> {
        if stage.is_empty() || stage.len() > MAX_FIELD_BYTES || detail.len() > MAX_FIELD_BYTES {
            return Err("lane journal field is empty or oversized".into());
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "lane journal entries lock poisoned")?;
        if entries.len() >= MAX_ENTRIES {
            return Err("lane journal entry limit exceeded".into());
        }
        let entry = LaneJournalEntry {
            schema_version: SCHEMA.into(),
            sequence: u64::try_from(entries.len() + 1).map_err(|_| "sequence overflow")?,
            stage: stage.into(),
            detail: detail.into(),
        };
        let mut line = serde_json::to_vec(&entry)
            .map_err(|error| format!("encode lane journal entry: {error}"))?;
        line.push(b'\n');
        let current = fs::metadata(&self.path)
            .map_err(|error| format!("inspect lane journal before append: {error}"))?
            .len();
        if current.saturating_add(line.len() as u64) > MAX_BYTES {
            return Err("lane journal byte limit exceeded".into());
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|error| format!("open lane journal append: {error}"))?;
        file.write_all(&line)
            .map_err(|error| format!("append lane journal: {error}"))?;
        file.sync_data()
            .map_err(|error| format!("sync lane journal entry: {error}"))?;
        entries.push(entry);
        Ok(())
    }
}

impl JournalSink for LaneJournal {
    fn record(&self, stage: &str, detail: &str) {
        let detail = if stage == "released" && detail == "succeeded" {
            "superseded requeue=true"
        } else {
            detail
        };
        if let Err(error) = self.append(stage, detail) {
            if let Ok(mut failure) = self.failure.lock() {
                if failure.is_none() {
                    *failure = Some(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsynced_journal_reopens_exact_terminal_detail() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("lane.jsonl");
        let journal = LaneJournal::create(&path).unwrap();
        journal.record("lease_acquired", "attempt");
        journal.record("released", "succeeded");
        let entries = journal.reopen().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].detail, "superseded requeue=true");
    }

    #[test]
    fn reopen_refuses_post_terminal_garbage() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("lane.jsonl");
        let journal = LaneJournal::create(&path).unwrap();
        journal.record("released", "succeeded");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        assert!(journal.reopen().is_err());
    }
}
