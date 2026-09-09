//! Append-only JSONL decision log for the CONNECT proxy, with a bounded
//! in-memory tail so probes and tests can inspect recent decisions.

use crate::error::EgressError;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const RECENT_CAPACITY: usize = 256;
const MAX_TARGET_CHARS: usize = 256;

/// What the proxy decided about one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Target admitted by the allowlist (status tells whether a tunnel opened).
    Allow,
    /// Target refused by the allowlist.
    Deny,
    /// Request never reached an allowlist decision (bad method, syntax, size).
    Malformed,
    /// Refused because the concurrent tunnel limit was reached.
    Limit,
}

/// One decision-log line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Policy provider label.
    pub provider: String,
    /// Request target as sent, bounded and ASCII-sanitized.
    pub target: String,
    /// Decision class.
    pub decision: Decision,
    /// Short reason token.
    pub reason: String,
    /// HTTP status answered to the client.
    pub status: u16,
}

struct Inner {
    file: File,
    recent: VecDeque<DecisionRecord>,
}

/// Append-only JSONL log with a bounded recent tail.
pub struct DecisionLog {
    path: PathBuf,
    provider: String,
    inner: Mutex<Inner>,
}

impl DecisionLog {
    /// Open (append, create) the log at `path`.
    ///
    /// # Errors
    ///
    /// `EGRESS_IO_FAILED` when the file cannot be opened.
    pub fn open(path: &Path, provider: &str) -> Result<Self, EgressError> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|err| EgressError::io("open decision log", &err))?;
        Ok(Self {
            path: path.to_path_buf(),
            provider: provider.to_string(),
            inner: Mutex::new(Inner {
                file,
                recent: VecDeque::with_capacity(RECENT_CAPACITY),
            }),
        })
    }

    /// Log file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one decision. Write failures are swallowed on purpose: the
    /// proxy must keep answering, and `sync` reports durability at teardown.
    pub fn record(&self, target: &str, decision: Decision, reason: &str, status: u16) {
        let record = DecisionRecord {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            provider: self.provider.clone(),
            target: sanitize_target(target),
            decision,
            reason: reason.to_string(),
            status,
        };
        let Ok(mut line) = serde_json::to_string(&record) else {
            return;
        };
        line.push('\n');
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.file.write_all(line.as_bytes());
            if inner.recent.len() == RECENT_CAPACITY {
                inner.recent.pop_front();
            }
            inner.recent.push_back(record);
        }
    }

    /// Recent decisions, oldest first (bounded to the last 256).
    #[must_use]
    pub fn recent(&self) -> Vec<DecisionRecord> {
        self.inner
            .lock()
            .map(|inner| inner.recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Flush and fsync the log file.
    ///
    /// # Errors
    ///
    /// `EGRESS_IO_FAILED` when the flush or fsync fails.
    pub fn sync(&self) -> Result<(), EgressError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| EgressError::new(crate::error::EgressCode::IoFailed, "log poisoned"))?;
        inner
            .file
            .flush()
            .and_then(|()| inner.file.sync_all())
            .map_err(|err| EgressError::io("sync decision log", &err))
    }
}

fn sanitize_target(target: &str) -> String {
    target
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(MAX_TARGET_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_jsonl_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = DecisionLog::open(&path, "claude").unwrap();
        log.record("api.anthropic.com:443", Decision::Allow, "allow", 200);
        log.record(
            "evil\u{1}\n:443\u{7f}",
            Decision::Deny,
            "host-not-allowlisted",
            403,
        );
        log.sync().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let second: DecisionRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second.target, "evil:443");
        assert_eq!(second.decision, Decision::Deny);
        assert_eq!(second.status, 403);
        assert!(second.ts.ends_with('Z'));
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["decision"], "allow");
        assert_eq!(first["provider"], "claude");
        let recent = log.recent();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].target, "api.anthropic.com:443");
    }

    #[test]
    fn recent_tail_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let log = DecisionLog::open(&dir.path().join("d.jsonl"), "codex").unwrap();
        for i in 0..(RECENT_CAPACITY + 10) {
            log.record(&format!("h{i}.example:443"), Decision::Deny, "x", 403);
        }
        let recent = log.recent();
        assert_eq!(recent.len(), RECENT_CAPACITY);
        assert_eq!(recent[0].target, "h10.example:443");
    }
}
