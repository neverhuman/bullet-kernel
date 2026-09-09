//! Checkpoint and salvage. Restart resumes from the last durable seq.

use crate::protocol::{Checkpoint, PROTOCOL_VERSION};
use std::fs;
use std::path::PathBuf;

/// Filesystem journal for one runner process.
pub struct Supervisor {
    dir: PathBuf,
}

impl Supervisor {
    /// Open a journal directory.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, session: &str) -> PathBuf {
        self.dir.join(format!("{session}.checkpoint.json"))
    }

    /// Load a checkpoint if it exists.
    ///
    /// # Errors
    ///
    /// Returns IO or decode failures.
    pub fn load(&self, session: &str) -> Result<Option<Checkpoint>, String> {
        let path = self.path(session);
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path).map_err(|err| err.to_string())?;
        let checkpoint: Checkpoint = serde_json::from_str(&text).map_err(|err| err.to_string())?;
        if checkpoint.protocol != PROTOCOL_VERSION {
            return Err(format!("protocol {}", checkpoint.protocol));
        }
        Ok(Some(checkpoint))
    }

    fn store(&self, checkpoint: &Checkpoint) -> Result<(), String> {
        let path = self.path(&checkpoint.session);
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string(checkpoint).map_err(|err| err.to_string())?;
        fs::write(&tmp, text).map_err(|err| err.to_string())?;
        fs::rename(&tmp, &path).map_err(|err| err.to_string())?;
        Ok(())
    }

    /// Start or return the existing session.
    ///
    /// # Errors
    ///
    /// Returns IO failures.
    pub fn dispatch(
        &self,
        session: &str,
        attempt_id: Option<String>,
    ) -> Result<Checkpoint, String> {
        if let Some(existing) = self.load(session)? {
            return Ok(existing);
        }
        let checkpoint = Checkpoint {
            protocol: PROTOCOL_VERSION,
            session: session.to_string(),
            seq: 1,
            last_command: "dispatch".into(),
            attempt_id,
        };
        self.store(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Advance the journal.
    ///
    /// # Errors
    ///
    /// Returns missing session or IO failures.
    pub fn heartbeat(&self, session: &str) -> Result<Checkpoint, String> {
        let mut checkpoint = self
            .load(session)?
            .ok_or_else(|| "session missing".to_string())?;
        checkpoint.seq = checkpoint.seq.saturating_add(1);
        checkpoint.last_command = "heartbeat".into();
        self.store(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Resume from the last durable seq. Missing session is unknown, not empty.
    ///
    /// # Errors
    ///
    /// Returns a salvage error when no checkpoint exists.
    pub fn salvage(&self, session: &str) -> Result<Checkpoint, String> {
        self.load(session)?
            .ok_or_else(|| "unknown: no checkpoint".to_string())
    }

    /// Mark the session terminated. Does not delete the journal.
    ///
    /// # Errors
    ///
    /// Returns missing session or IO failures.
    pub fn terminate(&self, session: &str) -> Result<Checkpoint, String> {
        let mut checkpoint = self
            .load(session)?
            .ok_or_else(|| "session missing".to_string())?;
        checkpoint.seq = checkpoint.seq.saturating_add(1);
        checkpoint.last_command = "terminate".into();
        self.store(&checkpoint)?;
        Ok(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salvage_resumes_same_seq() {
        let dir = std::env::temp_dir().join(format!("bullet-runner-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let sup = Supervisor::open(&dir).expect("open");
        let first = sup
            .dispatch("s1", Some("atm_live".into()))
            .expect("dispatch");
        let beat = sup.heartbeat("s1").expect("beat");
        assert!(beat.seq > first.seq);
        let resumed = sup.salvage("s1").expect("salvage");
        assert_eq!(resumed.seq, beat.seq);
        assert_eq!(resumed.attempt_id.as_deref(), Some("atm_live"));
        let again = sup
            .dispatch("s1", Some("other".into()))
            .expect("idempotent");
        assert_eq!(again.seq, beat.seq);
        assert!(sup.salvage("missing").is_err());
    }
}
