//! In-memory session store shared by adapter implementations. Locks are
//! short and never held across await points.

use crate::adapter::SessionHandle;
use crate::error::HarnessError;
use crate::event::AgentEvent;
use crate::session::SessionState;
use crate::spawnrun::PidSlot;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// One tracked session.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    /// Handle returned to callers.
    pub handle: SessionHandle,
    /// Child working directory.
    pub workdir: PathBuf,
    /// Raw transcript path.
    pub artifact_path: PathBuf,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Normalized envelopes in order.
    pub events: Vec<AgentEvent>,
    /// Live child pid slot for interrupt/terminate.
    pub pid_slot: PidSlot,
    /// Invocations executed for this session.
    pub invocations: u32,
    /// Interrupt requested.
    pub interrupted: bool,
    /// Model in effect when known.
    pub model: Option<String>,
}

impl SessionEntry {
    /// Fresh entry in Created state.
    #[must_use]
    pub fn new(handle: SessionHandle, workdir: PathBuf, artifact_path: PathBuf) -> Self {
        Self {
            handle,
            workdir,
            artifact_path,
            state: SessionState::Created,
            events: Vec::new(),
            pid_slot: Arc::new(Mutex::new(None)),
            invocations: 0,
            interrupted: false,
            model: None,
        }
    }
}

/// Thread-safe map of live sessions.
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session.
    pub fn insert(&self, entry: SessionEntry) {
        if let Ok(mut map) = self.inner.lock() {
            map.insert(entry.handle.session_id.as_str().to_string(), entry);
        }
    }

    /// Run a closure over one session entry.
    ///
    /// # Errors
    ///
    /// `SESSION_UNKNOWN` when the id is not tracked.
    pub fn with_entry<R>(
        &self,
        session_id: &str,
        f: impl FnOnce(&mut SessionEntry) -> R,
    ) -> Result<R, HarnessError> {
        let mut map = self.inner.lock().map_err(|_| HarnessError::Io {
            context: "session store lock".to_string(),
            reason: "poisoned".to_string(),
        })?;
        map.get_mut(session_id)
            .map(f)
            .ok_or_else(|| HarnessError::SessionUnknown {
                session: session_id.to_string(),
            })
    }

    /// Snapshot the events of one session (empty for unknown sessions so a
    /// stream request never panics).
    #[must_use]
    pub fn events_snapshot(&self, session_id: &str) -> Vec<AgentEvent> {
        self.with_entry(session_id, |entry| entry.events.clone())
            .unwrap_or_default()
    }

    /// Append events to one session.
    ///
    /// # Errors
    ///
    /// `SESSION_UNKNOWN` when the id is not tracked.
    pub fn push_events(
        &self,
        session_id: &str,
        events: Vec<AgentEvent>,
    ) -> Result<(), HarnessError> {
        self.with_entry(session_id, |entry| entry.events.extend(events))
    }

    /// Kill any live child process group for the session and mark it
    /// terminated. Returns whether a process was killed.
    ///
    /// # Errors
    ///
    /// `SESSION_UNKNOWN` when the id is not tracked.
    pub fn kill_live_process(&self, session_id: &str) -> Result<bool, HarnessError> {
        let pid = self.with_entry(session_id, |entry| {
            entry.interrupted = true;
            entry.pid_slot.lock().ok().and_then(|mut slot| slot.take())
        })?;
        if let Some(pid) = pid {
            crate::spawnrun::kill_process_group(pid);
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::AgentSessionId;

    fn handle(id: &str) -> SessionHandle {
        SessionHandle {
            session_id: AgentSessionId::new(id),
            provider: "sim".into(),
            native_session_id: None,
        }
    }

    #[test]
    fn unknown_session_is_typed() {
        let store = SessionStore::new();
        let err = store.with_entry("missing", |_| ()).unwrap_err();
        assert_eq!(err.reason_code(), "SESSION_UNKNOWN");
        assert!(store.events_snapshot("missing").is_empty());
    }

    #[test]
    fn insert_and_mutate() {
        let store = SessionStore::new();
        store.insert(SessionEntry::new(
            handle("s1"),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp/raw.jsonl"),
        ));
        store
            .with_entry("s1", |entry| entry.invocations += 1)
            .unwrap();
        let count = store.with_entry("s1", |entry| entry.invocations).unwrap();
        assert_eq!(count, 1);
        assert!(!store.kill_live_process("s1").unwrap());
    }
}
