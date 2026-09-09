//! The durable-journal port for attempt stage records. The bullet-runner
//! binary bridges this to its checkpoint supervisor; tests capture entries
//! in memory.

use std::sync::Mutex;

/// Durable-journal port. Every stage transition of the attempt loop is
/// recorded through it.
pub trait JournalSink: Send + Sync {
    /// Record one stage transition.
    fn record(&self, stage: &str, detail: &str);

    /// Required journal write. Default implementations treat `record` as
    /// infallible; the production supervisor overrides this.
    ///
    /// # Errors
    ///
    /// Returns the store/sync failure. Callers must not treat the stage as
    /// durable when this fails.
    fn try_record(&self, stage: &str, detail: &str) -> Result<(), String> {
        self.record(stage, detail);
        Ok(())
    }
}

/// In-memory journal for tests and embedded runs.
#[derive(Debug, Default)]
pub struct MemoryJournal {
    entries: Mutex<Vec<(String, String)>>,
}

impl MemoryJournal {
    /// Empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// All recorded entries in order.
    #[must_use]
    pub fn entries(&self) -> Vec<(String, String)> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Stage names in order.
    #[must_use]
    pub fn stages(&self) -> Vec<String> {
        self.entries().into_iter().map(|(stage, _)| stage).collect()
    }
}

/// Map a required journal write into a runner IO failure.
///
/// # Errors
///
/// `IO_FAILED` when the sink cannot persist the stage.
pub fn require_journal(
    journal: &dyn JournalSink,
    stage: &str,
    detail: &str,
) -> Result<(), crate::RunnerError> {
    journal
        .try_record(stage, detail)
        .map_err(|reason| crate::RunnerError::Io {
            context: format!("journal {stage}"),
            reason,
        })
}

impl JournalSink for MemoryJournal {
    fn record(&self, stage: &str, detail: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push((stage.to_string(), detail.to_string()));
        }
    }
}
