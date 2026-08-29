impl MemoryLedger {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a failpoint: after `allowed` further successful mutating calls,
    /// the next one fails with a store error and commits nothing.
    pub fn set_failpoint(&mut self, allowed: u32) {
        self.fail_after_writes = Some(allowed);
    }

    pub(super) fn tick(&mut self) -> Result<(), LedgerError> {
        match self.fail_after_writes {
            Some(0) => {
                self.fail_after_writes = None;
                Err(LedgerError::Store("injected failpoint".into()))
            }
            Some(n) => {
                self.fail_after_writes = Some(n - 1);
                Ok(())
            }
            None => Ok(()),
        }
    }
}

pub(super) fn json<T: serde::Serialize>(value: &T) -> Result<String, LedgerError> {
    serde_json::to_string(value).map_err(|err| LedgerError::Store(err.to_string()))
}

fn append_only<T: PartialEq + Clone>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: &T,
    what: &str,
) -> Result<bool, LedgerError> {
    if let Some(existing) = map.get(&key) {
        if existing == value {
            return Ok(false);
        }
        return Err(
            DomainError::Conflict(format!("{what} {key} differs from the stored row")).into(),
        );
    }
    map.insert(key, value.clone());
    Ok(true)
}
