//! Stable typed public-command worker refusals.

use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub(super) struct WorkerError {
    code: &'static str,
    detail: String,
}

impl WorkerError {
    pub(super) fn input(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub(super) const fn code(&self) -> &'static str {
        self.code
    }
}

impl Display for WorkerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for WorkerError {}

pub(super) trait WorkerContext<T> {
    fn worker(self, code: &'static str, context: &'static str) -> Result<T, WorkerError>;
}

impl<T, E: Display> WorkerContext<T> for Result<T, E> {
    fn worker(self, code: &'static str, context: &'static str) -> Result<T, WorkerError> {
        self.map_err(|error| WorkerError::input(code, format!("{context}: {error}")))
    }
}
