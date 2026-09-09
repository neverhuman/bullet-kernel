//! Future team-mode PostgreSQL configuration scaffold (Wave 10).
//!
//! Required CI never opens a database. Construction without `DATABASE_URL`
//! returns a typed `NOT_CONFIGURED` error. The live driver lands only after
//! SQLite conformance, workload identity, failover, and restore gates exist.
//! A configured DSN is not a distributed-readiness claim.

use thiserror::Error;

/// Adapter failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PostgresError {
    /// No `DATABASE_URL` and no explicit DSN.
    #[error("postgres ledger is not configured")]
    NotConfigured,
}

/// Handle that would own a Postgres ledger.
#[derive(Debug)]
pub struct PostgresLedger {
    dsn: String,
}

impl PostgresLedger {
    /// Open from `DATABASE_URL` when present.
    ///
    /// # Errors
    ///
    /// `NotConfigured` when the environment has no DSN.
    pub fn from_env() -> Result<Self, PostgresError> {
        match std::env::var("DATABASE_URL") {
            Ok(dsn) if !dsn.is_empty() => Ok(Self { dsn }),
            _ => Err(PostgresError::NotConfigured),
        }
    }

    /// Configured DSN. Never logged by callers; tests may assert non-empty.
    #[must_use]
    pub fn dsn_configured(&self) -> bool {
        !self.dsn.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_ci_refuses_or_records_configuration_without_connecting() {
        // Do not mutate process env; just prove the typed skip.
        if std::env::var("DATABASE_URL")
            .ok()
            .filter(|v| !v.is_empty())
            .is_some()
        {
            assert!(PostgresLedger::from_env().is_ok());
        } else {
            assert_eq!(
                PostgresLedger::from_env().expect_err("skip"),
                PostgresError::NotConfigured
            );
        }
    }
}
