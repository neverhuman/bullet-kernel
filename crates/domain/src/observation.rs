//! Four-valued observations. Read failure is never empty or healthy.

use serde::{Deserialize, Serialize};

/// Observation of an external or derived fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation<T> {
    /// A verified value.
    Value {
        /// Observed payload.
        value: T,
    },
    /// Authoritative absence.
    Empty,
    /// The probe did not establish a value.
    Unknown {
        /// Probe identity.
        source: String,
        /// Why the value is unknown.
        reason: String,
    },
    /// Distinct sources disagree.
    Contradictory {
        /// Disagreeing sources.
        sources: Vec<String>,
        /// Human-readable conflict.
        reason: String,
    },
}

impl<T> Observation<T> {
    /// Construct a verified value.
    #[must_use]
    pub fn value(value: T) -> Self {
        Self::Value { value }
    }

    /// True only for a verified value. Never treat unknown as success.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Value { .. })
    }

    /// Destructive actions require a verified positive observation.
    #[must_use]
    pub fn permits_destruction(&self) -> bool {
        self.is_verified()
    }

    /// Serialize the discriminant for APIs that must not collapse unknowns.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Value { .. } => "value",
            Self::Empty => "empty",
            Self::Unknown { .. } => "unknown",
            Self::Contradictory { .. } => "contradictory",
        }
    }
}

impl Observation<String> {
    /// Render for operator surfaces. Unknown stays unknown.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Value { value } => value.clone(),
            Self::Empty => "empty".to_string(),
            Self::Unknown { source, reason } => format!("unknown ({source}: {reason})"),
            Self::Contradictory { reason, .. } => format!("contradictory ({reason})"),
        }
    }
}
