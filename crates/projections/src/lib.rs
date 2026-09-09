//! Operator views from spec §25. A failed read is `unknown`, never an
//! empty list painted as "nothing to see".

use serde::{Deserialize, Serialize};

/// Loadable projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum View<T> {
    /// Verified payload.
    Value {
        /// Body.
        value: T,
        /// Ledger sequence covered.
        as_of_sequence: u64,
    },
    /// Probe failed.
    Unknown {
        /// Why.
        reason: String,
    },
}

/// One named portal surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Surface {
    /// §25.1
    ControlTower,
    /// §25.2
    MissionGraph,
    /// §25.3
    CognitiveRouter,
    /// §25.4
    FusionLab,
    /// §25.5
    Fleet,
    /// §25.6
    LiveAttempt,
    /// §25.7
    SessionSupervisor,
    /// §25.8
    ContextLineage,
    /// §25.9
    QuotaCapacity,
    /// §25.10
    StruggleCockpit,
    /// §25.11
    BehaviorCenter,
    /// §25.12
    WorkspaceHygiene,
    /// §25.13
    MergeRail,
    /// §25.14
    QualityLab,
    /// §25.15
    IncidentsAudit,
}

/// Catalog of surfaces the portal must render.
#[must_use]
pub fn surfaces() -> &'static [Surface] {
    &[
        Surface::ControlTower,
        Surface::MissionGraph,
        Surface::CognitiveRouter,
        Surface::FusionLab,
        Surface::Fleet,
        Surface::LiveAttempt,
        Surface::SessionSupervisor,
        Surface::ContextLineage,
        Surface::QuotaCapacity,
        Surface::StruggleCockpit,
        Surface::BehaviorCenter,
        Surface::WorkspaceHygiene,
        Surface::MergeRail,
        Surface::QualityLab,
        Surface::IncidentsAudit,
    ]
}

/// Card shown when a surface has no farmd route yet.
#[must_use]
pub fn unavailable(surface: Surface) -> View<()> {
    View::Unknown {
        reason: format!("{surface:?}: control plane has not published this projection"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifteen_surfaces_and_unknown_is_not_empty() {
        assert_eq!(surfaces().len(), 15);
        match unavailable(Surface::MergeRail) {
            View::Unknown { reason } => assert!(reason.contains("MergeRail")),
            View::Value { .. } => panic!("missing route must not look like a value"),
        }
    }
}
