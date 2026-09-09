//! Provider and SCM simulators. No live credentials, no I/O.

use bullet_domain::Observation;
use serde::{Deserialize, Serialize};

/// Simulated model invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedInvocation {
    /// Lane identity.
    pub lane: String,
    /// Artifact text.
    pub artifact: String,
}

/// Provider simulator used by the first demo.
#[derive(Default)]
pub struct ProviderSimulator;

impl ProviderSimulator {
    /// Produce two independent planning proposals and a fused plan.
    #[must_use]
    pub fn planning_council(&self) -> Vec<SimulatedInvocation> {
        vec![
            SimulatedInvocation {
                lane: "planner-a".into(),
                artifact: "plan-proposal-a".into(),
            },
            SimulatedInvocation {
                lane: "planner-b".into(),
                artifact: "plan-proposal-b".into(),
            },
            SimulatedInvocation {
                lane: "fusion".into(),
                artifact: "fused-plan-v1".into(),
            },
        ]
    }
}

/// Simulated GitHub/Jeryu effect with honest observations.
#[derive(Default)]
pub struct ScmSimulator {
    /// When true, the next push is UNKNOWN rather than verified.
    pub lose_response: bool,
}

impl ScmSimulator {
    /// Push a candidate ref and read it back.
    #[must_use]
    pub fn push_candidate(&self, ref_name: &str) -> Observation<String> {
        if self.lose_response {
            Observation::Unknown {
                source: "scm-simulator".into(),
                reason: "timeout after dispatch; not treated as non-execution".into(),
            }
        } else {
            Observation::value(ref_name.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_push_is_unknown() {
        let scm = ScmSimulator {
            lose_response: true,
        };
        let obs = scm.push_candidate("refs/heads/bullet/candidate/x");
        assert_eq!(obs.kind_name(), "unknown");
        assert!(!obs.is_verified());
    }
}
