//! Offline, non-authoritative routing scaffold. Wave 0 can emit only the T0
//! simulator decision; no output from this crate authorizes a provider spawn.

use bullet_domain::{Digest, ModelTier, Observation, TaskClass, TaskClassification};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A cognitive unit of work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CognitiveTask {
    /// Stable task id.
    pub id: String,
    /// Declared class.
    pub class: TaskClass,
    /// Digest of the prompt capsule.
    pub prompt_digest: String,
}

/// Remaining capacity when a provider reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Remaining calls or tokens in the current window.
    pub remaining: u64,
}

/// Chosen lane. Same inputs + seed always produce the same decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchDecision {
    /// Task that was routed.
    pub task_id: String,
    /// Provider lane.
    pub provider: String,
    /// Model identifier or `d0`.
    pub model: String,
    /// Economy tier.
    pub tier: ModelTier,
    /// Why this lane was chosen.
    pub reason: String,
    /// Replay seed.
    pub seed: u64,
    /// Always false until certification and activation records exist.
    pub transaction_gate_eligible: bool,
}

/// Router failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouterError {
    /// Capacity could not be established; general work must abstain.
    #[error("quota unknown: {observation_source}: {reason}")]
    QuotaUnknown {
        /// Observation source.
        observation_source: String,
        /// Why capacity is unavailable.
        reason: String,
    },
    /// No remaining capacity.
    #[error("quota empty")]
    QuotaEmpty,
    /// Distinct sources disagree.
    #[error("quota contradictory: {0}")]
    QuotaContradictory(String),
}

impl CognitiveTask {
    /// Build a task from an objective string.
    #[must_use]
    pub fn from_objective(id: impl Into<String>, class: TaskClass, objective: &str) -> Self {
        Self {
            id: id.into(),
            class,
            prompt_digest: Digest::of(objective.as_bytes()).to_hex(),
        }
    }
}

/// Classify a declared workflow step.
#[must_use]
pub fn classify(class: TaskClass, risk: &str) -> TaskClassification {
    TaskClassification::declared(class, risk)
}

/// Wave-0 lane selection is the universal T0 simulator fallback.
#[must_use]
pub const fn lane_for(_tier: ModelTier) -> (&'static str, &'static str) {
    ("sim", "d0")
}

/// Deterministic dispatch. Unknown quota abstains; it is never headroom.
///
/// # Errors
///
/// Unknown, empty, or contradictory quota refuses the invocation.
pub fn dispatch(
    task: &CognitiveTask,
    quota: &Observation<Quota>,
    seed: u64,
) -> Result<DispatchDecision, RouterError> {
    match quota {
        Observation::Empty => return Err(RouterError::QuotaEmpty),
        Observation::Contradictory { reason, .. } => {
            return Err(RouterError::QuotaContradictory(reason.clone()));
        }
        Observation::Unknown { source, reason } => {
            return Err(RouterError::QuotaUnknown {
                observation_source: source.clone(),
                reason: reason.clone(),
            });
        }
        Observation::Value { value } if value.remaining == 0 => {
            return Err(RouterError::QuotaEmpty)
        }
        Observation::Value { .. } => {}
    }
    let classification = classify(task.class, "R1");
    let requested_tier = classification.quality_floor;
    let tier = ModelTier::D0;
    let (provider, model) = lane_for(requested_tier);
    let reason = format!(
        "class={:?} requested_tier={requested_tier:?} fallback={tier:?} digest={} seed={seed}",
        task.class, task.prompt_digest
    );
    Ok(DispatchDecision {
        task_id: task.id.clone(),
        provider: provider.to_string(),
        model: model.to_string(),
        tier,
        reason,
        seed,
        transaction_gate_eligible: false,
    })
}

/// Shadow record for later calibration. Never used as an authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowRecord {
    /// Decision that would have been chosen.
    pub decision: DispatchDecision,
    /// Held-out lane that was not invoked.
    pub shadow_provider: String,
}

/// Record the unused alternative for calibration.
#[must_use]
pub fn shadow(decision: &DispatchDecision) -> ShadowRecord {
    let shadow_provider = "quarantined";
    ShadowRecord {
        decision: decision.clone(),
        shadow_provider: shadow_provider.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> CognitiveTask {
        CognitiveTask::from_objective("t1", TaskClass::DeterministicTransform, "format this")
    }

    #[test]
    fn replay_is_deterministic() {
        let quota = Observation::value(Quota { remaining: 3 });
        let first = dispatch(&task(), &quota, 7).expect("first");
        let second = dispatch(&task(), &quota, 7).expect("second");
        assert_eq!(first, second);
        assert_eq!(first.tier, ModelTier::D0);
        assert!(!first.transaction_gate_eligible);
    }

    #[test]
    fn unknown_quota_abstains() {
        let quota = Observation::Unknown {
            source: "claude".into(),
            reason: "remaining quota is not exposed".into(),
        };
        let error = dispatch(&task(), &quota, 1).expect_err("unknown quota must abstain");
        assert_eq!(
            error,
            RouterError::QuotaUnknown {
                observation_source: "claude".into(),
                reason: "remaining quota is not exposed".into(),
            }
        );
    }

    #[test]
    fn empty_quota_refuses() {
        let err = dispatch(&task(), &Observation::Empty, 1).expect_err("empty");
        assert_eq!(err, RouterError::QuotaEmpty);
    }

    #[test]
    fn shadow_is_not_the_chosen_lane() {
        let decision = dispatch(&task(), &Observation::value(Quota { remaining: 1 }), 0).unwrap();
        let record = shadow(&decision);
        assert_eq!(record.shadow_provider, "quarantined");
    }

    #[test]
    fn every_task_class_falls_back_to_t0() {
        for class in [
            TaskClass::FeatureImplementation,
            TaskClass::ArchitectureDesign,
            TaskClass::SecurityAnalysis,
        ] {
            let task = CognitiveTask::from_objective("fallback", class, "offline only");
            let decision = dispatch(&task, &Observation::value(Quota { remaining: 1 }), 0)
                .expect("T0 fallback");
            assert_eq!(
                (decision.provider.as_str(), decision.model.as_str()),
                ("sim", "d0")
            );
            assert!(!decision.transaction_gate_eligible);
        }
    }
}
