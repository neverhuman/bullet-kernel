//! Activation ledger for configuration generations (spec §49.2): exactly one
//! generation is activated at a time, generation numbers only advance,
//! admission binds only a fully acknowledged generation, and a stuck
//! activation has exactly one typed exit — [`ActivationLedger::abort_activation`],
//! which restores the retained last-known-good generation (or leaves no
//! active generation) and appends an immutable [`AbortRecord`] to history.
//! The aborted number stays used, so only a strictly newer generation can
//! follow. No clock, no store: instants are caller-supplied.

use super::generation::{
    validate_instant, validate_subject_and_instant, Component, ConfigurationGeneration,
    GenerationError, RecordedGeneration,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Activation state of the generation the ledger currently tracks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActivationState {
    /// Marked active; at least one required acknowledgement is outstanding.
    Activating,
    /// Every required component acknowledged the exact digest.
    Active,
}

/// Immutable record of an aborted activation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AbortRecord {
    /// Generation number that was activating.
    pub aborted_generation: u64,
    /// Digest that was activating.
    pub aborted_digest: String,
    /// Components that had acknowledged it before the abort.
    pub acknowledged_components: BTreeSet<Component>,
    /// Operator or process that aborted.
    pub subject: String,
    /// Caller-supplied abort instant.
    pub aborted_at_unix_ms: u64,
}

/// The single activation the ledger tracks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Activation {
    generation: ConfigurationGeneration,
    activated_at_unix_ms: u64,
    acknowledged: BTreeSet<Component>,
}

impl Activation {
    fn missing(&self) -> BTreeSet<Component> {
        self.generation
            .content()
            .required_components
            .difference(&self.acknowledged)
            .copied()
            .collect()
    }

    fn missing_names(&self) -> String {
        self.missing()
            .iter()
            .map(|component| component.name())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn state(&self) -> ActivationState {
        if self.missing().is_empty() {
            ActivationState::Active
        } else {
            ActivationState::Activating
        }
    }
}

/// In-process activation ledger. [`ActivationLedger::default`] is empty.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActivationLedger {
    current: Option<Activation>,
    last_known_good: Option<Activation>,
    history: Vec<AbortRecord>,
    highest: u64,
}

impl ActivationLedger {
    /// Atomically mark `row` the activating generation. Nothing changes on
    /// refusal. The previously active generation becomes last-known-good.
    ///
    /// # Errors
    ///
    /// The [`ConfigurationGeneration::from_recorded`] refusals;
    /// `ACTIVATION_IN_PROGRESS` while another generation is still collecting
    /// acknowledgements; `GENERATION_REGRESSION` unless the number is
    /// strictly greater than every generation ever activated (aborted
    /// numbers stay used).
    pub fn activate(
        &mut self,
        row: RecordedGeneration,
        activated_at_unix_ms: u64,
    ) -> Result<ActivationState, GenerationError> {
        let generation = ConfigurationGeneration::from_recorded(row)?;
        validate_instant("activation", activated_at_unix_ms)?;
        if activated_at_unix_ms < generation.content().created_at_unix_ms {
            return Err(GenerationError::ContentInvalid(
                "activation instant precedes generation creation".to_string(),
            ));
        }
        if self
            .current
            .as_ref()
            .is_some_and(|current| activated_at_unix_ms < current.activated_at_unix_ms)
        {
            return Err(GenerationError::ContentInvalid(
                "activation instant precedes the current activation".to_string(),
            ));
        }
        if let Some(pending) = self.pending() {
            return Err(GenerationError::ActivationInProgress {
                pending: pending.generation.number(),
                missing: pending.missing_names(),
            });
        }
        if generation.number() <= self.highest {
            return Err(GenerationError::Regression {
                requested: generation.number(),
                highest: self.highest,
            });
        }
        if let Some(previous) = self.current.take() {
            self.last_known_good = Some(previous);
        }
        self.highest = generation.number();
        let activation = Activation {
            generation,
            activated_at_unix_ms,
            acknowledged: BTreeSet::new(),
        };
        let state = activation.state();
        self.current = Some(activation);
        Ok(state)
    }

    /// Record that `component` acknowledged generation `number` at `digest`.
    ///
    /// # Errors
    ///
    /// `NO_ACTIVATION_PENDING`, `ACKNOWLEDGEMENT_TARGET_MISMATCH` for any
    /// other number or digest, `UNKNOWN_COMPONENT` when the generation does
    /// not require the component, `DUPLICATE_ACKNOWLEDGEMENT` on a repeat.
    pub fn acknowledge(
        &mut self,
        component: Component,
        number: u64,
        digest: &str,
    ) -> Result<ActivationState, GenerationError> {
        let Some(current) = self.current.as_mut() else {
            return Err(GenerationError::NoActivationPending);
        };
        let generation = current.generation.number();
        if number != generation || digest != current.generation.digest() {
            return Err(GenerationError::AcknowledgementTargetMismatch {
                acknowledged: number,
                activated: generation,
                activated_digest: current.generation.digest().to_string(),
            });
        }
        if !current
            .generation
            .content()
            .required_components
            .contains(&component)
        {
            return Err(GenerationError::UnknownComponent(component, generation));
        }
        if !current.acknowledged.insert(component) {
            return Err(GenerationError::DuplicateAcknowledgement(
                component, generation,
            ));
        }
        Ok(current.state())
    }

    /// Abort the activating generation: restore the retained last-known-good
    /// activation exactly as it was (or leave no active generation), and
    /// append an immutable [`AbortRecord`]. The aborted number stays used.
    ///
    /// # Errors
    ///
    /// `NO_ACTIVATION_PENDING` unless a generation is `Activating`;
    /// `GENERATION_CONTENT_INVALID` for a bad subject or instant. Nothing
    /// changes on refusal.
    pub fn abort_activation(
        &mut self,
        subject: &str,
        aborted_at_unix_ms: u64,
    ) -> Result<AbortRecord, GenerationError> {
        validate_subject_and_instant("abort", subject, aborted_at_unix_ms)?;
        let pending = self.pending().ok_or(GenerationError::NoActivationPending)?;
        if aborted_at_unix_ms < pending.activated_at_unix_ms {
            return Err(GenerationError::ContentInvalid(
                "abort instant precedes the pending activation".to_string(),
            ));
        }
        let Some(aborted) = self.current.take() else {
            return Err(GenerationError::NoActivationPending);
        };
        let record = AbortRecord {
            aborted_generation: aborted.generation.number(),
            aborted_digest: aborted.generation.digest().to_string(),
            acknowledged_components: aborted.acknowledged,
            subject: subject.to_string(),
            aborted_at_unix_ms,
        };
        self.current = self.last_known_good.take();
        self.history.push(record.clone());
        Ok(record)
    }

    /// The generation an Attempt admitted now would bind.
    ///
    /// # Errors
    ///
    /// `NO_ACTIVE_GENERATION` with nothing active; `GENERATION_ACTIVATING`
    /// while any required acknowledgement is outstanding.
    pub fn generation_for_admission(&self) -> Result<&ConfigurationGeneration, GenerationError> {
        let Some(current) = &self.current else {
            return Err(GenerationError::NoActiveGeneration);
        };
        if current.state() == ActivationState::Activating {
            return Err(GenerationError::Activating {
                generation: current.generation.number(),
                missing: current.missing_names(),
            });
        }
        Ok(&current.generation)
    }

    /// State of the tracked generation, if any.
    #[must_use]
    pub fn state(&self) -> Option<ActivationState> {
        self.current.as_ref().map(Activation::state)
    }

    /// The generation currently tracked (activating or active).
    #[must_use]
    pub fn current(&self) -> Option<&ConfigurationGeneration> {
        self.current.as_ref().map(|a| &a.generation)
    }

    /// Instant the current generation was marked active.
    #[must_use]
    pub fn activated_at_unix_ms(&self) -> Option<u64> {
        self.current.as_ref().map(|a| a.activated_at_unix_ms)
    }

    /// Components that have not yet acknowledged the current generation.
    #[must_use]
    pub fn missing_components(&self) -> BTreeSet<Component> {
        self.current
            .as_ref()
            .map(Activation::missing)
            .unwrap_or_default()
    }

    /// The previously active generation, retained for abort but never
    /// admitted while another generation is tracked.
    #[must_use]
    pub fn last_known_good(&self) -> Option<&ConfigurationGeneration> {
        self.last_known_good.as_ref().map(|a| &a.generation)
    }

    /// Every abort, oldest first. Records are never edited or removed.
    #[must_use]
    pub fn abort_history(&self) -> &[AbortRecord] {
        &self.history
    }

    /// Highest generation number ever activated, aborted ones included.
    #[must_use]
    pub const fn highest_generation(&self) -> u64 {
        self.highest
    }

    fn pending(&self) -> Option<&Activation> {
        self.current
            .as_ref()
            .filter(|current| current.state() == ActivationState::Activating)
    }
}
