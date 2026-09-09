//! Configuration generations (spec §49.2, Gastown E10/R33): an immutable,
//! content-addressed generation record. Pure application logic: no clock, no
//! store, no I/O; instants are supplied by the caller. Activation, component
//! acknowledgement, abort, and admission live in `activation`; every refusal
//! from either module is a [`GenerationError`] with a stable reason code.

use bullet_harness_core::launch_grant::{hash_canonical, is_lower_hex_64, MAX_SAFE_INTEGER};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Domain label under which generation content is digested.
pub const CONFIGURATION_GENERATION_DOMAIN: &str = "bullet.configuration-generation.v1";
/// Longest admitted activation or abort subject (bytes).
pub const MAX_ACTIVATION_SUBJECT_BYTES: usize = 256;

/// A component that must acknowledge a generation before it is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    /// The Kernel itself (ledger, admission).
    Kernel,
    /// Runner processes hosting Attempts.
    Runner,
    /// The verifier evaluating evidence.
    Verifier,
    /// The effects gateway.
    Effects,
}

impl Component {
    /// Every critical process that must acknowledge every generation.
    pub const ALL: [Self; 4] = [Self::Kernel, Self::Runner, Self::Verifier, Self::Effects];

    /// Stable lowercase name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Runner => "runner",
            Self::Verifier => "verifier",
            Self::Effects => "effects",
        }
    }
}

/// The exact content a generation digest covers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerationContent {
    /// Monotonic generation number (≥ 1).
    pub generation: u64,
    /// Framed `policy.snapshot` digest (64 lowercase hex).
    pub policy_digest: String,
    /// Routing configuration digest (64 lowercase hex).
    pub routing_digest: String,
    /// Operator or process that requested activation.
    pub activation_subject: String,
    /// Caller-supplied creation instant.
    pub created_at_unix_ms: u64,
    /// Exact closed critical set whose acknowledgement is required before `Active`.
    pub required_components: BTreeSet<Component>,
}

/// A durable generation row exactly as persisted: content plus the digest
/// recorded with it. Untrusted until [`ConfigurationGeneration::from_recorded`]
/// recomputes the digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordedGeneration {
    /// Recorded content.
    pub content: GenerationContent,
    /// Digest recorded alongside the content.
    pub digest: String,
}

/// An immutable, content-addressed configuration generation. Only
/// constructible by sealing content, so the digest always matches it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigurationGeneration {
    content: GenerationContent,
    digest: String,
}

/// The facts an Attempt binds when it is admitted under a generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerationBinding {
    /// Generation number.
    pub generation: u64,
    /// Generation digest.
    pub generation_digest: String,
    /// Policy digest the generation carries.
    pub policy_digest: String,
    /// Routing digest the generation carries.
    pub routing_digest: String,
}

impl ConfigurationGeneration {
    /// Validate and digest `content`.
    ///
    /// # Errors
    ///
    /// `GENERATION_CONTENT_INVALID` for a zero or unsafe number, malformed digests,
    /// a bad subject or instant, a non-critical component set, or unencodable content.
    pub fn seal(content: GenerationContent) -> Result<Self, GenerationError> {
        validate_content(&content)?;
        let digest = hash_canonical(CONFIGURATION_GENERATION_DOMAIN, &content)
            .map_err(|error| GenerationError::ContentInvalid(error.to_string()))?;
        Ok(Self { content, digest })
    }

    /// Re-admit a persisted row by recomputing its digest.
    ///
    /// # Errors
    ///
    /// The [`ConfigurationGeneration::seal`] refusals, or
    /// `GENERATION_DIGEST_MISMATCH` when the recorded digest disagrees.
    pub fn from_recorded(row: RecordedGeneration) -> Result<Self, GenerationError> {
        let sealed = Self::seal(row.content)?;
        if sealed.digest != row.digest {
            return Err(GenerationError::DigestMismatch {
                generation: sealed.content.generation,
                recorded: row.digest,
                computed: sealed.digest,
            });
        }
        Ok(sealed)
    }

    /// The persisted form.
    #[must_use]
    pub fn recorded(&self) -> RecordedGeneration {
        RecordedGeneration {
            content: self.content.clone(),
            digest: self.digest.clone(),
        }
    }

    /// Digest of the exact content.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Generation number.
    #[must_use]
    pub fn number(&self) -> u64 {
        self.content.generation
    }

    /// The sealed content.
    #[must_use]
    pub fn content(&self) -> &GenerationContent {
        &self.content
    }

    /// The facts an admitted Attempt binds.
    #[must_use]
    pub fn binding(&self) -> GenerationBinding {
        GenerationBinding {
            generation: self.content.generation,
            generation_digest: self.digest.clone(),
            policy_digest: self.content.policy_digest.clone(),
            routing_digest: self.content.routing_digest.clone(),
        }
    }
}

/// Subjects are 1..=256 printable ASCII bytes without spaces; instants never
/// exceed `MAX_SAFE_INTEGER`. Shared by activation and abort records.
pub(super) fn validate_subject_and_instant(
    kind: &str,
    subject: &str,
    instant_unix_ms: u64,
) -> Result<(), GenerationError> {
    if subject.is_empty()
        || subject.len() > MAX_ACTIVATION_SUBJECT_BYTES
        || !subject.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(GenerationError::ContentInvalid(format!(
            "{kind} subject must be 1..=256 printable ASCII bytes without spaces"
        )));
    }
    validate_instant(kind, instant_unix_ms)
}

pub(super) fn validate_instant(kind: &str, instant_unix_ms: u64) -> Result<(), GenerationError> {
    if instant_unix_ms > MAX_SAFE_INTEGER {
        return Err(GenerationError::ContentInvalid(format!(
            "{kind} instant must not exceed MAX_SAFE_INTEGER"
        )));
    }
    Ok(())
}

fn validate_content(content: &GenerationContent) -> Result<(), GenerationError> {
    let checks = [
        (
            content.generation == 0 || content.generation > MAX_SAFE_INTEGER,
            "generation number must be within 1..=MAX_SAFE_INTEGER",
        ),
        (
            !is_lower_hex_64(&content.policy_digest),
            "policy digest must be 64 lowercase hex characters",
        ),
        (
            !is_lower_hex_64(&content.routing_digest),
            "routing digest must be 64 lowercase hex characters",
        ),
        (
            content.required_components != Component::ALL.into_iter().collect(),
            "a generation requires exactly kernel, runner, verifier, and effects",
        ),
    ];
    if let Some((_, reason)) = checks.iter().find(|(broken, _)| *broken) {
        return Err(GenerationError::ContentInvalid((*reason).to_string()));
    }
    validate_subject_and_instant(
        "activation",
        &content.activation_subject,
        content.created_at_unix_ms,
    )
}

/// Fail-closed generation refusals. `missing` lists outstanding component
/// names joined by commas.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum GenerationError {
    /// Content failed validation or canonical encoding.
    #[error("generation content invalid: {0}")]
    ContentInvalid(String),
    /// Recorded digest differs from the digest of the recorded content.
    #[error("generation {generation} digest mismatch: recorded {recorded}, computed {computed}")]
    DigestMismatch {
        /// Generation number.
        generation: u64,
        /// Digest recorded with the row.
        recorded: String,
        /// Digest of the recorded content.
        computed: String,
    },
    /// The generation does not advance past the highest one activated.
    #[error("generation {requested} does not advance past generation {highest}")]
    Regression {
        /// Requested generation number.
        requested: u64,
        /// Highest generation number ever activated.
        highest: u64,
    },
    /// Another generation is still collecting acknowledgements.
    #[error("generation {pending} is still activating; missing {missing}")]
    ActivationInProgress {
        /// Generation still activating.
        pending: u64,
        /// Outstanding components.
        missing: String,
    },
    /// An acknowledgement or abort arrived with no generation activating.
    #[error("no generation is activating")]
    NoActivationPending,
    /// An acknowledgement named another generation or digest.
    #[error("acknowledgement targets generation {acknowledged}, activated is generation {activated} digest {activated_digest}")]
    AcknowledgementTargetMismatch {
        /// Generation named by the acknowledgement.
        acknowledged: u64,
        /// Activated generation.
        activated: u64,
        /// Activated digest.
        activated_digest: String,
    },
    /// The acknowledging component is not required by the generation.
    #[error("component {} is not required by generation {}", .0.name(), .1)]
    UnknownComponent(Component, u64),
    /// The component already acknowledged this generation.
    #[error("component {} already acknowledged generation {}", .0.name(), .1)]
    DuplicateAcknowledgement(Component, u64),
    /// No generation has ever been activated, or the only one was aborted.
    #[error("no active configuration generation")]
    NoActiveGeneration,
    /// Admission requested while the generation is still activating.
    #[error("generation {generation} is activating; missing {missing}")]
    Activating {
        /// Generation number.
        generation: u64,
        /// Outstanding components.
        missing: String,
    },
}

impl GenerationError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::ContentInvalid(_) => "GENERATION_CONTENT_INVALID",
            Self::DigestMismatch { .. } => "GENERATION_DIGEST_MISMATCH",
            Self::Regression { .. } => "GENERATION_REGRESSION",
            Self::ActivationInProgress { .. } => "ACTIVATION_IN_PROGRESS",
            Self::NoActivationPending => "NO_ACTIVATION_PENDING",
            Self::AcknowledgementTargetMismatch { .. } => "ACKNOWLEDGEMENT_TARGET_MISMATCH",
            Self::UnknownComponent(..) => "UNKNOWN_COMPONENT",
            Self::DuplicateAcknowledgement(..) => "DUPLICATE_ACKNOWLEDGEMENT",
            Self::NoActiveGeneration => "NO_ACTIVE_GENERATION",
            Self::Activating { .. } => "GENERATION_ACTIVATING",
        }
    }
}
