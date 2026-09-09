//! Cognitive task taxonomy. Difficulty is not risk.

use serde::{Deserialize, Serialize};

/// Primary cognitive class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    /// Formatting, schema generation, exact conversion.
    DeterministicTransform,
    /// Extract facts into a schema.
    ExtractStructured,
    /// Label task, risk, provider eligibility.
    ClassifyRoute,
    /// Bounded summary with citations.
    SummarizeLocal,
    /// Provider-portable context capsule.
    CompressContext,
    /// Mechanical rename or generated edit.
    MechanicalCodeEdit,
    /// Localized defect with a reproducible failure.
    BoundedBugFix,
    /// Multi-file product feature.
    FeatureImplementation,
    /// Architectural change.
    BroadRefactor,
    /// Choose components and tradeoffs.
    ArchitectureDesign,
    /// Auth, injection, secret, permission work.
    SecurityAnalysis,
    /// Schema or data migration.
    MigrationDesign,
    /// Semantic review of an exact Candidate.
    CodeReview,
    /// Compare cognitive artifacts.
    FusionRank,
    /// Create a superior answer from alternatives.
    FusionSynthesize,
    /// Determine whether the contract is satisfied.
    CompletionAssessment,
}

/// Model tier. Economy by default, quality by contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTier {
    /// Deterministic tool.
    D0,
    /// Economy model.
    M1,
    /// Standard model.
    M2,
    /// Frontier model.
    M3,
    /// Council or fusion.
    M4,
}

/// Structured classification attached to every Cognitive Task.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskClassification {
    /// Primary class.
    pub primary_class: TaskClass,
    /// Risk class `R0`..=`R3`.
    pub risk_class: String,
    /// Quality floor as a model tier.
    pub quality_floor: ModelTier,
    /// Evidence tier required.
    pub evidence_requirement: String,
    /// Classifier version.
    pub classifier_version: String,
}

impl TaskClass {
    /// Default eligible lane before repository calibration.
    #[must_use]
    pub fn default_tier(self) -> ModelTier {
        match self {
            Self::DeterministicTransform | Self::ClassifyRoute => ModelTier::D0,
            Self::ExtractStructured
            | Self::SummarizeLocal
            | Self::MechanicalCodeEdit
            | Self::CompletionAssessment => ModelTier::M1,
            Self::BoundedBugFix | Self::CompressContext | Self::FusionRank => ModelTier::M2,
            Self::FeatureImplementation | Self::CodeReview | Self::FusionSynthesize => {
                ModelTier::M3
            }
            Self::BroadRefactor
            | Self::ArchitectureDesign
            | Self::SecurityAnalysis
            | Self::MigrationDesign => ModelTier::M4,
        }
    }
}

impl TaskClassification {
    /// Classify from an explicit workflow declaration.
    #[must_use]
    pub fn declared(primary_class: TaskClass, risk_class: &str) -> Self {
        Self {
            primary_class,
            risk_class: risk_class.to_string(),
            quality_floor: primary_class.default_tier(),
            evidence_requirement: if risk_class >= "R2" {
                "E3".to_string()
            } else {
                "E1".to_string()
            },
            classifier_version: "bullet-taxonomy-v0".to_string(),
        }
    }
}
