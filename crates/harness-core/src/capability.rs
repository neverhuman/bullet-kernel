//! Capability negotiation (spec s8.3). Every capability defaults to
//! Unsupported until a pinned-version conformance suite proves otherwise.

use crate::error::HarnessError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The 24 negotiated capabilities of spec s8.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Machine-readable event stream.
    StructuredEvents,
    /// Enforced JSON schema on final output.
    StructuredOutputSchema,
    /// Resume a native provider session by id.
    NativeResume,
    /// Fork a native provider session.
    NativeFork,
    /// Export session state.
    SessionExport,
    /// Import session state.
    SessionImport,
    /// Interrupt a running turn.
    TurnInterrupt,
    /// Inject guidance mid-turn.
    MidTurnSteering,
    /// Structured tool approval flow.
    ToolApprovals,
    /// Control plan/read-only mode.
    PlanModeControl,
    /// Usage/cost events in the stream.
    UsageEvents,
    /// An authoritative quota source.
    QuotaSource,
    /// Structured login challenge.
    AuthChallenge,
    /// Select a model per session.
    ModelSelection,
    /// Select reasoning effort.
    ReasoningEffort,
    /// Drive a browser.
    BrowserControl,
    /// Accept image input.
    ImageInput,
    /// Model Context Protocol.
    Mcp,
    /// Reference files in prompts.
    FileReferences,
    /// Report context window usage.
    ContextUsage,
    /// Native context compaction.
    NativeCompaction,
    /// Non-interactive headless mode.
    HeadlessMode,
    /// Requires a PTY.
    PtyRequired,
    /// Multi-line prompt input.
    MultilinePrompt,
}

impl Capability {
    /// All 24 capabilities in declaration order.
    pub const ALL: [Capability; 24] = [
        Capability::StructuredEvents,
        Capability::StructuredOutputSchema,
        Capability::NativeResume,
        Capability::NativeFork,
        Capability::SessionExport,
        Capability::SessionImport,
        Capability::TurnInterrupt,
        Capability::MidTurnSteering,
        Capability::ToolApprovals,
        Capability::PlanModeControl,
        Capability::UsageEvents,
        Capability::QuotaSource,
        Capability::AuthChallenge,
        Capability::ModelSelection,
        Capability::ReasoningEffort,
        Capability::BrowserControl,
        Capability::ImageInput,
        Capability::Mcp,
        Capability::FileReferences,
        Capability::ContextUsage,
        Capability::NativeCompaction,
        Capability::HeadlessMode,
        Capability::PtyRequired,
        Capability::MultilinePrompt,
    ];

    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StructuredEvents => "structured_events",
            Self::StructuredOutputSchema => "structured_output_schema",
            Self::NativeResume => "native_resume",
            Self::NativeFork => "native_fork",
            Self::SessionExport => "session_export",
            Self::SessionImport => "session_import",
            Self::TurnInterrupt => "turn_interrupt",
            Self::MidTurnSteering => "mid_turn_steering",
            Self::ToolApprovals => "tool_approvals",
            Self::PlanModeControl => "plan_mode_control",
            Self::UsageEvents => "usage_events",
            Self::QuotaSource => "quota_source",
            Self::AuthChallenge => "auth_challenge",
            Self::ModelSelection => "model_selection",
            Self::ReasoningEffort => "reasoning_effort",
            Self::BrowserControl => "browser_control",
            Self::ImageInput => "image_input",
            Self::Mcp => "mcp",
            Self::FileReferences => "file_references",
            Self::ContextUsage => "context_usage",
            Self::NativeCompaction => "native_compaction",
            Self::HeadlessMode => "headless_mode",
            Self::PtyRequired => "pty_required",
            Self::MultilinePrompt => "multiline_prompt",
        }
    }
}

/// Conformance-proven state of one capability (spec s8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Proven by the pinned-version suite.
    Supported,
    /// Proven with documented limitations.
    SupportedWithLimitations,
    /// Works but unproven under fault conditions.
    Experimental,
    /// Not available; the honest default.
    Unsupported,
    /// Not yet probed. Dispatch refuses.
    Unknown,
}

/// Complete capability matrix. Construction fills all 24 keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrix {
    entries: BTreeMap<Capability, CapabilityState>,
}

impl Default for CapabilityMatrix {
    fn default() -> Self {
        let entries = Capability::ALL
            .iter()
            .map(|cap| (*cap, CapabilityState::Unsupported))
            .collect();
        Self { entries }
    }
}

impl CapabilityMatrix {
    /// All 24 capabilities set to Unsupported.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style override of one capability.
    #[must_use]
    pub fn with(mut self, capability: Capability, state: CapabilityState) -> Self {
        self.entries.insert(capability, state);
        self
    }

    /// Override one capability.
    pub fn set(&mut self, capability: Capability, state: CapabilityState) {
        self.entries.insert(capability, state);
    }

    /// State of one capability. A missing entry reads as Unknown (fail closed).
    #[must_use]
    pub fn state(&self, capability: Capability) -> CapabilityState {
        self.entries
            .get(&capability)
            .copied()
            .unwrap_or(CapabilityState::Unknown)
    }

    /// True when all 24 capabilities are present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        Capability::ALL
            .iter()
            .all(|cap| self.entries.contains_key(cap))
    }

    /// Refuse dispatch when any required capability is Unknown or Unsupported.
    ///
    /// # Errors
    ///
    /// `CAPABILITY_UNKNOWN` or `CAPABILITY_UNSUPPORTED` for the first
    /// offending capability.
    pub fn dispatch_allowed(&self, required: &[Capability]) -> Result<(), HarnessError> {
        for capability in required {
            match self.state(*capability) {
                CapabilityState::Unknown => {
                    return Err(HarnessError::CapabilityUnknown {
                        capability: capability.as_str().to_string(),
                    });
                }
                CapabilityState::Unsupported => {
                    return Err(HarnessError::CapabilityUnsupported {
                        capability: capability.as_str().to_string(),
                    });
                }
                CapabilityState::Supported
                | CapabilityState::SupportedWithLimitations
                | CapabilityState::Experimental => {}
            }
        }
        Ok(())
    }

    /// Iterate entries in stable order.
    pub fn iter(&self) -> impl Iterator<Item = (Capability, CapabilityState)> + '_ {
        self.entries.iter().map(|(c, s)| (*c, *s))
    }
}

/// Promotion ladder of spec s42.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStage {
    /// Under construction; never dispatched.
    Development,
    /// Full contract suite green.
    ContractPass,
    /// Synthetic canary traffic.
    SyntheticCanary,
    /// Internal canary traffic.
    InternalCanary,
    /// Limited production share.
    Limited,
    /// General availability.
    General,
}

impl PromotionStage {
    /// Stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "DEVELOPMENT",
            Self::ContractPass => "CONTRACT_PASS",
            Self::SyntheticCanary => "SYNTHETIC_CANARY",
            Self::InternalCanary => "INTERNAL_CANARY",
            Self::Limited => "LIMITED",
            Self::General => "GENERAL",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matrix_is_complete_and_unsupported() {
        let matrix = CapabilityMatrix::default();
        assert!(matrix.is_complete());
        for cap in Capability::ALL {
            assert_eq!(matrix.state(cap), CapabilityState::Unsupported);
        }
    }

    #[test]
    fn dispatch_refuses_unknown_and_unsupported() {
        let matrix = CapabilityMatrix::new()
            .with(Capability::StructuredEvents, CapabilityState::Supported)
            .with(Capability::UsageEvents, CapabilityState::Unknown);
        assert!(matrix
            .dispatch_allowed(&[Capability::StructuredEvents])
            .is_ok());
        let unknown = matrix
            .dispatch_allowed(&[Capability::UsageEvents])
            .unwrap_err();
        assert_eq!(unknown.reason_code(), "CAPABILITY_UNKNOWN");
        let unsupported = matrix
            .dispatch_allowed(&[Capability::BrowserControl])
            .unwrap_err();
        assert_eq!(unsupported.reason_code(), "CAPABILITY_UNSUPPORTED");
    }

    #[test]
    fn capability_count_is_24() {
        assert_eq!(Capability::ALL.len(), 24);
        let names: std::collections::BTreeSet<_> =
            Capability::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), 24);
    }
}
