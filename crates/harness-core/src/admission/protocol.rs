//! Required provider protocol identities. Runtime probes report what is
//! actually present; provider names never imply protocol support.

use crate::capability::Capability;
use crate::error::HarnessError;
use serde::{Deserialize, Serialize};

/// Provider protocol implemented by one exact executable build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProtocol {
    /// Claude bidirectional stream JSON with structured final output.
    ClaudeStreamJson,
    /// Legacy one-shot `codex exec --json` surface.
    CodexExecJson,
    /// Stable Codex App Server JSONL (`initialize`, `thread/start`, `turn/start`).
    CodexAppServerJsonl,
    /// Legacy Cursor headless stream JSON surface.
    CursorStreamJson,
    /// Cursor Agent Client Protocol over JSON-RPC.
    CursorAcp,
    /// Antigravity headless text output without an enforced schema.
    AntigravityHeadlessText,
    /// Antigravity 1.1.19+ headless structured-schema mode.
    AntigravityHeadlessStructured,
}

impl ProviderProtocol {
    /// Stable wire label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeStreamJson => "claude_stream_json",
            Self::CodexExecJson => "codex_exec_json",
            Self::CodexAppServerJsonl => "codex_app_server_jsonl",
            Self::CursorStreamJson => "cursor_stream_json",
            Self::CursorAcp => "cursor_acp",
            Self::AntigravityHeadlessText => "antigravity_headless_text",
            Self::AntigravityHeadlessStructured => "antigravity_headless_structured",
        }
    }
}

/// Frozen V1 protocol and minimum capability requirement for a provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRequirement {
    /// Provider wire name.
    pub provider: &'static str,
    /// Protocol a runtime probe must demonstrate.
    pub protocol: ProviderProtocol,
    /// Capabilities that must be conformant, not Unknown or Experimental.
    pub capabilities: &'static [Capability],
}

const STRUCTURED: &[Capability] = &[
    Capability::StructuredEvents,
    Capability::StructuredOutputSchema,
    Capability::HeadlessMode,
    Capability::MultilinePrompt,
];

const STRUCTURED_HEADLESS: &[Capability] = &[
    Capability::StructuredOutputSchema,
    Capability::HeadlessMode,
    Capability::MultilinePrompt,
];

/// Required V1 protocol for one provider. Unknown providers fail closed.
///
/// # Errors
///
/// `ADMISSION_REFUSED` when `provider` is not in the frozen provider set.
pub fn requirement(provider: &str) -> Result<ProtocolRequirement, HarnessError> {
    let requirement = match provider {
        "claude" => ProtocolRequirement {
            provider: "claude",
            protocol: ProviderProtocol::ClaudeStreamJson,
            capabilities: STRUCTURED,
        },
        "codex" => ProtocolRequirement {
            provider: "codex",
            protocol: ProviderProtocol::CodexAppServerJsonl,
            capabilities: STRUCTURED,
        },
        "cursor" => ProtocolRequirement {
            provider: "cursor",
            protocol: ProviderProtocol::CursorAcp,
            capabilities: STRUCTURED,
        },
        "agy" => ProtocolRequirement {
            provider: "agy",
            protocol: ProviderProtocol::AntigravityHeadlessStructured,
            capabilities: STRUCTURED_HEADLESS,
        },
        _ => {
            return Err(HarnessError::AdmissionRefused {
                reason: format!("provider {provider:?} has no frozen V1 protocol"),
            });
        }
    };
    Ok(requirement)
}
