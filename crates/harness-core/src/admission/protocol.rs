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

    /// Required protocol for an exact provider wire name. CLI aliases are not
    /// wire identities and are deliberately refused here.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` when `provider` is not one of the four frozen wire
    /// names.
    pub fn required_for_wire_provider(provider: &str) -> Result<Self, HarnessError> {
        frozen_provider(provider)
            .map(|(_, protocol)| protocol)
            .ok_or_else(|| unknown_provider(provider))
    }

    /// Normalize a provider name only at a CLI boundary. `antigravity` is an
    /// operator-facing alias for the canonical `agy` wire identity; it never
    /// becomes a second serialized provider value.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` when `provider` is not a frozen wire name or the
    /// single admitted CLI alias.
    pub fn wire_provider_from_cli(provider: &str) -> Result<&'static str, HarnessError> {
        let provider = if provider == "antigravity" {
            "agy"
        } else {
            provider
        };
        frozen_provider(provider)
            .map(|(wire, _)| wire)
            .ok_or_else(|| unknown_provider(provider))
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
    let (provider, protocol) =
        frozen_provider(provider).ok_or_else(|| unknown_provider(provider))?;
    let capabilities = if provider == "agy" {
        STRUCTURED_HEADLESS
    } else {
        STRUCTURED
    };
    Ok(ProtocolRequirement {
        provider,
        protocol,
        capabilities,
    })
}

fn frozen_provider(provider: &str) -> Option<(&'static str, ProviderProtocol)> {
    match provider {
        "claude" => Some(("claude", ProviderProtocol::ClaudeStreamJson)),
        "codex" => Some(("codex", ProviderProtocol::CodexAppServerJsonl)),
        "cursor" => Some(("cursor", ProviderProtocol::CursorAcp)),
        "agy" => Some(("agy", ProviderProtocol::AntigravityHeadlessStructured)),
        _ => None,
    }
}

fn unknown_provider(provider: &str) -> HarnessError {
    HarnessError::AdmissionRefused {
        reason: format!("provider {provider:?} has no frozen V1 protocol"),
    }
}
