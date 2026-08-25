//! Pure one-shot Antigravity headless JSON contract.
//!
//! Installed-runtime help and embedded 1.1.19 strings were observed read-only.
//! They establish the argv features and `structured_output` field used here,
//! but are not executable admission or live conformance. Raw results use the
//! shared recursive duplicate-key-rejecting decoder, but are not RFC 8785
//! canonicalized. Production dispatch remains blocked.

use bullet_domain::{Digest, ProfileId};
use bullet_harness_core::{
    proposal::{schema_source, validate_gate_ids},
    unsupported, AgentSessionId, EventNormalizer, HarnessError, InvocationId, PatchProposal,
};
use serde_json::Map;
use std::path::{Component, Path};

/// Exact installed build observed read-only on 2026-08-25.
pub const OBSERVED_AGY_VERSION: &str = "1.1.19";
/// SHA-256 of the observed installed ELF; this is not a signature.
pub const OBSERVED_AGY_BINARY_SHA256: &str =
    "sha256:68d229d37aeabde76d15af0003d4c1ce07b211414e7452fb0309be9714ae7dd4";
/// Maximum UTF-8 bytes in the prompt retained by one offline transcript.
pub const MAX_PROMPT_BYTES: usize = 256 * 1024;
/// Maximum aggregate UTF-8 bytes in one prepared argv vector.
pub const MAX_ARGV_BYTES: usize = 512 * 1024;
/// Maximum bytes in the single admitted JSON output frame.
pub const MAX_OUTPUT_FRAME_BYTES: usize = 1024 * 1024;
const MAX_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    AwaitResult,
    Terminal,
    Poisoned,
}

/// Exact local subject bound to an offline parsed proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgyHeadlessBinding {
    /// Exact provider wire name frozen by the descriptor.
    pub provider: String,
    /// Exact executable basename frozen by the descriptor.
    pub binary: String,
    /// Kernel credential-profile selection; provider identity remains unverified.
    pub profile_id: String,
    /// Kernel invocation correlation.
    pub invocation_id: String,
    /// Absolute read-only workspace path expected by future admission.
    pub cwd: String,
    /// Exact installed runtime version frozen by this parser.
    pub runtime_version: String,
    /// Exact observed binary digest; it is not a signature.
    pub binary_sha256: String,
    /// Domain-separated BLAKE3 digest of the exact prompt bytes.
    pub prompt_digest: String,
    /// Exact ordered policy-admitted gates.
    pub gate_ids: Vec<String>,
}

/// Locally validated writer proposal plus its offline subject binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgyHeadlessOutcome {
    /// Provider-authored proposal; never Evidence or verified truth.
    pub proposal: PatchProposal,
    /// Local binding used when the result was normalized.
    pub binding: AgyHeadlessBinding,
}

/// Deterministic one-turn machine for the conservative Antigravity JSON subset.
///
/// It performs no filesystem, environment, process, credential, clock, or
/// network I/O. A signed runtime admission must validate the absolute binary,
/// profile identity, containment, and egress before transporting its argv.
pub struct AgyHeadlessTranscript {
    pub(super) phase: Phase,
    pub(super) profile_id: String,
    pub(super) invocation_id: String,
    pub(super) expected_cwd: String,
    pub(super) expected_runtime_version: String,
    pub(super) expected_binary_sha256: String,
    pub(super) prompt: String,
    pub(super) prompt_digest: String,
    pub(super) admitted_gate_ids: Vec<String>,
    pub(super) normalizer: EventNormalizer,
    pub(super) outcome: Option<AgyHeadlessOutcome>,
}

impl AgyHeadlessTranscript {
    /// Bind the complete local subject for one offline structured turn.
    ///
    /// # Errors
    ///
    /// Refuses malformed IDs, cwd, prompt, runtime observation, or gate list.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: AgentSessionId,
        invocation_id: InvocationId,
        profile_id: ProfileId,
        expected_cwd: impl Into<String>,
        expected_runtime_version: impl Into<String>,
        expected_binary_sha256: impl Into<String>,
        prompt: impl Into<String>,
        admitted_gate_ids: Vec<String>,
    ) -> Result<Self, HarnessError> {
        let kernel_session_id = session_id.as_str();
        let invocation = invocation_id.as_str().to_string();
        let profile = profile_id.as_str().to_string();
        let expected_cwd = expected_cwd.into();
        let expected_runtime_version = expected_runtime_version.into();
        let expected_binary_sha256 = expected_binary_sha256.into();
        let prompt = prompt.into();
        if !valid_id(kernel_session_id) || !valid_id(&invocation) || !valid_id(&profile) {
            return Err(protocol(
                "invalid Kernel session, invocation, or profile id",
            ));
        }
        if !valid_cwd(&expected_cwd) {
            return Err(protocol("invalid absolute read-only cwd binding"));
        }
        if expected_runtime_version != OBSERVED_AGY_VERSION
            || expected_binary_sha256 != OBSERVED_AGY_BINARY_SHA256
        {
            return Err(protocol(
                "runtime version/digest has no frozen offline contract",
            ));
        }
        if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.contains('\0') {
            return Err(protocol("prompt is empty, oversized, or contains NUL"));
        }
        validate_gate_ids(&admitted_gate_ids)?;
        let prompt_digest = digest_prompt(&prompt);
        let mut normalizer = EventNormalizer::new(session_id, "agy");
        normalizer.set_invocation(invocation_id);
        Ok(Self {
            phase: Phase::New,
            profile_id: profile,
            invocation_id: invocation,
            expected_cwd,
            expected_runtime_version,
            expected_binary_sha256,
            prompt,
            prompt_digest,
            admitted_gate_ids,
            normalizer,
            outcome: None,
        })
    }

    /// Build the frozen 1.1.19-safe argv; the prompt is always the final `-p=`.
    ///
    /// # Errors
    ///
    /// Refuses an invalid timeout, repeat preparation, or oversized argv.
    pub fn turn_argv(&mut self, print_timeout: &str) -> Result<Vec<String>, HarnessError> {
        if self.phase != Phase::New {
            return self.fail("argv can be prepared exactly once");
        }
        if print_timeout != "10m" {
            return self.fail("print timeout differs from frozen 1.1.19 contract");
        }
        let args = vec![
            "--sandbox".to_string(),
            "--mode".to_string(),
            "plan".to_string(),
            "--print-timeout".to_string(),
            print_timeout.to_string(),
            "--output-format".to_string(),
            "json".to_string(),
            "--json-schema".to_string(),
            schema_source().to_string(),
            format!("-p={}", self.prompt),
        ];
        let encoded_bytes = args.iter().map(String::len).sum::<usize>() + args.len() - 1;
        if encoded_bytes > MAX_ARGV_BYTES {
            return self.fail("prepared argv exceeds aggregate byte limit");
        }
        self.phase = Phase::AwaitResult;
        Ok(args)
    }

    /// Read the outcome only after the one exact result was accepted.
    pub fn outcome(&self) -> Result<&AgyHeadlessOutcome, HarnessError> {
        if self.phase != Phase::Terminal {
            return Err(protocol("turn has no complete terminal outcome"));
        }
        self.outcome
            .as_ref()
            .ok_or_else(|| protocol("terminal outcome missing"))
    }

    /// Refuse cancellation because the native durable agreement is unknown.
    pub fn interrupt_request(&mut self) -> Result<(), HarnessError> {
        self.unsupported_cancellation("offline_interrupt")
    }

    /// Refuse timeout inference because the native durable agreement is unknown.
    pub fn timeout_request(&mut self) -> Result<(), HarnessError> {
        self.unsupported_cancellation("offline_timeout")
    }

    fn unsupported_cancellation(&mut self, operation: &'static str) -> Result<(), HarnessError> {
        self.phase = Phase::Poisoned;
        self.outcome = None;
        Err(unsupported("agy", operation))
    }

    fn fail<T>(&mut self, reason: impl Into<String>) -> Result<T, HarnessError> {
        self.phase = Phase::Poisoned;
        self.outcome = None;
        Err(protocol(reason))
    }
}

pub(super) fn protocol(reason: impl Into<String>) -> HarnessError {
    HarnessError::Protocol {
        provider: "agy".to_string(),
        reason: reason.into(),
    }
}

pub(super) fn exact_fields(object: &Map<String, serde_json::Value>, required: &[&str]) -> bool {
    object.len() == required.len() && required.iter().all(|key| object.contains_key(*key))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_cwd(value: &str) -> bool {
    if value.contains('\0') || value.len() > 4096 {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
}

fn digest_prompt(prompt: &str) -> String {
    let mut material = b"bullet.farm/agy-headless-prompt/v1\0".to_vec();
    material.extend_from_slice(prompt.as_bytes());
    format!("blake3:{}", Digest::of(&material).to_hex())
}
