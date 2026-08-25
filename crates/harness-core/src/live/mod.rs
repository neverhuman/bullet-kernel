//! Provider-side live-conformance building blocks: the guarded dispatch
//! primitive, the sealed receipt, the request shape, and the two ports the
//! `bullet_application` orchestrator drives — a per-provider [`LiveDispatcher`]
//! and an [`EgressBackend`]. This module owns none of the policy/ledger/issuer
//! orchestration; it only runs and parses one read-only turn once every
//! blocker has already been cleared by its own evidence.

pub mod dispatch;
pub mod receipt;
pub mod request;

pub use dispatch::{
    artifact_digest, capture_turn, run_interactive, scan_events, CommandFactory,
    InteractiveReaction, LineHandler, LiveTurnOutcome, RawCapture,
};
pub use receipt::{
    LiveConformanceReceipt, LiveOutcome, LiveStep, LiveStepRecord, StepLog, StepStatus,
    LIVE_CONFORMANCE_SCHEMA_VERSION,
};
pub use request::{LiveTurnRequest, CONFORMANCE_EXPECTED_RESPONSE, CONFORMANCE_PROMPT};

use crate::adapter::HarnessDescriptor;
use crate::admission::{EgressIsolationEvidence, EvaluatedAdmission, ProviderProtocol};
use crate::error::HarnessError;
use std::path::Path;
use std::process::Command;

/// True when a response is exactly the single admitted word, ignoring only
/// surrounding whitespace.
#[must_use]
pub fn is_pong(response: &str) -> bool {
    response.trim() == CONFORMANCE_EXPECTED_RESPONSE
}

/// One provider's guarded live dispatch. Implemented by each adapter crate;
/// the orchestrator selects one by `--provider` and never spawns a binary
/// itself.
pub trait LiveDispatcher {
    /// Provider wire name (`claude`, `codex`, `cursor`, `agy`).
    fn provider(&self) -> &str;

    /// The static adapter descriptor (provider, binary, capability matrix).
    fn descriptor(&self) -> HarnessDescriptor;

    /// Exact runtime version the frozen protocol contract expects.
    fn observed_runtime_version(&self) -> &str;

    /// Frozen V1 protocol a runtime probe must demonstrate.
    fn required_protocol(&self) -> ProviderProtocol;

    /// Dispatch exactly one read-only turn against an admission that has
    /// cleared every blocker, running it through `factory` (the egress
    /// sandbox) and parsing via this provider's frozen contract.
    ///
    /// # Errors
    ///
    /// A typed `HarnessError` on any argv, spawn, protocol, or canary failure.
    fn dispatch_live_turn(
        &self,
        admission: &EvaluatedAdmission,
        factory: &CommandFactory<'_>,
        request: &LiveTurnRequest,
    ) -> Result<LiveTurnOutcome, HarnessError>;
}

/// A prepared, proven egress boundary: it yields sealed containment evidence
/// and a command factory whose commands run inside the boundary.
pub trait PreparedEgress {
    /// The admission-facing containment evidence.
    fn evidence(&self) -> EgressIsolationEvidence;

    /// Build a command that runs `program` inside the boundary.
    fn command(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Command;
}

/// A backend that can build the provider egress boundary. The real backend
/// wraps `bullet-harness-egress`; a no-op backend drives the non-namespace
/// workspace test run.
pub trait EgressBackend {
    /// Digest of the intended sandbox manifest, known before the namespace is
    /// built, bound into the launch grant. Must be 64 lowercase hex.
    ///
    /// # Errors
    ///
    /// A typed `HarnessError` for an unknown provider or manifest failure.
    fn sandbox_manifest_digest(&self, provider: &str) -> Result<String, HarnessError>;

    /// Build and prove the egress boundary for `provider` under `workdir`.
    ///
    /// # Errors
    ///
    /// A typed `HarnessError` when the boundary cannot be built or proven.
    fn prepare(
        &self,
        provider: &str,
        workdir: &Path,
    ) -> Result<Box<dyn PreparedEgress + '_>, HarnessError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_single_word_matches() {
        assert!(is_pong("PONG"));
        assert!(is_pong("  PONG\n"));
        assert!(!is_pong("pong"));
        assert!(!is_pong("PONG PONG"));
        assert!(!is_pong("the answer is PONG"));
        assert!(!is_pong(""));
    }
}
