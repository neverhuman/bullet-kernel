//! Provider-side live-conformance building blocks: the guarded dispatch
//! primitive, the sealed receipt, the request shape, and the two ports the
//! `bullet_application` orchestrator drives — a per-provider [`LiveDispatcher`]
//! and an [`EgressBackend`]. This module owns none of the policy/ledger/issuer
//! orchestration; it only runs and parses one read-only turn once every
//! blocker has already been cleared by its own evidence.

pub mod dispatch;
pub mod probe;
pub mod receipt;
pub mod request;
pub mod s2_boundary;

pub use dispatch::{
    artifact_digest, capture_turn, capture_turn_supervised, run_interactive,
    run_interactive_supervised, scan_events, CommandFactory, DispatchCapture, DispatchSignal,
    DispatchStop, FallibleCommandFactory, InteractiveReaction, LineHandler, LiveTurnOutcome,
    RawCapture, SupervisedCommand,
};
pub use probe::{
    native_text, ContainmentClass, ExecutableIdentity, ObservedCapability, ProbeExit, ProbeFacts,
    ProbeGrantEvidence, ProtocolHandshake, RuntimeProbeError, RuntimeProbeObservation,
    MAX_PROBE_ARGV, MAX_PROBE_STDOUT_BYTES, MAX_PROBE_VERSION_BYTES, MAX_PROBE_WALL_MS,
    RUNTIME_PROBE_DOMAIN, RUNTIME_PROBE_SCHEMA_VERSION,
};
pub use receipt::{
    LiveConformanceReceipt, LiveOutcome, LiveStep, LiveStepRecord, StepLog, StepStatus,
    LIVE_CONFORMANCE_SCHEMA_VERSION,
};
pub use request::{LiveTurnRequest, CONFORMANCE_EXPECTED_RESPONSE, CONFORMANCE_PROMPT};
pub use s2_boundary::{admit_s2_spawn, S2BoundaryError};

use crate::adapter::HarnessDescriptor;
use crate::admission::{
    EgressIsolationEvidence, EvaluatedAdmission, ProviderProtocol, RuntimeProbeSnapshot,
};
use crate::error::HarnessError;
use crate::event::AgentEvent;
use crate::probe::ProfileRef;
use crate::proposal::PatchProposal;
use chrono::{DateTime, Utc};
use std::path::Path;
use std::process::Command;

/// Owned output of an isolated runtime and conformance observation.
///
/// This is validated data, not an authority grant or independently signed
/// proof. Production adapters currently return a typed refusal instead of
/// manufacturing any of these fields.
#[derive(Clone, Debug)]
pub struct RuntimeConformanceObservation {
    /// Exact runtime probe subject.
    probe: RuntimeProbeSnapshot,
    /// Captured stdout bytes scanned during admission.
    stdout: Vec<u8>,
    /// Captured stderr bytes scanned during admission.
    stderr: Vec<u8>,
    /// Normalized conformance events.
    events: Vec<AgentEvent>,
    /// Structurally validated proposal produced by the observation.
    proposal: PatchProposal,
}

impl RuntimeConformanceObservation {
    /// Construct an owned observation after validating its proposal subject.
    ///
    /// # Errors
    ///
    /// Returns a typed proposal error when the proposed mutation contract is
    /// malformed. Full probe/profile/capability validation remains the
    /// responsibility of `ProviderAdmission`.
    pub fn new(
        probe: RuntimeProbeSnapshot,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        events: Vec<AgentEvent>,
        proposal: PatchProposal,
    ) -> Result<Self, HarnessError> {
        proposal.validate()?;
        Ok(Self {
            probe,
            stdout,
            stderr,
            events,
            proposal,
        })
    }

    /// Consume the validated observation into the inputs independently
    /// rechecked by `ProviderAdmission`.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RuntimeProbeSnapshot,
        Vec<u8>,
        Vec<u8>,
        Vec<AgentEvent>,
        PatchProposal,
    ) {
        (
            self.probe,
            self.stdout,
            self.stderr,
            self.events,
            self.proposal,
        )
    }
}

/// What one runtime observation step produced. The two arms are disjoint
/// types: there is deliberately no `From<RuntimeProbeObservation>` for
/// [`RuntimeConformanceObservation`], no `into_parts` on the probe type, and
/// no constructor that accepts probe facts in place of a validated proposal.
/// An admission-style consumer must match this enum explicitly and can only
/// reach conformance evidence through the `Conformance` arm.
#[derive(Clone, Debug)]
pub enum ProbeOutcome {
    /// Facts only; never admits.
    ProbeOnly(Box<RuntimeProbeObservation>),
    /// A genuine conformance observation from a separately authorized turn.
    Conformance(Box<RuntimeConformanceObservation>),
}

impl ProbeOutcome {
    /// The conformance observation, if this outcome is one.
    ///
    /// # Errors
    ///
    /// `RUNTIME_PROBE_NOT_ADMISSIBLE` for a probe-only outcome.
    pub fn into_conformance(self) -> Result<RuntimeConformanceObservation, RuntimeProbeError> {
        match self {
            Self::Conformance(observation) => Ok(*observation),
            Self::ProbeOnly(_) => Err(RuntimeProbeError::NotAdmissible),
        }
    }

    /// The probe-only observation, if this outcome is one.
    #[must_use]
    pub fn probe_only(&self) -> Option<&RuntimeProbeObservation> {
        match self {
            Self::ProbeOnly(observation) => Some(observation),
            Self::Conformance(_) => None,
        }
    }
}

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

    /// Produce independently observed runtime and conformance facts without
    /// reading Kernel authority, preparing egress, or dispatching a task.
    ///
    /// The default is deliberately fail-closed. A future production
    /// implementation requires its own read-only probe authority and
    /// containment contract; none of the product adapters implements that
    /// boundary yet.
    ///
    /// # Errors
    ///
    /// `RUNTIME_PROBE_UNAVAILABLE` unless an adapter supplies a real observed
    /// subject, or another typed observation failure.
    fn observe_runtime_conformance(
        &self,
        _executable: &Path,
        _profile: &ProfileRef,
        _observed_at: DateTime<Utc>,
    ) -> Result<RuntimeConformanceObservation, HarnessError> {
        Err(HarnessError::RuntimeProbeUnavailable {
            provider: self.provider().to_string(),
        })
    }

    /// Produce probe-only facts from a separately granted, contained probe
    /// execution: executable identity, argv, native version text, handshake,
    /// capabilities, exit, wall time. The result carries no proposal and no
    /// turn lifecycle and can never satisfy runtime admission by itself.
    ///
    /// The default is deliberately fail-closed; an adapter overriding it must
    /// run under `grant`'s containment and bind the observation to that grant.
    ///
    /// # Errors
    ///
    /// `RUNTIME_PROBE_UNAVAILABLE` unless an adapter supplies a real contained
    /// probe, or another typed probe refusal.
    fn observe_runtime_probe(
        &self,
        _grant: &ProbeGrantEvidence,
    ) -> Result<RuntimeProbeObservation, RuntimeProbeError> {
        Err(RuntimeProbeError::Unavailable {
            provider: self.provider().to_string(),
        })
    }

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
