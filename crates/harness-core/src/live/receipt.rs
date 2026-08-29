//! The durable-shaped live-conformance receipt. It records exactly what each
//! step of the guarded path did — a step that never ran is `NOT_RUN`, never
//! omitted — plus the provider dispatch facts, and is sealed with a
//! domain-separated digest so a tampered receipt fails verification.

use crate::error::HarnessError;
use serde::{Deserialize, Serialize};

/// Frozen receipt schema identifier.
pub const LIVE_CONFORMANCE_SCHEMA_VERSION: &str = "bullet.live-conformance.v1";

/// Ordered steps of the guarded live-conformance path. Each records its own
/// status; nothing is ever collapsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LiveStep {
    /// Policy load and the live-admission gate.
    Policy,
    /// Operator enrollment record load and re-verification (facts, never evidence).
    Enrollment,
    /// Operator signing-key custody load.
    OperatorKey,
    /// Durable active lease for the conformance Attempt.
    Lease,
    /// Minting, registering, and verifying the single-use probe grant.
    ProbeGrant,
    /// Building and proving the egress-denied boundary the probe runs in.
    ProbeContainment,
    /// Exactly one granted, contained, proposal-free runtime probe.
    ProbeExecution,
    /// Matching probe facts to the enrollment and classifying the outcome.
    RuntimeAdmission,
    /// Local provider admission (prepare + finalize) from a genuine conformance observation.
    Admission,
    /// Launch-grant minting from the durable lease.
    Mint,
    /// Launch-grant verification and single-use nonce consumption.
    VerifyGrant,
    /// Clearing `SIGNED_ADMISSION_UNAVAILABLE` with the verified grant.
    AdmitSigned,
    /// Building and proving the egress isolation boundary.
    EgressPrepare,
    /// Clearing `EGRESS_ISOLATION_UNAVAILABLE` with sealed egress evidence.
    AdmitEgress,
    /// The final `require_dispatch()` chokepoint.
    RequireDispatch,
    /// Dispatching exactly one read-only turn.
    Dispatch,
    /// Scanning every provider-facing surface for canary exposure.
    CanaryScan,
    /// Matching the single-word `PONG` response.
    PongMatch,
}

impl LiveStep {
    /// The complete ordered step list.
    pub const ALL: [LiveStep; 18] = [
        Self::Policy,
        Self::Enrollment,
        Self::OperatorKey,
        Self::Lease,
        Self::ProbeGrant,
        Self::ProbeContainment,
        Self::ProbeExecution,
        Self::RuntimeAdmission,
        Self::Admission,
        Self::Mint,
        Self::VerifyGrant,
        Self::AdmitSigned,
        Self::EgressPrepare,
        Self::AdmitEgress,
        Self::RequireDispatch,
        Self::Dispatch,
        Self::CanaryScan,
        Self::PongMatch,
    ];
}

/// Status of one step. A step that did not run is `NotRun`, never omitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepStatus {
    /// The step ran and passed.
    Pass,
    /// The step deliberately refused (a designed, non-error refusal).
    Refused,
    /// The step ran and failed.
    Failed,
    /// The step never ran because an earlier step stopped the path.
    NotRun,
}

/// One step's recorded outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveStepRecord {
    /// Which step.
    pub step: LiveStep,
    /// Its status.
    pub status: StepStatus,
    /// Non-secret detail (reason code or note); `None` while `NotRun`.
    pub detail: Option<String>,
}

/// Terminal outcome of one live-conformance run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LiveOutcome {
    /// The provider replied `PONG`; every step passed.
    Pong,
    /// A designed policy, enrollment, or runtime-probe refusal.
    Refused,
    /// A step failed; the exact step and reason are recorded.
    Failed,
}

/// The complete, sealed live-conformance receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveConformanceReceipt {
    /// Domain-separated digest sealing every following field.
    pub receipt_id: String,
    /// Always [`LIVE_CONFORMANCE_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Provider wire name.
    pub provider: String,
    /// Terminal outcome.
    pub outcome: LiveOutcome,
    /// Stable reason code when refused or failed.
    pub refusal_reason: Option<String>,
    /// The step that refused or failed, when any.
    pub failed_step: Option<LiveStep>,
    /// Every step's status, in order, none omitted.
    pub steps: Vec<LiveStepRecord>,
    /// Absolute canonical executable path, once admission ran.
    pub executable_path: Option<String>,
    /// Exact executable digest, once admission ran.
    pub executable_blake3: Option<String>,
    /// BLAKE3 of the exact enrollment record bytes, once loaded and re-verified.
    pub enrollment_blake3: Option<String>,
    /// Domain-separated digest of the verified probe-grant claims, once verified.
    pub probe_grant_digest: Option<String>,
    /// Containment receipt digest of the boundary the probe ran in, once proven.
    pub probe_containment_receipt_digest: Option<String>,
    /// Domain-separated digest of the sealed runtime probe observation, once probed.
    pub probe_observation_digest: Option<String>,
    /// Grant identifier, once minted and verified.
    pub grant_id: Option<String>,
    /// Framed digest of the exact grant token, once verified.
    pub grant_envelope_digest: Option<String>,
    /// Egress containment receipt digest, once egress was admitted.
    pub egress_receipt_digest: Option<String>,
    /// Egress ruleset digest, once egress was admitted.
    pub egress_ruleset_digest: Option<String>,
    /// Egress allowlist digest, once egress was admitted.
    pub egress_allowlist_digest: Option<String>,
    /// Loaded policy snapshot digest.
    pub policy_snapshot_digest: Option<String>,
    /// Loaded policy generation.
    pub policy_generation: Option<u64>,
    /// The exact prompt dispatched.
    pub prompt: String,
    /// Domain-separated digest of the exact prompt bytes.
    pub prompt_blake3: String,
    /// The provider's response text, once dispatch ran.
    pub response_text: Option<String>,
    /// Whether the response was exactly the single word `PONG`.
    pub pong_match: bool,
    /// Reported spend in micro-USD, when the provider reported one.
    pub cost_micro_usd: Option<u64>,
    /// Observed wall time of the dispatch in milliseconds.
    pub duration_ms: Option<u64>,
    /// Provider process exit code, when it finished.
    pub exit_code: Option<i32>,
    /// Provider-native session id, when reported.
    pub native_session_id: Option<String>,
    /// Count of normalized envelopes collected.
    pub events: u64,
    /// Digest of the complete captured stdout.
    pub stdout_blake3: Option<String>,
    /// Digest of the complete captured stderr.
    pub stderr_blake3: Option<String>,
    /// Digest of the normalized event log.
    pub events_blake3: Option<String>,
    /// RFC 3339 UTC time the run began.
    pub started_at: String,
    /// RFC 3339 UTC time the run finished.
    pub completed_at: String,
}

impl LiveConformanceReceipt {
    /// Recompute and store the sealing digest.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` if the receipt cannot be serialized.
    pub fn seal(mut self) -> Result<Self, HarnessError> {
        self.receipt_id = self.seal_digest()?;
        Ok(self)
    }

    /// Re-derive the sealing digest and fail on any tamper.
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` if the receipt was modified or cannot serialize.
    pub fn verify(&self) -> Result<(), HarnessError> {
        if self.receipt_id != self.seal_digest()? {
            return Err(HarnessError::AdmissionRefused {
                reason: "live conformance receipt digest mismatch".into(),
            });
        }
        Ok(())
    }

    fn seal_digest(&self) -> Result<String, HarnessError> {
        let mut unsigned = self.clone();
        unsigned.receipt_id = String::new();
        let bytes =
            serde_json::to_vec(&unsigned).map_err(|error| HarnessError::AdmissionRefused {
                reason: format!("live conformance receipt serialization failed: {error}"),
            })?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bullet-live-conformance-receipt-v1\0");
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

/// A per-step status table initialized to all `NotRun`, updated as the path
/// runs. It is the single source of truth for the receipt's `steps` vector.
#[derive(Clone, Debug)]
pub struct StepLog {
    records: Vec<LiveStepRecord>,
}

impl Default for StepLog {
    fn default() -> Self {
        Self::new()
    }
}

impl StepLog {
    /// Every step `NotRun`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: LiveStep::ALL
                .into_iter()
                .map(|step| LiveStepRecord {
                    step,
                    status: StepStatus::NotRun,
                    detail: None,
                })
                .collect(),
        }
    }

    /// Mark a step with a status and optional detail.
    pub fn record(&mut self, step: LiveStep, status: StepStatus, detail: Option<String>) {
        if let Some(entry) = self.records.iter_mut().find(|entry| entry.step == step) {
            entry.status = status;
            entry.detail = detail;
        }
    }

    /// Mark a step `Pass`.
    pub fn pass(&mut self, step: LiveStep) {
        self.record(step, StepStatus::Pass, None);
    }

    /// The complete ordered step records.
    #[must_use]
    pub fn into_records(self) -> Vec<LiveStepRecord> {
        self.records
    }
}
