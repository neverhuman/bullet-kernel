//! Guarded live-conformance orchestration: policy load, operator enrollment,
//! operator key custody, a durable conformance lease, a granted and contained
//! runtime probe, runtime admission, local provider admission, launch-grant
//! mint/verify, egress isolation, and exactly one dispatched read-only turn —
//! then a sealed, fsync'd receipt. The checked-in v1alpha1 policy refuses at
//! `POLICY_LIVE_ADMISSION_DISABLED`; a valid v1alpha2 policy without an
//! enrollment record refuses at `ENROLLMENT_MISSING` before key read,
//! authority mutation, egress, or spawn; an enrolled executable is probed
//! once under its own grant and containment and, absent a genuine conformance
//! observation, refuses at `RUNTIME_PROBE_NOT_ADMISSIBLE` so `ADMISSION` is
//! never reached on probe facts alone (see `probe_steps`).

mod enrollment;
mod probe_steps;
mod steps;

#[cfg(any(test, feature = "test-seams"))]
pub mod egress;
#[cfg(any(test, feature = "test-seams"))]
pub mod seam;

#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod tests;

pub use enrollment::{
    enrollment_path, load_provider_enrollment, EnrolledProvider, EnrollmentError,
    ProviderEnrollmentV1, MAX_BUDGET_MICRO_USD, MAX_ENROLLMENT_BYTES, MAX_ENROLLMENT_WINDOW_MS,
    MAX_LABEL_BYTES, PROVIDER_ENROLLMENT_SCHEMA,
};
pub use probe_steps::{
    ProbeNonceLedger, PROBE_CONTAINMENT_UNPROVEN, RUNTIME_ADMISSION_MISMATCH,
    RUNTIME_PROBE_EXECUTABLE_DRIFT,
};
pub use steps::ENROLLMENT_SUBJECT_MISMATCH;

use crate::launch_grant::LaunchGrantNonceStore;
use crate::leases::LeaseService;
use crate::policy_snapshot::LoadedPolicy;
use crate::store::Ledger;
use bullet_domain::AttemptId;
use bullet_harness_core::launch_grant::{
    LaunchGrantExpectation, LaunchGrantVerificationKey, ProbeExpectation, SignedLaunchGrant,
    SignedProbeGrant,
};
use bullet_harness_core::live::artifact_digest;
use bullet_harness_core::{
    EgressBackend, HarnessError, LiveConformanceReceipt, LiveDispatcher, LiveOutcome, LiveStep,
    StepLog, StepStatus, CONFORMANCE_PROMPT, LIVE_CONFORMANCE_SCHEMA_VERSION,
};
use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Operator-supplied inputs for one live-conformance run. Lease facts are read
/// from the ledger; the operator never supplies them.
#[derive(Clone, Debug)]
pub struct LiveConformanceOptions {
    /// Provider wire name (`claude`, `codex`, `cursor`, `agy`).
    pub provider: String,
    /// Absolute canonical executable path, resolved and digested by the caller.
    pub executable: PathBuf,
    /// Expected runtime version checked against the observed admission subject.
    pub version: String,
    /// Expected account email checked against the observed profile identity.
    pub profile_email: String,
    /// Adapter label recorded in the grant.
    pub adapter_label: String,
    /// Model label recorded in the grant.
    pub model: String,
    /// Credential material generation.
    pub credential_generation: u64,
    /// Tightest cost cap in micro-USD.
    pub max_cost_micro_usd: u64,
    /// Wall-clock bound for the dispatched turn.
    pub wall_timeout: Duration,
    /// Grant window in milliseconds; clamped to the lease and 15000.
    pub ttl_ms: u64,
    /// Operator key issuer label.
    pub issuer: String,
    /// Operator key label.
    pub key_id: String,
    /// Deterministic conformance Mission seed.
    pub seed: String,
    /// Host canaries that must never reach a provider-facing surface.
    pub canaries: Vec<String>,
}

/// A completed run. `grant`/`expectation`/`verification_key` are populated only
/// on a `PONG` outcome so a caller can re-verify the grant (replay refusal).
#[derive(Debug)]
pub struct LiveConformanceRun {
    /// The sealed receipt.
    pub receipt: LiveConformanceReceipt,
    /// Where the receipt JSON was written.
    pub receipt_path: PathBuf,
    /// The verified grant, on a `PONG` outcome.
    pub grant: Option<SignedLaunchGrant>,
    /// The exact expectation the grant was verified against, on `PONG`.
    pub expectation: Option<LaunchGrantExpectation>,
    /// The policy-admitted verification key, on `PONG`.
    pub verification_key: Option<LaunchGrantVerificationKey>,
    /// The verified single-use probe grant, once `PROBE_GRANT` passed, so a
    /// caller can prove its nonce is spent (replay refusal).
    pub probe_grant: Option<ProbeGrantRecord>,
}

/// The verified probe grant with the exact subject and conformance Attempt it
/// was verified under; re-verifying it through [`ProbeNonceLedger`] on the
/// same ledger must refuse `PROBE_GRANT_REPLAYED`.
#[derive(Debug)]
pub struct ProbeGrantRecord {
    /// The signed single-use token.
    pub token: SignedProbeGrant,
    /// Provider, executable digest, and containment class it was verified for.
    pub expectation: ProbeExpectation,
    /// The conformance Attempt its nonce was registered under.
    pub attempt_id: AttemptId,
}

/// A step failure carrying the sealed, already-written receipt.
#[derive(Debug)]
pub struct LiveConformanceError {
    /// Stable reason code of the failing step.
    pub reason_code: String,
    /// The step that failed.
    pub step: LiveStep,
    /// The sealed receipt (outcome `FAILED`).
    pub receipt: LiveConformanceReceipt,
    /// Where the receipt JSON was written.
    pub receipt_path: PathBuf,
    /// Non-secret detail.
    pub detail: String,
}

impl std::fmt::Display for LiveConformanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {} at step {:?}",
            self.reason_code, self.detail, self.step
        )
    }
}

impl std::error::Error for LiveConformanceError {}

impl LiveConformanceError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }
}

/// Receipt facts collected as the steps run, plus the probe-grant run evidence
/// handed back to the caller (never sealed into the receipt).
#[derive(Default)]
pub(super) struct ReceiptFields {
    executable_path: Option<String>,
    executable_blake3: Option<String>,
    enrollment_blake3: Option<String>,
    probe_grant_digest: Option<String>,
    probe_containment_receipt_digest: Option<String>,
    probe_observation_digest: Option<String>,
    probe_grant: Option<ProbeGrantRecord>,
    grant_id: Option<String>,
    grant_envelope_digest: Option<String>,
    egress_receipt_digest: Option<String>,
    egress_ruleset_digest: Option<String>,
    egress_allowlist_digest: Option<String>,
    policy_snapshot_digest: Option<String>,
    policy_generation: Option<u64>,
    response_text: Option<String>,
    cost_micro_usd: Option<u64>,
    duration_ms: Option<u64>,
    exit_code: Option<i32>,
    native_session_id: Option<String>,
    events: u64,
    stdout_blake3: Option<String>,
    stderr_blake3: Option<String>,
    events_blake3: Option<String>,
    pong_match: bool,
}

pub(super) struct StepSuccess {
    pub pong_match: bool,
    pub grant: SignedLaunchGrant,
    pub expectation: LaunchGrantExpectation,
    pub verification_key: LaunchGrantVerificationKey,
}

pub(super) struct StepFailure {
    pub step: LiveStep,
    pub reason_code: String,
    pub detail: String,
    pub refusal: bool,
}

impl StepFailure {
    pub(super) fn harness(step: LiveStep, error: &HarnessError) -> Self {
        Self {
            step,
            reason_code: error.reason_code().to_string(),
            detail: error.to_string(),
            refusal: false,
        }
    }

    pub(super) fn refusal(step: LiveStep, error: &HarnessError) -> Self {
        Self {
            step,
            reason_code: error.reason_code().to_string(),
            detail: error.to_string(),
            refusal: true,
        }
    }

    pub(super) fn ledger(step: LiveStep, error: &crate::store::LedgerError) -> Self {
        Self {
            step,
            reason_code: error.reason_code().to_string(),
            detail: error.to_string(),
            refusal: false,
        }
    }

    pub(super) fn issue(
        step: LiveStep,
        error: &crate::launch_grant::LaunchGrantIssueError,
    ) -> Self {
        Self {
            step,
            reason_code: error.reason_code().to_string(),
            detail: error.to_string(),
            refusal: false,
        }
    }

    pub(super) fn message(step: LiveStep, reason_code: &str, detail: &str) -> Self {
        Self {
            step,
            reason_code: reason_code.to_string(),
            detail: detail.to_string(),
            refusal: false,
        }
    }
}

/// Run the guarded live-conformance path. Always writes a receipt: a `PONG`
/// outcome or a designed policy/runtime-observation refusal returns `Ok`; any other failure
/// returns `Err`, both after the receipt has been sealed and fsync'd.
///
/// # Errors
///
/// [`LiveConformanceError`] for any step failure (including a non-`PONG`
/// response), carrying the written receipt and the failing step.
pub fn run_live_conformance<L>(
    data_dir: &Path,
    ledger: &mut L,
    policy: &LoadedPolicy,
    dispatcher: &dyn LiveDispatcher,
    egress: &dyn EgressBackend,
    options: &LiveConformanceOptions,
    now: DateTime<Utc>,
) -> Result<LiveConformanceRun, Box<LiveConformanceError>>
where
    L: Ledger + LaunchGrantNonceStore,
{
    let started_at = LeaseService::rfc3339(now);
    let mut log = StepLog::new();
    let mut fields = ReceiptFields::default();
    let result = steps::run_steps(
        data_dir,
        ledger,
        policy,
        dispatcher,
        egress,
        options,
        now,
        &mut log,
        &mut fields,
    );
    let probe_grant = fields.probe_grant.take();

    match result {
        Ok(success) if success.pong_match => {
            let (receipt, receipt_path) = finalize(
                data_dir,
                options,
                &started_at,
                log,
                &fields,
                LiveOutcome::Pong,
                None,
                None,
            )?;
            Ok(LiveConformanceRun {
                receipt,
                receipt_path,
                grant: Some(success.grant),
                expectation: Some(success.expectation),
                verification_key: Some(success.verification_key),
                probe_grant,
            })
        }
        Ok(_) => {
            let reason = Some("PONG_MISMATCH".to_string());
            let (receipt, receipt_path) = finalize(
                data_dir,
                options,
                &started_at,
                log,
                &fields,
                LiveOutcome::Failed,
                reason,
                Some(LiveStep::PongMatch),
            )?;
            Err(Box::new(LiveConformanceError {
                reason_code: "PONG_MISMATCH".to_string(),
                step: LiveStep::PongMatch,
                receipt,
                receipt_path,
                detail: "response was not the single word PONG".to_string(),
            }))
        }
        Err(failure) => {
            let status = if failure.refusal {
                StepStatus::Refused
            } else {
                StepStatus::Failed
            };
            log.record(failure.step, status, Some(failure.detail.clone()));
            let outcome = if failure.refusal {
                LiveOutcome::Refused
            } else {
                LiveOutcome::Failed
            };
            let (receipt, receipt_path) = finalize(
                data_dir,
                options,
                &started_at,
                log,
                &fields,
                outcome,
                Some(failure.reason_code.clone()),
                Some(failure.step),
            )?;
            if failure.refusal {
                Ok(LiveConformanceRun {
                    receipt,
                    receipt_path,
                    grant: None,
                    expectation: None,
                    verification_key: None,
                    probe_grant,
                })
            } else {
                Err(Box::new(LiveConformanceError {
                    reason_code: failure.reason_code,
                    step: failure.step,
                    receipt,
                    receipt_path,
                    detail: failure.detail,
                }))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    data_dir: &Path,
    options: &LiveConformanceOptions,
    started_at: &str,
    log: StepLog,
    fields: &ReceiptFields,
    outcome: LiveOutcome,
    refusal_reason: Option<String>,
    failed_step: Option<LiveStep>,
) -> Result<(LiveConformanceReceipt, PathBuf), Box<LiveConformanceError>> {
    let now = Utc::now();
    let unsealed = LiveConformanceReceipt {
        receipt_id: String::new(),
        schema_version: LIVE_CONFORMANCE_SCHEMA_VERSION.to_string(),
        provider: options.provider.clone(),
        outcome,
        refusal_reason: refusal_reason.clone(),
        failed_step,
        steps: log.into_records(),
        executable_path: fields.executable_path.clone(),
        executable_blake3: fields.executable_blake3.clone(),
        enrollment_blake3: fields.enrollment_blake3.clone(),
        probe_grant_digest: fields.probe_grant_digest.clone(),
        probe_containment_receipt_digest: fields.probe_containment_receipt_digest.clone(),
        probe_observation_digest: fields.probe_observation_digest.clone(),
        grant_id: fields.grant_id.clone(),
        grant_envelope_digest: fields.grant_envelope_digest.clone(),
        egress_receipt_digest: fields.egress_receipt_digest.clone(),
        egress_ruleset_digest: fields.egress_ruleset_digest.clone(),
        egress_allowlist_digest: fields.egress_allowlist_digest.clone(),
        policy_snapshot_digest: fields.policy_snapshot_digest.clone(),
        policy_generation: fields.policy_generation,
        prompt: CONFORMANCE_PROMPT.to_string(),
        prompt_blake3: artifact_digest(b"prompt", CONFORMANCE_PROMPT.as_bytes()),
        response_text: fields.response_text.clone(),
        pong_match: fields.pong_match,
        cost_micro_usd: fields.cost_micro_usd,
        duration_ms: fields.duration_ms,
        exit_code: fields.exit_code,
        native_session_id: fields.native_session_id.clone(),
        events: fields.events,
        stdout_blake3: fields.stdout_blake3.clone(),
        stderr_blake3: fields.stderr_blake3.clone(),
        events_blake3: fields.events_blake3.clone(),
        started_at: started_at.to_string(),
        completed_at: LeaseService::rfc3339(now),
    };
    let step = failed_step.unwrap_or(LiveStep::PongMatch);
    let sealed = unsealed
        .clone()
        .seal()
        .map_err(|error| LiveConformanceError {
            reason_code: error.reason_code().to_string(),
            step,
            receipt: unsealed.clone(),
            receipt_path: PathBuf::new(),
            detail: error.to_string(),
        })?;
    let receipt_path =
        write_receipt(data_dir, &options.provider, now, &sealed).map_err(|error| {
            LiveConformanceError {
                reason_code: "RECEIPT_WRITE_FAILED".to_string(),
                step,
                receipt: sealed.clone(),
                receipt_path: PathBuf::new(),
                detail: error.to_string(),
            }
        })?;
    Ok((sealed, receipt_path))
}

fn write_receipt(
    data_dir: &Path,
    provider: &str,
    now: DateTime<Utc>,
    receipt: &LiveConformanceReceipt,
) -> Result<PathBuf, io::Error> {
    let directory = data_dir.join("live");
    std::fs::create_dir_all(&directory)?;
    let name = format!("{provider}-{}.json", now.format("%Y%m%dT%H%M%S%3fZ"));
    let path = directory.join(name);
    let json = serde_json::to_string_pretty(receipt)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut file = File::create(&path)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

pub(super) fn prepare_dir(path: &Path) -> Result<PathBuf, HarnessError> {
    std::fs::create_dir_all(path).map_err(|error| harness_io("create live directory", &error))?;
    path.canonicalize()
        .map_err(|error| harness_io("canonicalize live directory", &error))
}

fn harness_io(context: &str, error: &io::Error) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: error.to_string(),
    }
}
