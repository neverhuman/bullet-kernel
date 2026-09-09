//! The probe phase of the guarded live path (execution plan M3 / ADMIT-1):
//! `PROBE_GRANT`, `PROBE_CONTAINMENT`, `PROBE_EXECUTION`, and
//! `RUNTIME_ADMISSION`, run after the durable lease and before `ADMISSION`.
//!
//! The enrollment record (ENROLL-1, loaded by `steps::enrollment_step`) is an
//! operator assertion consumed only as input. The probe grant (PROBE-GRANT-1)
//! is minted with the same policy-admitted operator key the launch grant
//! uses, its nonce is registered in the same durable ledger under the
//! conformance Attempt, and it is verified — nonce spent — before any boundary
//! is built. The boundary must prove every containment probe refused before
//! the probe runs inside it. The probe (PROBE-1B `probe_claude`) is the only
//! spawn of this phase and seals a proposal-free `RuntimeProbeObservation`
//! from native bytes. `RUNTIME_ADMISSION` matches those facts against the
//! enrollment and classifies the outcome through the frozen `ProbeOutcome`:
//! the probe-only arm refuses `RUNTIME_PROBE_NOT_ADMISSIBLE`, so `ADMISSION`
//! is reached only through a genuine `RuntimeConformanceObservation` from the
//! dispatcher's separately authorized read-only turn port. No arm is
//! manufactured here.
//!
//! Executor linkage: `bullet-harness-claude` is a dev-dependency of this
//! crate, so the Claude executor is linked only into the test build. The
//! production build refuses `RUNTIME_PROBE_UNAVAILABLE` at `PROBE_EXECUTION`
//! for every provider until that dependency is promoted; nothing is faked.

use super::enrollment::EnrolledProvider;
use super::{LiveConformanceOptions, ProbeGrantRecord, ReceiptFields, StepFailure};
use crate::launch_grant::{durable_lease_binding, LaunchGrantNonceRecord, LaunchGrantNonceStore};
use crate::leases::LeaseService;
use crate::policy_snapshot::LoadedPolicy;
use crate::store::Ledger;
use bullet_domain::AttemptId;
use bullet_harness_core::launch_grant::{
    is_lower_hex_64, mint_probe_grant, random_hex_64, verify_probe_grant, LaunchGrantNonceLedger,
    LaunchGrantSigningKey, LaunchGrantVerificationKey, NonceConsumption, ProbeExpectation,
    ProbeGrantClaims, ProbeGrantError, ProbePurpose, SignedProbeGrant, MAX_PROBE_GRANT_TTL_MS,
    PROBE_GRANT_NONCE_SCOPE, PROBE_GRANT_SCHEMA,
};
use bullet_harness_core::live::{
    ContainmentClass, ExecutableIdentity, ProbeExit, ProbeGrantEvidence, ProbeOutcome,
    RuntimeProbeError, RuntimeProbeObservation,
};
use bullet_harness_core::{
    CanarySecrets, CommandFactory, EgressBackend, EgressIsolationEvidence, EgressProbeOutcome,
    HarnessError, LiveDispatcher, LiveStep, ProfileRef, RuntimeConformanceObservation, StepLog,
};
use chrono::{DateTime, Utc};
use std::path::Path;

/// The executable bytes at the enrolled path changed after enrollment.
pub const RUNTIME_PROBE_EXECUTABLE_DRIFT: &str = "RUNTIME_PROBE_EXECUTABLE_DRIFT";
/// The prepared boundary did not prove every containment probe refused.
pub const PROBE_CONTAINMENT_UNPROVEN: &str = "PROBE_CONTAINMENT_UNPROVEN";
/// Probe facts do not match the enrollment record or did not exit cleanly.
pub const RUNTIME_ADMISSION_MISMATCH: &str = "RUNTIME_ADMISSION_MISMATCH";

/// Everything the probe phase reads. Nothing here is evidence by itself.
pub(super) struct ProbeContext<'a, L> {
    pub data_dir: &'a Path,
    pub ledger: &'a mut L,
    pub policy: &'a LoadedPolicy,
    pub dispatcher: &'a dyn LiveDispatcher,
    pub egress: &'a dyn EgressBackend,
    pub options: &'a LiveConformanceOptions,
    pub enrolled: &'a EnrolledProvider,
    pub key: &'a LaunchGrantSigningKey,
    pub verification_key: &'a LaunchGrantVerificationKey,
    pub attempt_id: &'a AttemptId,
    pub profile: &'a ProfileRef,
    pub now: DateTime<Utc>,
    pub now_ms: u64,
}

/// What the probe phase hands to `ADMISSION`: a genuine conformance
/// observation and the validated canaries the probe already ran under.
pub(super) struct ProbeAdmitted {
    pub observation: RuntimeConformanceObservation,
    pub canaries: CanarySecrets,
}

/// Run `PROBE_GRANT` → `PROBE_CONTAINMENT` → `PROBE_EXECUTION` →
/// `RUNTIME_ADMISSION`. Every refusal names its step; later steps stay unrun.
pub(super) fn run_probe_phase<L>(
    mut context: ProbeContext<'_, L>,
    log: &mut StepLog,
    fields: &mut ReceiptFields,
) -> Result<ProbeAdmitted, StepFailure>
where
    L: Ledger + LaunchGrantNonceStore,
{
    // PROBE_GRANT — mint, register, and verify (nonce spent) before any boundary.
    let (token, expectation, evidence) = probe_grant_step(&mut context)?;
    let options = context.options;
    fields.probe_grant_digest = Some(evidence.grant_blake3.clone());
    fields.probe_grant = Some(ProbeGrantRecord {
        token,
        expectation,
        attempt_id: context.attempt_id.clone(),
    });
    log.pass(LiveStep::ProbeGrant);

    // PROBE_CONTAINMENT — build the boundary and require it proven.
    let step = LiveStep::ProbeContainment;
    let probe_dir = format!("probe-{}", options.provider);
    let workdir = super::prepare_dir(&context.data_dir.join("live").join(probe_dir))
        .map_err(|error| StepFailure::harness(step, &error))?;
    let egress_provider = super::steps::egress_provider_name(&options.provider);
    let prepared = context
        .egress
        .prepare(egress_provider, &workdir)
        .map_err(|error| StepFailure::harness(step, &error))?;
    let containment = prepared.evidence();
    require_contained(&containment)?;
    fields.probe_containment_receipt_digest = Some(containment.receipt_digest.clone());
    log.pass(step);

    // PROBE_EXECUTION — exactly one contained `--version` probe of the enrolled bytes.
    let step = LiveStep::ProbeExecution;
    let canaries = CanarySecrets::new(options.canaries.clone())
        .map_err(|error| StepFailure::harness(step, &error))?;
    let factory: &CommandFactory<'_> =
        &|program: &str, args: &[&str], env: &[(&str, &str)]| prepared.command(program, args, env);
    let record = context.enrolled.record();
    let subject = ProbeSubject {
        executable: &record.executable,
        expected_blake3: &record.executable_blake3,
        grant: &evidence,
        containment_receipt_blake3: &containment.receipt_digest,
        command: factory,
        canaries: &canaries,
        workdir: &workdir,
        now_unix_ms: context.now_ms,
    };
    let observation = execute_probe(context.enrolled.wire_provider(), &subject)?;
    let digest = observation
        .digest()
        .map_err(|error| probe_failure(step, &error))?;
    fields.probe_observation_digest = Some(digest);
    log.pass(step);

    // RUNTIME_ADMISSION — probe facts against the enrollment, then the outcome class.
    let observation = runtime_admission_step(&context, observation)?;
    log.pass(LiveStep::RuntimeAdmission);
    Ok(ProbeAdmitted {
        observation,
        canaries,
    })
}

/// Observe the enrolled executable, refuse drift before minting anything,
/// mint the grant for exactly those bytes, register its nonce under the
/// conformance Attempt, and verify it — the single nonce-spending side effect.
fn probe_grant_step<L: Ledger + LaunchGrantNonceStore>(
    context: &mut ProbeContext<'_, L>,
) -> Result<(SignedProbeGrant, ProbeExpectation, ProbeGrantEvidence), StepFailure> {
    let step = LiveStep::ProbeGrant;
    let record = context.enrolled.record();
    let identity =
        ExecutableIdentity::observe(&record.executable).map_err(|e| probe_failure(step, &e))?;
    if identity.blake3 != record.executable_blake3 {
        let detail = format!(
            "enrolled {}, observed {}",
            record.executable_blake3, identity.blake3
        );
        return Err(failure(
            step,
            RUNTIME_PROBE_EXECUTABLE_DRIFT,
            &detail,
            false,
        ));
    }
    let durable = durable_lease_binding(&mut *context.ledger, context.attempt_id)
        .map_err(|error| StepFailure::issue(step, &error))?;
    let ttl_ms = context.options.ttl_ms.clamp(1, MAX_PROBE_GRANT_TTL_MS);
    let expires_at_unix_ms = context
        .now_ms
        .saturating_add(ttl_ms)
        .min(durable.lease_expires_at_unix_ms);
    let nonce = random_hex_64().map_err(|error| StepFailure::harness(step, &error))?;
    let provider = context.enrolled.wire_provider().to_string();
    let claims = ProbeGrantClaims {
        schema: PROBE_GRANT_SCHEMA.to_string(),
        purpose: ProbePurpose::Probe,
        issuer: context.key.issuer().to_string(),
        key_id: context.key.key_id().to_string(),
        provider: provider.clone(),
        executable_blake3: identity.blake3.clone(),
        containment: ContainmentClass::EgressDenied,
        nonce,
        issued_at_unix_ms: context.now_ms,
        expires_at_unix_ms,
    };
    let token = mint_probe_grant(context.key, &claims).map_err(|e| grant_failure(&e))?;
    let grant_id = claims.digest().map_err(|e| grant_failure(&e))?;
    context
        .ledger
        .record_launch_grant_nonce(&LaunchGrantNonceRecord {
            grant_nonce: claims.nonce.clone(),
            grant_id,
            attempt_id: context.attempt_id.clone(),
            attempt_fence: durable.binding.attempt_fence,
            expires_at_unix_ms,
            issued_at: LeaseService::rfc3339(context.now),
        })
        .map_err(|error| StepFailure::ledger(step, &error))?;
    let expectation = ProbeExpectation {
        provider,
        executable_blake3: identity.blake3,
        containment: ContainmentClass::EgressDenied,
    };
    let mut nonces = ProbeNonceLedger {
        store: &mut *context.ledger,
        attempt_id: context.attempt_id,
    };
    let evidence = verify_probe_grant(
        &token,
        &context.policy.binding(),
        std::slice::from_ref(context.verification_key),
        &mut nonces,
        context.now_ms,
        &expectation,
    )
    .map_err(|e| grant_failure(&e))?;
    Ok((token, expectation, evidence))
}

/// Adapts the durable launch-grant nonce store to the probe-grant nonce port.
/// A probe nonce is registered under the conformance Attempt; the port's scope
/// slot must carry exactly `PROBE_GRANT_NONCE_SCOPE`, so a probe nonce
/// presented under any other scope (for example a launch grant's Attempt id)
/// is `Unknown` and is never spent. One ledger row per nonce keeps a nonce
/// single-use across both grant kinds.
pub struct ProbeNonceLedger<'a, S: LaunchGrantNonceStore> {
    /// The durable nonce store shared with launch grants.
    pub store: &'a mut S,
    /// The conformance Attempt the probe nonce was registered under.
    pub attempt_id: &'a AttemptId,
}

impl<S: LaunchGrantNonceStore> LaunchGrantNonceLedger for ProbeNonceLedger<'_, S> {
    fn consume_nonce(
        &mut self,
        nonce: &str,
        scope: &str,
        _now_unix_ms: u64,
    ) -> Result<NonceConsumption, HarnessError> {
        if scope != PROBE_GRANT_NONCE_SCOPE {
            return Ok(NonceConsumption::Unknown);
        }
        self.store
            .consume_launch_grant_nonce(nonce, self.attempt_id)
            .map_err(|error| HarnessError::Io {
                context: "probe grant nonce store".into(),
                reason: error.to_string(),
            })
    }
}

/// A boundary is proven only when its receipt is well formed and every
/// containment probe was refused or unreachable.
fn require_contained(evidence: &EgressIsolationEvidence) -> Result<(), StepFailure> {
    let unproven = |detail: &str| {
        failure(
            LiveStep::ProbeContainment,
            PROBE_CONTAINMENT_UNPROVEN,
            detail,
            false,
        )
    };
    if !is_lower_hex_64(&evidence.receipt_digest) {
        return Err(unproven(
            "containment receipt digest must be 64 lowercase hex",
        ));
    }
    if evidence.probes.is_empty() {
        return Err(unproven("containment evidence carries no probes"));
    }
    let contained = |outcome: EgressProbeOutcome| {
        matches!(
            outcome,
            EgressProbeOutcome::Refused | EgressProbeOutcome::Unreachable
        )
    };
    match evidence.probes.iter().find(|p| !contained(p.outcome)) {
        Some(probe) => Err(unproven(&format!(
            "containment probe {} was not refused: {:?}",
            probe.name, probe.outcome
        ))),
        None => Ok(()),
    }
}

/// The explicit inputs of one contained probe. Read by the Claude executor,
/// which the production build cannot link (see the module doc), so the
/// non-test build refuses before reading them.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct ProbeSubject<'a> {
    pub executable: &'a Path,
    pub expected_blake3: &'a str,
    pub grant: &'a ProbeGrantEvidence,
    pub containment_receipt_blake3: &'a str,
    pub command: &'a CommandFactory<'a>,
    pub canaries: &'a CanarySecrets,
    pub workdir: &'a Path,
    pub now_unix_ms: u64,
}

/// Dispatch the probe to the one real executor for `provider`; every other
/// provider is a typed `RUNTIME_PROBE_UNAVAILABLE` refusal without a spawn.
pub(super) fn execute_probe(
    provider: &str,
    subject: &ProbeSubject<'_>,
) -> Result<RuntimeProbeObservation, StepFailure> {
    match provider {
        "claude" => claude_probe(subject),
        other => Err(unavailable(other)),
    }
}

#[cfg(any(test, feature = "live-claude"))]
fn claude_probe(subject: &ProbeSubject<'_>) -> Result<RuntimeProbeObservation, StepFailure> {
    use bullet_harness_claude::{probe_claude, ProbeContainment, ProbeInput};
    let input = ProbeInput {
        executable: subject.executable.to_path_buf(),
        expected_blake3: subject.expected_blake3.to_string(),
        grant: subject.grant.clone(),
        containment: Some(ProbeContainment {
            receipt_blake3: subject.containment_receipt_blake3.to_string(),
            command: subject.command,
        }),
        canaries: subject.canaries.clone(),
        workdir: subject.workdir.to_path_buf(),
        now_unix_ms: subject.now_unix_ms,
    };
    probe_claude(&input).map_err(|refusal| {
        let code = refusal.reason_code();
        failure(LiveStep::ProbeExecution, code, &refusal.to_string(), false)
    })
}

/// Without the `live-claude` feature the production build cannot link the
/// Claude executor, so PROBE_EXECUTION refuses here and steps 8-18 of
/// `LiveStep::ALL` are unreachable. This is the default.
#[cfg(not(any(test, feature = "live-claude")))]
fn claude_probe(_subject: &ProbeSubject<'_>) -> Result<RuntimeProbeObservation, StepFailure> {
    Err(unavailable("claude"))
}

/// Match the sealed probe facts to the enrollment record, then classify the
/// outcome. The conformance arm exists only when the dispatcher's separately
/// authorized read-only turn port yields a genuine observation; its typed
/// `RUNTIME_PROBE_UNAVAILABLE` keeps the outcome probe-only, which refuses
/// `RUNTIME_PROBE_NOT_ADMISSIBLE` through the frozen `ProbeOutcome`.
fn runtime_admission_step<L>(
    context: &ProbeContext<'_, L>,
    observation: RuntimeProbeObservation,
) -> Result<RuntimeConformanceObservation, StepFailure> {
    let step = LiveStep::RuntimeAdmission;
    let facts = observation.facts();
    let record = context.enrolled.record();
    let mismatch = [
        (
            facts.provider != context.enrolled.wire_provider(),
            "provider",
        ),
        (
            Path::new(&facts.executable.path) != record.executable,
            "executable",
        ),
        (
            facts.executable.blake3 != record.executable_blake3,
            "executable_blake3",
        ),
        (
            !version_admits(observation.version(), &record.version),
            "version",
        ),
        (!matches!(facts.exit, ProbeExit::Code { code: 0 }), "exit"),
    ]
    .into_iter()
    .find_map(|(differs, field)| differs.then_some(field));
    if let Some(field) = mismatch {
        let detail = format!("probe {field} does not match the enrollment record");
        return Err(failure(step, RUNTIME_ADMISSION_MISMATCH, &detail, false));
    }
    let executable = &context.options.executable;
    let outcome = match context.dispatcher.observe_runtime_conformance(
        executable,
        context.profile,
        context.now,
    ) {
        Ok(conformance) => ProbeOutcome::Conformance(Box::new(conformance)),
        Err(HarnessError::RuntimeProbeUnavailable { .. }) => {
            ProbeOutcome::ProbeOnly(Box::new(observation))
        }
        Err(error) => return Err(StepFailure::harness(step, &error)),
    };
    outcome
        .into_conformance()
        .map_err(|error| failure(step, error.reason_code(), &error.to_string(), true))
}

/// The enrolled version label (printable ASCII, no whitespace) must be one
/// whole whitespace-delimited token of the observed first stdout line, so
/// `2.1.243` admits `2.1.243 (Claude Code)` but never `2.1.2430`.
pub(super) fn version_admits(observed: &str, enrolled: &str) -> bool {
    !enrolled.is_empty()
        && observed
            .split_ascii_whitespace()
            .any(|token| token == enrolled)
}

pub(super) fn failure(step: LiveStep, code: &str, detail: &str, refusal: bool) -> StepFailure {
    StepFailure {
        step,
        reason_code: code.to_string(),
        detail: detail.to_string(),
        refusal,
    }
}

fn probe_failure(step: LiveStep, error: &RuntimeProbeError) -> StepFailure {
    failure(step, error.reason_code(), &error.to_string(), false)
}

fn grant_failure(error: &ProbeGrantError) -> StepFailure {
    let code = error.reason_code();
    failure(LiveStep::ProbeGrant, code, &error.to_string(), false)
}

fn unavailable(provider: &str) -> StepFailure {
    let error = RuntimeProbeError::Unavailable {
        provider: provider.to_string(),
    };
    let code = error.reason_code();
    failure(LiveStep::ProbeExecution, code, &error.to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::super::tests::NOW_MS;
    use super::*;
    use crate::memory::MemoryLedger;

    #[test]
    fn probe_nonce_ledger_spends_only_under_the_probe_scope() {
        let mut ledger = MemoryLedger::new();
        let attempt = AttemptId::from_seed("probe-nonce-scope");
        let nonce = "5".repeat(64);
        ledger
            .record_launch_grant_nonce(&LaunchGrantNonceRecord {
                grant_nonce: nonce.clone(),
                grant_id: "6".repeat(64),
                attempt_id: attempt.clone(),
                attempt_fence: 1,
                expires_at_unix_ms: NOW_MS + 15_000,
                issued_at: "1970-01-01T00:00:01Z".into(),
            })
            .unwrap();
        let mut port = ProbeNonceLedger {
            store: &mut ledger,
            attempt_id: &attempt,
        };
        let consume = |port: &mut ProbeNonceLedger<'_, MemoryLedger>, nonce: &str, scope: &str| {
            port.consume_nonce(nonce, scope, NOW_MS).unwrap()
        };
        assert_eq!(
            consume(&mut port, &nonce, attempt.as_str()),
            NonceConsumption::Unknown,
            "an Attempt scope never spends a probe nonce"
        );
        assert_eq!(
            consume(&mut port, &nonce, "bullet.launch-grant.v1"),
            NonceConsumption::Unknown
        );
        assert_eq!(
            consume(&mut port, &nonce, PROBE_GRANT_NONCE_SCOPE),
            NonceConsumption::Consumed
        );
        assert_eq!(
            consume(&mut port, &nonce, PROBE_GRANT_NONCE_SCOPE),
            NonceConsumption::Replayed
        );
        assert_eq!(
            consume(&mut port, &"7".repeat(64), PROBE_GRANT_NONCE_SCOPE),
            NonceConsumption::Unknown
        );
    }

    #[test]
    fn version_admits_whole_tokens_only() {
        assert!(version_admits("2.1.243 (Claude Code)", "2.1.243"));
        assert!(version_admits("2.1.243", "2.1.243"));
        assert!(version_admits("codex-cli 0.42.0", "0.42.0"));
        assert!(!version_admits("2.1.2430 (Claude Code)", "2.1.243"));
        assert!(!version_admits("v2.1.243", "2.1.243"));
        assert!(!version_admits("2.1.243", ""));
        assert!(!version_admits("", "2.1.243"));
    }
}
