//! Probe-phase tests (ADMIT-1): the enrolled fake is probed exactly once under
//! its own grant and containment, `RUNTIME_ADMISSION` refuses the probe-only
//! outcome so `ADMISSION` is never reached on probe facts, and every hostile
//! enrollment, drift, containment, exit, and canary case stops without a
//! spawn. Also home of the strict `cfg(test)` dispatcher that supplies the
//! conformance arm for the positive tests in `tests` and `policy_tests`; no
//! production adapter can construct it. The fake-binary harness lives in
//! `tests`.

use super::egress::NoopEgressBackend;
use super::probe_steps::{execute_probe, ProbeSubject};
use super::seam::live_admission_policy;
use super::tests::{
    now, options, prepare, run_once, step_status, FakeMode, Harness, HostileEgress, EXPOSED_CANARY,
    HAPPY_CANARY, NOW_MS,
};
use super::{run_live_conformance, ProbeNonceLedger, ENROLLMENT_SUBJECT_MISMATCH};

use crate::memory::MemoryLedger;
use crate::store::Ledger;
use bullet_domain::Observation;
use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::launch_grant::{
    is_lower_hex_64, verify_probe_grant, LaunchGrantSigningKey,
};
use bullet_harness_core::live::{ContainmentClass, ProbeGrantEvidence};
use bullet_harness_core::{
    executable_digest, AgentEvent, AgentEventKind, CanarySecrets, CommandFactory, EgressBackend,
    EventNormalizer, HarnessDescriptor, HarnessError, LiveDispatcher, LiveOutcome, LiveStep,
    LiveTurnOutcome, LiveTurnRequest, NativeMeta, PatchMutation, PatchOperation, PatchProposal,
    Preimage, ProbeResult, ProfileIdentity, ProfileRef, ProviderProtocol,
    RuntimeConformanceObservation, RuntimeProbeSnapshot, StepStatus,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Arranges one hostile enrollment state on a fresh harness.
type Arrange = fn(&Harness);

/// Strict-test-only observed subject. Production adapters inherit
/// `LiveDispatcher`'s typed default refusal and can never construct this
/// positive path.
pub(super) struct ObservedClaudeDispatcher {
    inner: ClaudeAdapter,
}

impl ObservedClaudeDispatcher {
    pub(super) const fn new() -> Self {
        Self {
            inner: ClaudeAdapter::new(),
        }
    }
}

impl LiveDispatcher for ObservedClaudeDispatcher {
    fn provider(&self) -> &str {
        <ClaudeAdapter as LiveDispatcher>::provider(&self.inner)
    }

    fn descriptor(&self) -> HarnessDescriptor {
        <ClaudeAdapter as LiveDispatcher>::descriptor(&self.inner)
    }

    fn observed_runtime_version(&self) -> &str {
        <ClaudeAdapter as LiveDispatcher>::observed_runtime_version(&self.inner)
    }

    fn required_protocol(&self) -> ProviderProtocol {
        <ClaudeAdapter as LiveDispatcher>::required_protocol(&self.inner)
    }

    fn observe_runtime_conformance(
        &self,
        executable: &Path,
        profile: &ProfileRef,
        observed_at: DateTime<Utc>,
    ) -> Result<RuntimeConformanceObservation, HarnessError> {
        let mut descriptor = self.descriptor();
        descriptor.binary = executable
            .file_name()
            .expect("fixture executable basename")
            .to_string_lossy()
            .into_owned();
        descriptor.version = Observation::value(self.observed_runtime_version().to_string());
        let probe = RuntimeProbeSnapshot {
            descriptor,
            executable: executable.to_path_buf(),
            executable_blake3: executable_digest(executable)?,
            protocol: self.required_protocol(),
            identity: ProbeResult {
                profile: Observation::value(ProfileIdentity {
                    provider: self.provider().to_string(),
                    email: profile.expected.email.clone(),
                    account_id: None,
                    subscription: None,
                    auth_method: Some("strict-test-fixture".into()),
                }),
                version: self.observed_runtime_version().to_string(),
            },
            observed_at,
        };
        RuntimeConformanceObservation::new(
            probe,
            vec![],
            vec![],
            conformance_events(self.provider()),
            conformance_proposal(),
        )
    }

    fn dispatch_live_turn(
        &self,
        admission: &bullet_harness_core::EvaluatedAdmission,
        factory: &CommandFactory<'_>,
        request: &LiveTurnRequest,
    ) -> Result<LiveTurnOutcome, HarnessError> {
        <ClaudeAdapter as LiveDispatcher>::dispatch_live_turn(
            &self.inner,
            admission,
            factory,
            request,
        )
    }
}

fn conformance_events(provider: &str) -> Vec<AgentEvent> {
    let mut normalizer = EventNormalizer::new(
        bullet_harness_core::AgentSessionId::new("live-admission"),
        provider,
    );
    vec![
        normalizer.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none()),
        normalizer.accept(
            AgentEventKind::TurnCompleted,
            json!({}),
            &NativeMeta::none(),
        ),
    ]
}

fn conformance_proposal() -> PatchProposal {
    PatchProposal {
        schema_version: 1,
        proposal_id: format!("cnt_{}", "1".repeat(64)),
        producing_attempt_id: format!("atm_{}", "2".repeat(64)),
        base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
        base_checkpoint_digest: "4".repeat(64),
        intent_summary: "strict-test live conformance subject".into(),
        operations: vec![PatchOperation {
            path: "PONG.txt".into(),
            preimage: Preimage::Absent,
            mutation: PatchMutation::Write {
                content_utf8: "PONG\n".into(),
            },
        }],
        gate_ids: vec![super::steps::PROPOSAL_GATE_ID.to_string()],
        claims: vec![],
        uncertainties: vec![],
        done: true,
    }
}

#[test]
fn enrolled_fake_probe_passes_and_runtime_admission_refuses_probe_only() {
    let harness = Harness::new(FakeMode::Pong);
    let enrollment = harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 7);
    let run = run_once(
        &harness,
        &mut prepared,
        &ClaudeAdapter::new(),
        &NoopEgressBackend::new(),
        &options(&harness, HAPPY_CANARY),
    )
    .expect("a probe-only outcome is a designed refusal");
    let receipt = &run.receipt;
    assert_eq!(receipt.outcome, LiveOutcome::Refused);
    assert_eq!(
        receipt.refusal_reason.as_deref(),
        Some("RUNTIME_PROBE_NOT_ADMISSIBLE")
    );
    assert_eq!(receipt.failed_step, Some(LiveStep::RuntimeAdmission));
    let passed = [
        LiveStep::Policy,
        LiveStep::Enrollment,
        LiveStep::OperatorKey,
        LiveStep::Lease,
        LiveStep::ProbeGrant,
        LiveStep::ProbeContainment,
        LiveStep::ProbeExecution,
    ];
    for step in LiveStep::ALL {
        let expected = if passed.contains(&step) {
            StepStatus::Pass
        } else if step == LiveStep::RuntimeAdmission {
            StepStatus::Refused
        } else {
            StepStatus::NotRun
        };
        assert_eq!(step_status(&receipt.steps, step), expected, "{step:?}");
    }
    assert_eq!(
        harness.marker_lines(),
        vec!["ran --version".to_string()],
        "exactly one probe spawn and no turn"
    );
    let enrollment_bytes = fs::read(&enrollment).unwrap();
    assert_eq!(
        receipt.enrollment_blake3.as_deref(),
        Some(blake3::hash(&enrollment_bytes).to_hex().as_str())
    );
    for digest in [
        &receipt.probe_grant_digest,
        &receipt.probe_observation_digest,
        &receipt.probe_containment_receipt_digest,
    ] {
        assert!(is_lower_hex_64(digest.as_deref().unwrap()), "{digest:?}");
    }
    let noop = NoopEgressBackend::new();
    let expected_receipt = noop
        .prepare("claude", &harness.data_dir)
        .unwrap()
        .evidence()
        .receipt_digest;
    assert_eq!(
        receipt.probe_containment_receipt_digest.as_deref(),
        Some(expected_receipt.as_str())
    );
    assert!(
        receipt.executable_path.is_none()
            && receipt.grant_id.is_none()
            && receipt.egress_receipt_digest.is_none()
            && run.grant.is_none(),
        "nothing past RUNTIME_ADMISSION may be recorded"
    );
    receipt.verify().unwrap();

    // The probe grant bound exactly the enrolled bytes, and presenting it
    // again to the same durable ledger replays its spent nonce.
    let probe = run.probe_grant.as_ref().unwrap();
    assert_eq!(
        probe.expectation.executable_blake3,
        executable_digest(&harness.executable).unwrap()
    );
    assert_eq!(
        probe.expectation.containment,
        ContainmentClass::EgressDenied
    );
    let replay = verify_probe_grant(
        &probe.token,
        &prepared.policy.binding(),
        &[prepared.key.verification_key().unwrap()],
        &mut ProbeNonceLedger {
            store: &mut prepared.ledger,
            attempt_id: &probe.attempt_id,
        },
        NOW_MS,
        &probe.expectation,
    )
    .unwrap_err();
    assert_eq!(replay.reason_code(), "PROBE_GRANT_REPLAYED");
}

#[test]
fn a_missing_tampered_or_mismatched_enrollment_stops_before_key_read_or_spawn() {
    // The policy admits a key that is never written: the key read must not happen.
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let policy = live_admission_policy(&key, 4).unwrap();
    let key_file = |harness: &Harness| harness.data_dir.join("authority/launch-grant.key");

    let harness = Harness::new(FakeMode::Pong);
    let mut ledger = MemoryLedger::new();
    let run = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &NoopEgressBackend::new(),
        &options(&harness, HAPPY_CANARY),
        now(),
    )
    .expect("a missing enrollment is the designed neutral refusal");
    assert_eq!(run.receipt.outcome, LiveOutcome::Refused);
    assert_eq!(
        run.receipt.refusal_reason.as_deref(),
        Some("ENROLLMENT_MISSING")
    );
    assert_eq!(run.receipt.failed_step, Some(LiveStep::Enrollment));
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::Enrollment),
        StepStatus::Refused
    );
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::OperatorKey),
        StepStatus::NotRun
    );
    assert!(ledger.list_missions().unwrap().is_empty());
    assert_eq!(harness.marker_runs(), 0);
    assert!(!key_file(&harness).exists());
    run.receipt.verify().unwrap();

    let cases: [(&str, Arrange, &str); 3] = [
        (
            "executable tampered after enrollment",
            |h| {
                h.enroll(NOW_MS);
                fs::write(&h.executable, b"#!/bin/bash\necho tampered\n").unwrap();
                fs::set_permissions(&h.executable, fs::Permissions::from_mode(0o755)).unwrap();
            },
            "ENROLLMENT_EXECUTABLE_DIGEST_MISMATCH",
        ),
        (
            "malformed record",
            |h| {
                h.write_enrollment_bytes(b"{\"schema\":");
            },
            "ENROLLMENT_MALFORMED",
        ),
        (
            "enrollment names another version",
            |h| {
                let mut value = h.enrollment_record(NOW_MS);
                value["version"] = json!("9.9.9");
                h.write_enrollment(&value);
            },
            ENROLLMENT_SUBJECT_MISMATCH,
        ),
    ];
    for (name, arrange, code) in cases {
        let harness = Harness::new(FakeMode::Pong);
        arrange(&harness);
        let mut ledger = MemoryLedger::new();
        let error = run_live_conformance(
            &harness.data_dir,
            &mut ledger,
            &policy,
            &ClaudeAdapter::new(),
            &NoopEgressBackend::new(),
            &options(&harness, HAPPY_CANARY),
            now(),
        )
        .expect_err(name);
        assert_eq!(error.reason_code(), code, "{name}");
        assert_eq!(error.step, LiveStep::Enrollment, "{name}");
        assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
        assert_eq!(
            step_status(&error.receipt.steps, LiveStep::OperatorKey),
            StepStatus::NotRun
        );
        assert!(ledger.list_missions().unwrap().is_empty(), "{name}");
        assert_eq!(harness.marker_runs(), 0, "{name}: the fake binary ran");
        assert!(!key_file(&harness).exists(), "{name}");
        error.receipt.verify().unwrap();
    }
}

#[test]
fn executable_drift_after_the_probe_grant_is_refused_before_spawn() {
    let harness = Harness::new(FakeMode::Pong);
    harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 6);
    let egress = HostileEgress {
        reached: false,
        tamper: Some(harness.executable.clone()),
    };
    let error = run_once(
        &harness,
        &mut prepared,
        &ClaudeAdapter::new(),
        &egress,
        &options(&harness, HAPPY_CANARY),
    )
    .expect_err("drifted bytes must not spawn");
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_GRANT_MISMATCH");
    assert!(
        error.detail.contains("executable_blake3"),
        "{}",
        error.detail
    );
    assert_eq!(error.step, LiveStep::ProbeExecution);
    for step in [LiveStep::ProbeGrant, LiveStep::ProbeContainment] {
        assert_eq!(step_status(&error.receipt.steps, step), StepStatus::Pass);
    }
    assert_eq!(
        step_status(&error.receipt.steps, LiveStep::Admission),
        StepStatus::NotRun
    );
    assert!(error.receipt.probe_grant_digest.is_some());
    assert!(error.receipt.probe_observation_digest.is_none());
    assert_eq!(
        harness.marker_runs(),
        0,
        "neither the enrolled nor the drifted bytes may run"
    );
    error.receipt.verify().unwrap();
}

#[test]
fn a_probe_that_exits_nonzero_or_leaks_a_canary_never_reaches_admission() {
    // Even with a conformance arm available, probe facts are matched first.
    let harness = Harness::new(FakeMode::ProbeNonzero);
    harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 6);
    let error = run_once(
        &harness,
        &mut prepared,
        &ObservedClaudeDispatcher::new(),
        &NoopEgressBackend::new(),
        &options(&harness, HAPPY_CANARY),
    )
    .expect_err("exit 3 is not a clean probe");
    assert_eq!(error.reason_code(), "RUNTIME_ADMISSION_MISMATCH");
    assert!(error.detail.contains("exit"), "{}", error.detail);
    assert_eq!(error.step, LiveStep::RuntimeAdmission);
    assert_eq!(
        step_status(&error.receipt.steps, LiveStep::ProbeExecution),
        StepStatus::Pass
    );
    assert!(error.receipt.probe_observation_digest.is_some());
    assert_eq!(
        step_status(&error.receipt.steps, LiveStep::Admission),
        StepStatus::NotRun
    );
    assert_eq!(harness.marker_lines(), vec!["ran --version".to_string()]);
    error.receipt.verify().unwrap();

    let harness = Harness::new(FakeMode::ProbeCanary);
    harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 6);
    let error = run_once(
        &harness,
        &mut prepared,
        &ObservedClaudeDispatcher::new(),
        &NoopEgressBackend::new(),
        &options(&harness, EXPOSED_CANARY),
    )
    .expect_err("a canary on the probe surface fails the probe");
    assert_eq!(error.reason_code(), "SECRET_CANARY_EXPOSURE");
    assert_eq!(error.step, LiveStep::ProbeExecution);
    assert!(error.receipt.probe_observation_digest.is_none());
    assert_eq!(harness.marker_runs(), 1);
    error.receipt.verify().unwrap();
}

#[test]
fn other_providers_refuse_runtime_probe_unavailable_without_a_spawn() {
    let factory: &CommandFactory<'_> = &|_: &str, _: &[&str], _: &[(&str, &str)]| -> Command {
        panic!("a refused probe must never build a command")
    };
    let grant = ProbeGrantEvidence {
        grant_blake3: "1".repeat(64),
        provider: "codex".into(),
        executable_blake3: "2".repeat(64),
        containment: ContainmentClass::EgressDenied,
        expires_at_unix_ms: NOW_MS + 15_000,
    };
    let canaries = CanarySecrets::new(vec![HAPPY_CANARY.into()]).unwrap();
    let receipt = "3".repeat(64);
    let subject = ProbeSubject {
        executable: Path::new("/nonexistent/codex"),
        expected_blake3: &grant.executable_blake3,
        grant: &grant,
        containment_receipt_blake3: &receipt,
        command: factory,
        canaries: &canaries,
        workdir: Path::new("/"),
        now_unix_ms: NOW_MS,
    };
    for provider in ["codex", "cursor", "agy", "antigravity", "Claude", ""] {
        let refusal = execute_probe(provider, &subject).unwrap_err();
        assert_eq!(
            refusal.reason_code, "RUNTIME_PROBE_UNAVAILABLE",
            "{provider:?}"
        );
        assert_eq!(refusal.step, LiveStep::ProbeExecution);
        assert!(
            refusal.refusal,
            "{provider:?}: a designed refusal, never UNKNOWN"
        );
        assert!(refusal.detail.contains(provider), "{}", refusal.detail);
    }
}
