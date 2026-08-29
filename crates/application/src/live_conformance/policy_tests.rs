//! v1alpha2 gating of the live-conformance path through the production loader
//! (`load_policy` / `LoadedPolicy::from_bytes`, no policy bypass). Positive
//! fixture dispatch uses the strict `cfg(test)` observation wrapper; a real
//! product adapter with a valid policy/key and no enrollment refuses at
//! `ENROLLMENT` before authority, egress, or provider process activity.

use super::egress::NoopEgressBackend;
use super::probe_tests::ObservedClaudeDispatcher;
use super::run_live_conformance;
use super::tests::{options, step_status, FakeMode, Harness, HAPPY_CANARY};
use crate::memory::MemoryLedger;
use crate::policy_snapshot::{
    load_policy, LoadedPolicy, PolicySchemaVersion, LIVE_ADMISSION_MIN_GENERATION,
};
use crate::store::Ledger;
use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::launch_grant::{canonical_json, signing_key_path};
use bullet_harness_core::{
    EgressBackend, HarnessError, LiveOutcome, LiveStep, PreparedEgress, StepStatus,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/policy-v1alpha2-live-enabled.json");
const V1ALPHA1: &[u8] = include_bytes!("../../tests/fixtures/policy-v1alpha1.json");
const ISSUER: &str = "bullet-kernel-local";
const KEY_ID: &str = "authority-test-1";
const FIXTURE_PUBLIC_KEY_HEX: &str =
    "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
/// Fixture-only key material shared with bullet-wire's golden generator; its
/// public half is the `provider-runner` key the v1alpha2 fixture registers.
/// Normative policy must never trust it (ADR 0005).
const FIXTURE_SECRET_KEY: [u8; 64] = [
    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125, 159,
    133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116, 30, 185, 219, 187, 188, 4, 124, 3, 253, 112,
    96, 78, 0, 113, 240, 152, 126, 22, 178, 139, 117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177,
    162,
];
/// Fixture window start (`activation_at_unix_ms`).
const FIXTURE_ACTIVATION_MS: u64 = 1_787_577_000_000;
/// Fixture window end (`expires_at_unix_ms`).
const FIXTURE_EXPIRY_MS: u64 = 1_819_113_000_000;

type Mutate = fn(&mut Value);

fn instant(unix_ms: u64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(i64::try_from(unix_ms).unwrap())
        .single()
        .unwrap()
}

const IN_WINDOW_MS: u64 = FIXTURE_ACTIVATION_MS + 60_000;

fn in_window() -> DateTime<Utc> {
    instant(IN_WINDOW_MS)
}

/// A memory ledger whose deterministic simulation clock has been advanced to
/// `now`, so the durable conformance lease it grants is still active at the
/// run instant (the ledger never reads the wall clock).
fn ledger_at(now: DateTime<Utc>) -> MemoryLedger {
    let mut ledger = MemoryLedger::new();
    let start = DateTime::parse_from_rfc3339(&ledger.simulation_time())
        .unwrap()
        .timestamp_millis();
    let elapsed = now.timestamp_millis().saturating_sub(start).max(0) / 1_000;
    ledger
        .advance_simulation_time(u64::try_from(elapsed).unwrap())
        .unwrap();
    ledger
}

fn fixture_value() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn runner_key_index(value: &Value) -> usize {
    value["issuer_keys"]
        .as_array()
        .unwrap()
        .iter()
        .position(|key| key["issuer"] == json!(ISSUER) && key["key_id"] == json!(KEY_ID))
        .unwrap()
}

fn install_fixture_key(data_dir: &Path) {
    let path = signing_key_path(data_dir);
    let directory = path.parent().unwrap();
    fs::create_dir_all(directory).unwrap();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, FIXTURE_SECRET_KEY).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn fixture_options(harness: &Harness) -> super::LiveConformanceOptions {
    let mut options = options(harness, HAPPY_CANARY);
    options.issuer = ISSUER.into();
    options.key_id = KEY_ID.into();
    options
}

fn write_policy(harness: &Harness, value: &Value) -> std::path::PathBuf {
    let path = harness.data_dir.join("candidate-policy.json");
    fs::write(&path, canonical_json(value).unwrap()).unwrap();
    path
}

/// Any call proves the enrollment refusal happened too late.
struct RejectIfCalledEgress;

impl EgressBackend for RejectIfCalledEgress {
    fn sandbox_manifest_digest(&self, _provider: &str) -> Result<String, HarnessError> {
        panic!("egress manifest requested before enrollment")
    }

    fn prepare(
        &self,
        _provider: &str,
        _workdir: &Path,
    ) -> Result<Box<dyn PreparedEgress + '_>, HarnessError> {
        panic!("egress prepared before enrollment")
    }
}

#[test]
fn hub_fixture_passes_the_policy_step_through_the_production_loader_and_pongs() {
    let harness = Harness::new(FakeMode::Pong);
    harness.enroll(IN_WINDOW_MS);
    install_fixture_key(&harness.data_dir);
    fs::create_dir_all(harness.data_dir.join("policy")).unwrap();
    fs::write(harness.data_dir.join("policy/policy.json"), FIXTURE).unwrap();
    let policy = load_policy(&harness.data_dir, None).expect("production loader admits v1alpha2");
    assert_eq!(policy.schema(), PolicySchemaVersion::V1Alpha2);
    assert_eq!(policy.generation(), LIVE_ADMISSION_MIN_GENERATION);
    assert!(policy.live_admission_enabled());
    assert!(policy.binding().live_admission_enabled);

    let mut ledger = ledger_at(in_window());
    let run = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ObservedClaudeDispatcher::new(),
        &NoopEgressBackend::new(),
        &fixture_options(&harness),
        in_window(),
    )
    .expect("PONG under the operator-ratified fixture");
    assert_eq!(run.receipt.outcome, LiveOutcome::Pong);
    assert!(run.receipt.pong_match);
    assert_eq!(run.receipt.policy_generation, Some(2));
    assert_eq!(
        run.receipt.policy_snapshot_digest.as_deref(),
        Some(policy.digest())
    );
    assert!(run
        .receipt
        .steps
        .iter()
        .all(|record| record.status == StepStatus::Pass));
    let spawns = harness.marker_lines();
    assert_eq!(
        spawns.len(),
        2,
        "one probe spawn, then one turn: {spawns:?}"
    );
    assert_eq!(spawns[0], "ran --version");
    assert_eq!(
        run.verification_key.unwrap().public_key_hex(),
        FIXTURE_PUBLIC_KEY_HEX
    );
    run.receipt.verify().unwrap();
}

#[test]
fn structural_refusals_stop_at_the_loader_before_any_key_read_or_spawn() {
    let cases: [(&str, Mutate, &str); 6] = [
        (
            "v1alpha1 with live admission",
            |p| p["schema_version"] = json!("v1alpha1"),
            "UNSAFE_POLICY",
        ),
        (
            "generation 1",
            |p| p["policy_generation"] = json!(1),
            "LIVE_ADMISSION_REQUIRES_GENERATION",
        ),
        (
            "no provider-runner key",
            |p| {
                let index = runner_key_index(p);
                p["issuer_keys"].as_array_mut().unwrap().remove(index);
            },
            "LIVE_ADMISSION_REQUIRES_RUNNER_KEY",
        ),
        (
            "revoked provider-runner key",
            |p| {
                let index = runner_key_index(p);
                p["issuer_keys"][index]["revoked_at_unix_ms"] = json!(FIXTURE_EXPIRY_MS - 1);
            },
            "LIVE_ADMISSION_REQUIRES_RUNNER_KEY",
        ),
        (
            "evolutionary authority",
            |p| p["route_policy"]["evolutionary_authority"] = json!(true),
            "UNSAFE_POLICY",
        ),
        (
            "unsupported schema",
            |p| p["schema_version"] = json!("v1alpha3"),
            "UNSUPPORTED_POLICY_SCHEMA",
        ),
    ];
    for (name, mutate, expected) in cases {
        let harness = Harness::new(FakeMode::Pong);
        let mut value = fixture_value();
        mutate(&mut value);
        let path = write_policy(&harness, &value);
        let error = load_policy(&harness.data_dir, Some(&path)).unwrap_err();
        assert_eq!(error.reason_code(), "POLICY_INVALID", "{name}");
        let reason = error.to_string();
        assert!(
            reason.contains(&format!("{expected}: ")),
            "{name}: {reason}"
        );
        assert_eq!(harness.marker_runs(), 0, "{name}: the fake binary ran");
        assert!(
            !signing_key_path(&harness.data_dir).exists(),
            "{name}: no operator key was ever created or read"
        );
    }

    // The checked-in v1alpha1 fixture with live admission flipped on is the
    // same UNSAFE_POLICY it always was.
    let harness = Harness::new(FakeMode::Pong);
    let mut committed: Value = serde_json::from_slice(V1ALPHA1).unwrap();
    committed["sandbox_policy"]["live_admission_enabled"] = json!(true);
    let path = write_policy(&harness, &committed);
    let reason = load_policy(&harness.data_dir, Some(&path))
        .unwrap_err()
        .to_string();
    assert!(
        reason.contains("UNSAFE_POLICY: v1alpha1 Gate 0 policy must remain offline"),
        "{reason}"
    );
    assert_eq!(harness.marker_runs(), 0);
}

#[test]
fn an_out_of_window_instant_fails_the_policy_step_before_the_key_is_read() {
    for now_ms in [
        1_000,
        FIXTURE_ACTIVATION_MS - 1,
        FIXTURE_EXPIRY_MS,
        FIXTURE_EXPIRY_MS + 1,
    ] {
        let harness = Harness::new(FakeMode::Pong);
        // Deliberately no operator key: the policy step must fail first.
        let policy = LoadedPolicy::from_bytes(FIXTURE).unwrap();
        let mut ledger = MemoryLedger::new();
        let error = run_live_conformance(
            &harness.data_dir,
            &mut ledger,
            &policy,
            &ClaudeAdapter::new(),
            &NoopEgressBackend::new(),
            &fixture_options(&harness),
            instant(now_ms),
        )
        .expect_err("an inactive policy is a failure, not a neutral refusal");
        assert_eq!(error.reason_code(), "POLICY_INVALID", "{now_ms}");
        assert!(
            error.detail.contains("POLICY_NOT_ACTIVE"),
            "{}",
            error.detail
        );
        assert_eq!(error.step, LiveStep::Policy);
        assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
        assert_eq!(
            step_status(&error.receipt.steps, LiveStep::Policy),
            StepStatus::Failed
        );
        assert_eq!(
            step_status(&error.receipt.steps, LiveStep::Enrollment),
            StepStatus::NotRun
        );
        assert_eq!(harness.marker_runs(), 0, "{now_ms}: the fake binary ran");
        assert!(!signing_key_path(&harness.data_dir).exists());
        error.receipt.verify().unwrap();
    }

    // Inside the window the same policy passes the step and the enrollment
    // loads; without a key the path stops at OPERATOR_KEY, still before any
    // spawn.
    let harness = Harness::new(FakeMode::Pong);
    harness.enroll(IN_WINDOW_MS);
    let policy = LoadedPolicy::from_bytes(FIXTURE).unwrap();
    let mut ledger = MemoryLedger::new();
    let error = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ObservedClaudeDispatcher::new(),
        &NoopEgressBackend::new(),
        &fixture_options(&harness),
        in_window(),
    )
    .expect_err("no operator key");
    assert_eq!(error.step, LiveStep::OperatorKey);
    for step in [LiveStep::Policy, LiveStep::Enrollment] {
        assert_eq!(step_status(&error.receipt.steps, step), StepStatus::Pass);
    }
    assert!(error.receipt.enrollment_blake3.is_some());
    assert_eq!(harness.marker_runs(), 0);
}

#[test]
fn a_runner_key_not_yet_active_fails_the_policy_step_at_that_instant() {
    let harness = Harness::new(FakeMode::Pong);
    install_fixture_key(&harness.data_dir);
    let mut value = fixture_value();
    let index = runner_key_index(&value);
    let activates = FIXTURE_ACTIVATION_MS + 120_000;
    value["issuer_keys"][index]["activates_at_unix_ms"] = json!(activates);
    let path = write_policy(&harness, &value);
    // Structurally valid: the key still overlaps the policy window.
    let policy = load_policy(&harness.data_dir, Some(&path)).unwrap();

    let mut ledger = MemoryLedger::new();
    let error = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &NoopEgressBackend::new(),
        &fixture_options(&harness),
        in_window(),
    )
    .expect_err("no runner key is active yet");
    assert_eq!(error.reason_code(), "POLICY_INVALID");
    assert!(
        error.detail.contains("LIVE_ADMISSION_REQUIRES_RUNNER_KEY"),
        "{}",
        error.detail
    );
    assert_eq!(error.step, LiveStep::Policy);
    assert_eq!(harness.marker_runs(), 0);

    let mut ledger = ledger_at(instant(activates));
    let run = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &RejectIfCalledEgress,
        &fixture_options(&harness),
        instant(activates),
    )
    .expect("a missing enrollment is a designed refusal");
    assert_eq!(run.receipt.outcome, LiveOutcome::Refused);
    assert_eq!(
        run.receipt.refusal_reason.as_deref(),
        Some("ENROLLMENT_MISSING")
    );
    assert_eq!(run.receipt.failed_step, Some(LiveStep::Enrollment));
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::Policy),
        StepStatus::Pass
    );
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::Enrollment),
        StepStatus::Refused
    );
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::Admission),
        StepStatus::NotRun
    );
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::OperatorKey),
        StepStatus::NotRun
    );
    assert_eq!(
        step_status(&run.receipt.steps, LiveStep::Lease),
        StepStatus::NotRun
    );
    assert!(run.grant.is_none(), "no launch-grant nonce may be minted");
    assert!(ledger.list_missions().unwrap().is_empty());
    assert!(ledger.list_events().unwrap().is_empty());
    assert_eq!(harness.marker_runs(), 0);
    run.receipt.verify().unwrap();
}

#[test]
fn the_v1alpha1_neutral_refusal_is_clock_independent() {
    for now_ms in [1_000, FIXTURE_ACTIVATION_MS + 60_000, FIXTURE_EXPIRY_MS + 1] {
        let harness = Harness::new(FakeMode::Pong);
        let policy = LoadedPolicy::from_bytes(V1ALPHA1).unwrap();
        assert_eq!(policy.schema(), PolicySchemaVersion::V1Alpha1);
        let mut ledger = MemoryLedger::new();
        let run = run_live_conformance(
            &harness.data_dir,
            &mut ledger,
            &policy,
            &ClaudeAdapter::new(),
            &NoopEgressBackend::new(),
            &options(&harness, HAPPY_CANARY),
            instant(now_ms),
        )
        .expect("neutral refusal");
        assert_eq!(run.receipt.outcome, LiveOutcome::Refused, "{now_ms}");
        assert_eq!(
            run.receipt.refusal_reason.as_deref(),
            Some("POLICY_LIVE_ADMISSION_DISABLED")
        );
        assert_eq!(harness.marker_runs(), 0);
    }
}
