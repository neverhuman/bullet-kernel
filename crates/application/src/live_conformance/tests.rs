//! Full-path live-conformance tests. No real provider binary is spawned: a
//! fake `claude` shell script answers `--version` for the granted probe and
//! emits a canned stream-JSON transcript for the turn; every spawn appends its
//! argv to a marker. Enrollment records are written 0600 for the ENROLL-1
//! loader. A strict `cfg(test)` dispatcher supplies the otherwise unavailable
//! observed conformance subject; no production adapter can synthesize it. The
//! v1alpha2 test policy is loaded through the production loader (no bypass);
//! a no-op egress backend supplies well-formed containment evidence. The
//! fake-binary harness is shared with `policy_tests` and `probe_tests`, which
//! also owns the strict dispatcher.

use super::egress::NoopEgressBackend;
use super::probe_tests::ObservedClaudeDispatcher;
use super::seam::live_admission_policy;
use super::{
    enrollment_path, run_live_conformance, LiveConformanceError, LiveConformanceOptions,
    LiveConformanceRun, ProbeNonceLedger, PROVIDER_ENROLLMENT_SCHEMA,
};
use crate::launch_grant::StoreNonceLedger;
use crate::memory::MemoryLedger;
use crate::policy_snapshot::LoadedPolicy;
use bullet_domain::ProfileId;
use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::launch_grant::{
    verify_launch_grant, verify_probe_grant, write_new_signing_key, LaunchGrantSigningKey,
};
use bullet_harness_core::{
    executable_digest, EgressBackend, EgressIsolationEvidence, EgressProbe, EgressProbeOutcome,
    HarnessError, LiveDispatcher, LiveOutcome, LiveStep, LiveStepRecord, PreparedEgress,
    StepStatus,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const V1ALPHA1_POLICY: &[u8] = include_bytes!("../../tests/fixtures/policy-v1alpha1.json");
pub(super) const HAPPY_CANARY: &str = "bullet-conformance-canary-happy-0001";
pub(super) const EXPOSED_CANARY: &str = "bullet-conformance-canary-exposed-e2e-0001";
/// The enrolled version label; the fake prints it inside a longer line.
pub(super) const FAKE_VERSION: &str = "2.1.243";
const FAKE_VERSION_LINE: &str = "2.1.243 (Claude Code)";
/// The deterministic run instant of these tests.
pub(super) const NOW_MS: u64 = 1_000;

const INIT_PREFIX: &str = r#"{"type":"system","subtype":"init","uuid":"00000000-0000-4000-8000-000000000002","session_id":"00000000-0000-4000-8000-000000000001","apiKeySource":"none","claude_code_version":"2.1.243","cwd":""#;
const INIT_SUFFIX: &str = r#"","tools":["Read","Glob","Grep"],"mcp_servers":[],"model":"claude-offline-model","permissionMode":"plan","slash_commands":[],"output_style":"default","agents":[],"skills":[],"plugins":[],"analytics_disabled":true,"product_feedback_disabled":true}"#;
const ASSISTANT: &str = r#"{"type":"assistant","uuid":"00000000-0000-4000-8000-000000000003","session_id":"00000000-0000-4000-8000-000000000001","parent_tool_use_id":null,"message":{"id":"msg-000000000003","type":"message","role":"assistant","model":"claude-offline-model","content":[{"type":"text","text":"PONG"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":5}}}"#;
const RESULT: &str = r#"{"type":"result","subtype":"success","uuid":"00000000-0000-4000-8000-000000000004","session_id":"00000000-0000-4000-8000-000000000001","duration_ms":20,"duration_api_ms":10,"is_error":false,"num_turns":1,"result":"PONG","stop_reason":"end_turn","total_cost_usd":0.01,"usage":{"input_tokens":10,"output_tokens":5},"modelUsage":{"claude-offline-model":{"inputTokens":10,"outputTokens":5}},"permission_denials":[],"structured_output":{"schema_version":1,"proposal_id":"cnt_1111111111111111111111111111111111111111111111111111111111111111","producing_attempt_id":"atm_2222222222222222222222222222222222222222222222222222222222222222","base_checkpoint_id":"ckp_3333333333333333333333333333333333333333333333333333333333333333","base_checkpoint_digest":"4444444444444444444444444444444444444444444444444444444444444444","operations":[{"path":"PONG.txt","preimage":{"kind":"absent"},"mutation":{"kind":"write","content_utf8":"PONG\n"}}],"gate_ids":["gat_9999999999999999999999999999999999999999999999999999999999999999"],"intent_summary":"pong","claims":[],"uncertainties":[],"done":true},"terminal_reason":"completed"}"#;

#[derive(Clone, Copy)]
pub(super) enum FakeMode {
    Pong,
    Canary,
    NonzeroAfterPong,
    TimeoutAfterPong,
    /// `--version` leaks the exposed canary.
    ProbeCanary,
    /// `--version` prints the version line but exits 3.
    ProbeNonzero,
}

pub(super) struct Harness {
    _root: TempDir,
    pub(super) data_dir: PathBuf,
    pub(super) executable: PathBuf,
    marker: PathBuf,
}

impl Harness {
    pub(super) fn new(mode: FakeMode) -> Self {
        let root = TempDir::new().unwrap();
        let base = root.path().canonicalize().unwrap();
        let data_dir = base.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let bin_dir = base.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::set_permissions(&bin_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = bin_dir.join("claude");
        let marker = base.join("ran.marker");
        write_fake(&executable, &marker, mode);
        let executable = executable.canonicalize().unwrap();
        Self {
            _root: root,
            data_dir,
            executable,
            marker,
        }
    }

    /// One `ran <argv>` line per spawn of the fake, in order.
    pub(super) fn marker_lines(&self) -> Vec<String> {
        fs::read_to_string(&self.marker)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    pub(super) fn marker_runs(&self) -> usize {
        self.marker_lines().len()
    }

    /// A valid enrollment of the fake for a window around `now_ms`.
    pub(super) fn enrollment_record(&self, now_ms: u64) -> Value {
        json!({
            "schema": PROVIDER_ENROLLMENT_SCHEMA,
            "provider": "claude",
            "executable": self.executable,
            "executable_blake3": executable_digest(&self.executable).unwrap(),
            "protocol": "claude_stream_json",
            "version": FAKE_VERSION,
            "profile_id": ProfileId::from_seed("claude").as_str(),
            "budget_micro_usd_max": 250_000,
            "valid_from_unix_ms": now_ms.saturating_sub(60_000),
            "valid_until_unix_ms": now_ms + 60_000,
            "enrolled_by": "operator@conformance.test",
        })
    }

    /// Write raw enrollment bytes with the 0600 custody the loader requires.
    pub(super) fn write_enrollment_bytes(&self, bytes: &[u8]) -> PathBuf {
        let path = enrollment_path(&self.data_dir, "claude");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _ = fs::remove_file(&path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    pub(super) fn write_enrollment(&self, value: &Value) -> PathBuf {
        self.write_enrollment_bytes(&serde_json::to_vec(value).unwrap())
    }

    pub(super) fn enroll(&self, now_ms: u64) -> PathBuf {
        self.write_enrollment(&self.enrollment_record(now_ms))
    }
}

fn write_fake(path: &Path, marker: &Path, mode: FakeMode) {
    let version = match mode {
        FakeMode::ProbeCanary => format!("printf '%s\\n' '{EXPOSED_CANARY}'; exit 0"),
        FakeMode::ProbeNonzero => format!("printf '%s\\n' '{FAKE_VERSION_LINE}'; exit 3"),
        _ => format!("printf '%s\\n' '{FAKE_VERSION_LINE}'; exit 0"),
    };
    let turn = match mode {
        FakeMode::Canary => format!("printf '%s\\n' '{EXPOSED_CANARY}'"),
        _ => {
            let tail = match mode {
                FakeMode::NonzeroAfterPong => "exit 7",
                FakeMode::TimeoutAfterPong => "sleep 30",
                _ => "",
            };
            format!(
                "printf '%s%s%s\\n' '{INIT_PREFIX}' \"$PWD\" '{INIT_SUFFIX}'\n\
                 printf '%s\\n' '{ASSISTANT}'\nprintf '%s\\n' '{RESULT}'\n{tail}"
            )
        }
    };
    let script = format!(
        "#!/bin/bash\necho \"ran $*\" >> '{}'\nif [ \"$1\" = --version ]; then\n{version}\nfi\n{turn}\n",
        marker.display()
    );
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

pub(super) fn now() -> DateTime<Utc> {
    Utc.timestamp_millis_opt(NOW_MS as i64).single().unwrap()
}

/// Operator key custody, a live policy at `generation`, and a fresh ledger.
pub(super) struct Prepared {
    pub key: LaunchGrantSigningKey,
    pub policy: LoadedPolicy,
    pub ledger: MemoryLedger,
}

pub(super) fn prepare(harness: &Harness, generation: u64) -> Prepared {
    let key =
        write_new_signing_key(&harness.data_dir, "bullet-kernel", "launch-grant-alpha").unwrap();
    let policy = live_admission_policy(&key, generation).unwrap();
    Prepared {
        key,
        policy,
        ledger: MemoryLedger::new(),
    }
}

/// One run at the deterministic instant on the prepared ledger and policy.
pub(super) fn run_once(
    harness: &Harness,
    prepared: &mut Prepared,
    dispatcher: &dyn LiveDispatcher,
    egress: &dyn EgressBackend,
    options: &LiveConformanceOptions,
) -> Result<LiveConformanceRun, Box<LiveConformanceError>> {
    run_live_conformance(
        &harness.data_dir,
        &mut prepared.ledger,
        &prepared.policy,
        dispatcher,
        egress,
        options,
        now(),
    )
}

pub(super) fn step_status(records: &[LiveStepRecord], step: LiveStep) -> StepStatus {
    records.iter().find(|r| r.step == step).unwrap().status
}

pub(super) fn options(harness: &Harness, canary: &str) -> LiveConformanceOptions {
    LiveConformanceOptions {
        provider: "claude".into(),
        executable: harness.executable.clone(),
        version: FAKE_VERSION.into(),
        profile_email: "claude@conformance.test".into(),
        adapter_label: "claude-stream-json-v1".into(),
        model: "claude-offline-model".into(),
        credential_generation: 1,
        max_cost_micro_usd: 50_000,
        wall_timeout: std::time::Duration::from_secs(20),
        ttl_ms: 15_000,
        issuer: "bullet-kernel".into(),
        key_id: "launch-grant-alpha".into(),
        seed: "live-conformance-test".into(),
        canaries: vec![canary.into()],
    }
}

/// Egress backend whose evidence may report a reached destination and whose
/// `prepare` may rewrite the executable (drift between grant and spawn).
pub(super) struct HostileEgress {
    pub reached: bool,
    pub tamper: Option<PathBuf>,
}

impl EgressBackend for HostileEgress {
    fn sandbox_manifest_digest(&self, _provider: &str) -> Result<String, HarnessError> {
        Ok("a".repeat(64))
    }

    fn prepare(
        &self,
        _provider: &str,
        _workdir: &Path,
    ) -> Result<Box<dyn PreparedEgress + '_>, HarnessError> {
        if let Some(path) = &self.tamper {
            fs::write(path, b"#!/bin/bash\necho tampered\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Ok(Box::new(HostilePrepared {
            reached: self.reached,
        }))
    }
}

struct HostilePrepared {
    reached: bool,
}

impl PreparedEgress for HostilePrepared {
    fn evidence(&self) -> EgressIsolationEvidence {
        let direct = if self.reached {
            EgressProbeOutcome::Reached
        } else {
            EgressProbeOutcome::Refused
        };
        EgressIsolationEvidence {
            receipt_digest: "b".repeat(64),
            ruleset_digest: "c".repeat(64),
            allowlist_digest: "d".repeat(64),
            probes: vec![
                EgressProbe {
                    name: "direct-internet".into(),
                    outcome: direct,
                },
                EgressProbe {
                    name: "host-jeryu".into(),
                    outcome: EgressProbeOutcome::Refused,
                },
            ],
        }
    }

    fn command(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(program);
        command.args(args).env_clear();
        for (key, value) in env {
            command.env(key, value);
        }
        command
    }
}

#[test]
fn v1alpha1_policy_refuses_before_enrollment_key_probe_or_spawn() {
    let harness = Harness::new(FakeMode::Pong);
    harness.enroll(NOW_MS);
    // Deliberately no operator key is created: refusal must precede the key read.
    let policy = LoadedPolicy::from_bytes(V1ALPHA1_POLICY).unwrap();
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
    .expect("policy refusal is a designed, neutral outcome");
    assert_eq!(run.receipt.outcome, LiveOutcome::Refused);
    assert_eq!(
        run.receipt.refusal_reason.as_deref(),
        Some("POLICY_LIVE_ADMISSION_DISABLED")
    );
    assert_eq!(run.receipt.failed_step, Some(LiveStep::Policy));
    assert_eq!(run.receipt.steps.len(), LiveStep::ALL.len());
    for step in LiveStep::ALL.into_iter().skip(1) {
        assert_eq!(step_status(&run.receipt.steps, step), StepStatus::NotRun);
    }
    assert!(run.receipt.enrollment_blake3.is_none());
    assert!(run.grant.is_none() && run.probe_grant.is_none());
    assert_eq!(
        harness.marker_runs(),
        0,
        "the fake binary must never execute"
    );
    assert!(!harness.data_dir.join("authority/launch-grant.key").exists());
    run.receipt.verify().unwrap();
}

#[test]
fn v1alpha2_test_policy_probes_dispatches_pong_and_spends_both_nonces() {
    let harness = Harness::new(FakeMode::Pong);
    harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 7);
    let dispatcher = ObservedClaudeDispatcher::new();
    let egress = NoopEgressBackend::new();
    let run = run_once(
        &harness,
        &mut prepared,
        &dispatcher,
        &egress,
        &options(&harness, HAPPY_CANARY),
    )
    .expect("PONG");
    assert_eq!(run.receipt.outcome, LiveOutcome::Pong);
    assert!(run.receipt.pong_match);
    assert_eq!(run.receipt.response_text.as_deref(), Some("PONG"));
    assert_eq!(run.receipt.policy_generation, Some(7));
    assert_eq!(run.receipt.cost_micro_usd, Some(10_000));
    assert!(run.receipt.grant_id.is_some());
    assert!(run.receipt.egress_receipt_digest.is_some());
    assert!(run.receipt.probe_observation_digest.is_some());
    assert!(run.receipt_path.exists());
    let spawns = harness.marker_lines();
    assert_eq!(
        spawns.len(),
        2,
        "one probe spawn, then one turn: {spawns:?}"
    );
    assert_eq!(spawns[0], "ran --version");
    run.receipt.verify().unwrap();

    // Re-verifying either grant replays its single-use nonce.
    let (grant, vkey) = (run.grant.unwrap(), run.verification_key.unwrap());
    let mut expectation = run.expectation.unwrap();
    let replay = verify_launch_grant(
        &grant,
        &vkey,
        &expectation,
        &mut StoreNonceLedger(&mut prepared.ledger),
    )
    .unwrap_err();
    assert_eq!(replay.reason_code(), "LAUNCH_GRANT_REPLAYED");
    // Tampering the executable afterwards: a fresh observation must not match
    // the grant minted for the original bytes, and nothing else spawns.
    fs::write(&harness.executable, b"#!/bin/bash\necho tampered\n").unwrap();
    fs::set_permissions(&harness.executable, fs::Permissions::from_mode(0o755)).unwrap();
    expectation.provider.executable_digest = executable_digest(&harness.executable).unwrap();
    let error = verify_launch_grant(
        &grant,
        &vkey,
        &expectation,
        &mut StoreNonceLedger(&mut prepared.ledger),
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_SUBJECT_MISMATCH");
    assert_eq!(harness.marker_runs(), 2, "no additional provider spawn");
    let probe = run.probe_grant.unwrap();
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

    for (mode, reason_code) in [
        (FakeMode::NonzeroAfterPong, "PROVIDER_FAILURE"),
        (FakeMode::TimeoutAfterPong, "WALL_CLOCK_TIMEOUT"),
    ] {
        let hostile = Harness::new(mode);
        hostile.enroll(NOW_MS);
        let mut prepared = prepare(&hostile, 8);
        let mut hostile_options = options(&hostile, HAPPY_CANARY);
        hostile_options.wall_timeout = std::time::Duration::from_secs(1);
        let error = run_once(
            &hostile,
            &mut prepared,
            &dispatcher,
            &egress,
            &hostile_options,
        )
        .expect_err("a terminal PONG cannot override process failure");
        assert_eq!(error.reason_code(), reason_code);
        assert_eq!(error.step, LiveStep::Dispatch);
        assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
        assert!(!error.receipt.pong_match);
        error.receipt.verify().unwrap();
    }
}

#[test]
fn egress_evidence_that_reached_a_destination_blocks_the_probe_and_dispatch() {
    let harness = Harness::new(FakeMode::Pong);
    harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 5);
    let egress = HostileEgress {
        reached: true,
        tamper: None,
    };
    let error = run_once(
        &harness,
        &mut prepared,
        &ObservedClaudeDispatcher::new(),
        &egress,
        &options(&harness, HAPPY_CANARY),
    )
    .expect_err("reached egress must fail closed");
    assert_eq!(error.reason_code(), "PROBE_CONTAINMENT_UNPROVEN");
    assert_eq!(error.step, LiveStep::ProbeContainment);
    assert!(error.detail.contains("direct-internet"));
    assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
    assert_eq!(
        step_status(&error.receipt.steps, LiveStep::ProbeGrant),
        StepStatus::Pass
    );
    assert!(error.receipt.probe_containment_receipt_digest.is_none());
    assert_eq!(harness.marker_runs(), 0, "no spawn once egress is unproven");
    error.receipt.verify().unwrap();
}

#[test]
fn a_canary_in_provider_output_fails_the_run() {
    let harness = Harness::new(FakeMode::Canary);
    harness.enroll(NOW_MS);
    let mut prepared = prepare(&harness, 9);
    let error = run_once(
        &harness,
        &mut prepared,
        &ObservedClaudeDispatcher::new(),
        &NoopEgressBackend::new(),
        &options(&harness, EXPOSED_CANARY),
    )
    .expect_err("canary exposure must fail the run");
    assert_eq!(error.reason_code(), "SECRET_CANARY_EXPOSURE");
    assert_eq!(error.step, LiveStep::CanaryScan);
    assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
    assert!(!error.receipt.pong_match);
    assert_eq!(
        harness.marker_runs(),
        2,
        "the clean probe ran, then the turn"
    );
    error.receipt.verify().unwrap();
}
