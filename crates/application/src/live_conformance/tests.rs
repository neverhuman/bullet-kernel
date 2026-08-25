//! Full-path live-conformance tests. No real provider binary is spawned: a
//! fake `claude` shell script emits a canned stream-JSON transcript. The
//! v1alpha2 test policy is loaded through the production loader (no bypass);
//! a no-op egress backend supplies well-formed containment evidence. The
//! fake-binary harness is shared with `policy_tests`.

use super::egress::NoopEgressBackend;
use super::seam::live_admission_policy;
use super::{run_live_conformance, LiveConformanceOptions};
use crate::launch_grant::StoreNonceLedger;
use crate::memory::MemoryLedger;
use crate::policy_snapshot::LoadedPolicy;
use bullet_harness_claude::ClaudeAdapter;
use bullet_harness_core::launch_grant::{verify_launch_grant, write_new_signing_key};
use bullet_harness_core::{
    EgressBackend, EgressIsolationEvidence, EgressProbe, EgressProbeOutcome, HarnessError,
    LiveOutcome, LiveStep, PreparedEgress,
};
use chrono::{DateTime, TimeZone, Utc};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const V1ALPHA1_POLICY: &[u8] = include_bytes!("../../tests/fixtures/policy-v1alpha1.json");
pub(super) const HAPPY_CANARY: &str = "bullet-conformance-canary-happy-0001";
const EXPOSED_CANARY: &str = "bullet-conformance-canary-exposed-e2e-0001";

const INIT_PREFIX: &str = r#"{"type":"system","subtype":"init","uuid":"00000000-0000-4000-8000-000000000002","session_id":"00000000-0000-4000-8000-000000000001","apiKeySource":"none","claude_code_version":"2.1.243","cwd":""#;
const INIT_SUFFIX: &str = r#"","tools":["Read","Glob","Grep"],"mcp_servers":[],"model":"claude-offline-model","permissionMode":"plan","slash_commands":[],"output_style":"default","agents":[],"skills":[],"plugins":[],"analytics_disabled":true,"product_feedback_disabled":true}"#;
const ASSISTANT: &str = r#"{"type":"assistant","uuid":"00000000-0000-4000-8000-000000000003","session_id":"00000000-0000-4000-8000-000000000001","parent_tool_use_id":null,"message":{"id":"msg-000000000003","type":"message","role":"assistant","model":"claude-offline-model","content":[{"type":"text","text":"PONG"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":5}}}"#;
const RESULT: &str = r#"{"type":"result","subtype":"success","uuid":"00000000-0000-4000-8000-000000000004","session_id":"00000000-0000-4000-8000-000000000001","duration_ms":20,"duration_api_ms":10,"is_error":false,"num_turns":1,"result":"PONG","stop_reason":"end_turn","total_cost_usd":0.01,"usage":{"input_tokens":10,"output_tokens":5},"modelUsage":{"claude-offline-model":{"inputTokens":10,"outputTokens":5}},"permission_denials":[],"structured_output":{"schema_version":1,"proposal_id":"cnt_1111111111111111111111111111111111111111111111111111111111111111","producing_attempt_id":"atm_2222222222222222222222222222222222222222222222222222222222222222","base_checkpoint_id":"ckp_3333333333333333333333333333333333333333333333333333333333333333","base_checkpoint_digest":"4444444444444444444444444444444444444444444444444444444444444444","operations":[{"path":"PONG.txt","preimage":{"kind":"absent"},"mutation":{"kind":"write","content_utf8":"PONG\n"}}],"gate_ids":["gat_9999999999999999999999999999999999999999999999999999999999999999"],"intent_summary":"pong","claims":[],"uncertainties":[],"done":true},"terminal_reason":"completed"}"#;

pub(super) enum FakeMode {
    Pong,
    Canary,
}

pub(super) struct Harness {
    _root: TempDir,
    pub(super) data_dir: std::path::PathBuf,
    pub(super) executable: std::path::PathBuf,
    marker: std::path::PathBuf,
}

impl Harness {
    pub(super) fn new(mode: FakeMode) -> Self {
        let root = TempDir::new().unwrap();
        let base = root.path().canonicalize().unwrap();
        let data_dir = base.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let bin_dir = base.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
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

    pub(super) fn marker_runs(&self) -> usize {
        fs::read_to_string(&self.marker)
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }
}

fn write_fake(path: &Path, marker: &Path, mode: FakeMode) {
    let mut script = String::from("#!/bin/bash\n");
    script.push_str("echo ran >> '");
    script.push_str(&marker.display().to_string());
    script.push_str("'\n");
    match mode {
        FakeMode::Pong => {
            script.push_str("printf '%s%s%s\\n' '");
            script.push_str(INIT_PREFIX);
            script.push_str("' \"$PWD\" '");
            script.push_str(INIT_SUFFIX);
            script.push_str("'\n");
            script.push_str("printf '%s\\n' '");
            script.push_str(ASSISTANT);
            script.push_str("'\n");
            script.push_str("printf '%s\\n' '");
            script.push_str(RESULT);
            script.push_str("'\n");
        }
        FakeMode::Canary => {
            script.push_str("printf '%s\\n' '");
            script.push_str(EXPOSED_CANARY);
            script.push_str("'\n");
        }
    }
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn now() -> DateTime<Utc> {
    Utc.timestamp_millis_opt(1_000).single().unwrap()
}

pub(super) fn options(harness: &Harness, canary: &str) -> LiveConformanceOptions {
    LiveConformanceOptions {
        provider: "claude".into(),
        executable: harness.executable.clone(),
        version: "2.1.243".into(),
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

fn operator_key(data_dir: &Path) -> bullet_harness_core::launch_grant::LaunchGrantSigningKey {
    write_new_signing_key(data_dir, "bullet-kernel", "launch-grant-alpha").unwrap()
}

#[test]
fn v1alpha1_policy_refuses_before_key_probe_or_spawn() {
    let harness = Harness::new(FakeMode::Pong);
    // Deliberately no operator key is created: refusal must precede the key read.
    let policy = LoadedPolicy::from_bytes(V1ALPHA1_POLICY).unwrap();
    let mut ledger = MemoryLedger::new();
    let egress = NoopEgressBackend::new();
    let run = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &egress,
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
    assert!(run.grant.is_none());
    assert_eq!(
        harness.marker_runs(),
        0,
        "the fake binary must never execute"
    );
    assert!(!harness.data_dir.join("authority/launch-grant.key").exists());
    run.receipt.verify().unwrap();
}

#[test]
fn v1alpha2_test_policy_dispatches_pong_and_consumes_the_nonce() {
    let harness = Harness::new(FakeMode::Pong);
    let key = operator_key(&harness.data_dir);
    let policy = live_admission_policy(&key, 7).unwrap();
    let mut ledger = MemoryLedger::new();
    let egress = NoopEgressBackend::new();
    let run = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &egress,
        &options(&harness, HAPPY_CANARY),
        now(),
    )
    .expect("PONG");
    assert_eq!(run.receipt.outcome, LiveOutcome::Pong);
    assert!(run.receipt.pong_match);
    assert_eq!(run.receipt.response_text.as_deref(), Some("PONG"));
    assert_eq!(run.receipt.policy_generation, Some(7));
    assert_eq!(run.receipt.cost_micro_usd, Some(10_000));
    assert!(run.receipt.grant_id.is_some());
    assert!(run.receipt.egress_receipt_digest.is_some());
    assert!(run.receipt_path.exists());
    assert_eq!(harness.marker_runs(), 1, "exactly one provider spawn");
    run.receipt.verify().unwrap();

    // Second verification of the same grant replays the single-use nonce.
    let grant = run.grant.unwrap();
    let expectation = run.expectation.unwrap();
    let key = run.verification_key.unwrap();
    let replay = verify_launch_grant(
        &grant,
        &key,
        &expectation,
        &mut StoreNonceLedger(&mut ledger),
    )
    .unwrap_err();
    assert_eq!(replay.reason_code(), "LAUNCH_GRANT_REPLAYED");
}

#[test]
fn a_tampered_executable_never_verifies_and_never_dispatches() {
    let harness = Harness::new(FakeMode::Pong);
    let key = operator_key(&harness.data_dir);
    let policy = live_admission_policy(&key, 3).unwrap();
    let mut ledger = MemoryLedger::new();
    let egress = NoopEgressBackend::new();
    let run = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &egress,
        &options(&harness, HAPPY_CANARY),
        now(),
    )
    .expect("PONG");
    assert_eq!(harness.marker_runs(), 1);

    // Tamper the executable after minting; a fresh observation must not match
    // the grant that was minted for the original bytes.
    fs::write(&harness.executable, b"#!/bin/bash\necho tampered\n").unwrap();
    fs::set_permissions(&harness.executable, fs::Permissions::from_mode(0o755)).unwrap();
    let fresh = bullet_harness_core::executable_digest(&harness.executable).unwrap();
    let mut expectation = run.expectation.unwrap();
    expectation.provider.executable_digest = fresh;
    let grant = run.grant.unwrap();
    let vkey = run.verification_key.unwrap();
    let error = verify_launch_grant(
        &grant,
        &vkey,
        &expectation,
        &mut StoreNonceLedger(&mut ledger),
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_SUBJECT_MISMATCH");
    assert_eq!(harness.marker_runs(), 1, "no additional provider spawn");
}

#[test]
fn egress_evidence_that_reached_a_destination_blocks_dispatch() {
    let harness = Harness::new(FakeMode::Pong);
    let key = operator_key(&harness.data_dir);
    let policy = live_admission_policy(&key, 5).unwrap();
    let mut ledger = MemoryLedger::new();
    let egress = ReachedEgressBackend;
    let error = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &egress,
        &options(&harness, HAPPY_CANARY),
        now(),
    )
    .expect_err("reached egress must fail closed");
    assert_eq!(error.reason_code(), "ADMISSION_REFUSED");
    assert_eq!(error.step, LiveStep::AdmitEgress);
    assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
    assert_eq!(harness.marker_runs(), 0, "no spawn once egress is unproven");
    error.receipt.verify().unwrap();
}

#[test]
fn a_canary_in_provider_output_fails_the_run() {
    let harness = Harness::new(FakeMode::Canary);
    let key = operator_key(&harness.data_dir);
    let policy = live_admission_policy(&key, 9).unwrap();
    let mut ledger = MemoryLedger::new();
    let egress = NoopEgressBackend::new();
    let error = run_live_conformance(
        &harness.data_dir,
        &mut ledger,
        &policy,
        &ClaudeAdapter::new(),
        &egress,
        &options(&harness, EXPOSED_CANARY),
        now(),
    )
    .expect_err("canary exposure must fail the run");
    assert_eq!(error.reason_code(), "SECRET_CANARY_EXPOSURE");
    assert_eq!(error.step, LiveStep::CanaryScan);
    assert_eq!(error.receipt.outcome, LiveOutcome::Failed);
    assert!(!error.receipt.pong_match);
    error.receipt.verify().unwrap();
}

/// Egress backend whose evidence reports a destination was reached; admission
/// must retain the egress blocker.
struct ReachedEgressBackend;

impl EgressBackend for ReachedEgressBackend {
    fn sandbox_manifest_digest(&self, _provider: &str) -> Result<String, HarnessError> {
        Ok("a".repeat(64))
    }

    fn prepare(
        &self,
        _provider: &str,
        _workdir: &Path,
    ) -> Result<Box<dyn PreparedEgress + '_>, HarnessError> {
        Ok(Box::new(ReachedPrepared))
    }
}

struct ReachedPrepared;

impl PreparedEgress for ReachedPrepared {
    fn evidence(&self) -> EgressIsolationEvidence {
        EgressIsolationEvidence {
            receipt_digest: "b".repeat(64),
            ruleset_digest: "c".repeat(64),
            allowlist_digest: "d".repeat(64),
            probes: vec![
                EgressProbe {
                    name: "direct-internet".into(),
                    outcome: EgressProbeOutcome::Reached,
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
