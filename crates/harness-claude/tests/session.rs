//! ADAPT-1a/R2: `ClaudeSession` through the crate's PUBLIC surface only.
//! `session.rs` is no longer `#[path]`-included, so every privacy claim proved
//! here is the shipped one: outside this crate `send` is the only way to get a
//! `TurnRecord`. No provider CLI is ever spawned — the command factory is a
//! `/bin/sh` fake replaying a tempdir transcript, and the argv it is handed is
//! asserted to be the frozen read-only one; the compile-fail doctests in
//! `session.rs`/`session/turn.rs` carry the rest. Dense fixtures and packed
//! bodies are `#[rustfmt::skip]` to fit the proof in one 500-line file.
#![cfg(unix)]
#![recursion_limit = "256"]

use bullet_domain::{Observation, ProfileId};
use bullet_harness_claude::*;
use bullet_harness_core::*;
use serde_json::{from_value, json, Value};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::TempDir;

type Res<T> = Result<T, SessionError>;
/// One hostile edit to an admitted config, plus the caller's clock.
type Bend = fn(&mut SessionConfig, &mut u64);

const NATIVE: &str = "00000000-0000-4000-8000-000000000001";
const SESSION: &str = "kernel-session-1";
const VERSION: &str = "offline-1.0.0";
const EMAIL: &str = "claude@offline.invalid";
const MALFORMED: &str = "SESSION_TRANSCRIPT_MALFORMED";
const UNCONFIRMED: &str = "SESSION_KILL_UNCONFIRMED";
const NOW: u64 = 1_800_000_000_000;
const EXPIRES: u64 = NOW + 10_000;
const BUDGET: u64 = 10_000;
const GRANT_BUDGET: u64 = 20_000;
const INVOCATIONS: u64 = 6;
const COST: f64 = 0.002;
const WALL_MS: u64 = 5_000;
const CANARY: &str = "bullet-host-canary-7f2d9b61";
const FROZEN: &str =
    "--output-format stream-json --verbose --permission-mode plan --max-budget-usd";

/// `BULLET_PROVIDER_KILL` is process-global; every dispatching test takes it.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[rustfmt::skip]
fn hex(ch: char) -> String { ch.to_string().repeat(64) }

#[rustfmt::skip]
fn gate() -> String { format!("gat_{}", hex('8')) }

#[rustfmt::skip]
fn canaries() -> CanarySecrets { CanarySecrets::new(vec![CANARY.into()]).unwrap() }

#[rustfmt::skip]
fn executable() -> PathBuf { std::env::current_exe().unwrap().canonicalize().unwrap() }

/// A locally evaluated admission whose only remaining blockers are the two
/// that signed authority and egress evidence clear. `conformant = false`
/// keeps a capability blocker no evidence in this lane can clear.
#[rustfmt::skip]
fn evaluated(root: &Path, conformant: bool) -> EvaluatedAdmission {
    let (executable, ok) = (executable(), CapabilityState::Supported);
    let mut capabilities = CapabilityMatrix::new()
        .with(Capability::StructuredOutputSchema, ok)
        .with(Capability::HeadlessMode, ok).with(Capability::MultilinePrompt, ok);
    if conformant { capabilities.set(Capability::StructuredEvents, ok); }
    let descriptor = HarnessDescriptor {
        provider: "claude".into(), stage: PromotionStage::ContractPass, capabilities,
        binary: executable.file_name().unwrap().to_string_lossy().into(),
        version: Observation::value(VERSION.into()),
    };
    let profile = json!({"profile_id": ProfileId::from_seed("claude"),
        "expected": {"email": EMAIL, "account_id_prefix": null}});
    let policy = ProviderAdmissionPolicy {
        provider: "claude".into(), version: VERSION.into(), executable: executable.clone(),
        executable_blake3: executable_digest(&executable).unwrap(),
        descriptor_blake3: descriptor_digest(&descriptor).unwrap(),
        profile: from_value(profile).unwrap(), max_probe_age_seconds: 60,
        required_protocol: ProviderProtocol::ClaudeStreamJson,
        runtime_root: root.to_path_buf(), credential_targets: vec![], credentials: vec![],
    };
    let mut normalizer = EventNormalizer::new(AgentSessionId::new("offline"), "claude");
    let mut emit = |kind| normalizer.accept(kind, json!({}), &NativeMeta::none());
    let events = [emit(AgentEventKind::TurnStarted), emit(AgentEventKind::TurnCompleted)];
    // A `DateTime<Utc>` without a direct chrono dependency.
    let now = events[0].timestamp;
    let probe: RuntimeProbeSnapshot = from_value(json!({
        "descriptor": descriptor, "executable": executable, "observed_at": now,
        "executable_blake3": policy.executable_blake3, "protocol": "claude_stream_json",
        "identity": {"version": VERSION, "profile": {"kind": "value", "value": {
            "provider": "claude", "email": EMAIL, "account_id": null, "subscription": null,
            "auth_method": "oauth"}}}})).unwrap();
    let proposal = PatchProposal::from_value(&proposal_value()).unwrap();
    let env = vec![("LANG".to_string(), "C.UTF-8".to_string())];
    ProviderAdmission::prepare(policy, probe, env, canaries(), now).unwrap()
        .finalize(ConformanceEvidence {
            stdout: b"offline", stderr: b"", events: &events, proposal: &proposal })
        .unwrap()
}

#[rustfmt::skip]
fn claims_for(admission: &EvaluatedAdmission, budget: u64, invocations: u64) -> LaunchGrantClaims {
    let r = admission.receipt();
    let id = |prefix: &str, ch: char| format!("{prefix}_{}", hex(ch));
    from_value(json!({
        "schema_version": "v1alpha1", "grant_id": hex('1'), "audience": "provider-runner",
        "operation": "launch-provider", "issuer": "bullet-kernel", "key_id": "launch-grant-alpha",
        "issued_at_unix_ms": NOW, "not_before_unix_ms": NOW, "expires_at_unix_ms": EXPIRES,
        "grant_nonce": hex('2'), "mission_id": id("mis", '5'), "repository_id": id("rep", '4'),
        "graph_revision_id": id("grf", '8'), "work_package_id": id("wpk", 'a'),
        "variant_id": id("var", 'c'), "attempt_id": id("atm", 'd'), "attempt_fence": 1,
        "runner_id": id("run", 'e'), "runner_epoch": 1, "workspace_id": id("wsp", 'f'),
        "workspace_nonce_digest": hex('3'), "authority_epoch": 1, "freeze_generation": 0,
        "provider": r.provider, "adapter": "claude-stream-json-v1", "model": "claude-test",
        "provider_profile_id": r.profile_id, "credential_generation": 1,
        "protocol": r.current_protocol.as_str(), "executable_path": r.executable,
        "executable_digest": r.executable_blake3, "descriptor_digest": r.descriptor_blake3,
        "capability_digest": r.capability_blake3, "policy_snapshot_digest": hex('6'),
        "policy_generation": 2, "sandbox_manifest_digest": hex('7'), "gate_ids": [gate()],
        "environment_digest": environment_digest(admission.child_env()).unwrap(),
        "budget_reservation_id": hex('9'), "max_wall_clock_ms": 60_000,
        "max_invocations": invocations, "max_cost_micro_usd": budget})).expect("grant claims")
}

/// Clone the identically-named claim fields into one binding.
macro_rules! bind {
    ($c:ident, $t:ident { $($f:ident),* $(,)? } $($k:ident: $v:expr),*) => {
        $t { $($f: $c.$f.clone(),)* $($k: $v),* }
    };
}

#[rustfmt::skip]
fn expectation_for(c: &LaunchGrantClaims) -> LaunchGrantExpectation {
    let lease = bind!(c, LeaseBinding { mission_id, repository_id, graph_revision_id,
        work_package_id, variant_id, attempt_id, attempt_fence, runner_id, runner_epoch,
        workspace_id, workspace_nonce_digest, authority_epoch, freeze_generation });
    let provider = bind!(c, ProviderBinding { provider, adapter, provider_profile_id, model,
        credential_generation, executable_path, executable_digest, descriptor_digest,
        capability_digest, sandbox_manifest_digest, environment_digest }
        protocol: ProviderProtocol::ClaudeStreamJson);
    let policy = bind!(c, PolicyBinding { policy_snapshot_digest, policy_generation }
        live_admission_enabled: true);
    LaunchGrantExpectation { now_unix_ms: c.not_before_unix_ms, lease, provider, policy }
}

/// The signed grant is verified once (its nonce is single-use) and then spent
/// by `require`, the only path to the handle. Failures keep their code.
#[rustfmt::skip]
fn mint(admission: EvaluatedAdmission, budget: u64, invocations: u64, reached: bool)
    -> Result<DispatchCleared, String> {
    let key = LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap();
    let claims = claims_for(&admission, budget, invocations);
    let grant = key.sign(&claims).unwrap();
    let mut ledger = MemoryNonceLedger::new();
    ledger.register(&claims.grant_nonce, &claims.attempt_id, claims.expires_at_unix_ms);
    let verification = key.verification_key().unwrap();
    let verified = verify_launch_grant(&grant, &verification, &expectation_for(&claims),
        &mut ledger).unwrap();
    let egress: EgressIsolationEvidence = from_value(json!({
        "receipt_digest": hex('a'), "ruleset_digest": hex('b'), "allowlist_digest": hex('c'),
        "probes": [{"name": "direct-internet", "outcome": "Unreachable"},
            {"name": "host-jeryu", "outcome": if reached { "Reached" } else { "Refused" }}]}))
    .unwrap();
    DispatchCleared::require(admission, verified, egress).map_err(|error| {
        assert_ne!(error.reason_code(), "UNKNOWN");
        format!("{}|{error}", error.reason_code())
    })
}

#[rustfmt::skip]
fn cleared(root: &Path, n: u64) -> DispatchCleared {
    mint(evaluated(root, true), GRANT_BUDGET, n, false).expect("cleared handle")
}

#[rustfmt::skip]
fn config(workdir: &Path, wall_ms: u64) -> SessionConfig {
    SessionConfig {
        session_id: AgentSessionId::new(SESSION), workdir: workdir.to_path_buf(),
        gate_ids: vec![gate()], max_cost_micro_usd: BUDGET, canaries: canaries(),
        wall_timeout: Duration::from_millis(wall_ms),
    }
}

#[rustfmt::skip]
fn proposal_value() -> Value {
    json!({"schema_version": 1, "proposal_id": format!("cnt_{}", hex('1')),
        "producing_attempt_id": format!("atm_{}", hex('2')), "base_checkpoint_digest": hex('4'),
        "base_checkpoint_id": format!("ckp_{}", hex('3')), "gate_ids": [gate()], "claims": [],
        "intent_summary": "write fixture", "uncertainties": [], "done": true,
        "operations": [{"path": "PONG.txt", "preimage": {"kind": "absent"},
            "mutation": {"kind": "write", "content_utf8": "PONG\n"}}]})
}

#[rustfmt::skip]
fn init_event(cwd: &Path) -> Value {
    json!({"type": "system", "subtype": "init", "session_id": NATIVE, "cwd": cwd.to_string_lossy(),
        "uuid": "00000000-0000-4000-8000-000000000002", "apiKeySource": "offline-fixture",
        "claude_code_version": OBSERVED_CLAUDE_SCHEMA_VERSION, "mcp_servers": [], "agents": [],
        "tools": ["Read", "Glob", "Grep"], "model": "claude-offline-model", "plugins": [],
        "permissionMode": "plan", "slash_commands": [], "output_style": "default", "skills": [],
        "analytics_disabled": true, "product_feedback_disabled": true})
}

#[rustfmt::skip]
fn assistant_event() -> Value {
    json!({"type": "assistant", "uuid": "00000000-0000-4000-8000-000000000003",
        "session_id": NATIVE, "parent_tool_use_id": null, "message": {"id": "msg-1",
            "type": "message", "role": "assistant", "model": "claude-offline-model",
            "content": [{"type": "text", "text": "x"}], "stop_reason": "end_turn",
            "stop_sequence": null, "usage": {"input_tokens": 10, "output_tokens": 5}}})
}

/// `None` is a valid `error_max_turns` failure terminal without a proposal.
#[rustfmt::skip]
fn result_event(structured_output: Option<Value>, cost_usd: f64) -> Value {
    let mut result = json!({"type": "result", "subtype": "success", "session_id": NATIVE,
        "uuid": "00000000-0000-4000-8000-000000000004", "duration_ms": 20, "num_turns": 1,
        "duration_api_ms": 10, "is_error": false, "result": "untrusted text result",
        "stop_reason": "end_turn", "total_cost_usd": cost_usd, "permission_denials": [],
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "modelUsage": {"claude-offline-model": {"inputTokens": 10, "outputTokens": 5}}});
    if let Some(output) = structured_output { result["structured_output"] = output; return result; }
    for (key, value) in [("subtype", json!("error_max_turns")), ("is_error", json!(true)),
        ("stop_reason", Value::Null), ("errors", json!(["max turns"]))] { result[key] = value; }
    result.as_object_mut().unwrap().remove("result");
    result
}

#[rustfmt::skip]
fn lines(frames: &[Value]) -> Vec<String> { frames.iter().map(Value::to_string).collect() }

#[rustfmt::skip]
fn terminal(cwd: &Path, output: Option<Value>, cost_usd: f64) -> Vec<String> {
    lines(&[init_event(cwd), assistant_event(), result_event(output, cost_usd)])
}

/// Every refusal is typed, never `UNKNOWN`, and displays its code first.
#[rustfmt::skip]
fn refused<T: std::fmt::Debug>(result: Res<T>, expected: &str) -> SessionError {
    let error = result.expect_err("typed refusal");
    assert_eq!(error.reason_code(), expected, "{error}");
    assert!(expected != "UNKNOWN" && error.to_string().starts_with(expected));
    error
}

/// One admitted session plus the tempdir its workspace and transcripts live
/// in. Nothing here can reach a private item of the crate under test.
#[rustfmt::skip]
struct Live { root: PathBuf, argv: Arc<Mutex<Vec<String>>>, session: ClaudeSession, _dir: TempDir }

impl Live {
    #[rustfmt::skip]
    fn new(invocations: u64, wall_ms: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let config = config(&root, wall_ms);
        let mut session = ClaudeSession::new(cleared(&root, invocations), config, NOW).unwrap();
        session.start().expect("start");
        Self { root, argv: Arc::new(Mutex::new(Vec::new())), session, _dir: dir }
    }

    /// Replay `stdout` from a `/bin/sh` fake, then run `tail` (`exit 3`,
    /// `/bin/sleep 3`, …). The admitted program is asserted and never run.
    #[rustfmt::skip]
    fn dispatch(&mut self, stdout: &[String], tail: &str, now: u64) -> Res<TurnRecord> {
        let file = self.root.join("turn.jsonl");
        std::fs::write(&file, stdout.join("\n") + "\n").unwrap();
        let script = format!("/bin/cat {}\n{tail}\n", file.display());
        let argv = Arc::clone(&self.argv);
        let factory = |program: &str, args: &[&str], env: &[(&str, &str)]| -> Command {
            assert!(Path::new(program) == executable(), "argv names the admitted program");
            let mut seen = vec![program.to_string()];
            seen.extend(args.iter().map(|arg| (*arg).to_string()));
            *argv.lock().unwrap() = seen;
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg(&script).env_clear().process_group(0);
            command.envs(env.iter().copied());
            command
        };
        self.session.send(&factory, "produce the admitted proposal", now)
    }

    #[rustfmt::skip]
    fn happy(&mut self, cost_usd: f64, now: u64) -> Res<TurnRecord> {
        let stdout = terminal(&self.root.clone(), Some(proposal_value()), cost_usd);
        self.dispatch(&stdout, "", now)
    }

    #[rustfmt::skip]
    fn empty(&self) -> bool { self.session.turns().is_empty() && self.session.events().is_empty() }
}

#[test] #[rustfmt::skip]
fn only_a_dispatch_cleared_admission_and_a_bounded_config_make_a_session() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    // Only a complete clearing mints the handle: a surviving capability blocker
    // and unproven containment both refuse, and neither refusal is UNKNOWN.
    let blocked = mint(evaluated(&root, false), GRANT_BUDGET, INVOCATIONS, false).unwrap_err();
    assert!(blocked.starts_with("PROVIDER_ADMISSION_BLOCKED|"), "{blocked}");
    assert!(blocked.contains("CAPABILITY_NONCONFORMANT"), "{blocked}");
    let reached = mint(evaluated(&root, true), GRANT_BUDGET, INVOCATIONS, true).unwrap_err();
    assert!(reached.starts_with("ADMISSION_REFUSED|"), "{reached}");
    let make: fn(DispatchCleared, SessionConfig, u64) -> Res<ClaudeSession> = ClaudeSession::new;
    let mut session = make(cleared(&root, INVOCATIONS), config(&root, WALL_MS), NOW).unwrap();
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&session);
    refused(session.interrupt(), "SESSION_NOT_STARTED");
    refused(session.begin_turn("x"), "SESSION_NOT_STARTED");
    assert!(session.turns().is_empty() && session.phase() == SessionPhase::Created);
    // Config bounds first, then the bounds of the grant that cleared the handle.
    let cases: [(&str, Bend); 9] = [
        ("ADMISSION_REFUSED", |c, _| c.max_cost_micro_usd = 0),
        ("ADMISSION_REFUSED", |c, _| c.session_id = AgentSessionId::new("x".repeat(97))),
        ("PROTOCOL_ERROR", |c, _| c.session_id = AgentSessionId::new("bad id")),
        ("PROTOCOL_ERROR", |c, _| c.workdir = PathBuf::from("relative/dir")),
        ("PROPOSAL_PARSE_FAILED", |c, _| c.gate_ids = vec![]),
        ("SESSION_GATE_MISMATCH", |c, _| c.gate_ids = vec![format!("gat_{}", hex('7'))]),
        ("SESSION_BUDGET_EXCEEDED", |c, _| c.max_cost_micro_usd = GRANT_BUDGET + 1),
        ("SESSION_WALL_BOUND_EXCEEDED", |c, _| c.wall_timeout = Duration::from_secs(61)),
        ("SESSION_AUTHORITY_EXPIRED", |_, now| *now = EXPIRES),
    ];
    for (expected, mutate) in cases {
        let (mut bad, mut now) = (config(&root, WALL_MS), NOW);
        mutate(&mut bad, &mut now);
        refused(ClaudeSession::new(cleared(&root, INVOCATIONS), bad, now), expected);
    }
}

#[test] #[rustfmt::skip]
fn start_freezes_the_launch_record_and_send_refuses_at_the_kill_switch() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    let record = live.session.start().expect("start is idempotent");
    assert_eq!(live.session.phase(), SessionPhase::Started);
    assert_eq!(record.fixed_args, FROZEN.split(' ').chain(["0.010000"]).collect::<Vec<_>>());
    assert_eq!((record.workspace, record.program), (live.root.clone(), executable()));
    assert_eq!(record.wall_timeout, Duration::from_millis(WALL_MS));
    let keys = "HOME LANG TMPDIR XDG_CACHE_HOME XDG_CONFIG_HOME".split(' ');
    assert_eq!(record.env_keys, keys.collect::<Vec<_>>());
    assert!(live.session.events().is_empty(), "start fabricates no envelope");
    std::env::set_var("BULLET_PROVIDER_KILL", "1");
    let killed = live.happy(COST, NOW);
    std::env::remove_var("BULLET_PROVIDER_KILL");
    refused(killed, "PROVIDER_KILL_ACTIVE");
    assert!(live.empty() && live.session.phase() == SessionPhase::Started);
    assert!(live.argv.lock().unwrap().is_empty(), "the kill switch refuses pre-spawn");
    let ticket = live.session.begin_turn("next").unwrap();
    assert_eq!(live.session.request(&ticket).max_budget_usd(), "0.010000");
    assert_eq!(ticket.turn(), 2);
}

#[test] #[rustfmt::skip]
fn one_recorded_turn_yields_exactly_one_proposal() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    let record = live.happy(COST, NOW).expect("one dispatched turn");
    assert_eq!(live.session.phase(), SessionPhase::Started);
    assert_eq!((record.turn(), record.exit_code()), (1, Some(0)));
    assert!(!record.timed_out() && record.cost_micro_usd() == 2_000);
    assert_eq!(record.invocation_id().as_str(), "kernel-session-1.t1");
    assert_eq!(record.proposal().gate_ids, [gate()]);
    assert_eq!(record.proposal().operations[0].path, "PONG.txt");
    let kinds: Vec<&str> = record.events().iter().map(|e| e.kind.as_str()).collect();
    let expected = "session.identity session.ready turn.started turn.delta usage.reported";
    assert_eq!(kinds, expected.split(' ').chain(["turn.completed"]).collect::<Vec<_>>());
    assert!(record.events().iter().all(|event| event.session_id.as_str() == SESSION
        && event.invocation_id.as_ref() == Some(record.invocation_id())
        && event.native_session_id.as_deref() == Some(NATIVE)));
    assert_eq!(live.session.events(), record.events());
    assert_eq!(live.session.turns(), [record]);
    // The child saw exactly the frozen read-only argv, prompt included once.
    let argv = live.argv.lock().unwrap().join(" ");
    let expected = format!("{} -p produce the admitted proposal {FROZEN} 0.010000",
        executable().display());
    assert_eq!(argv, expected);
    let second = live.happy(COST, NOW).expect("second dispatched turn");
    assert_eq!((second.turn(), live.session.turns().len()), (2, 2));
}

#[test] #[rustfmt::skip]
fn ambiguous_misplaced_or_absent_proposals_never_become_a_turn() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    // Ambiguity and misplacement cannot be expressed from outside the crate: a
    // session only sees envelopes it parsed itself (the `session/turn.rs` unit
    // tests cover those arms), so the reachable case is an absent proposal.
    let stdout = terminal(&live.root.clone(), None, COST);
    let error = live.dispatch(&stdout, "", NOW).unwrap_err();
    assert_eq!(error, SessionError::NoProposal { turn: 1 });
    refused(Err::<(), _>(error), "SESSION_NO_PROPOSAL");
    assert!(live.empty() && live.session.phase() == SessionPhase::Started);
    let stdout = terminal(&live.root.clone(), Some(json!({"changes": []})), COST);
    let error = refused(live.dispatch(&stdout, "", NOW), MALFORMED);
    assert!(error.to_string().contains("PatchProposal invalid"), "{error}");
    assert!(live.empty());
}

#[test] #[rustfmt::skip]
fn malformed_transcripts_and_out_of_bounds_proposals_are_typed_refusals() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    let root = live.root.clone();
    let (mut too_many, mut huge) = (proposal_value(), proposal_value());
    too_many["operations"] = Value::Array(vec![too_many["operations"][0].clone(); 1_025]);
    huge["operations"][0]["mutation"]["content_utf8"] = json!("x".repeat(1_048_577));
    let cases = [
        (vec!["not-json".to_string()], MALFORMED, "malformed stream-JSON"),
        (lines(&[init_event(&root), assistant_event()]), MALFORMED, "no complete terminal"),
        (terminal(&root, Some(too_many), COST), MALFORMED, "operations"),
        (terminal(&root, Some(huge), COST), "IO_FAILED", "frame exceeds byte limit"),
    ];
    for (index, (stdout, code, detail)) in cases.into_iter().enumerate() {
        let rendered = refused(live.dispatch(&stdout, "", NOW), code).to_string();
        assert!(rendered.contains(detail), "{rendered}");
        assert!(code != MALFORMED || rendered.contains(&format!("turn {}", index + 1)));
        assert_eq!(live.session.phase(), SessionPhase::Started);
    }
    assert!(live.empty());
}

#[test] #[rustfmt::skip]
fn interrupt_and_terminate_are_idempotent_and_later_operations_are_typed() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    live.session.begin_turn("p").unwrap();
    assert!(live.session.interrupt().unwrap().acknowledged);
    assert!(live.session.interrupt().unwrap().acknowledged);
    assert_eq!(live.session.phase(), SessionPhase::Interrupted);
    let record = live.happy(COST, NOW).expect("a turn after an interrupt");
    assert_eq!((record.turn(), live.session.turns().len()), (2, 1));
    assert!(live.session.interrupt().unwrap().acknowledged);
    refused(live.session.begin_turn(""), "ADMISSION_REFUSED");
    assert_eq!(live.session.phase(), SessionPhase::Interrupted);
    assert!(live.session.terminate().unwrap().acknowledged);
    assert!(live.session.terminate().unwrap().acknowledged);
    assert_eq!(live.session.phase(), SessionPhase::Terminated);
    refused(live.session.start(), "SESSION_TERMINATED");
    refused(live.session.begin_turn("x"), "SESSION_TERMINATED");
    refused(live.session.interrupt(), "SESSION_TERMINATED");
    refused(live.happy(COST, NOW), "SESSION_TERMINATED");
    assert!(live.session.pid_slot().lock().unwrap().is_none());
}

#[test] #[rustfmt::skip]
fn cleared_authority_is_bound_to_its_grant_and_a_refusal_is_permanent() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    // Expiry is re-checked before every dispatch against the caller's clock,
    // and rewinding that clock never revives the authority.
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    refused(live.happy(COST, EXPIRES), "SESSION_AUTHORITY_EXPIRED");
    refused(live.happy(COST, NOW), "SESSION_AUTHORITY_EXPIRED");
    assert!(live.empty() && live.argv.lock().unwrap().is_empty());
    // The invocation allowance is the grant's, not the session's.
    let mut live = Live::new(2, WALL_MS);
    live.happy(COST, NOW).expect("first of two");
    live.happy(COST, NOW).expect("second of two");
    refused(live.happy(COST, NOW), "SESSION_INVOCATIONS_EXHAUSTED");
    assert_eq!(live.session.turns().len(), 2);
    // Spend accumulates across turns and is charged before any other verdict.
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    live.happy(0.008, NOW).expect("8_000 of a 10_000 budget");
    let over = refused(live.happy(0.008, NOW), "SESSION_BUDGET_EXCEEDED");
    assert_eq!(over, SessionError::BudgetExceeded { spent: 16_000, budget: BUDGET });
    refused(live.happy(COST, NOW), "SESSION_BUDGET_EXCEEDED");
    assert_eq!(live.session.turns().len(), 1);
}

#[test] #[rustfmt::skip]
fn timeouts_crashes_and_unconfirmed_teardown_are_never_reported_as_success() {
    let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    // Hanging past the wall bound is a timeout, a nonzero exit is an abort.
    let mut live = Live::new(INVOCATIONS, 300);
    let stdout = terminal(&live.root.clone(), Some(proposal_value()), COST);
    refused(live.dispatch(&stdout, "/bin/sleep 3", NOW), "SESSION_TURN_TIMED_OUT");
    let aborted = refused(live.dispatch(&stdout, "exit 3", NOW), "SESSION_TURN_ABORTED");
    assert_eq!(aborted, SessionError::TurnAborted { turn: 2, exit_code: Some(3) });
    assert!(live.empty() && live.session.phase() == SessionPhase::Started);
    // A pid whose group cannot be confirmed dead is a terminal refusal naming
    // the pid, and every later operation keeps returning it.
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    let mut child = Command::new("/bin/true").process_group(0).spawn().unwrap();
    *live.session.pid_slot().lock().unwrap() = Some(child.id());
    let error = refused(live.session.interrupt(), UNCONFIRMED);
    assert!(error.to_string().contains(&format!("pid {}", child.id())), "{error}");
    child.wait().expect("reap the fixture child");
    refused(live.session.terminate(), UNCONFIRMED);
    refused(live.happy(COST, NOW), UNCONFIRMED);
    assert_eq!(live.session.phase(), SessionPhase::Terminated);
    // A poisoned pid lock is the same refusal, never "no pid".
    let mut live = Live::new(INVOCATIONS, WALL_MS);
    let slot = live.session.pid_slot();
    let poison = std::thread::spawn(move || { let _held = slot.lock().unwrap(); panic!("poison"); });
    assert!(poison.join().is_err());
    let error = refused(live.session.terminate(), UNCONFIRMED);
    assert!(error.to_string().contains("poisoned"), "{error}");
    refused(live.session.start(), UNCONFIRMED);
}
