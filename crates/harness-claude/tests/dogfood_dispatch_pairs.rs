//! Synthetic transcripts through harmless real children. No provider or account is used.
#![cfg(unix)]

use bullet_harness_claude::{
    dogfood::{dispatch_dogfood_turn, DogfoodDispatchError, DogfoodTurnOutcome},
    ClaudeStreamTranscript, TranscriptProfile, OBSERVED_CLAUDE_SCHEMA_VERSION,
};
use bullet_harness_core::{
    admission::executable_digest, live::dispatch::artifact_digest, AgentEventKind, AgentSessionId,
    CanarySecrets, CommandFactory, InvocationId, LiveTurnRequest,
};
use serde_json::{json, Value};
use std::{
    cell::Cell, os::unix::fs::PermissionsExt, path::PathBuf, process::Command, time::Duration,
};

const CWD: &str = "/synthetic/k1";
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";
const NATIVE: &str = "00000000-0000-4000-8000-000000000001";
const CANARY: &str = "K1_OFFLINE_CANARY_0123456789_DO_NOT_LOG";

fn init() -> Value {
    json!({"type":"system", "subtype":"init", "uuid":"00000000-0000-4000-8000-000000000002",
        "session_id":NATIVE, "apiKeySource":"synthetic-fixture", "claude_code_version":OBSERVED_CLAUDE_SCHEMA_VERSION,
        "cwd":CWD, "tools":["Read","Glob","Grep"], "mcp_servers":[], "model":"claude-offline-model",
        "permissionMode":"plan", "slash_commands":[], "output_style":"default", "agents":[],
        "skills":[], "plugins":[], "analytics_disabled":true, "product_feedback_disabled":true})
}

fn assistant() -> Value {
    json!({"type":"assistant", "uuid":"00000000-0000-4000-8000-000000000003", "session_id":NATIVE,
        "parent_tool_use_id":null, "message":{"id":"msg-fixture", "type":"message", "role":"assistant",
        "model":"claude-offline-model", "content":[{"type":"text","text":"synthetic proposal"}],
        "stop_reason":"end_turn", "stop_sequence":null, "usage":{"input_tokens":10,"output_tokens":5}}})
}

fn terminal(success: bool, cost: Value) -> Value {
    let mut value = json!({"type":"result", "subtype":"success",
        "uuid":"00000000-0000-4000-8000-000000000004", "session_id":NATIVE,
        "duration_ms":20, "duration_api_ms":10, "is_error":false, "num_turns":1,
        "stop_reason":"end_turn", "total_cost_usd":cost, "usage":{"input_tokens":10,"output_tokens":5},
        "modelUsage":{"claude-offline-model":{"inputTokens":10,"outputTokens":5}}, "permission_denials":[]});
    if success {
        value["result"] = json!("synthetic");
        // A real 2.1.266 success result always carries these two; they are the
        // only place a turn admits work the transcript never showed. The
        // frozen conformance subject keeps its closed field set, so they go on
        // the success branch only.
        value["queued_turn_count"] = json!(0);
        value["subagent_stats"] = json!({"spawned": 0, "max_depth": 0});
        value["structured_output"] = json!({"schema_version":1, "proposal_id":format!("cnt_{}","1".repeat(64)),
            "producing_attempt_id":format!("atm_{}","2".repeat(64)), "base_checkpoint_id":format!("ckp_{}","3".repeat(64)),
            "base_checkpoint_digest":"4".repeat(64), "intent_summary":"synthetic fixture only",
            "operations":[{"path":"fixture.txt","preimage":{"kind":"absent"},"mutation":{"kind":"write","content_utf8":"fixture\n"}}],
            "gate_ids":[GATE], "claims":[], "uncertainties":[], "done":true});
    } else {
        value["subtype"] = json!("error_during_execution");
        value["is_error"] = json!(true);
        value["errors"] = json!(["synthetic failure"]);
    }
    value
}

fn transcript(result: Value) -> String {
    [init(), assistant(), result]
        .map(|v| v.to_string())
        .join("\n")
        + "\n"
}

struct Fixture {
    _directory: tempfile::TempDir,
    executable: PathBuf,
    digest: String,
    stream: PathBuf,
    marker: PathBuf,
    request: LiveTurnRequest,
}

impl Fixture {
    fn new(text: &str) -> Self {
        let directory = tempfile::tempdir().expect("private fixture");
        let root = directory.path().canonicalize().expect("canonical fixture");
        let executable = root.join("harmless-enrolled-fixture");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("fixture subject");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("fixture mode");
        let digest = executable_digest(&executable).expect("enrolled fixture digest");
        let stream = root.join("transcript.jsonl");
        std::fs::write(&stream, text).expect("synthetic stream");
        let marker = root.join("child-started");
        let request = LiveTurnRequest {
            session_id: AgentSessionId::new("synthetic-session"),
            invocation_id: InvocationId::new("synthetic-invocation"),
            prompt: "synthetic fixture only".into(),
            workdir: root,
            expected_runtime_version: OBSERVED_CLAUDE_SCHEMA_VERSION.into(),
            gate_ids: vec![GATE.into()],
            max_cost_micro_usd: 1_000_000,
            wall_timeout: Duration::from_secs(2),
            canaries: CanarySecrets::new(vec![CANARY.into()]).expect("synthetic canary"),
        };
        Self {
            _directory: directory,
            executable,
            digest,
            stream,
            marker,
            request,
        }
    }

    fn dispatch(
        &self,
        factory: &CommandFactory<'_>,
    ) -> Result<DogfoodTurnOutcome, DogfoodDispatchError> {
        dispatch_dogfood_turn(
            &self.executable,
            &self.digest,
            factory,
            &self.request,
            OBSERVED_CLAUDE_SCHEMA_VERSION,
            CWD,
        )
    }

    fn run(&self, ending: &str) -> Result<DogfoodTurnOutcome, DogfoodDispatchError> {
        self.dispatch(&|_, _, _| {
            let mut child = Command::new("/bin/sh");
            child
                .env_clear()
                .args([
                    "-c",
                    &format!(": > \"$1\"; /bin/cat \"$2\"; {ending}"),
                    "synthetic-k1",
                ])
                .arg(&self.marker)
                .arg(&self.stream);
            child
        })
    }
}

#[test]
fn completed_capture_requires_exit_zero_and_no_timeout() {
    let text = transcript(terminal(true, json!(0.25)));
    let expected_digest = artifact_digest(b"stdout", text.trim_end().as_bytes());
    for (ending, code, timeout) in [
        ("exit 0", Some(0), false),
        ("exit 1", Some(1), false),
        ("kill -TERM $$", None, false),
        ("exec /bin/sleep 5", None, true),
    ] {
        let mut fixture = Fixture::new(&text);
        if timeout {
            fixture.request.wall_timeout = Duration::from_secs(1);
        }
        let result = fixture.run(ending);
        assert!(fixture.marker.exists(), "harmless child actually ran");
        if code == Some(0) {
            let outcome = result.expect("only clean exit succeeds");
            assert_eq!(outcome.live.total_cost_micro_usd, Some(250_000));
            assert_eq!(outcome.live.stdout_blake3, expected_digest);
        } else {
            let error = result.expect_err("completion must refuse");
            assert_eq!(
                error.error().reason_code(),
                if timeout {
                    "WALL_CLOCK_TIMEOUT"
                } else {
                    "PROVIDER_FAILURE"
                }
            );
            let observed = error.observed().expect("capture facts");
            assert_eq!((observed.exit_code, observed.timed_out), (code, timeout));
            assert_eq!(observed.total_cost_micro_usd, Some(250_000));
            assert_eq!(observed.stdout_blake3, expected_digest);
        }
    }
}

#[test]
fn pre_capture_refusals_do_not_call_factory() {
    for refusal in ["version", "gates", "prompt", "digest"] {
        let mut fixture = Fixture::new(&transcript(terminal(true, json!(0.25))));
        match refusal {
            "version" => fixture.request.expected_runtime_version = "wrong".into(),
            "gates" => fixture.request.gate_ids.clear(),
            "prompt" => fixture.request.prompt.clear(),
            _ => fixture.digest = "0".repeat(64),
        }
        let calls = Cell::new(0);
        let error = fixture
            .dispatch(&|_, _, _| {
                calls.set(calls.get() + 1);
                Command::new("/bin/false")
            })
            .expect_err("pre-capture refusal");
        assert!(matches!(error, DogfoodDispatchError::BeforeSpawn(_)));
        assert_eq!(calls.get(), 0);
        assert!(!fixture.marker.exists());
    }
}

#[test]
fn unavailable_capture_does_not_invent_a_phase_or_observation() {
    let fixture = Fixture::new(&format!("{CANARY}\n"));
    let error = fixture.run("exit 0").expect_err("canary refuses capture");
    assert!(fixture.marker.exists(), "real harmless child wrote marker");
    assert!(matches!(error, DogfoodDispatchError::CaptureUnavailable(_)));
    assert!(error.observed().is_none());
    assert_eq!(error.error().reason_code(), "SECRET_CANARY_EXPOSURE");
    assert!(!error.to_string().contains(CANARY));
    let absent = Fixture::new("");
    let error = absent
        .dispatch(&|_, _, _| Command::new(absent.marker.with_extension("missing")))
        .expect_err("exec failure");
    assert!(matches!(error, DogfoodDispatchError::CaptureUnavailable(_)));
    assert!(error.observed().is_none());
    assert_eq!(error.error().reason_code(), "SPAWN_FAILED");
    assert!(!absent.marker.exists());
}

#[test]
fn validated_failure_cost_preserves_reported_zero_and_nonzero() {
    for (cost, expected) in [(0.25, 250_000), (0.0, 0)] {
        let fixture = Fixture::new(&transcript(terminal(false, json!(cost))));
        let error = fixture
            .run("exit 0")
            .expect_err("failure terminal remains failure");
        let observed = error.observed().expect("capture facts");
        assert_eq!(observed.total_cost_micro_usd, Some(expected));
        assert_eq!(observed.exit_code, Some(0));
    }
}

#[test]
fn validated_cost_survives_late_frame_refusal() {
    for success in [true, false] {
        let mut text = transcript(terminal(success, json!(0.25)));
        text.push_str(&format!("{}\n", assistant()));
        let error = Fixture::new(&text).run("exit 0").expect_err("late frame");
        assert!(error.error().to_string().contains("late frame"));
        assert_eq!(
            error.observed().expect("capture").total_cost_micro_usd,
            Some(250_000)
        );
    }
}

#[test]
fn malformed_missing_or_unrepresentable_cost_never_becomes_zero() {
    let mut absent = terminal(true, json!(0.25));
    absent
        .as_object_mut()
        .expect("terminal")
        .remove("total_cost_usd");
    for value in [
        absent,
        terminal(true, json!(-0.25)),
        terminal(true, json!("0.25")),
        terminal(true, Value::Null),
        terminal(true, json!(1e308)),
    ] {
        let error = Fixture::new(&transcript(value))
            .run("exit 0")
            .expect_err("invalid accounting");
        assert_eq!(
            error.observed().expect("capture").total_cost_micro_usd,
            None
        );
    }
    for text in [
        "not json\n".into(),
        transcript(terminal(true, json!(0.25)))
            .replace("\"total_cost_usd\":0.25", "\"total_cost_usd\":1e999"),
    ] {
        let error = Fixture::new(&text)
            .run("exit 0")
            .expect_err("malformed before admitted usage");
        assert_eq!(
            error.observed().expect("capture").total_cost_micro_usd,
            None
        );
    }
}

#[test]
fn rejected_terminal_subject_does_not_admit_its_cost() {
    let mut invalid = terminal(true, json!(0.25));
    invalid["structured_output"]["gate_ids"] = json!([format!("gat_{}", "9".repeat(64))]);
    let error = Fixture::new(&transcript(invalid))
        .run("exit 0")
        .expect_err("wrong gate subject");
    assert_eq!(
        error.observed().expect("capture").total_cost_micro_usd,
        None
    );
    let valid = Fixture::new(&transcript(terminal(true, json!(0.25))))
        .run("exit 0")
        .expect("valid subject");
    assert_eq!(valid.live.total_cost_micro_usd, Some(250_000));
}

#[test]
fn failure_usage_is_dogfood_only_and_preserves_conformance_sequence() {
    for profile in [
        TranscriptProfile::ConformanceV1,
        TranscriptProfile::DogfoodReadOnlyV0,
    ] {
        let mut machine = ClaudeStreamTranscript::new_with_profile(
            AgentSessionId::new("synthetic-session"),
            InvocationId::new("synthetic-invocation"),
            CWD,
            OBSERVED_CLAUDE_SCHEMA_VERSION,
            vec![GATE.into()],
            profile,
        )
        .expect("machine");
        machine.user_message("synthetic").expect("seed");
        let prefix = machine.ingest_line(&init().to_string()).expect("init");
        let events = machine
            .ingest_line(&terminal(false, json!(0.25)).to_string())
            .expect("valid failure");
        let expected = if profile == TranscriptProfile::ConformanceV1 {
            vec![AgentEventKind::TurnFailed]
        } else {
            vec![AgentEventKind::UsageReported, AgentEventKind::TurnFailed]
        };
        assert_eq!(events.iter().map(|e| e.kind).collect::<Vec<_>>(), expected);
        for (index, event) in events.iter().enumerate() {
            assert_eq!(
                event.sequence,
                prefix.last().expect("prefix").sequence + 1 + u64::try_from(index).expect("index")
            );
        }
        assert_eq!(
            events.last().expect("failure").payload,
            json!({"subtype":"error_during_execution", "terminal_event_id":"00000000-0000-4000-8000-000000000004"})
        );
    }
}
