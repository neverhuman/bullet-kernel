//! Untrusted error frames through both profiles and harmless real children.
#![cfg(unix)]

use bullet_harness_claude::{
    dogfood::{dispatch_dogfood_turn, DogfoodDispatchError},
    ClaudeStreamOutcome, ClaudeStreamTranscript, TranscriptProfile, OBSERVED_CLAUDE_SCHEMA_VERSION,
};
use bullet_harness_core::{
    admission::executable_digest, AgentEventKind, AgentSessionId, CanarySecrets, HarnessError,
    InvocationId, LiveTurnRequest,
};
use serde_json::{json, Value};
use std::{os::unix::fs::PermissionsExt, process::Command, time::Duration};

const CWD: &str = "/synthetic/provider-error";
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";
const NATIVE: &str = "00000000-0000-4000-8000-000000000001";
const CANARY: &str = "PROVIDER_ERROR_CANARY_0123456789_DO_NOT_LOG";
const WITHHELD: &str = "provider reported an assistant error; detail withheld";
const PROFILES: [TranscriptProfile; 2] = [
    TranscriptProfile::ConformanceV1,
    TranscriptProfile::DogfoodReadOnlyV0,
];

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
        "model":"claude-offline-model", "content":[{"type":"text","text":"safe control"}],
        "stop_reason":"end_turn", "stop_sequence":null, "usage":{"input_tokens":10,"output_tokens":5}}})
}

fn failure(cost: f64, detail: &str) -> Value {
    json!({"type":"result", "subtype":"error_during_execution",
        "uuid":"00000000-0000-4000-8000-000000000004", "session_id":NATIVE,
        "duration_ms":20, "duration_api_ms":10, "is_error":true, "num_turns":1,
        "stop_reason":"end_turn", "total_cost_usd":cost, "usage":{"input_tokens":10,"output_tokens":5},
        "modelUsage":{"claude-offline-model":{"inputTokens":10,"outputTokens":5}},
        "permission_denials":[], "errors":[detail]})
}

fn machine(profile: TranscriptProfile) -> ClaudeStreamTranscript {
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
    machine.ingest_line(&init().to_string()).expect("init");
    machine
}

fn escaped(line: &str) -> String {
    let unicode: String = CANARY
        .bytes()
        .map(|byte| format!("\\u{byte:04x}"))
        .collect();
    let encoded = line.replace(CANARY, &unicode);
    assert!(!encoded.contains(CANARY));
    encoded
}

fn assert_diagnostic(error: &HarnessError, expected: &str) {
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    let HarnessError::Protocol { reason, .. } = error else {
        panic!("expected protocol refusal");
    };
    assert_eq!(reason, expected);
    assert!(!error.to_string().contains(CANARY));
    assert!(!error.to_string().contains(['\n', '\r', '\x1b', '\x7f']));
}

fn refused(profile: TranscriptProfile, line: &str, expected: &str) {
    let mut machine = machine(profile);
    let error = machine.ingest_line(line).expect_err("frame must refuse");
    assert_diagnostic(&error, expected);
    assert!(machine.outcome().is_err());
    assert_diagnostic(
        &machine
            .ingest_line(&assistant().to_string())
            .expect_err("poisoned"),
        "transcript is poisoned",
    );
}

#[test]
fn provider_error_text_and_tags_are_not_public_diagnostics() {
    for profile in PROFILES {
        for tag in ["synthetic_provider_failure", CANARY] {
            let mut frame = assistant();
            frame["error"] = json!(tag);
            frame["message"]["content"][0]["text"] = json!(format!("\n\x1b[31m{CANARY}\r\x7f"));
            let raw = frame.to_string();
            let encoded = escaped(&raw);
            assert_eq!(
                serde_json::from_str::<Value>(&encoded).expect("JSON"),
                frame
            );
            refused(profile, &raw, WITHHELD);
            refused(profile, &encoded, WITHHELD);
        }
    }
    let mut flag = assistant();
    flag["is_api_error_message"] = json!(true);
    flag["message"]["content"][0]["text"] = json!(CANARY);
    refused(
        TranscriptProfile::DogfoodReadOnlyV0,
        &escaped(&flag.to_string()),
        WITHHELD,
    );
    refused(
        TranscriptProfile::ConformanceV1,
        &flag.to_string(),
        "assistant envelope is not an exact main-session message",
    );
}

#[test]
fn provider_error_subject_checks_precede_diagnostic() {
    for profile in PROFILES {
        let mut frame = assistant();
        frame["error"] = json!(CANARY);
        frame["session_id"] = json!("00000000-0000-4000-8000-000000000099");
        refused(
            profile,
            &frame.to_string(),
            "provider event names the wrong native session",
        );
        for missing in ["uuid", "message"] {
            let mut frame = assistant();
            frame["error"] = json!(CANARY);
            frame.as_object_mut().expect("object").remove(missing);
            refused(
                profile,
                &frame.to_string(),
                "assistant envelope is not an exact main-session message",
            );
        }
        let mut frame = assistant();
        frame["error"] = json!(CANARY);
        frame["parent_tool_use_id"] = json!(CANARY);
        refused(
            profile,
            &frame.to_string(),
            "assistant envelope is not an exact main-session message",
        );
        frame["parent_tool_use_id"] = Value::Null;
        frame["uuid"] = json!(CANARY);
        refused(
            profile,
            &frame.to_string(),
            "assistant has invalid event subject",
        );
    }
}

#[test]
fn ordinary_assistant_controls_keep_profile_contracts() {
    for profile in PROFILES {
        for null_error in [false, true] {
            let mut frame = assistant();
            if null_error {
                frame["error"] = Value::Null;
            }
            let events = machine(profile)
                .ingest_line(&frame.to_string())
                .expect("ordinary message");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].kind, AgentEventKind::TurnDelta);
            assert_eq!(
                events[0].payload,
                json!({"text":"safe control", "authoritative":false})
            );
        }
    }
    for marker in [Value::Null, json!(false)] {
        let mut frame = assistant();
        frame["is_api_error_message"] = marker;
        assert!(machine(TranscriptProfile::DogfoodReadOnlyV0)
            .ingest_line(&frame.to_string())
            .is_ok());
        refused(
            TranscriptProfile::ConformanceV1,
            &frame.to_string(),
            "assistant envelope is not an exact main-session message",
        );
    }
}

#[test]
fn malformed_error_markers_remain_refusals() {
    for marker in [
        json!(42),
        json!([]),
        json!({"detail":CANARY}),
        json!(CANARY),
    ] {
        let mut frame = assistant();
        frame["error"] = marker.clone();
        for profile in PROFILES {
            refused(profile, &escaped(&frame.to_string()), WITHHELD);
        }
        frame.as_object_mut().expect("object").remove("error");
        frame["is_api_error_message"] = marker;
        refused(
            TranscriptProfile::DogfoodReadOnlyV0,
            &escaped(&frame.to_string()),
            "assistant error marker is malformed",
        );
    }
}

#[test]
fn malformed_or_unknown_frames_do_not_reflect_decoded_fields() {
    for profile in PROFILES {
        let unknown = json!({"type":CANARY}).to_string();
        for line in [unknown.clone(), escaped(&unknown)] {
            refused(profile, &line, "unadmitted stream-JSON type");
        }
        let duplicate = format!("{{\"{CANARY}\":1,\"{CANARY}\":2,\"type\":\"assistant\"}}");
        for line in [duplicate.clone(), escaped(&duplicate)] {
            refused(profile, &line, "malformed stream-JSON");
        }
        refused(
            profile,
            &format!("{{\"type\":\"{CANARY}\n\"}}"),
            "invalid stream-JSON frame boundary",
        );
    }
}

fn dispatch(text: &str) -> DogfoodDispatchError {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private fixture");
    let root = directory.path().canonicalize().expect("canonical fixture");
    let executable = root.join("harmless-enrolled-fixture");
    std::fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("fixture subject");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let digest = executable_digest(&executable).expect("fixture digest");
    let stream = root.join("transcript.jsonl");
    std::fs::write(&stream, text).expect("synthetic stream");
    let request = LiveTurnRequest {
        session_id: AgentSessionId::new("synthetic-session"),
        invocation_id: InvocationId::new("synthetic-invocation"),
        prompt: "synthetic fixture only".into(),
        workdir: root,
        expected_runtime_version: OBSERVED_CLAUDE_SCHEMA_VERSION.into(),
        gate_ids: vec![GATE.into()],
        max_cost_micro_usd: 1_000_000,
        wall_timeout: Duration::from_secs(2),
        canaries: CanarySecrets::new(vec![CANARY.into()]).expect("canary"),
    };
    dispatch_dogfood_turn(
        &executable,
        &digest,
        &|_, _, _| {
            let mut child = Command::new("/bin/cat");
            child.arg(&stream).env_clear();
            child
        },
        &request,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        CWD,
    )
    .expect_err("failure remains failure")
}

#[test]
fn raw_and_escaped_capture_canaries_fail_without_invented_cost() {
    let mut frame = assistant();
    frame["error"] = json!("synthetic_provider_failure");
    frame["message"]["content"][0]["text"] = json!(CANARY);
    let raw = format!("{}\n{frame}\n", init());
    let raw_error = dispatch(&raw);
    assert!(matches!(
        raw_error,
        DogfoodDispatchError::CaptureUnavailable(_)
    ));
    assert_eq!(raw_error.error().reason_code(), "SECRET_CANARY_EXPOSURE");
    assert!(raw_error.observed().is_none());
    assert!(!raw_error.to_string().contains(CANARY));
    let encoded = escaped(&raw);
    let error = dispatch(&encoded);
    assert!(matches!(error, DogfoodDispatchError::AfterTurn { .. }));
    assert_diagnostic(error.error(), WITHHELD);
    assert!(!error.to_string().contains(CANARY));
    let observed = error.observed().expect("completed harmless capture");
    assert_eq!(observed.exit_code, Some(0));
    assert!(!observed.timed_out);
    assert_eq!(observed.total_cost_micro_usd, None);
}

#[test]
fn failure_terminal_preserves_cost_and_conformance_events() {
    for profile in PROFILES {
        let mut machine = machine(profile);
        let events = machine
            .ingest_line(&failure(0.25, CANARY).to_string())
            .expect("failure terminal");
        let expected = if profile == TranscriptProfile::ConformanceV1 {
            vec![AgentEventKind::TurnFailed]
        } else {
            vec![AgentEventKind::UsageReported, AgentEventKind::TurnFailed]
        };
        assert_eq!(
            events.iter().map(|event| event.kind).collect::<Vec<_>>(),
            expected
        );
        assert!(!serde_json::to_string(&events)
            .expect("events")
            .contains(CANARY));
        assert!(
            matches!(machine.outcome().expect("terminal"), ClaudeStreamOutcome::Failed(reason)
            if reason == "error_during_execution")
        );
    }
    for (cost, expected) in [(0.0, 0), (0.25, 250_000)] {
        let error = dispatch(&format!("{}\n{}\n", init(), failure(cost, "safe failure")));
        let observed = error.observed().expect("validated failure cost");
        assert_eq!(observed.total_cost_micro_usd, Some(expected));
        assert_eq!(observed.exit_code, Some(0));
    }
}
