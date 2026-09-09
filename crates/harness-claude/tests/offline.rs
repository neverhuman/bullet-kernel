//! Offline Claude stream-JSON contract proof. No provider process is spawned.

use bullet_harness_claude::{
    ClaudeAdapter, ClaudeStreamOutcome, ClaudeStreamTranscript, MAX_ASSISTANT_CONTENT_ITEMS,
    MAX_ASSISTANT_MESSAGES, OBSERVED_CLAUDE_SCHEMA_VERSION,
};
use bullet_harness_core::{
    conformance, AgentSessionId, Capability, CapabilityState, HarnessAdapter, InvocationId,
    ProfileRef, SessionHandle, StartSession, Turn,
};
use serde_json::{json, Value};
use std::time::Duration;

const KERNEL_SESSION: &str = "kernel-session-1";
const INVOCATION: &str = "kernel-invocation-1";
const NATIVE_SESSION: &str = "00000000-0000-4000-8000-000000000001";
const INIT_EVENT: &str = "00000000-0000-4000-8000-000000000002";
const ASSISTANT_EVENT: &str = "00000000-0000-4000-8000-000000000003";
const RESULT_EVENT: &str = "00000000-0000-4000-8000-000000000004";
const CWD: &str = "/private/readonly";
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";

fn proposal() -> Value {
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "write fixture",
        "operations": [{
            "path": "PONG.txt",
            "preimage": {"kind": "absent"},
            "mutation": {"kind": "write", "content_utf8": "PONG\n"}
        }],
        "gate_ids": [GATE],
        "claims": [],
        "uncertainties": [],
        "done": true,
    })
}

fn machine() -> ClaudeStreamTranscript {
    ClaudeStreamTranscript::new(
        AgentSessionId::new(KERNEL_SESSION),
        InvocationId::new(INVOCATION),
        CWD,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        vec![GATE.into()],
    )
    .expect("machine")
}

fn line(value: Value) -> String {
    serde_json::to_string(&value).expect("JSON")
}

fn acknowledgement(request_id: &str) -> Value {
    json!({
        "type": "control_response",
        "response": {"subtype": "success", "request_id": request_id, "response": {}},
    })
}

fn init_event() -> Value {
    json!({
        "type": "system",
        "subtype": "init",
        "uuid": INIT_EVENT,
        "session_id": NATIVE_SESSION,
        "apiKeySource": "offline-fixture",
        "claude_code_version": OBSERVED_CLAUDE_SCHEMA_VERSION,
        "cwd": CWD,
        "tools": ["Read", "Glob", "Grep"],
        "mcp_servers": [],
        "model": "claude-offline-model",
        "permissionMode": "plan",
        "slash_commands": [],
        "output_style": "default",
        "agents": [],
        "skills": [],
        "plugins": [],
        "capabilities": ["interrupt_receipt_v1", "interrupt_cancel_queued_v1", "msg_lifecycle_v1"],
        "analytics_disabled": true,
        "product_feedback_disabled": true,
    })
}

fn assistant_event(uuid: &str, text: &str) -> Value {
    json!({
        "type": "assistant",
        "uuid": uuid,
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {
            "id": format!("msg-{uuid}"),
            "type": "message",
            "role": "assistant",
            "model": "claude-offline-model",
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        },
    })
}

fn success_result(uuid: &str, structured_output: Value) -> Value {
    json!({
        "type": "result",
        "subtype": "success",
        "uuid": uuid,
        "session_id": NATIVE_SESSION,
        "duration_ms": 20,
        "duration_api_ms": 10,
        "is_error": false,
        "num_turns": 1,
        "result": "untrusted text result",
        "stop_reason": "end_turn",
        "total_cost_usd": 0.01,
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "modelUsage": {"claude-offline-model": {"inputTokens": 10, "outputTokens": 5}},
        "permission_denials": [],
        "structured_output": structured_output,
        "terminal_reason": "completed",
    })
}

fn failure_result(uuid: &str, terminal_reason: &str) -> Value {
    json!({
        "type": "result",
        "subtype": "error_during_execution",
        "uuid": uuid,
        "session_id": NATIVE_SESSION,
        "duration_ms": 20,
        "duration_api_ms": 10,
        "is_error": true,
        "num_turns": 1,
        "stop_reason": null,
        "total_cost_usd": 0.0,
        "usage": {},
        "modelUsage": {},
        "permission_denials": [],
        "errors": ["interrupted"],
        "terminal_reason": terminal_reason,
    })
}

fn establish(machine: &mut ClaudeStreamTranscript) {
    let user = machine
        .user_message("produce the admitted proposal")
        .expect("user");
    assert_eq!(user["uuid"], INVOCATION);
    assert!(user.get("origin").is_none());
    assert_eq!(user["session_id"], "");
    machine
        .ingest_line(&line(init_event()))
        .expect("system init");
}

fn complete(machine: &mut ClaudeStreamTranscript) -> Vec<bullet_harness_core::AgentEvent> {
    machine
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "not authoritative")))
        .expect("assistant");
    machine
        .ingest_line(&line(success_result(RESULT_EVENT, proposal())))
        .expect("result")
}

#[tokio::test]
async fn conformance_and_every_public_runtime_path_are_blocked_without_side_effects() {
    let adapter = ClaudeAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
    assert!(matches!(
        adapter.descriptor().version,
        bullet_domain::Observation::Unknown { .. }
    ));
    assert_eq!(
        adapter
            .descriptor()
            .capabilities
            .state(Capability::TurnInterrupt),
        CapabilityState::Unsupported
    );
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("offline"),
        expected: Default::default(),
    };
    assert_eq!(
        adapter.probe(&profile).await.unwrap_err().reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    let directory = tempfile::tempdir().expect("tempdir");
    let artifact_dir = directory.path().join("must-not-exist");
    let start = StartSession {
        session_id: AgentSessionId::new("blocked"),
        workdir: directory.path().to_path_buf(),
        artifact_dir: artifact_dir.clone(),
        model: None,
        structured_schema: None,
        max_budget_usd: None,
        wall_timeout: Duration::from_secs(1),
    };
    assert_eq!(
        adapter.start(start).await.unwrap_err().reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    assert!(!artifact_dir.exists());
    let handle = SessionHandle {
        session_id: AgentSessionId::new("blocked"),
        provider: "claude".into(),
        native_session_id: None,
    };
    assert_eq!(
        adapter
            .send(&handle, Turn { prompt: "x".into() })
            .await
            .unwrap_err()
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    assert_eq!(
        adapter.interrupt(&handle).await.unwrap_err().reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    assert_eq!(
        adapter.terminate(&handle).await.unwrap_err().reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
}

#[test]
fn exact_correlated_terminal_yields_only_the_structured_admitted_proposal() {
    let mut machine = machine();
    establish(&mut machine);
    let events = complete(&mut machine);
    let ClaudeStreamOutcome::Proposal(proposal) = machine.outcome().expect("outcome") else {
        panic!("expected proposal")
    };
    assert_eq!(proposal.gate_ids, [GATE]);
    assert_eq!(proposal.operations[0].path, "PONG.txt");
    assert!(events.iter().all(|event| {
        event.session_id.as_str() == KERNEL_SESSION
            && event.invocation_id.as_ref().map(InvocationId::as_str) == Some(INVOCATION)
    }));
}

#[test]
fn text_and_wrong_gate_structured_outputs_never_become_proposals() {
    let text = proposal().to_string();
    let mut missing = machine();
    establish(&mut missing);
    missing
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, &text)))
        .unwrap();
    let mut no_structured = success_result(RESULT_EVENT, Value::Null);
    no_structured
        .as_object_mut()
        .unwrap()
        .remove("structured_output");
    assert_eq!(
        missing
            .ingest_line(&line(no_structured))
            .unwrap_err()
            .reason_code(),
        "PROTOCOL_ERROR"
    );

    let mut wrong_gate = machine();
    establish(&mut wrong_gate);
    wrong_gate
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "done")))
        .unwrap();
    let mut changed = proposal();
    changed["gate_ids"] = json!(["other.gate"]);
    assert!(wrong_gate
        .ingest_line(&line(success_result(RESULT_EVENT, changed)))
        .is_err());
    assert!(wrong_gate.outcome().is_err());

    for mismatch in ["turns", "model"] {
        let mut subject = machine();
        establish(&mut subject);
        subject
            .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "done")))
            .unwrap();
        let mut terminal = success_result(RESULT_EVENT, proposal());
        match mismatch {
            "turns" => terminal["num_turns"] = json!(2),
            "model" => terminal["modelUsage"] = json!({"other-model": {}}),
            _ => unreachable!(),
        }
        assert!(subject.ingest_line(&line(terminal)).is_err(), "{mismatch}");
    }
}

#[test]
fn malformed_duplicate_wrong_subject_and_late_frames_poison_permanently() {
    for bad in [
        "not-json",
        "[]",
        "{}",
        "{\"type\":1}",
        "{\"type\":\"system\"}\r",
        "{\"type\":\"sys\0tem\"}",
    ] {
        let mut machine = machine();
        assert_eq!(
            machine.ingest_line(bad).unwrap_err().reason_code(),
            "PROTOCOL_ERROR"
        );
        assert_eq!(
            machine.ingest_line("{}").unwrap_err().reason_code(),
            "PROTOCOL_ERROR"
        );
    }
    let mut oversized = machine();
    assert!(oversized.ingest_line(&"x".repeat(1024 * 1024 + 1)).is_err());

    let mut nested = machine();
    establish(&mut nested);
    nested
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "done")))
        .unwrap();
    let terminal = line(success_result(RESULT_EVENT, proposal())).replacen(
        r#""gate_ids":["gat_8888888888888888888888888888888888888888888888888888888888888888"]"#,
        r#""gate_ids":["gat_7777777777777777777777777777777777777777777777777777777777777777"],"gate_ids":["gat_8888888888888888888888888888888888888888888888888888888888888888"]"#,
        1,
    );
    assert!(nested.ingest_line(&terminal).is_err());
    assert!(nested.ingest_line("{}").is_err());

    let mut duplicate = machine();
    establish(&mut duplicate);
    let assistant = line(assistant_event(ASSISTANT_EVENT, "x"));
    duplicate.ingest_line(&assistant).unwrap();
    assert!(duplicate.ingest_line(&assistant).is_err());

    let mut wrong_session = machine();
    establish(&mut wrong_session);
    let mut assistant = assistant_event(ASSISTANT_EVENT, "x");
    assistant["session_id"] = json!("00000000-0000-4000-8000-000000000099");
    assert!(wrong_session.ingest_line(&line(assistant)).is_err());

    let mut conflict = machine();
    establish(&mut conflict);
    conflict
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "first")))
        .unwrap();
    assert!(conflict
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "changed")))
        .is_err());

    let mut late = machine();
    establish(&mut late);
    complete(&mut late);
    assert!(late
        .ingest_line(&line(assistant_event(ASSISTANT_EVENT, "late")))
        .is_err());
    assert!(late.outcome().is_err());
}

#[test]
fn version_tools_and_every_provider_id_are_fail_closed() {
    assert!(ClaudeStreamTranscript::new(
        AgentSessionId::new("bad session"),
        InvocationId::new(INVOCATION),
        CWD,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        vec![GATE.into()],
    )
    .is_err());
    assert!(ClaudeStreamTranscript::new(
        AgentSessionId::new(KERNEL_SESSION),
        InvocationId::new(INVOCATION),
        CWD,
        "2.1.241",
        vec![GATE.into()],
    )
    .is_err());
    for mutation in [
        "version",
        "tool",
        "duplicate_tool",
        "duplicate_capability",
        "ambient_skill",
        "uuid",
        "session",
    ] {
        let mut machine = machine();
        machine.user_message("x").unwrap();
        let mut init = init_event();
        match mutation {
            "version" => init["claude_code_version"] = json!("2.1.241"),
            "tool" => init["tools"] = json!(["Read", "Write"]),
            "duplicate_tool" => init["tools"] = json!(["Read", "Read"]),
            "duplicate_capability" => {
                init["capabilities"] = json!(["interrupt_receipt_v1", "interrupt_receipt_v1"])
            }
            "ambient_skill" => init["skills"] = json!(["ambient"]),
            "uuid" => init["uuid"] = json!("not-a-uuid"),
            "session" => init["session_id"] = json!("not-a-uuid"),
            _ => unreachable!(),
        }
        assert!(machine.ingest_line(&line(init)).is_err(), "{mutation}");
    }

    let mut wrong_control = machine();
    wrong_control.user_message("x").unwrap();
    assert!(wrong_control
        .ingest_line(&line(acknowledgement("wrong-request")))
        .is_err());

    let mut bad_message_id = machine();
    establish(&mut bad_message_id);
    let mut assistant = assistant_event(ASSISTANT_EVENT, "x");
    assistant["message"]["id"] = json!("bad id");
    assert!(bad_message_id.ingest_line(&line(assistant)).is_err());
}

#[test]
fn interrupt_and_timeout_are_explicitly_unsupported_and_poison_authority() {
    for timeout in [false, true] {
        let mut machine = machine();
        establish(&mut machine);
        let error = if timeout {
            machine.timeout_request().unwrap_err()
        } else {
            machine.interrupt_request().unwrap_err()
        };
        assert_eq!(error.reason_code(), "UNSUPPORTED");
        assert!(machine
            .ingest_line(&line(success_result(RESULT_EVENT, proposal())))
            .is_err());
        assert!(machine.outcome().is_err());
    }
}

#[test]
fn valid_uncancelled_failure_is_terminal_but_never_passes() {
    let mut machine = machine();
    establish(&mut machine);
    let mut failure = failure_result(RESULT_EVENT, "model_error");
    failure["subtype"] = json!("error_max_turns");
    machine
        .ingest_line(&line(failure))
        .expect("failure terminal");
    assert_eq!(
        machine.outcome().unwrap(),
        &ClaudeStreamOutcome::Failed("error_max_turns".into())
    );
}

#[test]
fn transcript_and_content_limits_accept_the_boundary_then_poison_excess() {
    let provider_uuid = |index: u64| format!("00000000-0000-4000-8000-{index:012x}");
    let mut exact = machine();
    establish(&mut exact);
    for index in 100..100 + MAX_ASSISTANT_MESSAGES {
        exact
            .ingest_line(&line(assistant_event(&provider_uuid(index), "delta")))
            .expect("message at admitted boundary");
    }
    let mut terminal = success_result(RESULT_EVENT, proposal());
    terminal["num_turns"] = json!(MAX_ASSISTANT_MESSAGES);
    exact
        .ingest_line(&line(terminal))
        .expect("34th and terminal frame");
    assert!(matches!(
        exact.outcome().unwrap(),
        ClaudeStreamOutcome::Proposal(_)
    ));

    let mut excess = machine();
    establish(&mut excess);
    for index in 200..200 + MAX_ASSISTANT_MESSAGES {
        excess
            .ingest_line(&line(assistant_event(&provider_uuid(index), "delta")))
            .unwrap();
    }
    assert!(excess
        .ingest_line(&line(assistant_event(&provider_uuid(999), "excess")))
        .is_err());

    let mut escaped_prompt = machine();
    assert!(escaped_prompt
        .user_message(&"\u{1}".repeat(200_000))
        .is_err());

    for content_len in [MAX_ASSISTANT_CONTENT_ITEMS, MAX_ASSISTANT_CONTENT_ITEMS + 1] {
        let mut content_machine = machine();
        establish(&mut content_machine);
        let mut event = assistant_event(ASSISTANT_EVENT, "replaced");
        event["message"]["content"] = Value::Array(
            (0..content_len)
                .map(|_| json!({"type": "text", "text": "bounded"}))
                .collect(),
        );
        assert_eq!(
            content_machine.ingest_line(&line(event)).is_ok(),
            content_len == MAX_ASSISTANT_CONTENT_ITEMS
        );
    }
}
