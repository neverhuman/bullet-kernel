//! Dogfood read-only transcript profile (ADR 0015). No provider process is
//! spawned: these are pure state-machine vectors.
//!
//! The profile exists because the frozen conformance contract cannot parse a
//! real read-only coding turn. These vectors prove it now can, and — more
//! importantly — that widening the contract did not widen provider authority:
//! a `system/init` advertising a write-capable tool still poisons the
//! transcript, and the conformance profile is unchanged.

use bullet_harness_claude::{
    ClaudeStreamOutcome, ClaudeStreamTranscript, TranscriptProfile, OBSERVED_CLAUDE_SCHEMA_VERSION,
};
use bullet_harness_core::{AgentEventKind, AgentSessionId, InvocationId};
use serde_json::{json, Value};

const KERNEL_SESSION: &str = "kernel-session-1";
const INVOCATION: &str = "kernel-invocation-1";
const NATIVE_SESSION: &str = "00000000-0000-4000-8000-000000000001";
const INIT_EVENT: &str = "00000000-0000-4000-8000-000000000002";
const ASSISTANT_TOOL_EVENT: &str = "00000000-0000-4000-8000-000000000003";
const TOOL_RESULT_EVENT: &str = "00000000-0000-4000-8000-000000000004";
const ASSISTANT_TEXT_EVENT: &str = "00000000-0000-4000-8000-000000000005";
const RESULT_EVENT: &str = "00000000-0000-4000-8000-000000000006";
const CWD: &str = "/private/readonly";
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";
const MODEL: &str = "claude-dogfood-model";
const HELPER_MODEL: &str = "claude-dogfood-helper";
/// The runtime actually installed on the dogfood host, deliberately different
/// from the frozen conformance constant.
const ENROLLED_VERSION: &str = "2.1.248";
const TOOL_USE_ID: &str = "toolu_readme_read_1";

fn proposal() -> Value {
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "correct one stale date in a runbook",
        "operations": [{
            "path": "docs/runbooks/dogfood.md",
            "preimage": {"kind": "digest", "digest": "5".repeat(64)},
            "mutation": {"kind": "write", "content_utf8": "# Dogfood\n"}
        }],
        "gate_ids": [GATE],
        "claims": [],
        "uncertainties": [],
        "done": true,
    })
}

fn dogfood_machine(version: &str) -> ClaudeStreamTranscript {
    ClaudeStreamTranscript::new_with_profile(
        AgentSessionId::new(KERNEL_SESSION),
        InvocationId::new(INVOCATION),
        CWD,
        version,
        vec![GATE.into()],
        TranscriptProfile::DogfoodReadOnlyV0,
    )
    .expect("dogfood machine")
}

fn line(value: &Value) -> String {
    serde_json::to_string(value).expect("JSON")
}

fn init_event(version: &str, tools: Value) -> Value {
    json!({
        "type": "system",
        "subtype": "init",
        "uuid": INIT_EVENT,
        "session_id": NATIVE_SESSION,
        "apiKeySource": "dogfood-fixture",
        "claude_code_version": version,
        "cwd": CWD,
        "tools": tools,
        "mcp_servers": [],
        "model": MODEL,
        "permissionMode": "plan",
        "slash_commands": [],
        "output_style": "default",
        "agents": [],
        "skills": [],
        "plugins": [],
        "analytics_disabled": true,
        "product_feedback_disabled": true,
    })
}

/// An assistant message that calls one read-only tool.
fn assistant_tool_use(name: &str) -> Value {
    json!({
        "type": "assistant",
        "uuid": ASSISTANT_TOOL_EVENT,
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {
            "id": "msg-tool-use",
            "type": "message",
            "role": "assistant",
            "model": MODEL,
            "content": [{
                "type": "tool_use",
                "id": TOOL_USE_ID,
                "name": name,
                "input": {"file_path": "docs/runbooks/dogfood.md"},
            }],
            "stop_reason": "tool_use",
            "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        },
    })
}

fn tool_result(is_error: Option<bool>) -> Value {
    let mut item = json!({
        "type": "tool_result",
        "tool_use_id": TOOL_USE_ID,
        "content": "the file contents the model read",
    });
    if let Some(flag) = is_error {
        item["is_error"] = json!(flag);
    }
    json!({
        "type": "user",
        "uuid": TOOL_RESULT_EVENT,
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {"role": "user", "content": [item]},
    })
}

fn assistant_text() -> Value {
    json!({
        "type": "assistant",
        "uuid": ASSISTANT_TEXT_EVENT,
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {
            "id": "msg-text",
            "type": "message",
            "role": "assistant",
            "model": MODEL,
            "content": [{"type": "text", "text": "Here is the patch."}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 12, "output_tokens": 7},
        },
    })
}

/// A terminal that a real tool-using turn produces: `num_turns` below the
/// assistant-message count, and a helper model billed alongside the main one.
fn success_result(structured_output: Value) -> Value {
    json!({
        "type": "result",
        "subtype": "success",
        "uuid": RESULT_EVENT,
        "session_id": NATIVE_SESSION,
        "duration_ms": 20,
        "duration_api_ms": 10,
        "is_error": false,
        "num_turns": 1,
        "result": "untrusted text result",
        "stop_reason": "end_turn",
        "total_cost_usd": 0.02,
        "usage": {"input_tokens": 22, "output_tokens": 12},
        "modelUsage": {
            MODEL: {"inputTokens": 22, "outputTokens": 12},
            HELPER_MODEL: {"inputTokens": 3, "outputTokens": 1},
        },
        "permission_denials": [],
        "structured_output": structured_output,
        "terminal_reason": "completed",
    })
}

fn establish(machine: &mut ClaudeStreamTranscript, version: &str, tools: Value) {
    let _ = machine.user_message("do the task").expect("user message");
    machine
        .ingest_line(&line(&init_event(version, tools)))
        .expect("system/init");
}

#[test]
fn dogfood_profile_parses_a_real_read_only_tool_using_turn() {
    let mut machine = dogfood_machine(ENROLLED_VERSION);
    // Tools in a different order than the frozen conformance triple: the
    // dogfood profile checks set membership, not sequence.
    establish(
        &mut machine,
        ENROLLED_VERSION,
        json!(["Grep", "Read", "Glob"]),
    );

    let tool_events = machine
        .ingest_line(&line(&assistant_tool_use("Read")))
        .expect("assistant tool_use is admitted");
    assert!(
        tool_events
            .iter()
            .any(|event| event.kind == AgentEventKind::ToolRequested),
        "a tool_use block must surface as tool.requested"
    );

    let result_events = machine
        .ingest_line(&line(&tool_result(None)))
        .expect("tool result frame is admitted");
    assert!(
        result_events
            .iter()
            .any(|event| event.kind == AgentEventKind::ToolCompleted),
        "a tool_result must surface as tool.completed"
    );

    machine
        .ingest_line(&line(&assistant_text()))
        .expect("assistant text after the tool result");
    machine
        .ingest_line(&line(&success_result(proposal())))
        .expect("terminal success");

    match machine.outcome().expect("terminal outcome") {
        ClaudeStreamOutcome::Proposal(parsed) => {
            assert_eq!(parsed.gate_ids, vec![GATE.to_string()]);
        }
        other => panic!("expected a proposal, got {other:?}"),
    }
}

#[test]
fn a_failed_tool_result_is_recorded_as_failed_not_completed() {
    let mut machine = dogfood_machine(ENROLLED_VERSION);
    establish(
        &mut machine,
        ENROLLED_VERSION,
        json!(["Read", "Glob", "Grep"]),
    );
    machine
        .ingest_line(&line(&assistant_tool_use("Read")))
        .expect("assistant tool_use");
    let events = machine
        .ingest_line(&line(&tool_result(Some(true))))
        .expect("failed tool result is still a valid frame");
    assert!(
        events
            .iter()
            .any(|event| event.kind == AgentEventKind::ToolFailed),
        "is_error must select tool.failed so a failed read is not booked as a success"
    );
}

#[test]
fn write_capable_tools_are_refused_under_the_dogfood_profile() {
    // The security property the whole track rests on (ADR 0001): providers
    // propose, they never write. Widening the transcript must not widen this.
    for advertised in [
        json!(["Read", "Glob", "Grep", "Bash"]),
        json!(["Read", "Write"]),
        json!(["Edit"]),
        json!([]),
    ] {
        let mut machine = dogfood_machine(ENROLLED_VERSION);
        let _ = machine.user_message("do the task").expect("user message");
        let refusal = machine.ingest_line(&line(&init_event(ENROLLED_VERSION, advertised.clone())));
        assert!(
            refusal.is_err(),
            "system/init advertising {advertised} must poison the transcript"
        );
    }
}

#[test]
fn a_tool_named_outside_the_allowlist_is_refused_even_after_a_clean_init() {
    let mut machine = dogfood_machine(ENROLLED_VERSION);
    establish(
        &mut machine,
        ENROLLED_VERSION,
        json!(["Read", "Glob", "Grep"]),
    );
    assert!(
        machine
            .ingest_line(&line(&assistant_tool_use("Bash")))
            .is_err(),
        "a tool_use naming a write-capable tool must be refused"
    );
}

#[test]
fn the_conformance_profile_still_refuses_tool_use_and_tool_results() {
    let mut machine = ClaudeStreamTranscript::new(
        AgentSessionId::new(KERNEL_SESSION),
        InvocationId::new(INVOCATION),
        CWD,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        vec![GATE.into()],
    )
    .expect("conformance machine");
    establish(
        &mut machine,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        json!(["Read", "Glob", "Grep"]),
    );
    assert!(
        machine
            .ingest_line(&line(&assistant_tool_use("Read")))
            .is_err(),
        "the frozen V1 contract must keep refusing tool use"
    );

    let mut second = ClaudeStreamTranscript::new(
        AgentSessionId::new(KERNEL_SESSION),
        InvocationId::new(INVOCATION),
        CWD,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        vec![GATE.into()],
    )
    .expect("conformance machine");
    establish(
        &mut second,
        OBSERVED_CLAUDE_SCHEMA_VERSION,
        json!(["Read", "Glob", "Grep"]),
    );
    assert!(
        second.ingest_line(&line(&tool_result(None))).is_err(),
        "a user/tool_result frame is not part of the frozen V1 contract"
    );
}

#[test]
fn the_conformance_profile_still_rejects_a_non_frozen_runtime_version() {
    assert!(
        ClaudeStreamTranscript::new(
            AgentSessionId::new(KERNEL_SESSION),
            InvocationId::new(INVOCATION),
            CWD,
            ENROLLED_VERSION,
            vec![GATE.into()],
        )
        .is_err(),
        "conformance is pinned to the frozen constant"
    );
}

#[test]
fn the_dogfood_runtime_version_is_the_enrolled_one_and_must_be_well_formed() {
    // The pin moves to the operator's enrollment record, which binds the
    // executable digest; it does not disappear.
    for malformed in ["", "not-a-version", "v2.1.248", "2 1 248", "../etc"] {
        assert!(
            ClaudeStreamTranscript::new_with_profile(
                AgentSessionId::new(KERNEL_SESSION),
                InvocationId::new(INVOCATION),
                CWD,
                malformed,
                vec![GATE.into()],
                TranscriptProfile::DogfoodReadOnlyV0,
            )
            .is_err(),
            "malformed runtime version {malformed:?} must be refused"
        );
    }

    let mut machine = dogfood_machine(ENROLLED_VERSION);
    let _ = machine.user_message("do the task").expect("user message");
    assert!(
        machine
            .ingest_line(&line(&init_event("2.1.243", json!(["Read"]))))
            .is_err(),
        "system/init must still match the enrolled runtime exactly"
    );
}

#[test]
fn the_dogfood_terminal_still_requires_a_proposal_naming_the_admitted_gates() {
    let mut machine = dogfood_machine(ENROLLED_VERSION);
    establish(
        &mut machine,
        ENROLLED_VERSION,
        json!(["Read", "Glob", "Grep"]),
    );
    machine
        .ingest_line(&line(&assistant_text()))
        .expect("assistant text");

    let mut wrong_gates = proposal();
    wrong_gates["gate_ids"] = json!([format!("gat_{}", "9".repeat(64))]);
    assert!(
        machine
            .ingest_line(&line(&success_result(wrong_gates)))
            .is_err(),
        "a terminal proposal naming unadmitted gates must be refused"
    );
}

#[test]
fn a_dogfood_success_without_structured_output_is_refused() {
    let mut machine = dogfood_machine(ENROLLED_VERSION);
    establish(
        &mut machine,
        ENROLLED_VERSION,
        json!(["Read", "Glob", "Grep"]),
    );
    machine
        .ingest_line(&line(&assistant_text()))
        .expect("assistant text");
    let mut without = success_result(proposal());
    without
        .as_object_mut()
        .expect("result object")
        .remove("structured_output");
    assert!(
        machine.ingest_line(&line(&without)).is_err(),
        "a success terminal without a proposal is not a completed turn"
    );
}
