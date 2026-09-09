//! Identity and transport-bound hostiles for the dogfood transcript profile.
//! No provider process is spawned.

use bullet_harness_claude::{
    ClaudeStreamTranscript, TranscriptProfile, DOGFOOD_MAX_STREAM_JSON_FRAMES,
};
use bullet_harness_core::{live::dispatch::MAX_INTERACTIVE_LINES, AgentSessionId, InvocationId};
use serde_json::{json, Value};

const NATIVE_SESSION: &str = "00000000-0000-4000-8000-000000000001";
const CWD: &str = "/private/readonly";
const VERSION: &str = "2.1.248";
const MODEL: &str = "claude-dogfood-model";
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";

fn uuid(serial: u64) -> String {
    format!("00000000-0000-4000-8000-{serial:012x}")
}

fn line(value: &Value) -> String {
    serde_json::to_string(value).expect("JSON")
}

fn machine(seed: &str) -> ClaudeStreamTranscript {
    ClaudeStreamTranscript::new_with_profile(
        AgentSessionId::new(format!("kernel-session-{seed}")),
        InvocationId::new(format!("kernel-invocation-{seed}")),
        CWD,
        VERSION,
        vec![GATE.into()],
        TranscriptProfile::DogfoodReadOnlyV0,
    )
    .expect("dogfood machine")
}

fn establish(machine: &mut ClaudeStreamTranscript) {
    let _ = machine.user_message("inspect the private clone").unwrap();
    machine
        .ingest_line(&line(&json!({
            "type": "system",
            "subtype": "init",
            "uuid": uuid(2),
            "session_id": NATIVE_SESSION,
            "apiKeySource": "dogfood-fixture",
            "claude_code_version": VERSION,
            "cwd": CWD,
            "tools": ["Read", "Glob", "Grep"],
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
        })))
        .expect("system/init");
}

fn tool_request(event: u64, message: u64, tool: &str) -> Value {
    json!({
        "type": "assistant",
        "uuid": uuid(event),
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {
            "id": format!("msg-{message}"),
            "type": "message",
            "role": "assistant",
            "model": MODEL,
            "content": [{
                "type": "tool_use",
                "id": tool,
                "name": "Read",
                "input": {"file_path": "docs/runbooks/dogfood.md"},
            }],
            "stop_reason": "tool_use",
            "stop_sequence": null,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        },
    })
}

fn tool_result(event: u64, tool: &str) -> Value {
    json!({
        "type": "user",
        "uuid": uuid(event),
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {"role": "user", "content": [{
            "type": "tool_result",
            "tool_use_id": tool,
            "content": "read-only result",
        }]},
    })
}

fn assistant_text() -> Value {
    json!({
        "type": "assistant",
        "uuid": uuid(900_000),
        "session_id": NATIVE_SESSION,
        "parent_tool_use_id": null,
        "message": {
            "id": "msg-terminal",
            "type": "message",
            "role": "assistant",
            "model": MODEL,
            "content": [{"type": "text", "text": "proposal follows"}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        },
    })
}

fn terminal() -> Value {
    json!({
        "type": "result",
        "subtype": "success",
        "uuid": uuid(900_001),
        "session_id": NATIVE_SESSION,
        "duration_ms": 2,
        "duration_api_ms": 1,
        "is_error": false,
        "num_turns": 1,
        "result": "untrusted",
        "stop_reason": "end_turn",
        "total_cost_usd": 0.001,
        "usage": {"input_tokens": 2, "output_tokens": 2},
        "modelUsage": {MODEL: {"inputTokens": 2, "outputTokens": 2}},
        "permission_denials": [],
        "structured_output": {
            "schema_version": 1,
            "proposal_id": format!("cnt_{}", "1".repeat(64)),
            "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
            "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
            "base_checkpoint_digest": "4".repeat(64),
            "intent_summary": "bounded docs change",
            "operations": [{
                "path": "docs/runbooks/dogfood.md",
                "preimage": {"kind": "digest", "digest": "5".repeat(64)},
                "mutation": {"kind": "write", "content_utf8": "# Dogfood\n"},
            }],
            "gate_ids": [GATE],
            "claims": [],
            "uncertainties": [],
            "done": true,
        },
        "terminal_reason": "completed",
    })
}

#[test]
fn tool_lifecycle_identity_is_exact_and_single_use() {
    let mut unknown = machine("unknown");
    establish(&mut unknown);
    assert!(unknown
        .ingest_line(&line(&tool_result(10, "toolu_unknown")))
        .is_err());

    let mut duplicate_request = machine("duplicate-request");
    establish(&mut duplicate_request);
    duplicate_request
        .ingest_line(&line(&tool_request(20, 20, "toolu_same")))
        .unwrap();
    assert!(duplicate_request
        .ingest_line(&line(&tool_request(21, 21, "toolu_same")))
        .is_err());

    let mut duplicate_result = machine("duplicate-result");
    establish(&mut duplicate_result);
    duplicate_result
        .ingest_line(&line(&tool_request(30, 30, "toolu_once")))
        .unwrap();
    duplicate_result
        .ingest_line(&line(&tool_result(31, "toolu_once")))
        .unwrap();
    assert!(duplicate_result
        .ingest_line(&line(&tool_result(32, "toolu_once")))
        .is_err());

    let mut unresolved = machine("unresolved");
    establish(&mut unresolved);
    unresolved
        .ingest_line(&line(&tool_request(40, 40, "toolu_pending")))
        .unwrap();
    unresolved.ingest_line(&line(&assistant_text())).unwrap();
    assert!(unresolved.ingest_line(&line(&terminal())).is_err());
}

#[test]
fn dogfood_frame_ceiling_matches_and_enforces_guarded_transport() {
    assert_eq!(DOGFOOD_MAX_STREAM_JSON_FRAMES, MAX_INTERACTIVE_LINES as u64);
    let mut bounded = machine("frame-bound");
    establish(&mut bounded); // frame 1
    for index in 0_u64..511 {
        let tool = format!("toolu_bound_{index}");
        bounded
            .ingest_line(&line(&tool_request(1_000 + index, index, &tool)))
            .unwrap();
        bounded
            .ingest_line(&line(&tool_result(100_000 + index, &tool)))
            .unwrap();
    }
    let final_tool = "toolu_bound_final";
    bounded
        .ingest_line(&line(&tool_request(2_000, 2_000, final_tool)))
        .expect("frame at the exact transport ceiling");
    assert!(bounded
        .ingest_line(&line(&tool_result(200_000, final_tool)))
        .is_err());
}
