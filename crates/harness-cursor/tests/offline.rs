//! Offline Cursor ACP proof. No provider process is spawned.

use bullet_harness_core::{
    conformance, AgentEventKind, AgentSessionId, HarnessAdapter, InvocationId, PatchProposal,
};
use bullet_harness_cursor::{CursorAcpOutcome, CursorAcpTranscript, CursorAdapter};
use serde_json::{json, Value};

const RUNTIME: &str = "2026.08.11-e8db854";
const SUBJECT: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
const CWD: &str = "/private/bullet/workspace-7";
const NATIVE_SESSION: &str = "cursor-session-7";
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";

fn line(value: Value) -> String {
    serde_json::to_string(&value).expect("fixture serializes")
}

fn proposal() -> Value {
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "create fixture",
        "operations": [{
            "path": "PONG.txt",
            "preimage": {"kind": "absent"},
            "mutation": {"kind": "write", "content_utf8": "PONG\n"}
        }],
        "gate_ids": [GATE],
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

fn machine() -> CursorAcpTranscript {
    CursorAcpTranscript::new(
        AgentSessionId::new("kernel-session-7"),
        InvocationId::new("kernel-invocation-7"),
        "0.1.0",
        RUNTIME,
        SUBJECT,
        vec![GATE.into()],
    )
    .expect("machine")
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": 1,
        "agentCapabilities": {
            "loadSession": true,
            "promptCapabilities": {"image": true, "audio": false, "embeddedContext": false},
            "mcpCapabilities": {"http": true, "sse": true},
            "_meta": {"bullet.farm": {"patchProposal": "v1", "readOnly": true}}
        },
        "agentInfo": {"name": "Cursor Agent", "version": RUNTIME},
        "authMethods": [{"id": "cursor_login", "name": "Cursor Login"}]
    })
}

fn session_meta() -> Value {
    json!({"bullet.farm": {
        "protocol": "patch-proposal-v1",
        "subjectDigest": SUBJECT,
        "runtimeVersion": RUNTIME,
        "readOnly": true,
        "cwd": CWD
    }})
}

fn prompt_meta(proposal: Value) -> Value {
    json!({"bullet.farm": {
        "protocol": "patch-proposal-v1",
        "subjectDigest": SUBJECT,
        "runtimeVersion": RUNTIME,
        "readOnly": true,
        "cwd": CWD,
        "sessionId": NATIVE_SESSION,
        "requestId": 4,
        "proposal": proposal
    }})
}

fn establish(machine: &mut CursorAcpTranscript) {
    let initialize = machine.initialize_request().expect("initialize request");
    assert_eq!(initialize["jsonrpc"], "2.0");
    assert_eq!(initialize["id"], 1);
    assert_eq!(initialize["params"]["protocolVersion"], 1);
    assert_eq!(
        initialize["params"]["clientCapabilities"]["fs"]["writeTextFile"],
        false
    );
    assert_eq!(
        initialize["params"]["clientCapabilities"]["terminal"],
        false
    );
    machine
        .ingest_line(&line(json!({
            "jsonrpc": "2.0", "id": 1, "result": initialize_result()
        })))
        .expect("initialize response");

    let authenticate = machine
        .authenticate_request()
        .expect("authenticate request");
    assert_eq!(authenticate["id"], 2);
    assert_eq!(authenticate["params"]["methodId"], "cursor_login");
    machine
        .ingest_line(&line(json!({"jsonrpc": "2.0", "id": 2, "result": {}})))
        .expect("authenticate response");

    let session = machine.session_new_request(CWD).expect("session request");
    assert_eq!(session["id"], 3);
    assert_eq!(session["params"]["cwd"], CWD);
    assert_eq!(session["params"]["mcpServers"], json!([]));
    let events = machine
        .ingest_line(&line(json!({
            "jsonrpc": "2.0", "id": 3,
            "result": {"sessionId": NATIVE_SESSION, "_meta": session_meta()}
        })))
        .expect("session response");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, AgentEventKind::SessionReady);

    let prompt = machine
        .prompt_request("Return the typed patch.")
        .expect("prompt");
    assert_eq!(prompt["id"], 4);
    assert_eq!(prompt["params"]["sessionId"], NATIVE_SESSION);
    assert_eq!(
        prompt["params"]["_meta"]["bullet.farm"]["subjectDigest"],
        SUBJECT
    );
    assert_eq!(
        prompt["params"]["_meta"]["bullet.farm"]["gateIds"],
        json!([GATE])
    );
    assert!(prompt["params"]["_meta"]["bullet.farm"]["proposalSchema"].is_object());
}

fn establish_until_ready(machine: &mut CursorAcpTranscript) {
    machine.initialize_request().unwrap();
    machine
        .ingest_line(&line(
            json!({"jsonrpc":"2.0","id":1,"result":initialize_result()}),
        ))
        .unwrap();
    machine.authenticate_request().unwrap();
    machine
        .ingest_line(&line(json!({"jsonrpc":"2.0","id":2,"result":{}})))
        .unwrap();
    machine.session_new_request(CWD).unwrap();
    machine
        .ingest_line(&line(json!({
            "jsonrpc":"2.0","id":3,
            "result":{"sessionId":NATIVE_SESSION,"_meta":session_meta()}
        })))
        .unwrap();
}

fn completion(proposal: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 4,
        "result": {"stopReason": "end_turn", "_meta": prompt_meta(proposal)}
    })
}

fn text_update(text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": NATIVE_SESSION,
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": text}
            }
        }
    })
}

#[tokio::test]
async fn public_adapter_is_honest_offline_contract() {
    let adapter = CursorAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
    assert_eq!(adapter.descriptor().binary, "agent");
}

#[test]
fn exact_acp_transcript_yields_only_a_writer_proposal() {
    let mut machine = machine();
    establish(&mut machine);
    let delta = machine
        .ingest_line(&line(text_update("untrusted progress")))
        .expect("bounded delta");
    assert_eq!(delta[0].kind, AgentEventKind::TurnDelta);
    assert_eq!(delta[0].payload["authoritative"], false);
    let events = machine
        .ingest_line(&line(completion(proposal())))
        .expect("terminal response");
    assert_eq!(events[0].kind, AgentEventKind::TurnCompleted);
    assert_eq!(events[0].payload["verified"], false);
    let CursorAcpOutcome::Proposal(actual) = machine.outcome().expect("outcome");
    assert_eq!(actual.gate_ids, [GATE]);
    assert_eq!(actual.operations[0].path, "PONG.txt");
}

#[test]
fn cancellation_and_timeout_are_unsupported_and_never_outcomes() {
    for timed_out in [false, true] {
        let mut machine = machine();
        establish(&mut machine);
        let error = if timed_out {
            machine.timeout_notification().unwrap_err()
        } else {
            machine.cancel_notification().unwrap_err()
        };
        assert_eq!(error.reason_code(), "UNSUPPORTED");
        assert!(machine.outcome().is_err());
        assert!(machine
            .ingest_line(&line(json!({
                "jsonrpc": "2.0", "id": 4,
                "error": {"code": -32800, "message": "Request cancelled"}
            })))
            .is_err());
    }
}

#[test]
fn exact_subject_version_session_cwd_request_and_gates_are_bound() {
    let mut wrong_version = machine();
    wrong_version.initialize_request().unwrap();
    let mut init = initialize_result();
    init["agentInfo"]["version"] = json!("other");
    assert!(wrong_version
        .ingest_line(&line(json!({"jsonrpc": "2.0", "id": 1, "result": init})))
        .is_err());

    for (field, replacement) in [
        (
            "subjectDigest",
            json!("blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ),
        ("runtimeVersion", json!("other")),
        ("cwd", json!("/other")),
        ("sessionId", json!("other-session")),
        ("requestId", json!(99)),
    ] {
        let mut machine = machine();
        establish(&mut machine);
        let mut response = completion(proposal());
        response["result"]["_meta"]["bullet.farm"][field] = replacement;
        assert!(machine.ingest_line(&line(response)).is_err(), "{field}");
    }

    let mut wrong_gates = machine();
    establish(&mut wrong_gates);
    let mut bad = proposal();
    bad["gate_ids"] = json!(["other.gate"]);
    assert!(wrong_gates.ingest_line(&line(completion(bad))).is_err());

    let mut wrong_stop = machine();
    establish(&mut wrong_stop);
    let mut response = completion(proposal());
    response["result"]["stopReason"] = json!("max_tokens");
    assert!(wrong_stop.ingest_line(&line(response)).is_err());
}

#[test]
fn malformed_unknown_duplicate_conflicting_and_late_frames_poison() {
    for bad in ["not-json", "[]", "{}", r#"{"jsonrpc":"1.0"}"#] {
        let mut machine = machine();
        machine.initialize_request().unwrap();
        assert_eq!(
            machine.ingest_line(bad).unwrap_err().reason_code(),
            "PROTOCOL_ERROR"
        );
        assert!(machine
            .ingest_line(&line(json!({
                "jsonrpc": "2.0", "id": 1, "result": initialize_result()
            })))
            .is_err());
    }

    for delimiter in ['\n', '\r', '\0'] {
        let mut machine = machine();
        machine.initialize_request().unwrap();
        let valid = line(json!({"jsonrpc": "2.0", "id": 1, "result": initialize_result()}));
        assert!(machine.ingest_line(&format!("{valid}{delimiter}")).is_err());
        assert!(machine.ingest_line(&valid).is_err());
    }

    let mut nested = machine();
    nested.initialize_request().unwrap();
    let valid = line(json!({"jsonrpc": "2.0", "id": 1, "result": initialize_result()}));
    let duplicate = valid.replacen(
        r#""readOnly":true"#,
        r#""readOnly":false,"readOnly":true"#,
        1,
    );
    assert!(nested.ingest_line(&duplicate).is_err());
    assert!(nested.ingest_line(&valid).is_err());

    let mut malformed_capability = machine();
    malformed_capability.initialize_request().unwrap();
    let mut init = initialize_result();
    init["agentCapabilities"]["loadSession"] = json!("yes");
    assert!(malformed_capability
        .ingest_line(&line(json!({"jsonrpc": "2.0", "id": 1, "result": init})))
        .is_err());

    let mut duplicate_auth = machine();
    duplicate_auth.initialize_request().unwrap();
    let mut init = initialize_result();
    init["authMethods"] = json!([
        {"id": "cursor_login", "name": "one"},
        {"id": "cursor_login", "name": "two"}
    ]);
    assert!(duplicate_auth
        .ingest_line(&line(json!({"jsonrpc": "2.0", "id": 1, "result": init})))
        .is_err());

    let mut duplicate = machine();
    establish(&mut duplicate);
    let update = line(text_update("same"));
    duplicate.ingest_line(&update).unwrap();
    assert!(duplicate.ingest_line(&update).is_err());

    for frame in [
        json!({"jsonrpc":"2.0","id":9,"result":{}}),
        json!({"jsonrpc":"2.0","id":8,"method":"session/request_permission","params":{}}),
        json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"wrong","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"x"}}}}),
        json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":NATIVE_SESSION,"update":{"sessionUpdate":"tool_call","content":{"type":"text","text":"edit"}}}}),
    ] {
        let mut machine = machine();
        establish(&mut machine);
        assert!(machine.ingest_line(&line(frame)).is_err());
    }

    let mut late = machine();
    establish(&mut late);
    late.ingest_line(&line(completion(proposal()))).unwrap();
    assert!(late.ingest_line(&line(text_update("late"))).is_err());
}

#[test]
fn every_resource_dimension_is_bounded() {
    assert!(CursorAcpTranscript::new(
        AgentSessionId::new("s"),
        InvocationId::new("i"),
        "client",
        RUNTIME,
        "sha1:not-a-subject",
        vec![GATE.into()]
    )
    .is_err());
    assert!(CursorAcpTranscript::new(
        AgentSessionId::new("s"),
        InvocationId::new("i"),
        "client",
        RUNTIME,
        SUBJECT,
        vec![GATE.into(), GATE.into()]
    )
    .is_err());

    let mut bad_cwd = machine();
    bad_cwd.initialize_request().unwrap();
    bad_cwd
        .ingest_line(&line(
            json!({"jsonrpc":"2.0","id":1,"result":initialize_result()}),
        ))
        .unwrap();
    bad_cwd.authenticate_request().unwrap();
    bad_cwd
        .ingest_line(&line(json!({"jsonrpc":"2.0","id":2,"result":{}})))
        .unwrap();
    assert!(bad_cwd.session_new_request("relative").is_err());

    let mut huge_prompt = machine();
    establish_until_ready(&mut huge_prompt);
    assert!(huge_prompt
        .prompt_request(&"x".repeat(CursorAcpTranscript::MAX_PROMPT_BYTES + 1))
        .is_err());

    let mut huge_frame = machine();
    huge_frame.initialize_request().unwrap();
    assert!(huge_frame
        .ingest_line(&"x".repeat(CursorAcpTranscript::MAX_FRAME_BYTES + 1))
        .is_err());

    let mut huge_chunk = machine();
    establish(&mut huge_chunk);
    assert!(huge_chunk
        .ingest_line(&line(text_update(
            &"x".repeat(CursorAcpTranscript::MAX_CHUNK_BYTES + 1)
        )))
        .is_err());

    let mut updates = machine();
    establish(&mut updates);
    for index in 0..CursorAcpTranscript::MAX_UPDATES {
        updates
            .ingest_line(&line(text_update(&format!("chunk-{index}"))))
            .unwrap();
    }
    assert!(updates
        .ingest_line(&line(text_update("one-too-many")))
        .is_err());
}

#[test]
fn proposal_payload_is_not_free_text() {
    let free_text = Value::String(
        serde_json::to_string(&PatchProposal::from_value(&proposal()).unwrap()).unwrap(),
    );
    let mut machine = machine();
    establish(&mut machine);
    assert!(machine.ingest_line(&line(completion(free_text))).is_err());
}
