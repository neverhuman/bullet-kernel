//! Offline App Server contract proof. No provider process is spawned.
use bullet_harness_codex::{AppServerOutcome, CodexAdapter, CodexAppServerTranscript};
use bullet_harness_core::{
    conformance, AgentSessionId, HarnessAdapter, InvocationId, ProfileRef, SessionHandle,
    StartSession, Turn,
};
use serde_json::{json, Value};
use std::time::Duration;
const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";
const PROPOSAL: &str = r#"{"schema_version":1,"proposal_id":"cnt_1111111111111111111111111111111111111111111111111111111111111111","producing_attempt_id":"atm_2222222222222222222222222222222222222222222222222222222222222222","base_checkpoint_id":"ckp_3333333333333333333333333333333333333333333333333333333333333333","base_checkpoint_digest":"4444444444444444444444444444444444444444444444444444444444444444","operations":[{"path":"PONG.txt","preimage":{"kind":"absent"},"mutation":{"kind":"write","content_utf8":"PONG\n"}}],"gate_ids":["gat_8888888888888888888888888888888888888888888888888888888888888888"],"intent_summary":"write fixture","claims":[],"uncertainties":[],"done":true}"#;
fn machine() -> CodexAppServerTranscript {
    CodexAppServerTranscript::new(
        AgentSessionId::new("session-1"),
        InvocationId::new("invocation-1"),
        "0.1.0-test",
        "0.149.1",
        vec![GATE.into()],
    )
    .expect("machine")
}
fn line(value: Value) -> String {
    serde_json::to_string(&value).expect("json")
}
fn initialize_result() -> Value {
    json!({"codexHome":"/ephemeral/codex","platformFamily":"unix","platformOs":"linux","userAgent":"codex-test"})
}
fn thread(id: &str) -> Value {
    json!({"cliVersion":"0.149.1","createdAt":1,"cwd":"/private/readonly","ephemeral":true,"id":id,"modelProvider":"openai","preview":"","projectId":null,"sessionId":id,"source":"appServer","status":{"type":"idle"},"turns":[],"updatedAt":1})
}
fn thread_result(id: &str) -> Value {
    json!({"approvalPolicy":"never","approvalsReviewer":"user","cwd":"/private/readonly","model":"offline-model","modelProvider":"openai","sandbox":"read-only","thread":thread(id)})
}
fn turn(id: &str, status: &str) -> Value {
    json!({"id": id, "status": status, "items": []})
}
fn completed_turn(proposal: &str) -> Value {
    json!({"id":"turn-1","status":"completed","items":[{"id":"item-1","type":"agentMessage","text":proposal}]})
}
fn establish_thread(machine: &mut CodexAppServerTranscript) {
    let initialize = machine.initialize_request().expect("initialize");
    assert_eq!(initialize["method"], "initialize");
    assert_eq!(initialize["params"]["clientInfo"]["version"], "0.1.0-test");
    assert!(initialize.get("jsonrpc").is_none());
    machine
        .ingest_line(&line(json!({"id": 1, "result": initialize_result()})))
        .expect("initialize response");
    assert_eq!(
        machine.initialized_notification().expect("initialized"),
        json!({"method": "initialized", "params": {}})
    );
    assert_eq!(
        machine
            .thread_start_request("/private/readonly")
            .expect("thread request")["id"],
        2
    );
    machine
        .ingest_line(&line(
            json!({"method":"thread/started","params":{"thread":thread("thread-1")}}),
        ))
        .expect("thread notification may precede response");
    machine
        .ingest_line(&line(json!({"id":2,"result":thread_result("thread-1")})))
        .expect("thread response");
}
fn establish(machine: &mut CodexAppServerTranscript) {
    establish_thread(machine);
    let turn_request = machine
        .turn_start_request("produce the admitted proposal", "/private/readonly")
        .expect("turn request");
    assert_eq!(turn_request["id"], 3);
    assert_eq!(turn_request["params"]["approvalPolicy"], "never");
    assert_eq!(turn_request["params"]["sandboxPolicy"]["type"], "readOnly");
    assert_eq!(
        turn_request["params"]["outputSchema"]["title"],
        "PatchProposal"
    );
    machine
        .ingest_line(&line(
            json!({"id":3,"result":{"turn":turn("turn-1", "inProgress")}}),
        ))
        .expect("turn response");
    machine
        .ingest_line(&line(json!({"method":"turn/started","params":{"threadId":"thread-1","turn":turn("turn-1", "inProgress")}})))
        .expect("turn notification");
}
fn start_item(machine: &mut CodexAppServerTranscript, id: &str, kind: &str) {
    machine
        .ingest_line(&line(json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":id,"type":kind}}})))
        .expect("item started");
}
fn complete_item(machine: &mut CodexAppServerTranscript, id: &str, kind: &str, text: Option<&str>) {
    let mut item = json!({"id": id, "type": kind});
    if let Some(text) = text {
        item["text"] = Value::String(text.to_string());
    }
    machine
        .ingest_line(&line(json!({"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","completedAtMs":11,"item":item}})))
        .expect("item completed");
}
fn complete(machine: &mut CodexAppServerTranscript, proposal: &str) {
    start_item(machine, "item-1", "agentMessage");
    machine
        .ingest_line(&line(json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":"{"}})))
        .expect("delta");
    complete_item(machine, "item-1", "agentMessage", Some(proposal));
    machine
        .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":completed_turn(proposal)}})))
        .expect("turn completed");
}
#[tokio::test]
async fn offline_conformance_and_every_public_runtime_path_are_blocked() {
    let adapter = CodexAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
    let descriptor = adapter.descriptor();
    assert_eq!(descriptor.binary, "codex");
    assert!(matches!(
        descriptor.version,
        bullet_domain::Observation::Unknown { .. }
    ));
    let profile = ProfileRef {
        profile_id: bullet_domain::ProfileId::from_seed("offline"),
        expected: Default::default(),
    };
    assert_eq!(
        adapter
            .probe(&profile)
            .await
            .expect_err("ambient probe blocked")
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let err = adapter
        .start(StartSession {
            session_id: AgentSessionId::new("blocked"),
            workdir: dir.path().to_path_buf(),
            artifact_dir: dir.path().join("artifacts"),
            model: None,
            structured_schema: None,
            max_budget_usd: None,
            wall_timeout: Duration::from_secs(1),
        })
        .await
        .expect_err("dispatch blocked");
    assert_eq!(err.reason_code(), "PROVIDER_ADMISSION_BLOCKED");
    assert!(!dir.path().join("artifacts").exists());
    let handle = SessionHandle {
        session_id: AgentSessionId::new("blocked"),
        provider: "codex".into(),
        native_session_id: None,
    };
    assert_eq!(
        adapter
            .send(&handle, Turn { prompt: "x".into() })
            .await
            .expect_err("send blocked")
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
}

#[test]
fn stable_correlated_lifecycle_yields_only_exact_admitted_proposal() {
    let mut machine = machine();
    establish(&mut machine);
    complete(&mut machine, PROPOSAL);
    let AppServerOutcome::Proposal(proposal) = machine.outcome().expect("outcome") else {
        panic!("expected proposal");
    };
    assert_eq!(proposal.gate_ids, [GATE]);
    assert_eq!(proposal.operations[0].path, "PONG.txt");
}

#[test]
fn malformed_wrong_duplicate_and_late_frames_poison_the_transcript() {
    for bad in [
        "not-json",
        "[]",
        "{\"id\":1}",
        "{\"method\":1,\"params\":{}}",
        r#"{"id":1,"result":{"codexHome":"/x","platformFamily":"unix","platformOs":"bad","platformOs":"linux","userAgent":"codex-test"}}"#,
    ] {
        let mut machine = machine();
        machine.initialize_request().unwrap();
        assert_eq!(
            machine.ingest_line(bad).unwrap_err().reason_code(),
            "PROTOCOL_ERROR"
        );
        assert_eq!(
            machine.ingest_line("{}").unwrap_err().reason_code(),
            "PROTOCOL_ERROR"
        );
    }

    let mut wrong = machine();
    wrong.initialize_request().unwrap();
    assert!(wrong
        .ingest_line(&line(json!({"id":9,"result":{}})))
        .is_err());

    let mut server_error = machine();
    server_error.initialize_request().unwrap();
    assert!(server_error
        .ingest_line(&line(json!({"id":1,"error":{"code":-1,"message":"no"}})))
        .is_err());

    let mut duplicate = machine();
    establish(&mut duplicate);
    let repeated = line(
        json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":"item-1","type":"agentMessage"}}}),
    );
    duplicate.ingest_line(&repeated).unwrap();
    assert!(duplicate.ingest_line(&repeated).is_err());

    let mut late = machine();
    establish(&mut late);
    complete(&mut late, PROPOSAL);
    assert!(late.ingest_line("{}").is_err());
}

#[test]
fn handshake_shapes_versions_and_subjects_are_exact() {
    let mut missing_runtime_shape = machine();
    missing_runtime_shape.initialize_request().unwrap();
    assert!(missing_runtime_shape
        .ingest_line(&line(json!({"id":1,"result":{"userAgent":"0.149.1"}})))
        .is_err());

    let mut thread_mismatch = machine();
    thread_mismatch.initialize_request().unwrap();
    thread_mismatch
        .ingest_line(&line(json!({"id":1,"result":initialize_result()})))
        .unwrap();
    thread_mismatch.initialized_notification().unwrap();
    thread_mismatch
        .thread_start_request("/private/readonly")
        .unwrap();
    thread_mismatch
        .ingest_line(&line(
            json!({"method":"thread/started","params":{"thread":thread("thread-1")}}),
        ))
        .unwrap();
    assert!(thread_mismatch
        .ingest_line(&line(json!({"id":2,"result":thread_result("thread-2")})))
        .is_err());

    let mut cwd_mismatch = machine();
    establish_thread(&mut cwd_mismatch);
    assert!(cwd_mismatch
        .turn_start_request("x", "/different/read-only")
        .is_err());

    let mut turn_mismatch = machine();
    establish_thread(&mut turn_mismatch);
    turn_mismatch
        .turn_start_request("x", "/private/readonly")
        .unwrap();
    turn_mismatch
        .ingest_line(&line(
            json!({"id":3,"result":{"turn":turn("turn-1", "inProgress")}}),
        ))
        .unwrap();
    assert!(turn_mismatch
        .ingest_line(&line(json!({"method":"turn/started","params":{"threadId":"thread-1","turn":turn("turn-2", "inProgress")}})))
        .is_err());
}

#[test]
fn terminal_items_are_the_exact_completed_set() {
    let invalid = [
        json!([{"id":"other","type":"agentMessage","text":PROPOSAL}]),
        json!([{"id":"item-1","type":"agentMessage","text":"different"}]),
        json!([{"id":"item-1","type":"fileChange","text":PROPOSAL}]),
        json!([{"id":"item-1","type":"unknown","text":PROPOSAL}]),
        json!([
            {"id":"item-1","type":"agentMessage","text":PROPOSAL},
            {"id":"item-1","type":"agentMessage","text":PROPOSAL}
        ]),
    ];
    for items in invalid {
        let mut machine = machine();
        establish(&mut machine);
        start_item(&mut machine, "item-1", "agentMessage");
        complete_item(&mut machine, "item-1", "agentMessage", Some(PROPOSAL));
        assert!(machine
            .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":items}}})))
            .is_err());
    }

    let mut multiple = machine();
    establish(&mut multiple);
    start_item(&mut multiple, "item-1", "agentMessage");
    complete_item(&mut multiple, "item-1", "agentMessage", Some(PROPOSAL));
    start_item(&mut multiple, "item-2", "agentMessage");
    assert!(multiple.ingest_line(&line(json!({"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","completedAtMs":11,"item":{"id":"item-2","type":"agentMessage","text":PROPOSAL}}}))).is_err());

    let mut missing = machine();
    establish(&mut missing);
    start_item(&mut missing, "reason-1", "reasoning");
    complete_item(&mut missing, "reason-1", "reasoning", None);
    start_item(&mut missing, "item-1", "agentMessage");
    complete_item(&mut missing, "item-1", "agentMessage", Some(PROPOSAL));
    assert!(missing
        .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":completed_turn(PROPOSAL)}})))
        .is_err());
}

#[test]
fn subject_mismatch_replay_and_file_change_are_refused() {
    let mutations = [
        json!({"method":"item/started","params":{"threadId":"other","turnId":"turn-1","startedAtMs":10,"item":{"id":"item-1","type":"agentMessage"}}}),
        json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"other","startedAtMs":10,"item":{"id":"item-1","type":"agentMessage"}}}),
        json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":"item-1","type":"fileChange"}}}),
    ];
    for mutation in mutations {
        let mut machine = machine();
        establish(&mut machine);
        assert_eq!(
            machine
                .ingest_line(&line(mutation))
                .unwrap_err()
                .reason_code(),
            "PROTOCOL_ERROR"
        );
    }

    let mut replay = machine();
    replay.initialize_request().unwrap();
    replay
        .ingest_line(&line(json!({"id":1,"result":initialize_result()})))
        .unwrap();
    replay.initialized_notification().unwrap();
    replay.thread_start_request("/private/readonly").unwrap();
    let response = line(json!({"id":2,"result":thread_result("thread-1")}));
    replay.ingest_line(&response).unwrap();
    assert!(replay.ingest_line(&response).is_err());
}

#[test]
fn proposal_and_gate_mismatches_never_complete() {
    for proposal in [
        "not-json",
        r#"{"intent_summary":"x","changes":[],"gate_ids":["cargo test"],"claims":[],"uncertainties":[],"done":true}"#,
        r#"{"intent_summary":"x","changes":[],"gate_ids":["other.gate"],"claims":[],"uncertainties":[],"done":true}"#,
        r#"{"intent_summary":"x","changes":[],"gate_ids":["other.gate"],"gate_ids":["repo.gate.v1"],"claims":[],"uncertainties":[],"done":true}"#,
    ] {
        let mut machine = machine();
        establish(&mut machine);
        machine
            .ingest_line(&line(json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":"item-1","type":"agentMessage"}}})))
            .unwrap();
        machine
            .ingest_line(&line(json!({"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","completedAtMs":11,"item":{"id":"item-1","type":"agentMessage","text":proposal}}})))
            .unwrap();
        assert!(machine
            .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":completed_turn(proposal)}})))
            .is_err());
    }

    let mut delta_only = machine();
    establish(&mut delta_only);
    delta_only
        .ingest_line(&line(json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":"item-1","type":"agentMessage"}}})))
        .unwrap();
    delta_only
        .ingest_line(&line(json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":PROPOSAL}})))
        .unwrap();
    assert!(delta_only
        .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":completed_turn(PROPOSAL)}})))
        .is_err());

    let mut ordered = CodexAppServerTranscript::new(
        AgentSessionId::new("session-order"),
        InvocationId::new("invocation-order"),
        "0.1.0-test",
        "0.149.1",
        vec![GATE.into(), format!("gat_{}", "9".repeat(64))],
    )
    .unwrap();
    establish(&mut ordered);
    let reversed = PROPOSAL.replace(
        &format!("\"{GATE}\""),
        &format!("\"gat_{}\",\"{GATE}\"", "9".repeat(64)),
    );
    ordered
        .ingest_line(&line(json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":"item-1","type":"agentMessage"}}})))
        .unwrap();
    ordered
        .ingest_line(&line(json!({"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","completedAtMs":11,"item":{"id":"item-1","type":"agentMessage","text":reversed}}})))
        .unwrap();
    assert!(ordered
        .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":completed_turn(&reversed)}})))
        .is_err());
}

#[test]
fn cancel_and_timeout_require_exact_ack_and_interrupted_terminal() {
    for timed_out in [false, true] {
        let mut machine = machine();
        establish(&mut machine);
        let request = if timed_out {
            machine.timeout_request().unwrap()
        } else {
            machine.interrupt_request().unwrap()
        };
        assert_eq!(request["method"], "turn/interrupt");
        assert_eq!(request["params"]["threadId"], "thread-1");
        assert_eq!(request["params"]["turnId"], "turn-1");
        machine
            .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":turn("turn-1", "interrupted")}})))
            .unwrap();
        assert!(machine.outcome().is_err(), "ack is still required");
        machine
            .ingest_line(&line(json!({"id":4,"result":{}})))
            .unwrap();
        let expected = if timed_out {
            &AppServerOutcome::TimedOut
        } else {
            &AppServerOutcome::Interrupted
        };
        assert_eq!(machine.outcome().unwrap(), expected);
    }

    let mut disagreement = machine();
    establish(&mut disagreement);
    disagreement.interrupt_request().unwrap();
    disagreement
        .ingest_line(&line(json!({"id":4,"result":{}})))
        .unwrap();
    assert!(disagreement
        .ingest_line(&line(json!({"method":"turn/completed","params":{"threadId":"thread-1","turn":turn("turn-1", "completed")}})))
        .is_err());
}

#[test]
fn frame_transcript_and_item_limits_are_exact() {
    let cwd = "/private/readonly";
    let mut base = machine();
    establish_thread(&mut base);
    let base_len = line(base.turn_start_request("x", cwd).unwrap()).len();
    let exact_prompt = "x".repeat(CodexAppServerTranscript::MAX_FRAME_BYTES - base_len + 1);
    let mut exact_outbound = machine();
    establish_thread(&mut exact_outbound);
    let request = exact_outbound
        .turn_start_request(&exact_prompt, cwd)
        .expect("exact outbound frame limit");
    assert_eq!(
        line(request).len(),
        CodexAppServerTranscript::MAX_FRAME_BYTES
    );
    let mut oversized_outbound = machine();
    establish_thread(&mut oversized_outbound);
    assert!(oversized_outbound
        .turn_start_request(&(exact_prompt + "x"), cwd)
        .is_err());

    let active = || {
        let mut machine = machine();
        establish(&mut machine);
        start_item(&mut machine, "item-1", "agentMessage");
        machine
    };
    let empty_delta = line(
        json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":""}}),
    );
    let exact_delta = "x".repeat(CodexAppServerTranscript::MAX_FRAME_BYTES - empty_delta.len());
    let exact_line = line(
        json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":exact_delta}}),
    );
    assert_eq!(exact_line.len(), CodexAppServerTranscript::MAX_FRAME_BYTES);
    active()
        .ingest_line(&exact_line)
        .expect("exact inbound frame limit");
    let oversized_line = line(
        json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":format!("{}x", exact_delta)}}),
    );
    assert_eq!(
        oversized_line.len(),
        CodexAppServerTranscript::MAX_FRAME_BYTES + 1
    );
    assert!(active().ingest_line(&oversized_line).is_err());

    let mut frames = active();
    for index in 6..CodexAppServerTranscript::MAX_TRANSCRIPT_FRAMES {
        frames.ingest_line(&line(json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":index.to_string()}}))).unwrap();
    }
    assert!(frames.ingest_line(&line(json!({"method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","delta":"over"}}))).is_err());

    let mut items = machine();
    establish(&mut items);
    for index in 0..CodexAppServerTranscript::MAX_ITEMS {
        let id = format!("reason-{index}");
        start_item(&mut items, &id, "reasoning");
        complete_item(&mut items, &id, "reasoning", None);
    }
    assert!(items.ingest_line(&line(json!({"method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","startedAtMs":10,"item":{"id":"reason-over","type":"reasoning"}}}))).is_err());
}
