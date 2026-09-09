//! Offline Antigravity contract proof. No provider process is spawned.

use bullet_domain::ProfileId;
use bullet_harness_antigravity::{
    AgyHeadlessTranscript, AntigravityAdapter, MAX_OUTPUT_FRAME_BYTES, MAX_PROMPT_BYTES,
    OBSERVED_AGY_BINARY_SHA256, OBSERVED_AGY_VERSION,
};
use bullet_harness_core::{
    conformance, proposal::schema_source, AgentEventKind, AgentSessionId, Capability,
    CapabilityState, HarnessAdapter, InvocationId, ProfileRef, SessionHandle, StartSession, Turn,
};
use futures::StreamExt;
use serde_json::{json, Value};
use std::time::Duration;

const SESSION: &str = "kernel-session-1";
const INVOCATION: &str = "kernel-invocation-1";
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

fn result_line(value: Value) -> String {
    serde_json::to_string(&json!({"structured_output": value})).expect("JSON")
}

fn machine_with_prompt(prompt: impl Into<String>) -> AgyHeadlessTranscript {
    AgyHeadlessTranscript::new(
        AgentSessionId::new(SESSION),
        InvocationId::new(INVOCATION),
        ProfileId::from_seed("agy-offline"),
        CWD,
        OBSERVED_AGY_VERSION,
        OBSERVED_AGY_BINARY_SHA256,
        prompt,
        vec![GATE.into()],
    )
    .expect("machine")
}

fn machine() -> AgyHeadlessTranscript {
    machine_with_prompt("produce the admitted proposal")
}

fn prepared() -> AgyHeadlessTranscript {
    let mut machine = machine();
    machine.turn_argv("10m").expect("argv");
    machine
}

#[tokio::test]
async fn conformance_and_all_public_runtime_paths_fail_closed() {
    let adapter = AntigravityAdapter::new();
    conformance::offline_suite(&adapter)
        .await
        .expect("offline suite");
    let descriptor = adapter.descriptor();
    assert!(matches!(
        descriptor.version,
        bullet_domain::Observation::Unknown { .. }
    ));
    assert_eq!(
        descriptor.capabilities.state(Capability::StructuredEvents),
        CapabilityState::Unsupported
    );
    assert_eq!(
        descriptor
            .capabilities
            .state(Capability::StructuredOutputSchema),
        CapabilityState::SupportedWithLimitations
    );
    assert_eq!(
        descriptor.capabilities.state(Capability::TurnInterrupt),
        CapabilityState::Unsupported
    );

    let profile = ProfileRef {
        profile_id: ProfileId::from_seed("blocked"),
        expected: Default::default(),
    };
    assert_eq!(
        adapter
            .probe(&profile)
            .await
            .expect_err("probe blocked")
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    let request = StartSession {
        session_id: AgentSessionId::new("blocked-session"),
        workdir: CWD.into(),
        artifact_dir: "/must/not/exist".into(),
        model: None,
        structured_schema: Some(json!({"type": "object"})),
        max_budget_usd: None,
        wall_timeout: Duration::from_secs(1),
    };
    assert_eq!(
        adapter
            .start(request)
            .await
            .expect_err("start blocked")
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    let handle = SessionHandle {
        session_id: AgentSessionId::new("blocked-session"),
        provider: "agy".into(),
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
    assert_eq!(
        adapter
            .interrupt(&handle)
            .await
            .expect_err("interrupt unsupported")
            .reason_code(),
        "UNSUPPORTED"
    );
    assert_eq!(
        adapter
            .terminate(&handle)
            .await
            .expect_err("terminate blocked")
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    assert!(adapter.events(&handle).collect::<Vec<_>>().await.is_empty());
}

#[test]
fn argv_binds_schema_plan_sandbox_timeout_and_final_multiline_prompt() {
    let prompt = "line one\nline two";
    let mut machine = machine_with_prompt(prompt);
    let args = machine.turn_argv("10m").expect("argv");
    assert_eq!(
        &args[..8],
        [
            "--sandbox",
            "--mode",
            "plan",
            "--print-timeout",
            "10m",
            "--output-format",
            "json",
            "--json-schema",
        ]
    );
    assert_eq!(args[8], schema_source());
    assert_eq!(args.last().expect("prompt"), &format!("-p={prompt}"));
    assert!(args[..args.len() - 1]
        .iter()
        .all(|arg| !arg.starts_with("-p=")));
    assert_eq!(
        machine
            .turn_argv("10m")
            .expect_err("one request only")
            .reason_code(),
        "PROTOCOL_ERROR"
    );
}

#[test]
fn exact_structured_output_yields_only_a_bound_unverified_proposal() {
    let mut machine = prepared();
    let events = machine
        .ingest_result_line(&result_line(proposal()))
        .expect("result");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, AgentEventKind::TurnCompleted);
    assert_eq!(events[0].payload["verified"], false);
    assert_eq!(events[0].payload["binding"]["provider"], "agy");
    assert_eq!(events[0].payload["binding"]["binary"], "agy");
    assert_eq!(events[0].payload["binding"]["invocation_id"], INVOCATION);
    assert_eq!(
        events[0].payload["binding"]["profile_id"],
        ProfileId::from_seed("agy-offline").as_str()
    );
    assert_eq!(events[0].payload["binding"]["cwd"], CWD);
    assert_eq!(
        events[0].payload["binding"]["runtime_version"],
        OBSERVED_AGY_VERSION
    );
    assert_eq!(
        events[0].payload["binding"]["binary_sha256"],
        OBSERVED_AGY_BINARY_SHA256
    );
    let outcome = machine.outcome().expect("outcome");
    assert_eq!(outcome.proposal.gate_ids, [GATE]);
    assert!(outcome.binding.prompt_digest.starts_with("blake3:"));
    assert_eq!(outcome.binding.prompt_digest.len(), 71);

    let mut different_prompt = machine_with_prompt("different prompt");
    different_prompt.turn_argv("10m").expect("argv");
    different_prompt
        .ingest_result_line(&result_line(proposal()))
        .expect("result");
    assert_ne!(
        outcome.binding.prompt_digest,
        different_prompt
            .outcome()
            .expect("different outcome")
            .binding
            .prompt_digest
    );
}

#[test]
fn subject_and_outbound_boundaries_are_exact() {
    for (version, digest, cwd) in [
        ("1.1.20", OBSERVED_AGY_BINARY_SHA256, CWD),
        (OBSERVED_AGY_VERSION, "sha256:00", CWD),
        (OBSERVED_AGY_VERSION, OBSERVED_AGY_BINARY_SHA256, "relative"),
        (OBSERVED_AGY_VERSION, OBSERVED_AGY_BINARY_SHA256, "/x/../y"),
    ] {
        let error = AgyHeadlessTranscript::new(
            AgentSessionId::new(SESSION),
            InvocationId::new(INVOCATION),
            ProfileId::from_seed("agy-offline"),
            cwd,
            version,
            digest,
            "prompt",
            vec![GATE.into()],
        )
        .err()
        .expect("subject rejected");
        assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    }
    let mut max = machine_with_prompt("x".repeat(MAX_PROMPT_BYTES));
    assert!(max.turn_argv("10m").is_ok());
    let too_large = AgyHeadlessTranscript::new(
        AgentSessionId::new(SESSION),
        InvocationId::new(INVOCATION),
        ProfileId::from_seed("agy-offline"),
        CWD,
        OBSERVED_AGY_VERSION,
        OBSERVED_AGY_BINARY_SHA256,
        "x".repeat(MAX_PROMPT_BYTES + 1),
        vec![GATE.into()],
    )
    .err()
    .expect("prompt max plus one rejected");
    assert_eq!(too_large.reason_code(), "PROTOCOL_ERROR");
    for timeout in ["", "0s", "10", "180s", "10ms", "10h"] {
        assert_eq!(
            machine()
                .turn_argv(timeout)
                .expect_err("timeout rejected")
                .reason_code(),
            "PROTOCOL_ERROR"
        );
    }
}

#[test]
fn raw_result_boundary_accepts_max_and_rejects_max_plus_one_lf_cr_nul() {
    let valid = result_line(proposal());
    let exact = format!(
        "{valid}{}",
        " ".repeat(MAX_OUTPUT_FRAME_BYTES - valid.len())
    );
    let mut max = prepared();
    assert!(max.ingest_result_line(&exact).is_ok());

    let oversized = format!("{exact} ");
    for raw in [
        oversized,
        format!("{valid}\n"),
        format!("{valid}\r"),
        format!("{valid}\0"),
    ] {
        let mut machine = prepared();
        assert_eq!(
            machine
                .ingest_result_line(&raw)
                .expect_err("boundary rejected")
                .reason_code(),
            "PROTOCOL_ERROR"
        );
        assert!(
            machine.ingest_result_line(&valid).is_err(),
            "poison persists"
        );
        assert!(machine.outcome().is_err());
    }
}

#[test]
fn free_text_smuggling_gate_mutation_unknown_fields_and_replay_fail_closed() {
    let mut wrong_gates = proposal();
    wrong_gates["gate_ids"] = json!(["different.gate"]);
    let cases = [
        "free text proposal".to_string(),
        serde_json::to_string(&json!({"text": proposal()})).expect("JSON"),
        serde_json::to_string(&json!({
            "structured_output": proposal(),
            "response": "untrusted",
        }))
        .expect("JSON"),
        result_line(proposal()).replacen(
            r#""gate_ids":["gat_8888888888888888888888888888888888888888888888888888888888888888"]"#,
            r#""gate_ids":["gat_7777777777777777777777777777777777777777777777777777777777777777"],"gate_ids":["gat_8888888888888888888888888888888888888888888888888888888888888888"]"#,
            1,
        ),
        result_line(wrong_gates),
    ];
    for raw in cases {
        let mut machine = prepared();
        assert!(machine.ingest_result_line(&raw).is_err());
        assert!(machine
            .ingest_result_line(&result_line(proposal()))
            .is_err());
    }
    let mut complete = prepared();
    let valid = result_line(proposal());
    complete.ingest_result_line(&valid).expect("result");
    assert!(
        complete.ingest_result_line(&valid).is_err(),
        "late replay poisons"
    );
    assert!(
        complete.outcome().is_err(),
        "late replay invalidates outcome"
    );
}

#[test]
fn cancellation_and_timeout_are_unsupported_and_never_outcomes() {
    for timeout in [false, true] {
        let mut machine = prepared();
        let error = if timeout {
            machine.timeout_request()
        } else {
            machine.interrupt_request()
        }
        .expect_err("unsupported");
        assert_eq!(error.reason_code(), "UNSUPPORTED");
        assert!(machine.outcome().is_err());
        assert!(machine
            .ingest_result_line(&result_line(proposal()))
            .is_err());
    }
}
