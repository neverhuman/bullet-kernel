//! Adversarial contract tests for provider-selected gate identifiers.

mod support;

use bullet_application::Ledger;
use bullet_domain::{AttemptId, RunnerId};
use bullet_harness_core::PatchProposal;
use bullet_runner_core::{
    run_attempt, run_gate, AcquireRequest, AttemptConfig, DirectLeaseClient, GateRegistry,
    MemoryJournal, MonotonicClock, REPOSITORY_GATE_ID,
};
use serde_json::{json, Value};
use std::sync::Arc;

fn proposal(gate_ids: Value) -> Value {
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "gate authority probe",
        "operations": [{
            "path": "PONG.txt",
            "preimage": {"kind": "absent"},
            "mutation": {"kind": "write", "content_utf8": "PONG\n"}
        }],
        "gate_ids": gate_ids,
        "claims": [],
        "uncertainties": [],
        "done": true
    })
}

#[test]
fn proposal_rejects_unknown_fields_legacy_commands_and_bounds() {
    let mut unknown = proposal(json!([REPOSITORY_GATE_ID]));
    unknown["command"] = json!("touch PWNED");
    assert!(PatchProposal::from_value(&unknown).is_err());

    let mut legacy = proposal(json!([REPOSITORY_GATE_ID]));
    legacy.as_object_mut().unwrap().remove("gate_ids");
    legacy["tests_to_run"] = json!(["touch PWNED"]);
    assert!(PatchProposal::from_value(&legacy).is_err());

    for invalid in [
        json!([]),
        json!([REPOSITORY_GATE_ID, REPOSITORY_GATE_ID]),
        json!([format!("{REPOSITORY_GATE_ID};touch-PWNED")]),
        json!(["a".repeat(65)]),
        Value::Array(
            (0..17)
                .map(|index| json!(format!("gate.{index}")))
                .collect(),
        ),
    ] {
        assert!(PatchProposal::from_value(&proposal(invalid)).is_err());
    }
}

#[test]
fn registry_requires_the_exact_policy_selection() {
    let registry = GateRegistry::v1();
    let admitted = vec![REPOSITORY_GATE_ID.to_string()];
    assert!(registry.require_exact(&admitted, &admitted).is_ok());
    assert!(registry
        .require_exact(&admitted, &["unknown.gate.v1".into()])
        .is_err());
}

#[tokio::test]
async fn unknown_config_gate_is_refused_before_lease_or_provider_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, base_sha) = support::build_origin(directory.path());
    let (ledger, work_package_id) = support::seeded_ledger("unknown-config-gate");
    let adapter = Arc::new(support::ScriptedSim::new());
    let journal = Arc::new(MemoryJournal::new());
    let request = AcquireRequest {
        work_package_id,
        runner_id: RunnerId::from_seed("unknown-config-gate"),
        runner_epoch: 1,
        idempotency_key: "unknown-config-gate-1".into(),
        ttl_seconds: 15,
    };
    let workspace_root = directory.path().join("farm");
    let config = AttemptConfig::new(
        origin,
        base_sha,
        workspace_root.clone(),
        "must remain inert".into(),
        vec!["PONG.txt".into()],
        vec!["attacker.gate.v1".into()],
    );

    let error = run_attempt(
        Arc::new(DirectLeaseClient::new(ledger.clone())),
        adapter.clone(),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .expect_err("unknown gate must fail closed");
    assert_eq!(error.reason_code(), "GATE_SELECTION_REFUSED");
    assert!(adapter.prompts().is_empty());
    assert!(journal.stages().is_empty());
    assert!(!workspace_root.exists());
    assert!(ledger
        .lock()
        .unwrap()
        .get_attempt(&AttemptId::from_seed("unknown-config-gate-1"))
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn provider_text_and_repository_script_cannot_supply_argv() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("PWNED");
    std::fs::write(directory.path().join("PONG.txt"), "PONG\n").unwrap();
    std::fs::write(
        directory.path().join("gate.sh"),
        format!("#!/bin/sh\ntouch {}\n", marker.display()),
    )
    .unwrap();

    let report = run_gate(directory.path(), REPOSITORY_GATE_ID)
        .await
        .unwrap();
    assert_eq!(report.argv, ["/usr/bin/grep", "-qx", "PONG", "PONG.txt"]);
    assert!(report.passed());
    assert!(!marker.exists());

    let command_text = format!("{REPOSITORY_GATE_ID};/usr/bin/touch{}", marker.display());
    assert!(run_gate(directory.path(), &command_text).await.is_err());
    assert!(!marker.exists());
}
