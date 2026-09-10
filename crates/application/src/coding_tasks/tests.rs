use super::*;
use serde_json::{json, Value};

fn fixture() -> Value {
    json!({
        "schema_version": RUN_CODING_TASK_SCHEMA,
        "task": {
            "title": "Synthetic task contract", "objective": "Exercise durable intent only.",
            "repository_id": format!("rep_{}", "1".repeat(64)),
            "base_commit": "2".repeat(40), "scope_paths": ["src/lib.rs"],
            "acceptance_criteria": ["The regression executes."],
            "gate_ids": [format!("gat_{}", "3".repeat(64))], "dependencies": [],
            "budget": {"max_invocations": 2, "max_cost_microusd": 5000000},
            "deadline_unix_ms": 2000000000000_u64
        },
        "selection": {"provider": "codex", "account_id": "synthetic", "model": "fixture", "effort": null}
    })
}

fn parse(value: &Value) -> Result<RunCodingTaskPayload, DomainError> {
    RunCodingTaskPayload::parse(&value.to_string())
}

#[test]
fn closed_task_payload_rejects_authority_fields_duplicate_keys_and_missing_nullable_selection() {
    let original = fixture();
    assert!(parse(&original).is_ok());
    for field in [
        "allocated_run",
        "launch_nonce",
        "quota_reservation",
        "expected_revision",
        "executable",
    ] {
        let mut value = original.clone();
        value[field] = json!("caller-selected");
        assert!(parse(&value).is_err(), "{field}");
    }
    for pointer in ["", "/task", "/task/budget", "/selection"] {
        let mut value = original.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(true));
        assert!(parse(&value).is_err(), "{pointer}");
    }
    let raw = original.to_string().replace(
        "\"max_invocations\":2",
        "\"max_invocations\":2,\"max_invocations\":2",
    );
    assert!(RunCodingTaskPayload::parse(&raw).is_err());
    let mut missing = original.clone();
    missing["selection"]
        .as_object_mut()
        .unwrap()
        .remove("effort");
    assert!(parse(&missing).is_err());
    let mut unknown = original;
    unknown["schema_version"] = json!("bullet.run-coding.v999");
    assert!(CodingSubmission::parse(&unknown.to_string()).is_err());
}

#[test]
fn task_limits_count_utf8_bytes_and_refuse_traversal_controls_and_ambiguous_subjects() {
    let original = fixture();
    let mut value = original.clone();
    value["task"]["title"] = json!("界".repeat(80));
    assert!(parse(&value).is_ok());
    value["task"]["title"] = json!("界".repeat(81));
    assert!(parse(&value).is_err());
    for path in [
        "/src",
        "src/../secret",
        "src//lib.rs",
        "./src",
        "src/.git/config",
        "src\\lib.rs",
        "src/\u{1b}[2J",
    ] {
        let mut value = original.clone();
        value["task"]["scope_paths"] = json!([path]);
        assert!(parse(&value).is_err(), "{path:?}");
    }
    for field in ["scope_paths", "acceptance_criteria", "gate_ids"] {
        let mut value = original.clone();
        let entry = value["task"][field][0].clone();
        value["task"][field] = json!([entry, entry]);
        assert!(parse(&value).is_err(), "{field}");
        value["task"][field] = json!([]);
        assert!(parse(&value).is_err(), "{field}");
    }
    for (field, bad) in [
        ("repository_id", "rep_short"),
        ("base_commit", "main"),
        ("objective", "\u{1b}[2J"),
    ] {
        let mut value = original.clone();
        value["task"][field] = json!(bad);
        assert!(parse(&value).is_err(), "{field}");
    }
    for bad in [
        json!(["ctr_short"]),
        json!((0..65).map(|i| format!("ctr_{i:064x}")).collect::<Vec<_>>()),
        json!(vec![format!("ctr_{}", "1".repeat(64)); 2]),
    ] {
        let mut value = original.clone();
        value["task"]["dependencies"] = bad;
        assert!(parse(&value).is_err());
    }
    for count in [0, 17] {
        let mut value = original.clone();
        value["task"]["budget"]["max_invocations"] = json!(count);
        assert!(parse(&value).is_err());
    }
    let mut value = original;
    value["task"]["deadline_unix_ms"] = json!(MAX_CODING_SAFE_INTEGER + 1);
    assert!(parse(&value).is_err());
}

#[test]
fn accepted_revision_is_operator_scoped_and_run_tracking_is_separate_from_runtime_selection() {
    let input = fixture();
    let payload = parse(&input).unwrap();
    let operator = format!("opr_{}", "a".repeat(64));
    let revision = payload.task.revision_id(&operator).unwrap();
    let reordered: RunCodingTaskPayload =
        serde_json::from_str(&serde_json::to_string_pretty(&input).unwrap()).unwrap();
    assert_eq!(revision, reordered.task.revision_id(&operator).unwrap());
    assert_ne!(
        revision,
        payload
            .task
            .revision_id(&format!("opr_{}", "b".repeat(64)))
            .unwrap()
    );
    let mut other_runtime = payload.clone();
    other_runtime.selection.provider = CodingProvider::Claude;
    assert_eq!(revision, other_runtime.task.revision_id(&operator).unwrap());
    let mut changed = payload.clone();
    changed
        .task
        .acceptance_criteria
        .push("Additional requirement".into());
    assert_ne!(revision, changed.task.revision_id(&operator).unwrap());
    let request = CommandRequest::new("synthetic-one", crate::RUN_CODING_KIND, &input).unwrap();
    let second = CommandRequest::new("synthetic-two", crate::RUN_CODING_KIND, &input).unwrap();
    assert_ne!(coding_run_id(&request.id()), coding_run_id(&second.id()));
    assert!(bullet_domain::RunnerId::parse(coding_run_id(&request.id())).is_err());
    assert!(matches!(
        CodingSubmission::parse(&request.payload).unwrap(),
        CodingSubmission::Task(_)
    ));
    assert!(payload.task.revision_id("not-an-operator").is_err());
}
