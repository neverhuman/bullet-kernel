use super::*;
use serde_json::{json, Value};

fn snapshot() -> (bullet_domain::CommandId, Value) {
    let payload = payload(fixture(), "fixture-account", "codex", "fixture-model", None).unwrap();
    let public_payload = serde_json::to_value(&payload).unwrap();
    let request =
        bullet_application::CommandRequest::new("task-reader", "run_coding", &public_payload)
            .unwrap();
    let value = json!({"data":{
        "command":{"id":request.id().as_str(),"kind":"run_coding","payload_digest":request.digest().to_hex(),"status":"PENDING","result":null},
        "run_id":coding_run_id(&request.id()),"task_revision_id":format!("ctr_{}","ab".repeat(32)),
        "task":payload.task,"selection":payload.selection,"accepted_at":"2026-09-10T00:00:00.000Z",
        "blockers":[{"code":"CODING_BINDING_ADMISSION_UNAVAILABLE","subject":null}]},
        "as_of_sequence":1,"observed_at":"2026-09-10T00:00:01.000Z","source":"bullet-kernel/sqlite-ledger"});
    (request.id(), value)
}
fn response(body: Value) -> http::HttpResponse {
    http::HttpResponse {
        status: 200,
        body,
        set_cookie: None,
        sequence: Some(1),
    }
}

#[test]
fn task_reader_refuses_substituted_run_command_watermark_time_and_invalid_task_fields() {
    let (id, valid) = snapshot();
    let accepted = validate(response(valid.clone()), &id).unwrap();
    assert_eq!(accepted.data.run_id, coding_run_id(&id));
    assert_eq!(accepted.data.task.title, fixture().title);
    for (pointer, replacement) in [
        ("/data/run_id", json!(format!("crn_{}", "cd".repeat(32)))),
        (
            "/data/command/id",
            json!(bullet_domain::CommandId::from_seed("foreign").as_str()),
        ),
        ("/data/command/kind", json!("run_demo")),
        ("/as_of_sequence", json!(2)),
        ("/data/accepted_at", json!("2026-09-11T00:00:00.000Z")),
        ("/data/task/scope_paths", json!(["../escape"])),
        ("/data/task/title", json!("é".repeat(121))),
        ("/data/selection/provider", json!("sim")),
        ("/data/task/gate_ids", json!(["not-a-gate"])),
        ("/data/command/result", json!({"forged":"PASS"})),
        ("/source", json!("other-store")),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(validate(response(bad), &id).is_err(), "{pointer}");
    }
    let mut missing = valid.clone();
    missing["data"]["selection"]
        .as_object_mut()
        .unwrap()
        .remove("effort");
    assert!(validate(response(missing), &id).is_err());
    let mut extra = valid;
    extra["data"]["task"]["authority"] = json!("forged");
    assert!(validate(response(extra), &id).is_err());
}

#[test]
fn task_file_requires_bounded_regular_closed_json_and_rejects_duplicate_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("task.json");
    let body = serde_json::to_string(&fixture()).unwrap();
    std::fs::write(&path, &body).unwrap();
    assert_eq!(load_contract(&path).unwrap(), fixture());
    for invalid in [
        body.replacen('{', "{\"title\":\"duplicate\",", 1),
        body.replace("src/lib.rs", "../escape"),
        "x".repeat(262_145),
        "{}".into(),
    ] {
        std::fs::write(&path, invalid).unwrap();
        assert!(load_contract(&path).is_err());
    }
    assert!(load_contract(dir.path()).is_err());
    assert!(load_contract(&dir.path().join("missing")).is_err());
}

#[test]
fn empty_cache_task_projection_binds_all_accepted_content_to_the_original_command_digest() {
    let (id, valid) = snapshot();
    assert!(validate(response(valid.clone()), &id).is_ok());
    for (pointer, value) in [
        ("/data/command/payload_digest", json!("00".repeat(32))),
        ("/data/task/title", json!("Different valid task")),
        ("/data/selection/model", json!("another-model")),
        ("/data/selection/effort", json!("high")),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate(response(bad), &id).is_err(),
            "substitution {pointer}"
        );
    }
}

#[test]
fn task_text_never_turns_an_unchecked_server_phase_into_verified_evidence() {
    let (id, mut value) = snapshot();
    value["data"]["command"]["status"] = json!("VERIFIED");
    value["data"]["command"]["result"] = json!({"evidence":"unverified-claim"});
    let observation = validate(response(value), &id).unwrap();
    let text = format_task(&observation);
    assert!(text.contains("server phase VERIFIED"));
    assert!(text.contains("verification UNKNOWN (receipt unchecked)"));
    assert!(!text.contains("unverified-claim"));
    assert!(!text.contains('\u{1b}'));
}
