use bullet_application::{
    materialize_plan, CommandRecord, CommandRequest, LeaseService, Ledger, MemoryLedger, PlanInput,
};
use bullet_domain::{CommandPhase, DomainError, TaskClass};

const AT: &str = "2026-01-01T00:00:00.000Z";

fn plan() -> PlanInput {
    PlanInput {
        title: "command integrity".into(),
        objective: "bind every durable effect to the exact request".into(),
        packages: vec![("package".into(), TaskClass::BoundedBugFix)],
    }
}

#[test]
fn command_digest_and_replay_bind_kind_and_exact_payload() {
    let first = CommandRequest::from_json("same-key", "first_kind", r#"{"value":1}"#)
        .expect("first request");
    let changed_kind = CommandRequest::from_json("same-key", "second_kind", r#"{"value":1}"#)
        .expect("changed request");
    assert_ne!(first.digest(), changed_kind.digest());

    let mut ledger = MemoryLedger::new();
    let record = ledger.record_command(&first).expect("record");
    assert_eq!(
        ledger.get_command_by_id(&record.id).expect("lookup"),
        Some(record)
    );
    let error = ledger
        .record_command(&changed_kind)
        .expect_err("kind-conflicting replay");
    assert!(matches!(
        error,
        bullet_application::LedgerError::Domain(DomainError::Idempotency(_))
    ));
}

#[test]
fn public_submission_is_atomic_and_exactly_once_in_memory() {
    let request = CommandRequest::new(
        "public-command",
        "run_demo",
        &serde_json::json!({"requested": true}),
    )
    .expect("request");
    let mut ledger = MemoryLedger::new();
    ledger.set_failpoint(1);
    assert_eq!(
        ledger
            .submit_command(&request)
            .expect_err("outbox failpoint")
            .reason_code(),
        "STORE_FAILURE"
    );
    assert!(ledger
        .get_command(&request.idempotency_key)
        .expect("lookup")
        .is_none());
    assert!(ledger.outbox_all().expect("outbox").is_empty());

    let first = ledger.submit_command(&request).expect("submit");
    let replay = ledger.submit_command(&request).expect("replay");
    assert_eq!(first, replay);
    let rows = ledger.outbox_for_command(&first.id).expect("correlation");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "command_dispatch");
    let events = ledger.list_events().expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "command_submitted");
    assert_eq!(events[0].correlation_id.as_deref(), Some(first.id.as_str()));
}

#[test]
fn offline_worker_is_atomic_idempotent_and_never_green() {
    let request =
        CommandRequest::new("worker-command", "run_demo", &serde_json::json!({})).expect("request");
    let mut ledger = MemoryLedger::new();
    let pending = ledger.submit_command(&request).expect("submit");
    ledger.set_failpoint(1);
    assert_eq!(
        ledger
            .reconcile_offline_command(&pending.id, AT)
            .expect_err("atomic rollback")
            .reason_code(),
        "STORE_FAILURE"
    );
    assert_eq!(
        ledger
            .get_command_by_id(&pending.id)
            .expect("lookup")
            .expect("command")
            .phase,
        CommandPhase::Pending
    );
    assert_eq!(ledger.list_events().expect("events").len(), 1);

    let settled = ledger
        .reconcile_offline_command(&pending.id, AT)
        .expect("settle");
    assert_eq!(settled.phase, CommandPhase::Unknown);
    let response: serde_json::Value =
        serde_json::from_str(settled.response.as_deref().expect("response")).expect("json");
    assert_eq!(response["command_id"], pending.id.as_str());
    assert_eq!(response["payload_digest"], request.digest().to_hex());
    assert_eq!(response["code"], "EXECUTION_ADAPTER_UNAVAILABLE");
    let replay = ledger
        .reconcile_offline_command(&pending.id, "2027-01-01T00:00:00.000Z")
        .expect("exact replay");
    assert_eq!(replay, settled);
    let events = ledger.list_events().expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[1].correlation_id.as_deref(),
        Some(pending.id.as_str())
    );
    assert_eq!(
        events[1].body,
        settled.response.as_deref().expect("response")
    );
    let outbox = ledger.outbox_for_command(&pending.id).expect("outbox");
    assert_eq!(outbox[0].phase, CommandPhase::Unknown);
    assert_eq!(outbox[0].acked_at.as_deref(), Some(AT));

    let unsupported =
        CommandRequest::new("worker-unsupported", "not_admitted", &serde_json::json!({}))
            .expect("request");
    let unsupported = ledger.submit_command(&unsupported).expect("submit");
    let refused = ledger
        .reconcile_offline_command(&unsupported.id, AT)
        .expect("refuse");
    assert_eq!(refused.phase, CommandPhase::Failed);
    assert_ne!(refused.phase, CommandPhase::Verified);
    assert_ne!(settled.phase, CommandPhase::Verified);
}

#[test]
fn malformed_or_incoherent_commands_are_inert() {
    for (key, kind, payload) in [
        ("", "valid", "{}"),
        ("key", "Uppercase", "{}"),
        ("key", "valid", "not-json"),
    ] {
        assert!(CommandRequest::from_json(key, kind, payload).is_err());
    }

    let mut ledger = MemoryLedger::new();
    let request = CommandRequest::from_json("pending", "valid", "{}").expect("request");
    ledger.record_command(&request).expect("record");
    let error = ledger
        .set_command_phase("pending", CommandPhase::Pending, Some("{}"))
        .expect_err("pending result must fail");
    assert_eq!(error.reason_code(), "ENCODING_FAILURE");
    let stored = ledger
        .get_command("pending")
        .expect("lookup")
        .expect("record");
    assert_eq!(stored.phase, CommandPhase::Pending);
    assert!(stored.response.is_none());
}

#[test]
fn command_request_and_record_wires_reject_unknown_fields() {
    let request =
        CommandRequest::new("closed-command", "run_demo", &serde_json::json!({})).expect("request");
    let mut request_wire = serde_json::to_value(&request).expect("request JSON");
    request_wire["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CommandRequest>(request_wire).is_err());

    let mut ledger = MemoryLedger::new();
    let record = ledger.submit_command(&request).expect("record");
    let mut record_wire = serde_json::to_value(record).expect("record JSON");
    record_wire["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CommandRecord>(record_wire).is_err());
}

#[test]
fn lease_dispatch_is_correlated_to_its_exact_command_only() {
    let mut ledger = MemoryLedger::new();
    let graph = materialize_plan(&mut ledger, "memory-command", &plan(), AT).expect("plan");
    let request = LeaseService::request_for(&graph, 0, "memory-lease", 5).expect("request");
    let grant = ledger.acquire_lease(&request).expect("acquire");
    let command = ledger
        .get_command(&request.idempotency_key)
        .expect("lookup")
        .expect("lease command");
    assert_eq!(command.id, request_id(&request));

    let correlated = ledger
        .outbox_for_command(&command.id)
        .expect("correlated outbox");
    assert_eq!(correlated.len(), 1);
    assert_eq!(correlated[0].command_id.as_ref(), Some(&command.id));
    assert_eq!(correlated[0].kind, "dispatch_attempt");
    assert_eq!(
        correlated[0].payload,
        serde_json::to_string(&grant).expect("grant json")
    );

    ledger
        .outbox_enqueue("maintenance", "{}")
        .expect("generic row");
    assert_eq!(
        ledger
            .outbox_for_command(&command.id)
            .expect("filter")
            .len(),
        1
    );
    assert!(ledger
        .outbox_all()
        .expect("all")
        .iter()
        .any(|item| item.command_id.is_none()));
}

fn request_id(request: &bullet_application::LeaseRequest) -> bullet_domain::CommandId {
    CommandRequest::from_json(
        &request.idempotency_key,
        "acquire_lease",
        request.stable_payload().expect("stable payload"),
    )
    .expect("command request")
    .id()
}
