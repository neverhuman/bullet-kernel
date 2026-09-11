use super::*;
use bullet_application::coding_tasks::{coding_run_id, RunCodingTaskPayload};
use bullet_application::operator_commands::OperatorCommandStore;
use bullet_application::operator_sessions::{BootstrapRegistration, OperatorSessionStore};
use bullet_application::{CommandDispatchStore, Ledger};
use bullet_domain::{CommandPhase, Digest, RunnerId};

mod corruption;

fn register(ledger: &mut SqliteLedger) -> String {
    let operator = format!("opr_{}", Digest::of(b"task-owner").to_hex());
    ledger
        .register_operator_bootstrap(&BootstrapRegistration {
            digest: Digest::of(b"task-bootstrap"),
            proposed_operator_id: operator.clone(),
            origin: "http://127.0.0.1:7420".into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    operator
}
fn payload() -> RunCodingTaskPayload {
    RunCodingTaskPayload::parse(&serde_json::json!({
        "schema_version":"bullet.run-coding.v2",
        "task": {"title":"Bound task acceptance", "objective":"Preserve intent through response loss",
            "repository_id":format!("rep_{}","ab".repeat(32)), "base_commit":"ab".repeat(20),
            "scope_paths":["src/lib.rs"], "acceptance_criteria":["Retry retains original subject"],
            "gate_ids":[format!("gat_{}","cd".repeat(32))], "dependencies":[],
            "budget":{"max_invocations":2,"max_cost_microusd":1000}, "deadline_unix_ms":4_102_444_800_000u64},
        "selection":{"account_id":"fixture-account","provider":"claude","model":"fixture-model","effort":null}
    }).to_string()).unwrap()
}
fn request(key: &str, payload: &RunCodingTaskPayload) -> CommandRequest {
    CommandRequest::new(key, "run_coding", payload).unwrap()
}
fn counts(ledger: &SqliteLedger) -> Vec<i64> {
    [
        "commands",
        "outbox",
        "events",
        "operator_command_ownership",
        "coding_task_revisions",
        "coding_task_dependencies",
        "coding_runs",
        "authority_nonces",
        "budget_reservations",
        "command_dispatch_claims",
    ]
    .iter()
    .map(|table| {
        ledger
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    })
    .collect()
}

#[test]
fn task_dependency_run_owner_and_outbox_roll_back_at_every_write_boundary() {
    for boundary in 0..=10 {
        let dir = crate::test_support::private_tempdir();
        let path = dir.path().join("tasks.sqlite");
        let mut ledger = SqliteLedger::open(&path).unwrap();
        let owner = register(&mut ledger);
        let parent = payload();
        ledger
            .submit_operator_command(&owner, &request("parent", &parent))
            .unwrap();
        let mut child = parent.clone();
        child
            .task
            .dependencies
            .push(parent.task.revision_id(&owner).unwrap());
        let child = request("child", &child);
        let before = counts(&ledger);
        ledger.set_command_submission_failpoint(boundary);
        let error = ledger.submit_operator_command(&owner, &child).unwrap_err();
        assert!(
            error.to_string().contains("STORE"),
            "boundary {boundary}: {error}"
        );
        assert_eq!(counts(&ledger), before, "boundary {boundary}");
        drop(ledger);
        let mut ledger = SqliteLedger::open(&path).unwrap();
        assert_eq!(counts(&ledger), before);
        ledger.submit_operator_command(&owner, &child).unwrap();
        let observation = ledger
            .get_operator_coding(&owner, &child.id())
            .unwrap()
            .unwrap();
        assert_eq!(
            observation.task.dependencies,
            [parent.task.revision_id(&owner).unwrap()]
        );
        assert_eq!(counts(&ledger), [2, 2, 2, 2, 2, 1, 2, 2, 2, 0]);
    }
}

#[test]
fn lost_response_reopen_and_empty_cache_discovery_preserve_original_task_and_run() {
    let dir = crate::test_support::private_tempdir();
    let path = dir.path().join("tasks.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let owner = register(&mut ledger);
    let request = request("lost-response", &payload());
    let original = ledger.submit_operator_command(&owner, &request).unwrap();
    let before = counts(&ledger);
    drop(ledger);
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let retry = ledger.submit_operator_command(&owner, &request).unwrap();
    assert_eq!(retry, original);
    assert_eq!(counts(&ledger), before);
    let page = ledger.list_operator_commands(&owner, 0, 100).unwrap();
    assert_eq!(page.commands, [original.command]);
    let observed = ledger
        .get_operator_coding(&owner, &page.commands[0].id)
        .unwrap()
        .unwrap();
    assert_eq!(observed.run_id, coding_run_id(&request.id()));
    assert_eq!(observed.task, payload().task);
    assert_eq!(observed.selection, payload().selection);
    assert_eq!(observed.as_of_sequence, page.as_of_sequence);
    assert!(
        observed
            .blockers
            .iter()
            .all(|blocker| blocker.code != "CODING_BINDING_ADMISSION_UNAVAILABLE"),
        "admitted v2 tasks bind nonce and quota: {:?}",
        observed.blockers
    );
    assert!(RunnerId::parse(&observed.run_id).is_err());
}

#[test]
fn queued_tasks_enter_dispatch_after_binding_admission() {
    let dir = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(dir.path().join("tasks.sqlite")).unwrap();
    let owner = register(&mut ledger);
    let coding = request("queued", &payload());
    assert!(
        ledger.submit_command(&coding).is_err(),
        "unowned ingress cannot accept task intent"
    );
    assert_eq!(counts(&ledger), [0; 10]);
    ledger.submit_operator_command(&owner, &coding).unwrap();
    assert_eq!(counts(&ledger), [1, 1, 1, 1, 1, 0, 1, 1, 1, 0]);
    let runner = RunnerId::from_seed("component-worker");
    let now = "2026-09-10T05:00:00.000Z";
    let claim = ledger
        .claim_next_command_dispatch(&runner, 1, now)
        .unwrap()
        .unwrap();
    assert_eq!(claim.command_id, coding.id());
    assert_eq!(claim.request.kind, "run_coding");
    assert_eq!(
        ledger
            .get_operator_command(&owner, &coding.id())
            .unwrap()
            .unwrap()
            .command
            .phase,
        CommandPhase::Pending
    );
}

#[test]
fn dependency_deadline_and_shared_invocation_limit_refuse_without_side_effects() {
    let dir = crate::test_support::private_tempdir();
    let mut ledger = SqliteLedger::open(dir.path().join("tasks.sqlite")).unwrap();
    let owner = register(&mut ledger);
    for (key, body, expected) in [
        (
            "expired",
            {
                let mut p = payload();
                p.task.deadline_unix_ms = 1;
                p
            },
            "CODING_TASK_DEADLINE_EXPIRED",
        ),
        (
            "unknown-dependency",
            {
                let mut p = payload();
                p.task.dependencies.push(format!("ctr_{}", "ef".repeat(32)));
                p
            },
            "CODING_DEPENDENCY_NOT_ACCEPTED",
        ),
    ] {
        let error = ledger
            .submit_operator_command(&owner, &request(key, &body))
            .unwrap_err();
        assert_eq!(error.reason_code(), expected);
        assert_eq!(counts(&ledger), [0; 10]);
    }
    let first = request("first", &payload());
    ledger.submit_operator_command(&owner, &first).unwrap();
    let mut other = payload();
    other.selection.account_id = "another-account".into();
    ledger
        .submit_operator_command(&owner, &request("second", &other))
        .unwrap();
    let before = counts(&ledger);
    assert_eq!(
        before[4], 1,
        "selection does not create a fresh task budget"
    );
    assert!(ledger
        .submit_operator_command(&owner, &request("third", &payload()))
        .is_err());
    assert_eq!(counts(&ledger), before);
    assert!(
        ledger.submit_operator_command(&owner, &first).is_ok(),
        "retry consumes no invocation"
    );
    assert!(ledger
        .submit_operator_command(&owner, &request("first", &other))
        .is_err());
    assert_eq!(counts(&ledger), before);
}

#[test]
fn concurrent_clients_share_one_admission_and_enforce_the_task_limit() {
    let dir = crate::test_support::private_tempdir();
    let path = dir.path().join("tasks.sqlite");
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let owner = register(&mut ledger);
    let mut body = payload();
    body.task.budget.max_invocations = 1;
    let same = request("concurrent", &body);
    let other = SqliteLedger::open(&path).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let join = {
        let barrier = barrier.clone();
        let owner = owner.clone();
        let same = same.clone();
        std::thread::spawn(move || {
            let mut other = other;
            barrier.wait();
            other.submit_operator_command(&owner, &same).unwrap()
        })
    };
    barrier.wait();
    let admitted = ledger.submit_operator_command(&owner, &same).unwrap();
    assert_eq!(admitted, join.join().unwrap());
    assert_eq!(counts(&ledger), [1, 1, 1, 1, 1, 0, 1, 1, 1, 0]);
    assert!(ledger
        .submit_operator_command(&owner, &request("different-key", &body))
        .is_err());
    assert_eq!(counts(&ledger), [1, 1, 1, 1, 1, 0, 1, 1, 1, 0]);
}
