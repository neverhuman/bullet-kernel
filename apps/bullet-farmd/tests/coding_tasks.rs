//! Authenticated task intent over real local HTTP; component fixtures, no providers.
#[path = "support/command_http.rs"]
mod http;
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::coding_tasks::{coding_run_id, RunCodingTaskPayload};
use bullet_application::{CommandRequest, Ledger};
use bullet_domain::RunnerId;
use http::*;
use serde_json::{json, Value};
use tokio::time::{timeout, Duration};

fn coding(key: &str) -> String {
    json!({"idempotency_key":key,"kind":"run_coding","payload":{
        "schema_version":"bullet.run-coding.v2",
        "task":{"title":"Preserve task intent","objective":"Survive response loss",
            "repository_id":format!("rep_{}","ab".repeat(32)),"base_commit":"ab".repeat(20),
            "scope_paths":["src/lib.rs"],"acceptance_criteria":["Retry returns original task"],
            "gate_ids":[format!("gat_{}","cd".repeat(32))],"dependencies":[],
            "budget":{"max_invocations":1,"max_cost_microusd":1000},"deadline_unix_ms":4_102_444_800_000u64},
        "selection":{"account_id":"fixture-account","provider":"claude","model":"fixture-model","effort":null}
    }}).to_string()
}
fn effects(ledger: &SqliteLedger) -> (usize, usize) {
    (
        ledger.list_events().unwrap().len(),
        ledger.outbox_all().unwrap().len(),
    )
}

#[tokio::test]
async fn coding_reads_and_submission_enforce_session_origin_csrf_and_closed_intent() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let ledger = SqliteLedger::open(&path).unwrap();
    let before = effects(&ledger);
    let body = coding("auth");
    for (headers, expected) in [
        (vec![], "ORIGIN_REQUIRED"),
        (vec![("Origin", ORIGIN)], "SESSION_REQUIRED"),
        (
            vec![("Cookie", cookie.as_str()), ("Origin", ORIGIN)],
            "CSRF_REQUIRED",
        ),
        (
            vec![
                ("Cookie", cookie.as_str()),
                ("Origin", "http://example.invalid"),
                ("X-Bullet-CSRF", csrf.as_str()),
            ],
            "ORIGIN_DENIED",
        ),
    ] {
        let response = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
        assert_eq!(http::body(&response)["code"], expected);
        assert_eq!(effects(&ledger), before);
    }
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let mut invalid: Value = serde_json::from_str(&body).unwrap();
    invalid["payload"]["allocated_run"] = json!(RunnerId::from_seed("caller-authority").as_str());
    let refused = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &invalid.to_string(),
    )
    .await;
    assert_eq!(status(&refused), 400);
    assert_eq!(effects(&ledger), before);
    let accepted = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&accepted), 202);
    let id = http::body(&accepted)["id"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/commands/{id}/coding");
    let anonymous = request(server.addr, "GET", &url, &[], "").await;
    assert_eq!(status(&anonymous), 401);
    assert_eq!(http::body(&anonymous)["code"], "SESSION_REQUIRED");
    let snapshot = check_snapshot(&request(server.addr, "GET", &url, &headers, "").await);
    assert_eq!(snapshot["data"]["command"], http::body(&accepted));
    assert_eq!(
        snapshot["data"]["task"],
        serde_json::from_str::<Value>(&body).unwrap()["payload"]["task"]
    );
    assert_eq!(
        snapshot["data"]["blockers"][0]["code"],
        "CODING_BINDING_ADMISSION_UNAVAILABLE"
    );
    let demo = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &envelope("demo"),
    )
    .await;
    let url = format!(
        "/api/v1/commands/{}/coding",
        http::body(&demo)["id"].as_str().unwrap()
    );
    assert_eq!(
        status(&request(server.addr, "GET", &url, &headers, "").await),
        404
    );
    server.stop().await;
}

#[tokio::test]
async fn new_legacy_authority_shape_is_explicitly_retired_without_any_effect() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let ledger = SqliteLedger::open(&path).unwrap();
    let before = effects(&ledger);
    let legacy=json!({"idempotency_key":"retired","kind":"run_coding","payload":{
        "account_id":"fixture-account","provider":"claude","model":"fixture-model",
        "expected_revision":1,"launch_nonce":"ab".repeat(32),"quota_reservation":format!("rsv_{}","cd".repeat(32)),
        "quota_units":3,"allocated_run":RunnerId::from_seed("fixture-run").as_str()}}).to_string();
    let response = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &[
            ("Cookie", &cookie),
            ("Origin", ORIGIN),
            ("X-Bullet-CSRF", &csrf),
        ],
        &legacy,
    )
    .await;
    assert_eq!(status(&response), 409);
    assert_eq!(
        body(&response)["code"],
        "RUN_CODING_LEGACY_AUTHORITY_SHAPE_RETIRED"
    );
    assert_eq!(effects(&ledger), before);
    assert!(ledger.get_command("retired").unwrap().is_none());
    server.stop().await;
}

#[tokio::test]
async fn task_response_loss_restart_discovery_and_exact_retry_keep_server_subjects() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let ledger = SqliteLedger::open(&path).unwrap();
    let body = coding("lost");
    drop(
        open(
            server.addr,
            "POST",
            "/api/v1/commands",
            &headers,
            "{",
            body.len(),
        )
        .await,
    );
    tokio::task::yield_now().await;
    assert!(ledger.get_command("lost").unwrap().is_none());
    let unread = open(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &body,
        body.len(),
    )
    .await;
    timeout(Duration::from_secs(5), async {
        while ledger.get_command("lost").unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(unread);
    let original = ledger.get_command("lost").unwrap().unwrap();
    let before = effects(&ledger);
    let decoded: Value = serde_json::from_str(&body).unwrap();
    let payload = RunCodingTaskPayload::parse(&decoded["payload"].to_string()).unwrap();
    let expected = CommandRequest::new("lost", "run_coding", &payload).unwrap();
    assert_eq!(original.id, expected.id());
    server.stop().await;
    drop(ledger);
    let server = Server::start(&path, None).await;
    let discovery =
        check_snapshot(&request(server.addr, "GET", "/api/v1/commands", &headers, "").await);
    assert_eq!(discovery["data"]["commands"].as_array().unwrap().len(), 1);
    let retry = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&retry), 202);
    assert_eq!(http::body(&retry)["status"], "PENDING");
    let url = format!("/api/v1/commands/{}/coding", original.id);
    let snapshot = check_snapshot(&request(server.addr, "GET", &url, &headers, "").await);
    assert_eq!(snapshot["data"]["run_id"], coding_run_id(&expected.id()));
    assert_eq!(snapshot["data"]["command"], http::body(&retry));
    assert_eq!(snapshot["as_of_sequence"], discovery["as_of_sequence"]);
    assert_eq!(snapshot["data"]["task"], decoded["payload"]["task"]);
    assert_eq!(effects(&SqliteLedger::open(&path).unwrap()), before);
    server.stop().await;
}
