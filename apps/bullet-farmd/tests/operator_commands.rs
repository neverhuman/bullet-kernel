//! Operator command recovery over actual HTTP, with isolated synthetic work.
#[path = "support/command_http.rs"]
mod http;
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::{
    CommandDispatchStore, CommandRequest, ComponentCommandCompletionV1, Ledger,
};
use bullet_domain::{CommandId, Digest, RunnerId};
use http::*;
use serde_json::json;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn lost_submission_responses_recover_current_phase_and_empty_cache_after_restart() {
    let directory = support::private_tempdir();
    let path = directory.path().join("commands.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Origin", ORIGIN),
        ("Cookie", cookie.as_str()),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let mut observer = SqliteLedger::open(&path).unwrap();
    // Disconnect before the complete body: no command may be admitted.
    let before = envelope("before-body");
    drop(
        open(
            server.addr,
            "POST",
            "/api/v1/commands",
            &headers,
            "{",
            before.len(),
        )
        .await,
    );
    tokio::task::yield_now().await;
    assert!(observer.get_command("before-body").unwrap().is_none());
    let admitted = request(server.addr, "POST", "/api/v1/commands", &headers, &before).await;
    assert_eq!(status(&admitted), 202);
    assert_eq!(body(&admitted)["status"], "PENDING");
    // This client's response is never read. Wait for independent durable commit,
    // then lose the socket and retry exactly the original request.
    let after = envelope("after-commit");
    let unread = open(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &after,
        after.len(),
    )
    .await;
    timeout(Duration::from_secs(5), async {
        loop {
            if observer.get_command("after-commit").unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(unread);
    let runner = RunnerId::from_seed("fixture-runner");
    // Settle both queued commands through the real component dispatch port.
    for _ in 0..2 {
        let claim = observer
            .claim_next_command_dispatch(&runner, 1, "2026-09-10T00:00:00.000Z")
            .unwrap()
            .unwrap();
        let receipt =
            ComponentCommandCompletionV1::new(&claim, Digest::of(b"component-fixture")).unwrap();
        observer
            .settle_component_command_dispatch(
                &claim.claim_id,
                &runner,
                1,
                &receipt,
                "2026-09-10T00:00:00.000Z",
            )
            .unwrap();
    }
    let counts = (
        observer.list_events().unwrap().len(),
        observer.outbox_all().unwrap().len(),
    );
    let replay = request(server.addr, "POST", "/api/v1/commands", &headers, &after).await;
    assert_eq!(status(&replay), 202);
    assert_eq!(header(&replay, "cache-control"), Some("no-store"));
    assert_eq!(body(&replay)["status"], "UNKNOWN");
    assert_eq!(
        (
            observer.list_events().unwrap().len(),
            observer.outbox_all().unwrap().len()
        ),
        counts
    );
    server.stop().await;
    drop(observer);
    let restarted = Server::start(&path, None).await;
    // No command ID is supplied: the admitted session recovers the complete page.
    let page = check_snapshot(
        &request(
            restarted.addr,
            "GET",
            "/api/v1/commands",
            &[("Cookie", &cookie)],
            "",
        )
        .await,
    );
    assert_eq!(page["data"]["commands"].as_array().unwrap().len(), 2);
    assert!(page["data"]["next_after"].is_null());
    assert!(page["data"]["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|command| command == &body(&replay)));
    let id = body(&replay)["id"].as_str().unwrap().to_string();
    let detail = request(
        restarted.addr,
        "GET",
        &format!("/api/v1/commands/{id}"),
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    assert_eq!(status(&detail), 200);
    assert_eq!(body(&detail), body(&replay));
    assert!(header(&detail, "x-bullet-as-of-sequence").is_some());
    restarted.stop().await;
}

#[tokio::test]
async fn discovery_authenticates_before_query_parsing_and_never_adopts_history() {
    let directory = support::private_tempdir();
    let path = directory.path().join("commands.sqlite");
    let mut legacy = SqliteLedger::open(&path).unwrap();
    let historical = legacy
        .submit_command(&CommandRequest::new("historical", "run_demo", &json!({})).unwrap())
        .unwrap();
    drop(legacy);
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Origin", ORIGIN),
        ("Cookie", cookie.as_str()),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    for query in [
        "after=bad",
        "after=1&after=2",
        "limit=0",
        "limit=101",
        "owner=foreign",
        "limit=02",
        "after=9007199254740992",
    ] {
        let route = format!("/api/v1/commands?{query}");
        assert_eq!(
            status(&request(server.addr, "GET", &route, &[], "").await),
            401
        );
        let malformed = request(server.addr, "GET", &route, &[("Cookie", &cookie)], "").await;
        assert_eq!(status(&malformed), 400);
        assert_eq!(body(&malformed)["code"], "OPERATOR_COMMAND_REQUEST_INVALID");
    }
    let foreign_origin = request(
        server.addr,
        "GET",
        "/api/v1/commands",
        &[("Cookie", &cookie), ("Origin", "https://attacker.invalid")],
        "",
    )
    .await;
    assert_eq!(status(&foreign_origin), 403);
    let history = request(
        server.addr,
        "GET",
        &format!("/api/v1/commands/{}", historical.id),
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    assert_eq!(status(&history), 404);
    let conflict = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &envelope("historical"),
    )
    .await;
    assert_eq!(status(&conflict), 409);
    assert_eq!(body(&conflict)["code"], "COMMAND_OWNERSHIP_CONFLICT");
    let empty = check_snapshot(
        &request(
            server.addr,
            "GET",
            "/api/v1/commands",
            &[("Cookie", &cookie)],
            "",
        )
        .await,
    );
    assert!(empty["data"]["commands"].as_array().unwrap().is_empty());
    let mut expected = Vec::new();
    for key in ["one", "two", "three"] {
        let response = request(
            server.addr,
            "POST",
            "/api/v1/commands",
            &headers,
            &envelope(key),
        )
        .await;
        assert_eq!(status(&response), 202);
        expected.push(body(&response));
    }
    let first = check_snapshot(
        &request(
            server.addr,
            "GET",
            "/api/v1/commands?limit=2",
            &[("Cookie", &cookie)],
            "",
        )
        .await,
    );
    let cursor = first["data"]["next_after"].as_u64().unwrap();
    let second = check_snapshot(
        &request(
            server.addr,
            "GET",
            &format!("/api/v1/commands?limit=2&after={cursor}"),
            &[("Cookie", &cookie)],
            "",
        )
        .await,
    );
    assert!(second["data"]["next_after"].is_null());
    let actual: Vec<_> = first["data"]["commands"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["data"]["commands"].as_array().unwrap())
        .cloned()
        .collect();
    assert_eq!(actual, expected);
    let still = SqliteLedger::open(&path)
        .unwrap()
        .get_command_by_id(&historical.id)
        .unwrap()
        .unwrap();
    assert_eq!(still, historical);
    server.stop().await;
}

#[tokio::test]
async fn independent_http_clients_share_one_key_and_only_their_durable_result() {
    let directory = support::private_tempdir();
    let path = directory.path().join("commands.sqlite");
    let first = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(first.addr).await;
    let second = Server::start(&path, None).await;
    let headers = [
        ("Origin", ORIGIN),
        ("Cookie", cookie.as_str()),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let payload = envelope("race");
    let (one, two) = tokio::join!(
        request(first.addr, "POST", "/api/v1/commands", &headers, &payload),
        request(second.addr, "POST", "/api/v1/commands", &headers, &payload)
    );
    assert_eq!(status(&one), 202);
    assert_eq!(status(&two), 202);
    assert_eq!(body(&one), body(&two));
    let record = SqliteLedger::open(&path)
        .unwrap()
        .get_command_by_id(&CommandId::parse(body(&one)["id"].as_str().unwrap()).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(record.idempotency_key, "race");
    let changed =
        json!({"idempotency_key":"race","kind":"run_demo","payload":{"changed":true}}).to_string();
    let conflict = request(second.addr, "POST", "/api/v1/commands", &headers, &changed).await;
    assert_eq!(status(&conflict), 409);
    assert_eq!(body(&conflict)["code"], "IDEMPOTENCY_CONFLICT");
    let page = check_snapshot(
        &request(
            second.addr,
            "GET",
            "/api/v1/commands",
            &[("Cookie", &cookie)],
            "",
        )
        .await,
    );
    assert_eq!(page["data"]["commands"], json!([body(&one)]));
    first.stop().await;
    second.stop().await;
}
