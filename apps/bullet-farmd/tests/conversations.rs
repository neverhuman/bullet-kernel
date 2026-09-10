//! Real local HTTP with synthetic operator fixtures; no native head execution.
#[path = "support/command_http.rs"]
mod http;
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::Ledger;
use http::*;
use serde_json::{json, Value};
use tokio::time::{timeout, Duration};

#[path = "../../../contracts/generated/api.rs"]
mod wire;

fn message(key: &str, cursor: Value, content: &str) -> String {
    json!({"idempotency_key":key,"kind":"conversation_message","payload":{
        "schema_version":"bullet.conversation-message.v1","cursor":cursor,"content":content
    }})
    .to_string()
}
fn effects(ledger: &SqliteLedger) -> (usize, usize) {
    (
        ledger.list_events().unwrap().len(),
        ledger.outbox_all().unwrap().len(),
    )
}
fn conversation(response: &str) -> Value {
    let value = check_snapshot(response);
    let _: wire::ConversationSnapshot = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        value["data"]["head_blocker"],
        "HEAD_RUNTIME_BINDING_REQUIRED"
    );
    value
}

#[tokio::test]
async fn conversation_response_loss_and_restart_recover_complete_original_messages() {
    let directory = support::private_tempdir();
    let path = directory.path().join("conversation.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let ledger = SqliteLedger::open(&path).unwrap();
    let content =
        "  CONVERSATION_PRIVATE_CANARY_v1 Build a readable console.\nKeep my full UTF-8 🦀 goal.\t";
    let requested = message("lost-conversation", Value::Null, content);
    drop(
        open(
            server.addr,
            "POST",
            "/api/v1/commands",
            &headers,
            "{",
            requested.len(),
        )
        .await,
    );
    tokio::task::yield_now().await;
    assert!(ledger.get_command("lost-conversation").unwrap().is_none());
    let unread = open(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &requested,
        requested.len(),
    )
    .await;
    timeout(Duration::from_secs(5), async {
        while ledger.get_command("lost-conversation").unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(unread);
    let before = effects(&ledger);
    let original = ledger.get_command("lost-conversation").unwrap().unwrap();
    let receipt: Value = serde_json::from_str(original.response.as_deref().unwrap()).unwrap();
    let _: wire::ConversationMessageReceipt = serde_json::from_value(receipt.clone()).unwrap();
    server.stop().await;
    drop(ledger);
    let server = Server::start(&path, None).await;
    let index =
        check_snapshot(&request(server.addr, "GET", "/api/v1/conversations", &headers, "").await);
    let _: wire::ConversationIndexSnapshot = serde_json::from_value(index.clone()).unwrap();
    assert_eq!(index["data"]["conversations"].as_array().unwrap().len(), 1);
    assert_eq!(
        index["data"]["conversations"][0]["cursor"],
        receipt["cursor"]
    );
    let id = receipt["cursor"]["conversation_id"].as_str().unwrap();
    let url = format!("/api/v1/conversations/{id}");
    let page = conversation(&request(server.addr, "GET", &url, &headers, "").await);
    assert_eq!(page["as_of_sequence"], index["as_of_sequence"]);
    chrono::DateTime::parse_from_rfc3339(page["observed_at"].as_str().unwrap()).unwrap();
    assert_eq!(
        page["data"]["messages"][0]["accepted_at"],
        index["data"]["conversations"][0]["created_at"]
    );
    assert_eq!(page["data"]["messages"][0]["content"], content);
    assert_eq!(page["data"]["messages"][0]["role"], "user");
    assert_eq!(
        page["data"]["messages"][0]["command_id"],
        original.id.as_str()
    );
    assert_eq!(page["data"]["messages"][0]["cursor"], receipt["cursor"]);
    assert!(page["data"]["next_after"].is_null());
    let retry = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &requested,
    )
    .await;
    assert_eq!(status(&retry), 202);
    assert_eq!(body(&retry)["status"], "APPLIED");
    assert_eq!(body(&retry)["result"], receipt);
    let detail = request(
        server.addr,
        "GET",
        &format!("/api/v1/commands/{}", original.id),
        &headers,
        "",
    )
    .await;
    assert_eq!(body(&detail), body(&retry));
    let ledger = SqliteLedger::open(&path).unwrap();
    assert_eq!(effects(&ledger), before);
    assert!(
        !format!("{:?}", ledger.outbox_all().unwrap()).contains("CONVERSATION_PRIVATE_CANARY_v1")
    );
    assert!(
        !format!("{:?}", ledger.list_events().unwrap()).contains("CONVERSATION_PRIVATE_CANARY_v1")
    );
    server.stop().await;
}

#[tokio::test]
async fn concurrent_conversation_clients_conflict_then_refresh_without_duplicate_messages() {
    let directory = support::private_tempdir();
    let server = Server::start(&directory.path().join("concurrent.sqlite"), Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let first = message("first", Value::Null, "One goal");
    let accepted = request(server.addr, "POST", "/api/v1/commands", &headers, &first).await;
    assert_eq!(status(&accepted), 202);
    let cursor = body(&accepted)["result"]["cursor"].clone();
    let left = message("left", cursor.clone(), "CLI follow-up");
    let right = message("right", cursor.clone(), "Web follow-up");
    let (a, b) = tokio::join!(
        request(server.addr, "POST", "/api/v1/commands", &headers, &left),
        request(server.addr, "POST", "/api/v1/commands", &headers, &right)
    );
    let mut statuses = [status(&a), status(&b)];
    statuses.sort_unstable();
    assert_eq!(statuses, [202, 409]);
    let refused = if status(&a) == 409 { &a } else { &b };
    assert_eq!(body(refused)["code"], "CONVERSATION_CURSOR_CONFLICT");
    let url = format!(
        "/api/v1/conversations/{}",
        cursor["conversation_id"].as_str().unwrap()
    );
    let page =
        conversation(&request(server.addr, "GET", &format!("{url}?limit=1"), &headers, "").await);
    assert_eq!(page["data"]["cursor"]["sequence"], 2);
    assert_eq!(page["data"]["messages"][0]["cursor"]["sequence"], 1);
    assert_eq!(page["data"]["next_after"], 1);
    let next = conversation(
        &request(
            server.addr,
            "GET",
            &format!("{url}?after=1&limit=1"),
            &headers,
            "",
        )
        .await,
    );
    assert_eq!(
        next["data"]["messages"][0]["cursor"],
        page["data"]["cursor"]
    );
    assert_eq!(
        next["data"]["messages"][0]["parent_message_id"],
        cursor["message_id"]
    );
    assert!(next["data"]["next_after"].is_null());
    let replay = request(server.addr, "POST", "/api/v1/commands", &headers, &first).await;
    assert_eq!(body(&replay), body(&accepted));
    let refreshed = conversation(&request(server.addr, "GET", &url, &headers, "").await);
    assert_eq!(refreshed["data"]["messages"].as_array().unwrap().len(), 2);
    assert_eq!(refreshed["as_of_sequence"], page["as_of_sequence"]);
    server.stop().await;
}

#[tokio::test]
async fn conversation_auth_queries_and_author_shapes_fail_without_effects() {
    let directory = support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let ledger = SqliteLedger::open(&path).unwrap();
    let before = effects(&ledger);
    let requested = message("auth", Value::Null, "Private goal");
    for (bad, code) in [
        (vec![("Origin", ORIGIN)], "SESSION_REQUIRED"),
        (
            vec![("Cookie", cookie.as_str()), ("Origin", ORIGIN)],
            "CSRF_REQUIRED",
        ),
        (
            vec![
                ("Cookie", cookie.as_str()),
                ("Origin", "https://attacker.invalid"),
                ("X-Bullet-CSRF", csrf.as_str()),
            ],
            "ORIGIN_DENIED",
        ),
    ] {
        let response = request(server.addr, "POST", "/api/v1/commands", &bad, &requested).await;
        assert_eq!(body(&response)["code"], code);
        assert_eq!(effects(&ledger), before);
    }
    for field in ["role", "operator_id", "run_id", "head_turn_id"] {
        let mut forged: Value = serde_json::from_str(&requested).unwrap();
        forged["payload"][field] = json!("assistant");
        assert_eq!(
            status(
                &request(
                    server.addr,
                    "POST",
                    "/api/v1/commands",
                    &headers,
                    &forged.to_string()
                )
                .await
            ),
            400
        );
        assert_eq!(effects(&ledger), before);
    }
    let accepted = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &requested,
    )
    .await;
    assert_eq!(status(&accepted), 202);
    let url = format!(
        "/api/v1/conversations/{}",
        body(&accepted)["result"]["cursor"]["conversation_id"]
            .as_str()
            .unwrap()
    );
    for base in ["/api/v1/conversations", url.as_str()] {
        for query in [
            "after=bad",
            "after=01",
            "after=1&after=2",
            "limit=0",
            "limit=101",
            "owner=foreign",
            "after=9007199254740991",
        ] {
            let route = format!("{base}?{query}");
            assert_eq!(
                status(&request(server.addr, "GET", &route, &[], "").await),
                401
            );
            assert_eq!(
                status(&request(server.addr, "GET", &route, &headers, "").await),
                400
            );
        }
        assert_eq!(
            status(
                &request(
                    server.addr,
                    "GET",
                    base,
                    &[("Cookie", &cookie), ("Origin", "https://attacker.invalid")],
                    ""
                )
                .await
            ),
            403
        );
    }
    let absent = format!("/api/v1/conversations/cnv_{}", "a".repeat(64));
    assert_eq!(
        status(&request(server.addr, "GET", &absent, &headers, "").await),
        404
    );
    // Ordinary commands never become conversation entries.
    assert_eq!(
        status(
            &request(
                server.addr,
                "POST",
                "/api/v1/commands",
                &headers,
                &envelope("ordinary")
            )
            .await
        ),
        202
    );
    let index =
        check_snapshot(&request(server.addr, "GET", "/api/v1/conversations", &headers, "").await);
    assert_eq!(index["data"]["conversations"].as_array().unwrap().len(), 1);
    let revoked = request(server.addr, "POST", "/api/v1/auth/revoke", &headers, "{}").await;
    assert_eq!(status(&revoked), 200);
    for route in ["/api/v1/conversations", url.as_str()] {
        assert_eq!(
            status(&request(server.addr, "GET", route, &headers, "").await),
            401
        );
    }
    server.stop().await;
}
