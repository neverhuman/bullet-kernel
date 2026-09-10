//! Authenticated aggregate reads preserve existing route subjects and reject
//! partial truth. Fixtures are component inputs, never provider evidence.

#[path = "support/operator.rs"]
mod operator;
mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::run_demo;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

async fn get(
    client: &operator::Client,
    route: &str,
    cookie: &str,
    origin: &str,
) -> (u16, Value, String) {
    let mut stream = TcpStream::connect(client.addr).await.expect("connect");
    stream
        .write_all(
            format!(
        "GET {route} HTTP/1.1\r\nHost: localhost\r\n{cookie}{origin}Connection: close\r\n\r\n"
    )
            .as_bytes(),
        )
        .await
        .expect("write");
    let mut response = String::new();
    timeout(
        Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .expect("deadline")
    .expect("read");
    let (headers, body) = response.split_once("\r\n\r\n").expect("body");
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (
        status,
        serde_json::from_str(body).expect("JSON body"),
        headers.into(),
    )
}

#[tokio::test]
async fn operator_snapshot_matches_all_durable_routes_at_one_watermark() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    run_demo(&mut SqliteLedger::open(&db).expect("ledger")).expect("component demo");
    let client = operator::serve(
        bullet_farmd::api::router_with_bootstrap(&db, operator::BOOTSTRAP, operator::ORIGIN.into())
            .expect("router"),
    )
    .await;
    let cookie = format!("Cookie: {}\r\n", client.cookie);
    let (status, snapshot, headers) = get(&client, "/api/v1/operator-snapshot", &cookie, "").await;
    assert_eq!(status, 200);
    let sequence = snapshot["as_of_sequence"].as_u64().expect("watermark");
    assert!(sequence > 0);
    assert!(headers
        .to_ascii_lowercase()
        .contains(&format!("x-bullet-as-of-sequence: {sequence}\r\n")));
    assert!(headers
        .to_ascii_lowercase()
        .contains("cache-control: no-store"));
    assert_eq!(snapshot["source"], "bullet-kernel/sqlite-ledger");
    chrono::DateTime::parse_from_rfc3339(snapshot["observed_at"].as_str().unwrap()).unwrap();
    for (field, route) in [
        ("missions", "missions"),
        ("outbox", "outbox"),
        ("ready", "ready"),
        ("fleet", "fleet"),
        ("sessions", "sessions"),
        ("context_lineage", "context-lineage"),
        ("merge_rail", "merge-rail"),
        ("quality_lab", "quality-lab"),
        ("audit", "audit"),
    ] {
        let (status, mut individual, _) =
            get(&client, &format!("/api/v1/{route}"), &cookie, "").await;
        assert_eq!(status, 200, "{route}");
        assert_eq!(individual["as_of_sequence"], sequence, "{route}");
        if field == "fleet" {
            // Each route records its own database clock observation.
            individual["data"]["authority_time"] =
                snapshot["data"][field]["authority_time"].clone();
        }
        assert_eq!(snapshot["data"][field], individual["data"], "{route}");
    }
    let mission = snapshot["data"]["missions"][0]["id"].as_str().unwrap();
    let (status, graph, _) =
        get(&client, &format!("/api/v1/missions/{mission}"), &cookie, "").await;
    assert_eq!(status, 200);
    assert_eq!(snapshot["data"]["graphs"][0], graph["data"]);
}

#[tokio::test]
async fn operator_snapshot_requires_session_and_rejects_foreign_origin_and_corruption() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    let client = operator::serve(
        bullet_farmd::api::router_with_bootstrap(&db, operator::BOOTSTRAP, operator::ORIGIN.into())
            .expect("router"),
    )
    .await;
    let route = "/api/v1/operator-snapshot";
    let cookie = format!("Cookie: {}\r\n", client.cookie);
    let (status, problem, _) = get(&client, route, "", "").await;
    assert_eq!(
        (status, problem["code"].as_str()),
        (401, Some("SESSION_REQUIRED"))
    );
    let (status, problem, _) =
        get(&client, route, &cookie, "Origin: https://other.invalid\r\n").await;
    assert_eq!(
        (status, problem["code"].as_str()),
        (403, Some("ORIGIN_DENIED"))
    );
    let (status, empty, _) = get(&client, route, &cookie, "").await;
    assert_eq!(status, 200);
    assert_eq!(empty["as_of_sequence"], 0);
    assert_eq!(empty["data"]["ready"], Value::Null);
    assert_eq!(empty["data"]["missions"], serde_json::json!([]));
    rusqlite::Connection::open(&db)
        .expect("fixture connection")
        .execute(
            "INSERT INTO candidates (id, body) VALUES ('can_corrupt', 'not json')",
            [],
        )
        .expect("corrupt fixture subject");
    let (status, problem, _) = get(&client, route, &cookie, "").await;
    assert_eq!(
        (status, problem["code"].as_str()),
        (500, Some("STORE_FAILURE"))
    );
    assert!(
        problem.get("data").is_none(),
        "no partially successful projection"
    );
    assert!(
        !problem.to_string().contains("expected value"),
        "no parser detail"
    );
}
