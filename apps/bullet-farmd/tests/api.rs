//! HTTP surface tests against a real served socket and a temp database.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::run_demo;
use bullet_domain::Digest;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

async fn start(db: &Path) -> SocketAddr {
    let app = bullet_farmd::api::router(db).expect("router");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

async fn request(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let text = raw_request(addr, method, path).await;
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn raw_request(addr: SocketAddr, method: &str, path: &str) -> String {
    raw_request_with_headers(addr, method, path, "").await
}

async fn raw_request_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .expect("response before timeout")
        .expect("read");
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn cross_origin_requests_never_receive_wildcard_cors_authority() {
    let dir = support::private_tempdir();
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let response = raw_request_with_headers(
        addr,
        "GET",
        "/health",
        "Origin: https://attacker.invalid\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert_eq!(
        response_header(&response, "access-control-allow-origin"),
        None
    );
}

fn response_header(response: &str, name: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn json_body(body: &str) -> Value {
    // Connection: close responses may arrive chunked; strip framing if so.
    if let Ok(value) = serde_json::from_str(body) {
        return value;
    }
    let unchunked: String = body
        .lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect();
    serde_json::from_str(&unchunked).expect("json body")
}

fn snapshot_data(body: &str) -> Value {
    let snapshot = json_body(body);
    let object = snapshot.as_object().expect("snapshot object");
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["as_of_sequence", "data", "observed_at", "source"],
        "snapshot has exactly the four public fields"
    );
    assert!(snapshot["as_of_sequence"].is_u64());
    chrono::DateTime::parse_from_rfc3339(snapshot["observed_at"].as_str().expect("observed_at"))
        .expect("RFC 3339 observation time");
    assert_eq!(snapshot["source"], "bullet-kernel/sqlite-ledger");
    snapshot["data"].clone()
}

fn insert_events(db: &Path, count: u64) {
    drop(SqliteLedger::open(db).expect("initialize ledger"));
    let mut connection = Connection::open(db).expect("raw open");
    let transaction = connection.transaction().expect("transaction");
    for sequence in 1..=count {
        let kind = "fixture";
        let body = sequence.to_string();
        let id = Digest::of(format!("evt:{sequence}:{kind}:{body}").as_bytes()).to_hex();
        transaction
            .execute(
                "INSERT INTO events (seq, kind, body, at, event_id, sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?1)",
                params![sequence, kind, body, "2026-01-01T00:00:00.000Z", id],
            )
            .expect("fixture event");
    }
    transaction.commit().expect("commit fixtures");
}

fn seed_demo(db: &Path) -> Value {
    let mut ledger = SqliteLedger::open(db).expect("demo ledger");
    serde_json::to_value(run_demo(&mut ledger).expect("seed durable demo")).expect("receipt json")
}

#[tokio::test]
async fn health_missions_and_demo_are_null_safe_on_empty_db() {
    let dir = support::private_tempdir();
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let (status, body) = request(addr, "GET", "/health").await;
    assert_eq!(status, 200);
    assert_eq!(json_body(&body)["status"], "ok");
    for legacy in ["/v1", "/v1/missions"] {
        let (status, body) = request(addr, "GET", legacy).await;
        assert_eq!(status, 410, "{legacy}");
        let problem = json_body(&body);
        assert_eq!(problem["code"], "API_VERSION_RETIRED");
        assert_eq!(problem["retryable"], false);
    }
    let (status, body) = request(addr, "GET", "/api/v1/missions").await;
    assert_eq!(status, 200);
    assert_eq!(snapshot_data(&body), Value::Array(vec![]));
    let (status, body) = request(addr, "GET", "/api/v1/demo").await;
    assert_eq!(status, 200);
    assert_eq!(
        snapshot_data(&body),
        Value::Null,
        "no fabricated receipt before a run"
    );
    let (status, body) = request(addr, "GET", "/api/v1/outbox").await;
    assert_eq!(status, 200);
    assert_eq!(snapshot_data(&body)["items"], Value::Array(vec![]));
}

#[tokio::test]
async fn demo_projection_uses_durable_rows_and_direct_mutation_is_gone() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    let receipt = seed_demo(&db);
    let addr = start(&db).await;
    let (status, body) = request(addr, "POST", "/api/v1/demo/run").await;
    assert_eq!(status, 410);
    assert_eq!(json_body(&body)["code"], "MUTATION_ENDPOINT_REMOVED");
    assert_eq!(receipt["fence_first"], 1);
    assert_eq!(receipt["fence_second"], 2);
    assert_eq!(receipt["stale_refused"], true);
    assert_eq!(receipt["candidate_head"], "NOT_PRODUCED");
    assert_eq!(receipt["evidence_result"], "NOT_RUN");
    assert_eq!(receipt["effect_outcome"], "NOT_DISPATCHED");
    assert_eq!(receipt["effect_unknown_outcome"], "NOT_DISPATCHED");
    let (status, body) = request(addr, "GET", "/api/v1/demo").await;
    assert_eq!(status, 200);
    assert_eq!(snapshot_data(&body)["fence_second"], 2);
    let mission_id = receipt["mission_id"]
        .as_str()
        .expect("mission id")
        .to_string();
    let (status, body) = request(addr, "GET", &format!("/api/v1/missions/{mission_id}")).await;
    assert_eq!(status, 200);
    let view = snapshot_data(&body);
    assert_eq!(view["mission"]["id"], receipt["mission_id"]);
    assert_eq!(view["fence"], 2);
    let (status, body) = request(addr, "GET", "/api/v1/outbox").await;
    assert_eq!(status, 200);
    let outbox = snapshot_data(&body);
    let items = outbox["items"].as_array().expect("items");
    let dispatches: Vec<_> = items
        .iter()
        .filter(|item| item["kind"] == "dispatch_attempt")
        .collect();
    assert_eq!(dispatches.len(), 2);
    assert!(dispatches.iter().all(|item| item["phase"] == "pending"));
    assert!(items.iter().all(|item| item["phase"] != "verified"));
    assert!(items.iter().all(|item| item["phase"] != "unknown"));
}

#[tokio::test]
async fn events_sse_streams_the_first_chunk_with_sequence_ids() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    seed_demo(&db);
    let addr = start(&db).await;
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"GET /api/v1/events?after=0 HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n",
        )
        .await
        .expect("write");
    let mut collected = String::new();
    let mut chunk = [0u8; 4096];
    let deadline = Duration::from_secs(10);
    loop {
        let read = timeout(deadline, stream.read(&mut chunk))
            .await
            .expect("sse data before timeout")
            .expect("read");
        assert!(read > 0, "stream closed before first event");
        collected.push_str(&String::from_utf8_lossy(&chunk[..read]));
        if collected.matches("data:").count() >= 2 {
            break;
        }
    }
    assert!(collected.contains("text/event-stream"));
    assert!(collected.contains("id: 1"), "first frame carries seq 1");
    assert!(collected.find("id: 1") < collected.find("id: 2"));
    assert!(
        !collected.contains("\nevent:"),
        "protocol uses only default SSE messages"
    );
    let data = collected
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .expect("default SSE data line");
    let envelope: Value = serde_json::from_str(data).expect("EventEnvelope JSON");
    let object = envelope.as_object().expect("envelope object");
    assert_eq!(object.len(), 5);
    assert_eq!(envelope["seq"], 1);
    assert_eq!(envelope["kind"], "planner_proposal");
    assert!(envelope["at"].as_str().expect("at").starts_with("20"));
    assert!(envelope["id"].as_str().is_some_and(|id| id.len() == 64));
}

#[tokio::test]
async fn event_cursors_are_exclusive_and_last_event_id_resumes_after_the_cursor() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    seed_demo(&db);
    let addr = start(&db).await;

    let conflict = raw_request_with_headers(
        addr,
        "GET",
        "/api/v1/events?after=1",
        "Last-Event-ID: 1\r\n",
    )
    .await;
    assert!(conflict.starts_with("HTTP/1.1 400"));
    assert!(conflict.contains("CONFLICTING_CURSOR"));

    let malformed = raw_request(addr, "GET", "/api/v1/events?after=not-a-sequence").await;
    assert!(malformed.starts_with("HTTP/1.1 400"));
    assert!(malformed.contains("INVALID_CURSOR"));

    for path in ["/api/v1/events?after=1&after=2", "/api/v1/events?cursor=1"] {
        let rejected = raw_request(addr, "GET", path).await;
        assert!(rejected.starts_with("HTTP/1.1 400"), "{path}");
    }
    let duplicate_header = raw_request_with_headers(
        addr,
        "GET",
        "/api/v1/events",
        "Last-Event-ID: 1\r\nLast-Event-ID: 2\r\n",
    )
    .await;
    assert!(duplicate_header.starts_with("HTTP/1.1 400"));
    assert!(duplicate_header.contains("CONFLICTING_CURSOR"));

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nLast-Event-ID: 1\r\n\r\n",
        )
        .await
        .expect("write");
    let mut collected = String::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("resumed SSE data before timeout")
            .expect("read");
        assert!(read > 0, "stream closed before resumed event");
        collected.push_str(&String::from_utf8_lossy(&chunk[..read]));
        if collected.contains("data:") {
            break;
        }
    }
    assert!(collected.contains("id: 2"), "cursor is exclusive");
}

#[tokio::test]
async fn mission_and_outbox_snapshots_share_the_durable_event_watermark() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    let addr = start(&db).await;

    for path in ["/api/v1/missions", "/api/v1/outbox"] {
        let response = raw_request(addr, "GET", path).await;
        assert_eq!(
            response_header(&response, "x-bullet-as-of-sequence").as_deref(),
            Some("0")
        );
    }

    seed_demo(&db);
    let missions = raw_request(addr, "GET", "/api/v1/missions").await;
    let outbox = raw_request(addr, "GET", "/api/v1/outbox").await;
    let mission_sequence = response_header(&missions, "x-bullet-as-of-sequence")
        .expect("mission watermark")
        .parse::<u64>()
        .expect("numeric mission watermark");
    let outbox_sequence = response_header(&outbox, "x-bullet-as-of-sequence")
        .expect("outbox watermark")
        .parse::<u64>()
        .expect("numeric outbox watermark");
    assert!(mission_sequence > 0);
    assert_eq!(mission_sequence, outbox_sequence);
    let mission_body = missions
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("mission response body");
    let mission_snapshot = json_body(mission_body);
    assert_eq!(mission_snapshot["as_of_sequence"], mission_sequence);
    let mission_rows = snapshot_data(mission_body);
    let mission_id = mission_rows[0]["id"].as_str().expect("mission id");
    for path in [
        format!("/api/v1/missions/{mission_id}"),
        "/api/v1/ready".into(),
    ] {
        let response = raw_request(addr, "GET", &path).await;
        assert_eq!(
            response_header(&response, "x-bullet-as-of-sequence")
                .expect("projection watermark")
                .parse::<u64>()
                .expect("numeric projection watermark"),
            mission_sequence,
            "{path} must cover the same durable sequence"
        );
        let body = response.split_once("\r\n\r\n").expect("body").1;
        assert_eq!(json_body(body)["as_of_sequence"], mission_sequence);
    }
}

#[tokio::test]
async fn missing_durable_stale_refusal_makes_demo_projection_unknown() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    seed_demo(&db);
    let addr = start(&db).await;
    Connection::open(&db)
        .expect("raw open")
        .execute(
            "DELETE FROM events WHERE kind = 'demo_stale_authority_refused'",
            [],
        )
        .expect("remove proof");
    let (status, body) = request(addr, "GET", "/api/v1/demo").await;
    assert_eq!(status, 200);
    assert_eq!(snapshot_data(&body), Value::Null);
}

#[tokio::test]
async fn unavailable_and_corrupt_replays_fail_before_sse_200() {
    for (name, mutation, after, expected) in [
        (
            "retained-prefix",
            "DELETE FROM events WHERE seq = 1",
            0,
            410,
        ),
        ("internal-gap", "DELETE FROM events WHERE seq = 2", 1, 410),
        (
            "corrupt-first",
            "UPDATE events SET event_id = 'bad' WHERE seq = 1",
            0,
            500,
        ),
    ] {
        let dir = support::private_tempdir();
        let db = dir.path().join(format!("{name}.sqlite"));
        seed_demo(&db);
        let addr = start(&db).await;
        Connection::open(&db)
            .expect("raw open")
            .execute(mutation, [])
            .expect("hostile mutation");
        let response = raw_request(addr, "GET", &format!("/api/v1/events?after={after}")).await;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected}")),
            "{name}: {response}"
        );
        assert_eq!(
            response_header(&response, "content-type").as_deref(),
            Some("application/problem+json")
        );
        assert!(!response.contains("text/event-stream"));
    }

    let dir = support::private_tempdir();
    let late_gap = dir.path().join("late-gap.sqlite");
    insert_events(&late_gap, 100);
    Connection::open(&late_gap)
        .expect("raw open")
        .execute("DELETE FROM events WHERE seq = 70", [])
        .expect("late gap");
    let response = raw_request(start(&late_gap).await, "GET", "/api/v1/events?after=0").await;
    assert!(response.starts_with("HTTP/1.1 410"));
    assert!(!response.contains("text/event-stream"));

    let db = dir.path().join("bounded.sqlite");
    insert_events(&db, 1_025);
    let response = raw_request(start(&db).await, "GET", "/api/v1/events?after=0").await;
    assert!(response.starts_with("HTTP/1.1 410"));

    let future = raw_request(
        start(&dir.path().join("empty.sqlite")).await,
        "GET",
        "/api/v1/events?after=1",
    )
    .await;
    assert!(future.starts_with("HTTP/1.1 410"));
    assert!(future.contains("REPLAY_UNAVAILABLE"));
}

#[tokio::test]
async fn problem_details_cover_400_404_and_500() {
    let dir = support::private_tempdir();
    let db = dir.path().join("ledger.sqlite");
    let addr = start(&db).await;
    let invalid = raw_request(addr, "GET", "/api/v1/missions/not-an-id").await;
    assert!(invalid.starts_with("HTTP/1.1 400"));
    assert_eq!(
        response_header(&invalid, "content-type").as_deref(),
        Some("application/problem+json")
    );
    let problem = json_body(invalid.split_once("\r\n\r\n").expect("body").1);
    assert_eq!(problem["code"], "INVALID_ID");
    assert_eq!(problem["status"], 400);
    for field in [
        "type",
        "title",
        "detail",
        "instance",
        "request_id",
        "correlation_id",
        "repair",
    ] {
        assert!(
            problem[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{field}"
        );
    }
    let legacy = format!("/api/v1/missions/mis_{}", "0".repeat(32));
    let (status, body) = request(addr, "GET", &legacy).await;
    assert_eq!(status, 400);
    assert_eq!(json_body(&body)["code"], "INVALID_ID");

    let missing = format!("/api/v1/missions/mis_{}", "0".repeat(64));
    let (status, body) = request(addr, "GET", &missing).await;
    assert_eq!(status, 404);
    let problem = json_body(&body);
    assert_eq!(problem["code"], "NOT_FOUND");
    assert_eq!(problem["retryable"], false);
    // Corrupt a graph row directly; the projection must map to a 500
    // problem-details body without leaking the parser error.
    let conn = rusqlite::Connection::open(&db).expect("open raw");
    conn.execute(
        "INSERT INTO graphs (mission_id, body) VALUES ('mis_corrupt', 'not json')",
        [],
    )
    .expect("corrupt row");
    let (status, body) = request(addr, "GET", "/api/v1/missions").await;
    assert_eq!(status, 500);
    let problem = json_body(&body);
    assert_eq!(problem["code"], "STORE_FAILURE");
    assert_eq!(problem["retryable"], true);
    assert!(problem["correlation_id"]
        .as_str()
        .expect("corr")
        .starts_with("corr_"));
    assert!(
        !body.contains("expected value"),
        "raw parser detail must not leak"
    );
}
