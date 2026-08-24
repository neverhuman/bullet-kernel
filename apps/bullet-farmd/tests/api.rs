//! HTTP surface tests against a real served socket and a temp database.

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
    let dir = tempfile::tempdir().expect("tempdir");
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

#[tokio::test]
async fn health_missions_and_demo_are_null_safe_on_empty_db() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let (status, body) = request(addr, "GET", "/health").await;
    assert_eq!(status, 200);
    assert_eq!(json_body(&body)["status"], "ok");
    let (status, body) = request(addr, "GET", "/v1/missions").await;
    assert_eq!(status, 200);
    assert_eq!(json_body(&body), Value::Array(vec![]));
    let (status, body) = request(addr, "GET", "/v1/demo").await;
    assert_eq!(status, 200);
    assert_eq!(
        json_body(&body),
        Value::Null,
        "no fabricated receipt before a run"
    );
    let (status, body) = request(addr, "GET", "/v1/outbox").await;
    assert_eq!(status, 200);
    assert_eq!(json_body(&body)["items"], Value::Array(vec![]));
}

#[tokio::test]
async fn demo_run_populates_views_with_real_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let (status, body) = request(addr, "POST", "/v1/demo/run").await;
    assert_eq!(status, 200);
    let receipt = json_body(&body);
    assert_eq!(receipt["fence"], 1);
    assert_eq!(receipt["fence_second"], 2);
    assert_eq!(receipt["stale_refused"], true);
    assert_eq!(receipt["effect_unknown_outcome"], "unknown");
    let (status, body) = request(addr, "GET", "/v1/demo").await;
    assert_eq!(status, 200);
    assert_eq!(json_body(&body)["fence_second"], 2);
    let mission_id = receipt["mission_id"]
        .as_str()
        .expect("mission id")
        .to_string();
    let (status, body) = request(addr, "GET", &format!("/v1/missions/{mission_id}")).await;
    assert_eq!(status, 200);
    let view = json_body(&body);
    assert_eq!(view["mission"]["id"], receipt["mission_id"]);
    assert_eq!(view["fence"], 2);
    let (status, body) = request(addr, "GET", "/v1/outbox").await;
    assert_eq!(status, 200);
    let outbox = json_body(&body);
    let items = outbox["items"].as_array().expect("items");
    assert!(items.iter().any(|item| item["kind"] == "dispatch_attempt"));
    assert!(items.iter().any(|item| item["phase"] == "verified"));
    assert!(items.iter().any(|item| item["phase"] == "unknown"));
}

#[tokio::test]
async fn events_sse_streams_the_first_chunk_with_sequence_ids() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let (status, _body) = request(addr, "POST", "/v1/demo/run").await;
    assert_eq!(status, 200);
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"GET /v1/events?after=0 HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n",
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
        if collected.contains("data:") {
            break;
        }
    }
    assert!(collected.contains("text/event-stream"));
    assert!(collected.contains("id: 1"), "first frame carries seq 1");
    assert!(
        !collected.contains("\nevent:"),
        "protocol uses only default SSE messages"
    );
    assert!(
        collected.contains("\"kind\":\"planner_proposal\"")
            && collected.contains("\"at\":\"20")
            && collected.contains("\"id\":"),
        "data is a durable EventEnvelope"
    );
}

#[tokio::test]
async fn event_cursors_are_exclusive_and_last_event_id_resumes_after_the_cursor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = start(&dir.path().join("ledger.sqlite")).await;
    let (status, _) = request(addr, "POST", "/v1/demo/run").await;
    assert_eq!(status, 200);

    let conflict =
        raw_request_with_headers(addr, "GET", "/v1/events?after=1", "Last-Event-ID: 1\r\n").await;
    assert!(conflict.starts_with("HTTP/1.1 400"));
    assert!(conflict.contains("CONFLICTING_CURSOR"));

    let malformed = raw_request(addr, "GET", "/v1/events?after=not-a-sequence").await;
    assert!(malformed.starts_with("HTTP/1.1 400"));
    assert!(malformed.contains("INVALID_CURSOR"));

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            b"GET /v1/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nLast-Event-ID: 1\r\n\r\n",
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
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = start(&dir.path().join("ledger.sqlite")).await;

    for path in ["/v1/missions", "/v1/outbox"] {
        let response = raw_request(addr, "GET", path).await;
        assert_eq!(
            response_header(&response, "x-bullet-as-of-sequence").as_deref(),
            Some("0")
        );
    }

    let (status, _) = request(addr, "POST", "/v1/demo/run").await;
    assert_eq!(status, 200);
    let missions = raw_request(addr, "GET", "/v1/missions").await;
    let outbox = raw_request(addr, "GET", "/v1/outbox").await;
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
    let mission_rows = json_body(mission_body);
    let mission_id = mission_rows[0]["id"].as_str().expect("mission id");
    for path in [format!("/v1/missions/{mission_id}"), "/v1/ready".into()] {
        let response = raw_request(addr, "GET", &path).await;
        assert_eq!(
            response_header(&response, "x-bullet-as-of-sequence")
                .expect("projection watermark")
                .parse::<u64>()
                .expect("numeric projection watermark"),
            mission_sequence,
            "{path} must cover the same durable sequence"
        );
    }
}

#[tokio::test]
async fn problem_details_cover_400_404_and_500() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("ledger.sqlite");
    let addr = start(&db).await;
    let (status, body) = request(addr, "GET", "/v1/missions/not-an-id").await;
    assert_eq!(status, 400);
    let problem = json_body(&body);
    assert_eq!(problem["code"], "INVALID_ID");
    assert_eq!(problem["status"], 400);
    let missing = format!("/v1/missions/mis_{}", "0".repeat(32));
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
    let (status, body) = request(addr, "GET", "/v1/missions").await;
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
