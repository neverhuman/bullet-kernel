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
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .expect("response before timeout")
        .expect("read");
    let text = String::from_utf8_lossy(&buf).to_string();
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
        collected.contains("planner_proposal"),
        "first ledger event is the council proposal"
    );
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
