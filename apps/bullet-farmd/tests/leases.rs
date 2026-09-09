//! The browser API exposes readiness only. Runner lease mutations require a
//! separate authenticated internal transport and therefore fail closed here.

mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, Ledger, PlanInput};
use bullet_domain::TaskClass;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

fn seed_graph(db: &Path) -> String {
    let mut ledger = SqliteLedger::open(db).expect("open ledger");
    let graph = materialize_plan(
        &mut ledger,
        "public-ready",
        &PlanInput {
            title: "ready projection".into(),
            objective: "keep runner mutation authority off the browser API".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("plan");
    graph.packages[0].id.to_string()
}

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
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .expect("response timeout")
        .expect("read");
    let response = String::from_utf8_lossy(&bytes).to_string();
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("status");
    (status, response)
}

fn json_body(response: &str) -> Value {
    let body = response.split_once("\r\n\r\n").expect("body").1;
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
async fn ready_is_a_read_only_watermarked_projection() {
    let directory = support::private_tempdir();
    let db = directory.path().join("ready.sqlite");
    let package = seed_graph(&db);
    let (status, response) = request(start(&db).await, "GET", "/api/v1/ready").await;
    assert_eq!(status, 200);
    let snapshot = json_body(&response);
    assert_eq!(snapshot.as_object().expect("snapshot").len(), 4);
    assert_eq!(snapshot["data"]["work_package_id"], package);
    assert!(snapshot["as_of_sequence"].is_u64());
    assert_eq!(snapshot["source"], "bullet-kernel/sqlite-ledger");
}

#[tokio::test]
async fn runner_mutations_are_not_mounted_on_the_public_router() {
    let directory = support::private_tempdir();
    let db = directory.path().join("closed.sqlite");
    let package = seed_graph(&db);
    let addr = start(&db).await;
    for path in [
        "/api/v1/leases/acquire",
        "/api/v1/leases/heartbeat",
        "/api/v1/leases/release",
        "/api/v1/attempts/advance",
    ] {
        let (status, response) = request(addr, "POST", path).await;
        assert_eq!(status, 404, "{path}");
        assert_eq!(json_body(&response)["code"], "NOT_FOUND");
        assert!(response.contains("application/problem+json"));
    }
    let ledger = SqliteLedger::open(&db).expect("reopen");
    assert!(ledger
        .ready_rows()
        .expect("ready")
        .iter()
        .any(|row| row.work_package_id.as_str() == package));
}
