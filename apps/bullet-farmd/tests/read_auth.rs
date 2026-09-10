//! Operator reads use the same browser session as commands, over real HTTP.

mod support;

use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const ORIGIN: &str = "http://127.0.0.1:7420";
const BOOTSTRAP: &str = "boot_0000000000000000000000000000000000000000000000000000000000000000";
const WORKER: &str = "wrk_2222222222222222222222222222222222222222222222222222222222222222";
const READS: &[&str] = &[
    "/api/v1/missions",
    "/api/v1/missions/not-an-id",
    "/api/v1/demo",
    "/api/v1/commands/not-an-id",
    "/api/v1/outbox",
    "/api/v1/events?after=invalid",
    "/api/v1/ready",
    "/api/v1/fleet",
    "/api/v1/sessions",
    "/api/v1/context-lineage",
    "/api/v1/merge-rail",
    "/api/v1/quality-lab",
    "/api/v1/audit",
];

async fn start(app: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn open(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> BufReader<TcpStream> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    stream.write_all(format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    ).as_bytes()).await.unwrap();
    BufReader::new(stream)
}

async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut stream = open(addr, method, path, headers, body).await;
    let mut response = String::new();
    timeout(
        Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    response
}

fn status(response: &str) -> u16 {
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
}

async fn bootstrap(addr: SocketAddr) -> String {
    let response = request(
        addr,
        "POST",
        "/api/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        &json!({"bootstrap_token": BOOTSTRAP}).to_string(),
    )
    .await;
    assert_eq!(status(&response), 200, "{response}");
    header(&response, "set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}

#[tokio::test]
async fn every_operator_read_authenticates_before_parsing_or_accessing_data() {
    let dir = support::private_tempdir();
    let addr = start(
        bullet_farmd::api::router_with_authorities(
            &dir.path().join("reads.sqlite"),
            BOOTSTRAP,
            ORIGIN.into(),
            WORKER,
        )
        .unwrap(),
    )
    .await;
    let cookie = bootstrap(addr).await;
    let forged = format!("bullet_session=ses_{}", "f".repeat(64));
    let duplicate = format!("{cookie}; {cookie}");
    let worker_bearer = format!("Bearer {WORKER}");
    for path in READS {
        for headers in [
            vec![],
            vec![("Cookie", forged.as_str())],
            vec![("Cookie", duplicate.as_str())],
            vec![("Cookie", cookie.as_str()), ("Cookie", cookie.as_str())],
            vec![("Authorization", worker_bearer.as_str())],
            vec![("Cookie", BOOTSTRAP)],
        ] {
            let response = request(addr, "GET", path, &headers, "").await;
            assert_eq!(status(&response), 401, "{path}: {response}");
            assert_eq!(
                header(&response, "content-type"),
                Some("application/problem+json")
            );
            assert!(!response.contains(&cookie));
            assert!(!response.contains("as_of_sequence"));
        }
        let head = request(addr, "HEAD", path, &[], "").await;
        assert_eq!(status(&head), 401, "{path}: {head}");
        let hostile_origin = request(
            addr,
            "GET",
            path,
            &[("Cookie", &cookie), ("Origin", "https://attacker.invalid")],
            "",
        )
        .await;
        assert_eq!(status(&hostile_origin), 403, "{path}: {hostile_origin}");
    }
    for path in ["/health", "/openapi.yaml"] {
        assert_eq!(status(&request(addr, "GET", path, &[], "").await), 200);
    }
    for path in READS
        .iter()
        .filter(|path| !path.contains("not-an-id") && !path.contains("events"))
    {
        let response = request(addr, "GET", path, &[("Cookie", &cookie)], "").await;
        assert_eq!(status(&response), 200, "{path}: {response}");
        assert_eq!(header(&response, "cache-control"), Some("no-store"));
        assert!(header(&response, "x-bullet-as-of-sequence").is_some());
    }
    let conn = rusqlite::Connection::open(dir.path().join("reads.sqlite")).unwrap();
    let events: i64 = conn
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(events, 0, "read and rejected requests mutated the ledger");
}

#[tokio::test]
async fn disabled_authentication_and_foreign_daemon_cookies_never_enable_reads() {
    let dir = support::private_tempdir();
    let origin = start(
        bullet_farmd::api::router_with_bootstrap(
            &dir.path().join("origin.sqlite"),
            BOOTSTRAP,
            ORIGIN.into(),
        )
        .unwrap(),
    )
    .await;
    let cookie = bootstrap(origin).await;
    for app in [
        bullet_farmd::api::router(&dir.path().join("disabled.sqlite")).unwrap(),
        bullet_farmd::api::router_with_bootstrap(
            &dir.path().join("other.sqlite"),
            BOOTSTRAP,
            ORIGIN.into(),
        )
        .unwrap(),
    ] {
        let addr = start(app).await;
        for path in READS {
            let response = request(addr, "GET", path, &[("Cookie", &cookie)], "").await;
            assert_eq!(status(&response), 401, "{path}: {response}");
            assert!(response.contains("SESSION_INVALID"));
        }
    }
}

#[tokio::test]
async fn empty_authenticated_sse_opens_without_waiting_for_an_event_or_keepalive() {
    let dir = support::private_tempdir();
    let db = dir.path().join("empty-sse.sqlite");
    let addr =
        start(bullet_farmd::api::router_with_bootstrap(&db, BOOTSTRAP, ORIGIN.into()).unwrap())
            .await;
    let cookie = bootstrap(addr).await;
    let mut stream = open(
        addr,
        "GET",
        "/api/v1/events?after=0",
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    timeout(Duration::from_secs(2), async {
        let mut received = String::new();
        loop {
            let mut line = String::new();
            assert!(stream.read_line(&mut line).await.unwrap() > 0);
            received.push_str(&line);
            if line.starts_with(": connected") {
                break;
            }
        }
        assert_eq!(status(&received), 200);
        assert!(!received.contains("data:"));
        assert!(!received.contains("id:"));
    })
    .await
    .expect("empty SSE must flush before the client's header timeout");
    let conn = rusqlite::Connection::open(db).unwrap();
    let events: i64 = conn
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(events, 0, "opening a stream must not invent a ledger event");
}

#[tokio::test]
async fn authenticated_sse_replays_real_ledger_events_without_csrf() {
    let dir = support::private_tempdir();
    let db = dir.path().join("sse.sqlite");
    let mut ledger = bullet_adapters::SqliteLedger::open(&db).unwrap();
    bullet_application::run_demo(&mut ledger).unwrap();
    drop(ledger);
    let addr =
        start(bullet_farmd::api::router_with_bootstrap(&db, BOOTSTRAP, ORIGIN.into()).unwrap())
            .await;
    let cookie = bootstrap(addr).await;
    let mut stream = open(
        addr,
        "GET",
        "/api/v1/events?after=0",
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    timeout(Duration::from_secs(10), async {
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert!(stream.read_line(&mut line).await.unwrap() > 0);
            headers.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        assert_eq!(status(&headers), 200, "{headers}");
        assert_eq!(header(&headers, "content-type"), Some("text/event-stream"));
        assert_eq!(header(&headers, "cache-control"), Some("no-store"));
        loop {
            let mut line = String::new();
            assert!(stream.read_line(&mut line).await.unwrap() > 0);
            if let Some(data) = line.strip_prefix("data: ") {
                let event: Value = serde_json::from_str(data.trim()).unwrap();
                assert_eq!(event["seq"], 1);
                assert!(!event["kind"].as_str().unwrap().is_empty());
                break;
            }
        }
    })
    .await
    .unwrap();
}
