//! Real-socket browser authority and public command reconciliation tests.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const ORIGIN: &str = "http://127.0.0.1:7420";
const BOOTSTRAP: &str = "boot_0000000000000000000000000000000000000000000000000000000000000000";

struct TestServer {
    addr: SocketAddr,
    db: PathBuf,
}

struct HttpResponse {
    status: u16,
    text: String,
    body: Value,
}

type GuardCase<'a> = (&'a [(&'a str, &'a str)], u16, &'a str);

async fn start(db: &Path) -> TestServer {
    let app = bullet_farmd::api::router_with_bootstrap(db, BOOTSTRAP, ORIGIN.to_string())
        .expect("router");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    TestServer {
        addr,
        db: db.to_path_buf(),
    }
}

async fn request(
    server: &TestServer,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> HttpResponse {
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");
    let payload = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    ));
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .expect("response timeout")
        .expect("read");
    let text = String::from_utf8_lossy(&bytes).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("status");
    let body = decode_body(text.split_once("\r\n\r\n").expect("body").1);
    HttpResponse { status, text, body }
}

fn decode_body(body: &str) -> Value {
    if body.trim().is_empty() {
        return Value::Null;
    }
    if let Ok(value) = serde_json::from_str(body) {
        return value;
    }
    let unchunked: String = body
        .lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect();
    serde_json::from_str(&unchunked).expect("json body")
}

fn header(response: &HttpResponse, name: &str) -> Option<String> {
    response.text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

async fn bootstrap(server: &TestServer) -> (String, String) {
    let response = request(
        server,
        "POST",
        "/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        Some(&json!({"bootstrap_token": BOOTSTRAP})),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.text);
    assert_eq!(response.body["status"], "AUTHENTICATED");
    let set_cookie = header(&response, "set-cookie").expect("session cookie");
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Path=/"));
    assert!(!set_cookie.contains("Domain="));
    let cookie = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    let csrf = response.body["csrf_token"]
        .as_str()
        .expect("csrf")
        .to_string();
    (cookie, csrf)
}

fn command_headers<'a>(cookie: &'a str, csrf: &'a str) -> [(&'a str, &'a str); 3] {
    [
        ("Origin", ORIGIN),
        ("Cookie", cookie),
        ("X-Bullet-CSRF", csrf),
    ]
}

#[tokio::test]
async fn bootstrap_is_strict_one_time_and_never_enables_wildcard_cors() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = start(&directory.path().join("auth.sqlite")).await;
    let missing = request(
        &server,
        "POST",
        "/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        Some(&json!({})),
    )
    .await;
    assert_eq!(missing.status, 400);
    assert_eq!(missing.body["code"], "INVALID_JSON");
    let wrong = request(
        &server,
        "POST",
        "/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        Some(&json!({
            "bootstrap_token":
                "boot_1111111111111111111111111111111111111111111111111111111111111111"
        })),
    )
    .await;
    assert_eq!(wrong.status, 401);
    assert_eq!(wrong.body["code"], "BOOTSTRAP_INVALID");
    let _session = bootstrap(&server).await;
    let replay = request(
        &server,
        "POST",
        "/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        Some(&json!({"bootstrap_token": BOOTSTRAP})),
    )
    .await;
    assert_eq!(replay.status, 401);
    assert_eq!(replay.body["code"], "BOOTSTRAP_CONSUMED");
    assert_eq!(header(&replay, "access-control-allow-origin"), None);
}

#[tokio::test]
async fn origin_cookie_and_csrf_each_fail_closed_before_command_mutation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = start(&directory.path().join("guards.sqlite")).await;
    let (cookie, csrf) = bootstrap(&server).await;
    let command = json!({"idempotency_key":"guarded","kind":"run_demo","payload":{}});
    let cases: &[GuardCase<'_>] = &[
        (&[], 403, "ORIGIN_REQUIRED"),
        (
            &[("Origin", "https://attacker.invalid")],
            403,
            "ORIGIN_DENIED",
        ),
        (&[("Origin", ORIGIN)], 401, "SESSION_REQUIRED"),
        (
            &[("Origin", ORIGIN), ("Cookie", &cookie)],
            403,
            "CSRF_REQUIRED",
        ),
        (
            &[
                ("Origin", ORIGIN),
                ("Cookie", &cookie),
                (
                    "X-Bullet-CSRF",
                    "csrf_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                ),
            ],
            403,
            "CSRF_INVALID",
        ),
    ];
    for (headers, status, code) in cases {
        let response = request(&server, "POST", "/v1/commands", headers, Some(&command)).await;
        assert_eq!(response.status, *status, "{code}");
        assert_eq!(response.body["code"], *code);
        assert_eq!(response.body["status"], *status);
        assert!(response.body["request_id"].as_str().is_some());
        assert!(response.body["repair"].as_str().is_some());
        assert_eq!(
            header(&response, "content-type").as_deref(),
            Some("application/problem+json")
        );
    }
    let count: i64 = Connection::open(&server.db)
        .expect("open")
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 0);
    assert!(!csrf.is_empty());
}

#[tokio::test]
async fn command_submission_replay_conflict_and_statuses_are_durable_truth() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = start(&directory.path().join("commands.sqlite")).await;
    let (cookie, csrf) = bootstrap(&server).await;
    let headers = command_headers(&cookie, &csrf);
    let command = json!({
        "idempotency_key": "run-once",
        "kind": "run_demo",
        "payload": {"requested": true}
    });
    let first = request(&server, "POST", "/v1/commands", &headers, Some(&command)).await;
    assert_eq!(first.status, 202, "{}", first.text);
    assert_eq!(first.body["status"], "PENDING");
    assert_eq!(first.body["result"], Value::Null);
    let command_id = first.body["id"].as_str().expect("id");
    let replay = request(&server, "POST", "/v1/commands", &headers, Some(&command)).await;
    assert_eq!(replay.status, 202);
    assert_eq!(replay.body, first.body);
    let conflict = request(
        &server,
        "POST",
        "/v1/commands",
        &headers,
        Some(&json!({
            "idempotency_key": "run-once",
            "kind": "run_demo",
            "payload": {"requested": false}
        })),
    )
    .await;
    assert_eq!(conflict.status, 409);
    assert_eq!(conflict.body["code"], "IDEMPOTENCY_CONFLICT");

    let connection = Connection::open(&server.db).expect("raw open");
    let outbox_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE command_id = ?1 AND kind = 'command_dispatch'",
            params![command_id],
            |row| row.get(0),
        )
        .expect("outbox count");
    assert_eq!(outbox_count, 1);
    for (phase, result, expected) in [
        ("applied", Some(r#"{"applied":true}"#), "APPLIED"),
        ("verified", Some(r#"{"verified":true}"#), "VERIFIED"),
        ("failed", Some(r#"{"error":"gate"}"#), "FAILED"),
        ("unknown", None, "UNKNOWN"),
    ] {
        connection
            .execute(
                "UPDATE commands SET phase = ?1, response_json = ?2 WHERE id = ?3",
                params![phase, result, command_id],
            )
            .expect("phase fixture");
        let status = request(
            &server,
            "GET",
            &format!("/v1/commands/{command_id}"),
            &[("Cookie", &cookie)],
            None,
        )
        .await;
        assert_eq!(status.status, 200, "{phase}: {}", status.text);
        assert_eq!(status.body["status"], expected);
    }
}

#[tokio::test]
async fn strict_envelope_and_authenticated_status_reads_refuse_ambiguity() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = start(&directory.path().join("strict.sqlite")).await;
    let (cookie, csrf) = bootstrap(&server).await;
    let headers = command_headers(&cookie, &csrf);
    let unknown_field = request(
        &server,
        "POST",
        "/v1/commands",
        &headers,
        Some(&json!({
            "idempotency_key":"strict",
            "kind":"run_demo",
            "payload":{},
            "optimistic_success":true
        })),
    )
    .await;
    assert_eq!(unknown_field.status, 400);
    assert_eq!(unknown_field.body["code"], "INVALID_JSON");
    let missing_session = request(
        &server,
        "GET",
        &format!("/v1/commands/cmd_{}", "0".repeat(32)),
        &[],
        None,
    )
    .await;
    assert_eq!(missing_session.status, 401);
    assert_eq!(missing_session.body["code"], "SESSION_REQUIRED");
    let missing = request(
        &server,
        "GET",
        &format!("/v1/commands/cmd_{}", "0".repeat(32)),
        &[("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body["code"], "NOT_FOUND");

    let admitted = request(
        &server,
        "POST",
        "/v1/commands",
        &headers,
        Some(&json!({"idempotency_key":"strict","kind":"run_demo","payload":{}})),
    )
    .await;
    assert_eq!(admitted.status, 202);
    let admitted_id = admitted.body["id"].as_str().expect("command id");
    let connection = Connection::open(&server.db).expect("raw open");
    connection
        .execute(
            "DELETE FROM events
             WHERE kind = 'command_submitted' AND body = ?1 AND correlation_id = ?1",
            params![admitted_id],
        )
        .expect("remove submitted audit truth");
    let missing_event = request(
        &server,
        "GET",
        &format!("/v1/commands/{admitted_id}"),
        &[("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(missing_event.status, 500);
    assert_eq!(missing_event.body["code"], "STORE_FAILURE");

    let outbox_command = request(
        &server,
        "POST",
        "/v1/commands",
        &headers,
        Some(&json!({
            "idempotency_key":"strict-outbox",
            "kind":"run_demo",
            "payload":{}
        })),
    )
    .await;
    assert_eq!(outbox_command.status, 202);
    let outbox_command_id = outbox_command.body["id"].as_str().expect("command id");
    connection
        .execute(
            "DELETE FROM outbox WHERE command_id = ?1",
            params![outbox_command_id],
        )
        .expect("remove dispatch truth");
    let corrupt = request(
        &server,
        "GET",
        &format!("/v1/commands/{outbox_command_id}"),
        &[("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(corrupt.status, 500);
    assert_eq!(corrupt.body["code"], "STORE_FAILURE");
}
