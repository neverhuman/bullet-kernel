use super::*;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn session(directory: &std::path::Path) -> Session {
    Session {
        directory: directory.join("state"),
        credentials: crate::auth::store::Credentials {
            schema_version: 1,
            farmd: "http://127.0.0.1:7420".into(),
            origin: "http://127.0.0.1:7420".into(),
            cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
            csrf: format!("csrf_{}", "b".repeat(64)),
        },
    }
}
fn page() -> Value {
    json!({"data":{"commands":[{
        "id":format!("cmd_{}", "1".repeat(64)),"kind":"run_coding",
        "payload_digest":"2".repeat(64),"status":"UNKNOWN","result":null
    }],"next_after":3},"as_of_sequence":5,
    "observed_at":"2026-09-10T00:00:00Z","source":"bullet-kernel/sqlite-ledger"})
}
fn response(body: Value) -> http::HttpResponse {
    http::HttpResponse {
        status: 200,
        body,
        set_cookie: None,
        sequence: Some(5),
    }
}
fn private_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[test]
fn empty_journal_discovery_uses_authenticated_get_and_preserves_continuation() {
    let temp = private_temp();
    let mut session = session(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    session.credentials.farmd = format!("http://{}", listener.local_addr().unwrap());
    session.credentials.origin = session.farmd.clone();
    let expected_cookie = session.cookie.clone();
    let expected_origin = session.origin.clone();
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) => panic!("accept failed: {error}"),
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 4096);
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("GET /api/v1/commands?after=1&limit=1 HTTP/1.1\r\n"));
        assert!(text.contains(&format!("cookie: {expected_cookie}\r\n")));
        assert!(text.contains(&format!("origin: {expected_origin}\r\n")));
        assert!(!text.contains("csrf"));
        let body = page().to_string();
        write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-bullet-as-of-sequence: 5\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    });
    let result = list(&session, 1, 1);
    server.join().unwrap();
    assert_eq!(result.unwrap(), page());
    assert!(!session
        .directory
        .join(format!("cmd_{}.json", "1".repeat(64)))
        .exists());
}

#[test]
fn discovery_refuses_inconsistent_pages_instead_of_reporting_empty_success() {
    let temp = private_temp();
    let session = session(temp.path());
    let mut malformed = Vec::new();
    for next in [json!(0), json!(1), json!(6)] {
        let mut body = page();
        body["data"]["next_after"] = next;
        malformed.push(body);
    }
    let mut duplicate = page();
    let row = duplicate["data"]["commands"][0].clone();
    duplicate["data"]["commands"]
        .as_array_mut()
        .unwrap()
        .push(row);
    malformed.push(duplicate);
    let mut empty = page();
    empty["data"]["commands"] = json!([]);
    malformed.push(empty);
    let mut foreign = page();
    foreign["source"] = json!("foreign");
    malformed.push(foreign);
    let mut extra = page();
    extra["data"]["authority"] = json!(true);
    malformed.push(extra);
    let mut phase = page();
    phase["data"]["commands"][0]["status"] = json!("VERIFIED");
    malformed.push(phase);
    let mut date = page();
    date["observed_at"] = json!("bad");
    malformed.push(date);
    for body in malformed {
        assert!(validate(&session, response(body), 1, 100).is_err());
    }
    for header in [None, Some(4)] {
        let mut changed = response(page());
        changed.sequence = header;
        assert!(validate(&session, changed, 1, 100).is_err());
    }
    let mut denied = response(page());
    denied.status = 401;
    assert!(validate(&session, denied, 1, 100)
        .unwrap_err()
        .contains("HTTP 401"));
    assert!(validate(&session, response(page()), 6, 100).is_err());
    let mut last = page();
    last["data"]["next_after"] = Value::Null;
    assert!(validate(&session, response(last), 3, 100).is_ok());
}

#[test]
fn discovery_correlates_available_journal_before_returning_server_subjects() {
    let temp = private_temp();
    let session = session(temp.path());
    let payload = super::super::task::payload(
        super::super::task::fixture(),
        "acct",
        "codex",
        "model",
        None,
    )
    .unwrap();
    let input = super::super::SubmitRequest {
        payload: &payload,
        idempotency_key: Some("discovery-journal"),
    };
    let (_, request) = journal::prepare(&session, &input).unwrap();
    let mut body = page();
    body["data"]["commands"][0]["id"] = json!(request.id().as_str());
    assert!(validate(&session, response(body.clone()), 1, 100)
        .unwrap_err()
        .contains("FARMD_COMMAND_SUBJECT_MISMATCH"));
    body["data"]["commands"][0]["payload_digest"] = json!(request.digest().to_hex());
    assert!(validate(&session, response(body), 1, 100).is_ok());
}
