use super::*;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

#[test]
fn revocation_requires_the_observed_identity_and_exact_authenticated_empty_request() {
    for outcome in [
        "valid",
        "foreign",
        "lost",
        "malformed",
        "long_session",
        "backwards_session",
        "early_revoke",
        "expired_revoke",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let credentials = Credentials {
            schema_version: 1,
            farmd: endpoint.clone(),
            origin: endpoint.clone(),
            cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
            csrf: format!("csrf_{}", "b".repeat(64)),
        };
        let worker = std::thread::spawn(move || {
            let methods = if outcome.ends_with("_session") {
                &["GET"][..]
            } else {
                &["GET", "POST"][..]
            };
            for &method in methods {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(e) => panic!("accept failed: {e}"),
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
                    assert!(bytes.len() < 16_384);
                }
                let request = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
                let path = if method == "GET" { "session" } else { "revoke" };
                assert!(request.starts_with(&format!(
                    "{} /api/v1/auth/{path} http/1.1\r\n",
                    method.to_ascii_lowercase()
                )));
                assert!(request.contains(&format!("\r\norigin: {endpoint}\r\n")));
                assert!(request.contains(&format!(
                    "\r\ncookie: bullet_session=ses_{}\r\n",
                    "a".repeat(64)
                )));
                if method == "POST" {
                    assert!(request
                        .contains(&format!("\r\nx-bullet-csrf: csrf_{}\r\n", "b".repeat(64))));
                    assert!(request.contains("\r\ncontent-length: 2\r\n"));
                    let mut body = [0; 2];
                    socket.read_exact(&mut body).unwrap();
                    assert_eq!(&body, b"{}");
                    if outcome == "lost" {
                        continue;
                    }
                }
                let operator = format!("opr_{}", "1".repeat(64));
                let session = format!("sid_{}", "2".repeat(64));
                let expiry = match outcome {
                    "long_session" => "2026-09-10T08:00:01Z",
                    "backwards_session" => "2026-09-10T00:00:00Z",
                    _ => "2026-09-10T08:00:00Z",
                };
                let revoked_at = match outcome {
                    "early_revoke" => "2026-09-09T23:59:59Z",
                    "expired_revoke" => "2026-09-10T08:00:00Z",
                    _ => "2026-09-10T00:01:00Z",
                };
                let body=if method=="GET" {
                    json!({"status":"AUTHENTICATED","operator_id":operator,"session_id":session,"issued_at":"2026-09-10T00:00:00Z","expires_at":expiry})
                } else if outcome=="malformed" { json!({}) }
                else { json!({"status":"REVOKED","operator_id":operator,"session_id":if outcome=="foreign" {format!("sid_{}","3".repeat(64))} else {session},"revoked_at":revoked_at}) }.to_string();
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        let result = revoke(&credentials);
        worker.join().unwrap();
        match outcome {
            "valid" => assert!(result.is_ok()),
            "foreign" => assert!(result
                .err()
                .unwrap()
                .contains("AUTH_REVOCATION_SUBJECT_MISMATCH")),
            "lost" => assert!(result.err().unwrap().contains("AUTH_REVOCATION_UNKNOWN")),
            _ => assert!(result.is_err()),
        }
    }
}
