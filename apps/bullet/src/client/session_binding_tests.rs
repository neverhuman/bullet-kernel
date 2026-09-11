//! Actual TCP consumers: session observation followed by the selected read.
use super::*;
use crate::auth::store::Credentials;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn fixture(
    path: &'static str,
    status: u16,
    ack: Option<&'static str>,
    body: Value,
    suffix: &'static str,
) -> (Credentials, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let credentials = Credentials {
        schema_version: 1,
        farmd: endpoint.clone(),
        origin: endpoint,
        cookie: format!("bullet_session=ses_{}", suffix.repeat(64)),
        csrf: format!("csrf_{}", "b".repeat(64)),
    };
    let server = std::thread::spawn(move || {
        for selected in ["/api/v1/auth/session", path] {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => panic!("accept: {error}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "actual caller did not reach selected read"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16_384);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!("GET {selected} HTTP/1.1\r\n")));
            assert!(request.contains(&format!(
                "cookie: bullet_session=ses_{}\r\n",
                suffix.repeat(64)
            )));
            let discovery = selected == "/api/v1/auth/session";
            let session = format!("sid_{}", suffix.repeat(64));
            if discovery {
                assert!(!request.contains("x-bullet-expected-session:"));
            } else {
                assert!(request.contains(&format!("x-bullet-expected-session: {session}\r\n")));
            }
            let (status, acknowledgement, response) = if discovery {
                (
                    200,
                    format!("x-bullet-session-id: {session}\r\n"),
                    json!({
                    "status":"AUTHENTICATED","operator_id":format!("opr_{}",suffix.repeat(64)),
                    "session_id":session,"issued_at":"2026-09-10T00:00:00Z","expires_at":"2026-09-10T08:00:00Z"}),
                )
            } else {
                (
                    status,
                    ack.map(|value| format!("x-bullet-session-id: sid_{}\r\n", value.repeat(64)))
                        .unwrap_or_default(),
                    body.clone(),
                )
            };
            let body = response.to_string();
            write!(socket, "HTTP/1.1 {status} Fixture\r\n{acknowledgement}x-bullet-as-of-sequence: 0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    (credentials, server)
}

#[test]
fn actual_command_discovery_uses_observed_session_for_each_credential_snapshot() {
    for suffix in ["a", "c"] {
        let body = json!({"data":{"commands":[],"next_after":null},"as_of_sequence":0,
            "observed_at":"2026-09-10T00:00:00Z","source":"bullet-kernel/sqlite-ledger"});
        let (credentials, server) = fixture("/api/v1/commands", 200, Some(suffix), body, suffix);
        let result = coding_commands(&credentials);
        server.join().unwrap();
        assert!(result.unwrap().data.commands.is_empty());
    }
}

#[test]
fn actual_snapshot_and_command_readers_refuse_foreign_or_unacknowledged_response() {
    for path in ["/api/v1/operator-snapshot", "/api/v1/commands"] {
        for ack in [None, Some("b")] {
            let (credentials, server) =
                fixture(path, 200, ack, json!({"PRIVATE":"not a projection"}), "a");
            let result = if path.ends_with("operator-snapshot") {
                operator_snapshot(&credentials).map(|_| ())
            } else {
                coding_commands(&credentials).map(|_| ())
            };
            server.join().unwrap();
            assert_eq!(
                result.unwrap_err(),
                if ack.is_none() {
                    "FARMD_SESSION_ACK_MISSING"
                } else {
                    "FARMD_SESSION_ACK_MISMATCH"
                }
            );
        }
    }
}

#[test]
fn shared_authenticated_read_accepts_absence_only_for_observed_owner() {
    for ack in [None, Some("b"), Some("a")] {
        let (credentials, server) = fixture(
            "/api/v1/commands/absent",
            404,
            ack,
            json!({"status":404}),
            "a",
        );
        let result = authenticated_get(&credentials, "/api/v1/commands/absent", &[]);
        server.join().unwrap();
        if ack == Some("a") {
            assert_eq!(result.unwrap().status, 404);
        } else {
            assert_eq!(
                result.err().unwrap(),
                if ack.is_none() {
                    "FARMD_SESSION_ACK_MISSING"
                } else {
                    "FARMD_SESSION_ACK_MISMATCH"
                }
            );
        }
    }
}
