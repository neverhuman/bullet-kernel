use super::*;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

#[test]
fn auth_status_releases_credential_custody_before_waiting_for_http() {
    use crate::auth::store::CredentialStore;
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    CredentialStore::open(directory.path())
        .unwrap()
        .save(&Credentials {
            schema_version: 1,
            farmd: endpoint.clone(),
            origin: endpoint,
            cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
            csrf: format!("csrf_{}", "b".repeat(64)),
        })
        .unwrap();
    let path = directory.path().to_path_buf();
    let client = std::thread::spawn(move || {
        crate::auth::run(crate::auth::AuthCommands::Status {
            state_dir: Some(path),
        })
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => panic!("accept failed: {e}"),
        }
        assert!(Instant::now() < deadline, "status did not reach HTTP");
        std::thread::sleep(Duration::from_millis(5));
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() < 16_384);
    }
    // Both results are captured while Status is blocked awaiting the server.
    let snapshot = CredentialStore::read_credentials(directory.path());
    let writer = CredentialStore::open(directory.path());
    let writer_available = writer.is_ok();
    drop(writer);
    let body = json!({
        "status":"AUTHENTICATED", "operator_id":format!("opr_{}", "1".repeat(64)),
        "session_id":format!("sid_{}", "2".repeat(64)),
        "issued_at":"2026-09-10T00:00:00Z", "expires_at":"2026-09-10T08:00:00Z"
    })
    .to_string();
    write!(socket,"HTTP/1.1 200 OK\r\nx-bullet-session-id: sid_{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}","2".repeat(64),body.len()).unwrap();
    assert!(client.join().unwrap().is_ok());
    assert!(request.starts_with(b"GET /api/v1/auth/session HTTP/1.1\r\n"));
    assert!(snapshot.unwrap().is_some(), "status excluded other readers");
    assert!(
        writer_available,
        "status held credential custody across HTTP"
    );
}

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
                    assert_eq!(
                        request
                            .lines()
                            .filter(|line| line.starts_with("x-bullet-expected-session:"))
                            .collect::<Vec<_>>(),
                        vec![format!("x-bullet-expected-session: sid_{}", "2".repeat(64))]
                    );
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
                let acknowledgement = format!("x-bullet-session-id: sid_{}\r\n", "2".repeat(64));
                write!(socket,"HTTP/1.1 200 OK\r\n{acknowledgement}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
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

type SessionFixture = (
    std::sync::mpsc::Receiver<Result<crate::client::models::OperatorSessionView, String>>,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
    std::thread::JoinHandle<()>,
);

fn observed_session_fixture(acknowledgement: String, body: String) -> SessionFixture {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let credentials = Credentials {
        schema_version: 1,
        farmd: endpoint.clone(),
        origin: endpoint,
        cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
        csrf: format!("csrf_{}", "b".repeat(64)),
    };
    let (release, wait) = std::sync::mpsc::channel();
    let (sent, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
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
        assert!(request.starts_with("GET /api/v1/auth/session HTTP/1.1\r\n"));
        assert!(request.contains(&format!(
            "cookie: bullet_session=ses_{}\r\n",
            "a".repeat(64)
        )));
        assert!(!request.contains("x-bullet-expected-session:"));
        write!(socket, "HTTP/1.1 200 OK\r\n{acknowledgement}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
        socket.flush().unwrap();
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        let _ = socket.write_all(body.as_bytes());
    });
    let client = std::thread::spawn(move || {
        let _ = sent.send(status(&credentials));
    });
    (received, release, server, client)
}

#[test]
fn session_discovery_refuses_missing_invalid_or_duplicate_ack_before_reading_body() {
    let valid = format!("x-bullet-session-id: sid_{}\r\n", "2".repeat(64));
    for (ack, reason) in [
        (String::new(), "FARMD_SESSION_ACK_MISSING"),
        (
            "x-bullet-session-id: \r\n".into(),
            "FARMD_SESSION_ACK_INVALID",
        ),
        (
            format!("x-bullet-session-id: sid_{}\r\n", "A".repeat(64)),
            "FARMD_SESSION_ACK_INVALID",
        ),
        (
            format!("x-bullet-session-id: ses_{}\r\n", "2".repeat(64)),
            "FARMD_SESSION_ACK_INVALID",
        ),
        (valid.repeat(2), "FARMD_SESSION_ACK_AMBIGUOUS"),
    ] {
        let (received, release, server, client) =
            observed_session_fixture(ack, "PRIVATE_NOT_JSON".into());
        let early = received.recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        server.join().unwrap();
        client.join().unwrap();
        let error = early
            .expect("ack refusal must precede body release")
            .err()
            .unwrap();
        assert_eq!(error, reason);
        assert!(!error.contains("PRIVATE"));
    }
}

#[test]
fn session_discovery_requires_generated_body_to_match_acknowledged_session() {
    for suffix in ["2", "3"] {
        let expected = format!("sid_{}", "2".repeat(64));
        let body = json!({"status":"AUTHENTICATED","operator_id":format!("opr_{}","1".repeat(64)),
            "session_id":format!("sid_{}",suffix.repeat(64)),"issued_at":"2026-09-10T00:00:00Z",
            "expires_at":"2026-09-10T08:00:00Z"})
        .to_string();
        let (received, release, server, client) =
            observed_session_fixture(format!("x-bullet-session-id: {expected}\r\n"), body);
        let early = received.recv_timeout(Duration::from_millis(100));
        release.send(()).unwrap();
        server.join().unwrap();
        client.join().unwrap();
        assert!(matches!(
            early,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        let result = received.recv_timeout(Duration::from_secs(2)).unwrap();
        if suffix == "2" {
            assert_eq!(result.unwrap().session_id, expected);
        } else {
            assert_eq!(result.err().unwrap(), "AUTH_SESSION_SUBJECT_MISMATCH");
        }
    }
}

#[test]
fn revoke_acknowledgement_precedes_body_and_local_credential_removal() {
    use crate::auth::store::CredentialStore;
    use std::os::unix::fs::PermissionsExt;
    for outcome in ["missing", "foreign", "duplicate", "absent", "lost", "valid"] {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
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
        CredentialStore::open(directory.path())
            .unwrap()
            .save(&credentials)
            .unwrap();
        let path = directory.path().to_path_buf();
        let (sent, received) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            sent.send(crate::auth::run(crate::auth::AuthCommands::Revoke {
                state_dir: Some(path),
            }))
            .unwrap();
        });
        for method in ["GET", "POST"] {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("accept failed: {e}"),
                }
                assert!(Instant::now() < deadline, "caller did not reach {method}");
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
            let request = String::from_utf8(bytes).unwrap();
            let path = if method == "GET" { "session" } else { "revoke" };
            assert!(request.starts_with(&format!("{method} /api/v1/auth/{path} HTTP/1.1\r\n")));
            for (name, value) in [
                ("cookie", &credentials.cookie),
                ("origin", &credentials.origin),
            ] {
                assert!(request.contains(&format!("\r\n{name}: {value}\r\n")));
            }
            let sid = format!("sid_{}", "2".repeat(64));
            let expected = if method == "GET" {
                vec![]
            } else {
                vec![format!("x-bullet-expected-session: {sid}")]
            };
            assert_eq!(
                request
                    .lines()
                    .filter(|line| line.starts_with("x-bullet-expected-session:"))
                    .collect::<Vec<_>>(),
                expected
            );
            let operator = format!("opr_{}", "1".repeat(64));
            if method == "GET" {
                assert!(!request.contains("csrf"));
                let body = json!({"status":"AUTHENTICATED","operator_id":operator,"session_id":sid,"issued_at":"2026-09-10T00:00:00Z","expires_at":"2026-09-10T08:00:00Z"}).to_string();
                write!(socket,"HTTP/1.1 200 OK\r\nx-bullet-session-id: {sid}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                continue;
            }
            assert!(request.contains(&format!("\r\nx-bullet-csrf: {}\r\n", credentials.csrf)));
            assert!(request.contains("\r\ncontent-length: 2\r\n"));
            let mut bytes = [0; 2];
            socket.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"{}");
            if outcome == "lost" {
                drop(socket);
                continue;
            }
            let ack = match outcome {
                "missing" | "absent" => String::new(),
                "foreign" => format!("x-bullet-session-id: sid_{}\r\n", "3".repeat(64)),
                "duplicate" => format!("x-bullet-session-id: {sid}\r\n").repeat(2),
                _ => format!("x-bullet-session-id: {sid}\r\n"),
            };
            let body = json!({"status":"REVOKED","operator_id":operator,"session_id":sid,"revoked_at":"2026-09-10T00:01:00Z"}).to_string();
            let status = if outcome == "absent" { 404 } else { 200 };
            write!(socket,"HTTP/1.1 {status} Fixture\r\n{ack}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len()).unwrap();
            socket.flush().unwrap();
            let early = received.recv_timeout(Duration::from_millis(if outcome == "valid" {
                100
            } else {
                2000
            }));
            if outcome == "valid" {
                assert!(matches!(
                    early,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ));
                socket.write_all(body.as_bytes()).unwrap();
            } else {
                let _ = socket.write_all(body.as_bytes());
                assert!(early
                    .expect("ack refusal must precede body release")
                    .unwrap_err()
                    .contains("AUTH_REVOCATION_UNKNOWN"));
            }
        }
        client.join().unwrap();
        if outcome == "valid" {
            assert!(received
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_ok());
            assert!(CredentialStore::read_credentials(directory.path())
                .unwrap()
                .is_none());
        } else {
            if outcome == "lost" {
                assert!(received
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap_err()
                    .contains("AUTH_REVOCATION_UNKNOWN"));
            }
            let retained = CredentialStore::read_credentials(directory.path())
                .unwrap()
                .unwrap();
            assert_eq!(retained.cookie, credentials.cookie);
            assert_eq!(retained.csrf, credentials.csrf);
            assert_eq!(retained.farmd, credentials.farmd);
            assert_eq!(retained.origin, credentials.origin);
        }
    }
}
