use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn status_reconciles_the_saved_request_and_refuses_same_id_foreign_payloads() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;
    for mismatch in [None, Some("kind"), Some("payload_digest")] {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let session = Session {
            directory: temp.path().join("state"),
            credentials: crate::auth::store::Credentials {
                schema_version: 1,
                farmd: endpoint.clone(),
                origin: endpoint,
                cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
                csrf: format!("csrf_{}", "b".repeat(64)),
            },
        };
        let payload = super::super::task::payload(
            super::super::task::fixture(),
            "acct",
            "codex",
            "model",
            None,
        )
        .unwrap();
        let input = SubmitRequest {
            payload: &payload,
            idempotency_key: Some("lost-response"),
        };
        let (_, request) = prepare(&session, &input).unwrap();
        let mut body = serde_json::json!({"id":request.id().as_str(),"kind":request.kind,"payload_digest":request.digest().to_hex(),"status":"FAILED","result":{"reason":"component_fixture"}});
        if let Some(field) = mismatch {
            body[field] = serde_json::json!(if field == "kind" {
                "run_demo".into()
            } else {
                "0".repeat(64)
            });
        }
        let expected_path = format!("GET /api/v1/commands/{} HTTP/1.1\r\n", request.id());
        let expected_cookie = session.cookie.clone();
        let expected_origin = session.origin.clone();
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            for selected in [
                "GET /api/v1/auth/session HTTP/1.1\r\n",
                expected_path.as_str(),
            ] {
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(e) => panic!("accept failed: {e}"),
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "caller did not reach {selected}"
                    );
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
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.starts_with(selected));
                assert!(text.contains(&format!("cookie: {expected_cookie}\r\n")));
                assert!(text.contains(&format!("origin: {expected_origin}\r\n")));
                assert!(!text.contains("csrf"));
                let sid = format!("sid_{}", "c".repeat(64));
                let discovery = selected.starts_with("GET /api/v1/auth/session ");
                let expected = if discovery {
                    vec![]
                } else {
                    vec![format!("x-bullet-expected-session: {sid}")]
                };
                assert_eq!(
                    text.lines()
                        .filter(|line| line.starts_with("x-bullet-expected-session:"))
                        .collect::<Vec<_>>(),
                    expected
                );
                let response = if discovery {
                    serde_json::json!({"status":"AUTHENTICATED","operator_id":format!("opr_{}","d".repeat(64)),
                        "session_id":sid,"issued_at":"2026-09-10T00:00:00Z","expires_at":"2026-09-10T08:00:00Z"})
                } else {
                    body.clone()
                }.to_string();
                write!(socket,"HTTP/1.1 200 OK\r\nx-bullet-session-id: {sid}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
            }
        });
        let result = super::super::status(&session, request.id().as_str());
        server.join().unwrap();
        match mismatch {
            None => assert_eq!(result.unwrap()["status"], "FAILED"),
            Some(_) => assert!(result
                .unwrap_err()
                .contains("FARMD_COMMAND_SUBJECT_MISMATCH")),
        }
    }
}
#[test]
fn retries_after_client_restart_reuse_all_original_authority_bytes() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let session = Session {
        directory: temp.path().join("state"),
        credentials: crate::auth::store::Credentials {
            schema_version: 1,
            farmd: "http://127.0.0.1:7420".into(),
            origin: "http://127.0.0.1:7420".into(),
            cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
            csrf: format!("csrf_{}", "b".repeat(64)),
        },
    };
    let envelope = serde_json::json!({"idempotency_key":"retry-key","kind":"run_coding","payload":{
        "account_id":"acct","provider":"codex","model":"model","expected_revision":1,
        "launch_nonce":"ab".repeat(32),"quota_reservation":format!("rsv_{}","cd".repeat(32)),"quota_units":1,
        "allocated_run":bullet_domain::RunnerId::from_seed("historical-cli").as_str()}});
    let original = CommandRequest::new("retry-key", "run_coding", &envelope["payload"]).unwrap();
    let store = crate::auth::store::CredentialStore::open(&session.directory).unwrap();
    let record = Journal {
        schema_version: 1,
        farmd: session.farmd.clone(),
        origin: session.origin.clone(),
        envelope: envelope.clone(),
    };
    store
        .record_command(&original.id(), &serde_json::to_value(record).unwrap())
        .unwrap();
    drop(store);
    let request = reconciliation_request(&session, original.id().as_str())
        .unwrap()
        .unwrap();
    let retry = reconciliation_request(&session, original.id().as_str())
        .unwrap()
        .unwrap();
    assert_eq!(request, original);
    assert_eq!(retry, original);
    assert_eq!(
        serde_json::from_str::<Value>(&request.payload).unwrap(),
        envelope["payload"]
    );
    let response = serde_json::json!({"id":request.id().as_str(),"kind":"run_coding","payload_digest":request.digest().to_hex()});
    assert!(correlate(&request, &response).is_ok());
    let mut wrong = response;
    wrong["payload_digest"] = serde_json::json!("other");
    assert!(correlate(&request, &wrong).is_err());
    let bytes = std::fs::read_to_string(
        session
            .directory
            .join(format!("{}.json", request.id().as_str())),
    )
    .unwrap();
    assert!(!bytes.contains("ses_"));
    assert!(!bytes.contains("csrf_"));
}
#[test]
fn terminal_json_escapes_untrusted_controls_without_changing_the_value() {
    let value = serde_json::json!({"kind":"a\u{009b}\u{202e}b"});
    let safe = super::super::terminal_json(&value.to_string());
    assert!(!safe.contains('\u{009b}'));
    assert!(!safe.contains('\u{202e}'));
    assert_eq!(serde_json::from_str::<Value>(&safe).unwrap(), value);
}

#[test]
fn task_journal_retry_preserves_intent_and_refuses_changed_task_model_or_effort() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let session = Session {
        directory: temp.path().join("state"),
        credentials: crate::auth::store::Credentials {
            schema_version: 1,
            farmd: "http://127.0.0.1:7420".into(),
            origin: "http://127.0.0.1:7420".into(),
            cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
            csrf: format!("csrf_{}", "b".repeat(64)),
        },
    };
    let original = super::super::task::payload(
        super::super::task::fixture(),
        "acct",
        "codex",
        "model",
        Some("high"),
    )
    .unwrap();
    let input = SubmitRequest {
        payload: &original,
        idempotency_key: Some("task-retry"),
    };
    let (first, request) = prepare(&session, &input).unwrap();
    assert_eq!(prepare(&session, &input).unwrap().0, first);
    for changed in [
        {
            let mut p = original.clone();
            p.task.objective = "Different task".into();
            p
        },
        {
            let mut p = original.clone();
            p.selection.model = "another-model".into();
            p
        },
        {
            let mut p = original.clone();
            p.selection.effort = None;
            p
        },
    ] {
        assert!(prepare(
            &session,
            &SubmitRequest {
                payload: &changed,
                idempotency_key: Some("task-retry")
            }
        )
        .unwrap_err()
        .contains("IDEMPOTENCY_CONFLICT"));
    }
    assert_eq!(
        reconciliation_request(&session, request.id().as_str())
            .unwrap()
            .unwrap(),
        request
    );
    let file = session.directory.join(format!("{}.json", request.id()));
    let bytes = std::fs::read_to_string(&file).unwrap();
    for absent in [
        "ses_",
        "csrf_",
        "launch_nonce",
        "quota_reservation",
        "allocated_run",
    ] {
        assert!(!bytes.contains(absent));
    }
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

fn submission_socket(
    listener: &std::net::TcpListener,
    selected: &str,
) -> (std::net::TcpStream, String) {
    use std::io::Read;
    // Submission commits and syncs its journal before connecting. Allow bounded
    // setup time for real storage under load; acknowledgement-before-body has
    // its own two-second assertion below and must not inherit this allowance.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => panic!("accept failed: {e}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "caller did not reach {selected}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 16_384);
    }
    let request = String::from_utf8(bytes).unwrap();
    assert!(request.starts_with(selected));
    (socket, request)
}

#[test]
fn submission_acknowledgement_precedes_body_and_preserves_journal_after_response_loss() {
    use std::io::{Read, Write};
    use std::time::Duration;
    for outcome in ["missing", "foreign", "duplicate", "absent", "lost", "valid"] {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let session = Session {
            directory: temp.path().join("state"),
            credentials: crate::auth::store::Credentials {
                schema_version: 1,
                farmd: endpoint.clone(),
                origin: endpoint,
                cookie: format!("bullet_session=ses_{}", "a".repeat(64)),
                csrf: format!("csrf_{}", "b".repeat(64)),
            },
        };
        let payload = super::super::task::payload(
            super::super::task::fixture(),
            "acct",
            "codex",
            "model",
            None,
        )
        .unwrap();
        let envelope = serde_json::json!({"idempotency_key":"acknowledged-submit","kind":"run_coding","payload":payload});
        let expected =
            CommandRequest::new("acknowledged-submit", "run_coding", &envelope["payload"]).unwrap();
        let journal = session.directory.join(format!("{}.json", expected.id()));
        let body = serde_json::json!({"id":expected.id().as_str(),"kind":expected.kind,"payload_digest":expected.digest().to_hex(),"status":"PENDING","result":null}).to_string();
        let sid = format!("sid_{}", "c".repeat(64));
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let client = scope.spawn(|| {
                sent.send(super::super::submit(
                    &session,
                    SubmitRequest {
                        payload: &payload,
                        idempotency_key: Some("acknowledged-submit"),
                    },
                ))
                .unwrap();
            });
            let (mut discovery, request) =
                submission_socket(&listener, "GET /api/v1/auth/session HTTP/1.1\r\n");
            let original = std::fs::read(&journal).expect("journal must commit before discovery");
            assert_eq!(
                serde_json::from_slice::<Value>(&original).unwrap()["envelope"],
                envelope
            );
            assert!(!request.contains("x-bullet-expected-session:"));
            assert!(!request.contains("csrf"));
            let view = serde_json::json!({"status":"AUTHENTICATED","operator_id":format!("opr_{}","d".repeat(64)),"session_id":sid,"issued_at":"2026-09-10T00:00:00Z","expires_at":"2026-09-10T08:00:00Z"}).to_string();
            write!(discovery,"HTTP/1.1 200 OK\r\nx-bullet-session-id: {sid}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{view}",view.len()).unwrap();
            drop(discovery);
            let (mut socket, request) =
                submission_socket(&listener, "POST /api/v1/commands HTTP/1.1\r\n");
            assert_eq!(
                request
                    .lines()
                    .filter(|line| line.starts_with("x-bullet-expected-session:"))
                    .collect::<Vec<_>>(),
                vec![format!("x-bullet-expected-session: {sid}")]
            );
            for (name, value) in [
                ("cookie", &session.cookie),
                ("origin", &session.origin),
                ("x-bullet-csrf", &session.csrf),
            ] {
                assert!(request.contains(&format!("\r\n{name}: {value}\r\n")));
            }
            let length: usize = request
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert!(length < 16_384);
            let mut submitted = vec![0; length];
            socket.read_exact(&mut submitted).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&submitted).unwrap(),
                envelope
            );
            let acknowledgement = match outcome {
                "missing" | "absent" => String::new(),
                "foreign" => format!("x-bullet-session-id: sid_{}\r\n", "e".repeat(64)),
                "duplicate" => format!("x-bullet-session-id: {sid}\r\n").repeat(2),
                _ => format!("x-bullet-session-id: {sid}\r\n"),
            };
            let result = if outcome == "lost" {
                drop(socket);
                received.recv_timeout(Duration::from_secs(2)).unwrap()
            } else {
                let status = if outcome == "absent" { 404 } else { 202 };
                write!(socket,"HTTP/1.1 {status} Fixture\r\n{acknowledgement}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len()).unwrap();
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
                    received.recv_timeout(Duration::from_secs(2)).unwrap()
                } else {
                    let _ = socket.write_all(body.as_bytes());
                    early.expect("session refusal must precede body release")
                }
            };
            client.join().unwrap();
            if outcome == "valid" {
                assert_eq!(result.unwrap()["id"], expected.id().as_str());
            } else {
                let reason = match outcome {
                    "missing" | "absent" => "FARMD_SESSION_ACK_MISSING",
                    "foreign" => "FARMD_SESSION_ACK_MISMATCH",
                    "duplicate" => "FARMD_SESSION_ACK_AMBIGUOUS",
                    _ => "FARMD_REQUEST_FAILED",
                };
                let error = result.unwrap_err();
                assert!(error.starts_with(reason), "{outcome}: {error}");
                assert!(error.contains(expected.id().as_str()));
            }
            assert_eq!(std::fs::read(&journal).unwrap(), original);
        });
        let reopened = Session {
            directory: session.directory.clone(),
            credentials: session.credentials,
        };
        assert_eq!(
            reconciliation_request(&reopened, expected.id().as_str())
                .unwrap()
                .unwrap(),
            expected
        );
        assert_eq!(
            std::fs::read_dir(&reopened.directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("cmd_"))
                .count(),
            1
        );
    }
}
