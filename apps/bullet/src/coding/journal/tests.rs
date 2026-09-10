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
        let input = SubmitRequest {
            account: "acct",
            provider: "codex",
            model: "model",
            expected_revision: 1,
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
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("accept failed: {e}"),
                }
                assert!(std::time::Instant::now() < deadline);
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
            assert!(String::from_utf8(bytes)
                .unwrap()
                .starts_with(&expected_path));
            let body = body.to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
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
    let mut input = SubmitRequest {
        account: "acct",
        provider: "codex",
        model: "model",
        expected_revision: 1,
        idempotency_key: Some("retry-key"),
    };
    let (first, request) = prepare(&session, &input).unwrap();
    let (retry, _) = prepare(&session, &input).unwrap();
    assert_eq!(first, retry);
    input.model = "changed";
    assert!(prepare(&session, &input)
        .unwrap_err()
        .contains("IDEMPOTENCY_CONFLICT"));
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
