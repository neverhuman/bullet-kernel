use super::*;
use std::io::Write;
use std::net::TcpListener;

fn read_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 4096);
    }
    bytes
}

fn serve(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        read_request(&mut socket);
        let _ = socket.write_all(&response);
    });
    (address, handle)
}

fn response(raw: &[u8]) -> Result<HttpResponse, String> {
    let (url, server) = serve(raw.to_vec());
    let result = request(&url, "GET", "/health", &[], None);
    server.join().unwrap();
    result
}

#[test]
fn chunk_extensions_are_decoded_by_the_http_client() {
    let result = response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7;name=value\r\n{\"a\":1}\r\n0\r\n\r\n").unwrap();
    assert_eq!(result.body, json!({"a": 1}));
}

#[test]
fn malformed_truncated_and_non_utf8_json_are_refused_without_echoing_body() {
    for body in [
        b"secret-not-json".as_slice(),
        b"{\"x\":\"\xff\"}",
        b"{\"incomplete\":",
        br#"{"status":"PRIVATE_CANARY","status":"ok"}"#,
        br#"{"messages":[{"role":"PRIVATE_CANARY","role":"user"}]}"#,
        br#"{"content":"PRIVATE_CANARY","\u0063ontent":"replaced"}"#,
    ] {
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        let error = response(&raw).err().unwrap();
        assert!(error.starts_with("FARMD_JSON_INVALID"));
        assert!(!error.contains("secret-not-json"));
        assert!(!error.contains("PRIVATE_CANARY"));
    }
    assert!(response(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{}"
    )
    .is_err());
}

#[test]
fn redirects_and_oversized_responses_are_refused() {
    assert_eq!(
        response(
            b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\n\r\n"
        )
        .err()
        .unwrap(),
        "FARMD_REDIRECT_REFUSED"
    );
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        MAX_RESPONSE_BYTES + 1
    );
    assert_eq!(
        response(raw.as_bytes()).err().unwrap(),
        "FARMD_RESPONSE_TOO_LARGE"
    );
}

#[test]
fn untrusted_content_type_cookie_ambiguity_and_url_authorities_are_refused() {
    assert!(
        response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}")
            .is_err()
    );
    assert_eq!(response(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nSet-Cookie: c=d\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").err().unwrap(), "FARMD_COOKIE_AMBIGUOUS");
    for url in [
        "http://user:secret@127.0.0.1:7420",
        "http://127.0.0.1:7420/path",
        "http://127.0.0.1:7420?x=y",
        "http://example.com:7420",
        "http://127.0.0.1:0",
    ] {
        assert!(parse_loopback(url).is_err());
    }
    assert_eq!(
        parse_loopback("http://[::1]:7420/").unwrap(),
        ("::1".into(), 7420)
    );
}

#[test]
fn query_pairs_are_encoded_without_changing_the_authority_or_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let bytes = read_request(&mut socket);
        assert!(String::from_utf8(bytes).unwrap().starts_with(
            "GET /api/v1/commands?after=23&limit=50&hostile=%26after%3D0%23%2F%2Fevil.invalid HTTP/1.1\r\n"
        ));
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .unwrap();
    });
    assert_eq!(
        request_query(
            &url,
            "GET",
            "/api/v1/commands",
            &[
                ("after", "23"),
                ("limit", "50"),
                ("hostile", "&after=0#//evil.invalid")
            ],
            &[],
            None
        )
        .unwrap()
        .status,
        200
    );
    server.join().unwrap();
    for path in ["//evil.invalid", "/commands?after=0", "/commands#fragment"] {
        assert!(request_query(&url, "GET", path, &[], &[], None).is_err());
    }
}

#[test]
fn expected_session_header_refuses_invalid_and_duplicate_values_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let session = format!("sid_{}", "a".repeat(64));
    for value in [
        "".to_owned(),
        "sid_bad".into(),
        format!("sid_{}", "A".repeat(64)),
        format!("ses_{}", "a".repeat(64)),
        format!("{} ", session),
    ] {
        let error = request(
            &url,
            "GET",
            "/api/v1/commands/absent",
            &[("X-Bullet-Expected-Session", &value)],
            None,
        )
        .err()
        .unwrap();
        assert_eq!(error, "FARMD_EXPECTED_SESSION_INVALID");
    }
    let error = request(
        &url,
        "GET",
        "/api/v1/commands/absent",
        &[
            ("x-bullet-expected-session", &session),
            ("X-Bullet-Expected-Session", &session),
        ],
        None,
    )
    .err()
    .unwrap();
    assert_eq!(error, "FARMD_EXPECTED_SESSION_AMBIGUOUS");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

type ResponseFixture = (
    std::sync::mpsc::Receiver<Result<HttpResponse, String>>,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
    std::thread::JoinHandle<()>,
);

fn held_session_response(
    status: u16,
    acknowledgement: String,
    body: &'static str,
) -> ResponseFixture {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (release, wait) = std::sync::mpsc::channel();
    let (sent, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let request = String::from_utf8(read_request(&mut socket)).unwrap();
        assert!(request.contains(&format!(
            "x-bullet-expected-session: sid_{}\r\n",
            "a".repeat(64)
        )));
        let headers = format!(
            "HTTP/1.1 {status} Fixture\r\n{acknowledgement}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        socket.write_all(headers.as_bytes()).unwrap();
        socket.flush().unwrap();
        // The client must reject an unacknowledged response while this body is
        // still withheld, rather than failing later on JSON or the request timeout.
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        let _ = socket.write_all(body.as_bytes());
    });
    let client = std::thread::spawn(move || {
        let session = format!("sid_{}", "a".repeat(64));
        let result = request(
            &url,
            "GET",
            "/api/v1/commands/absent",
            &[("x-bullet-expected-session", &session)],
            None,
        );
        let _ = sent.send(result);
    });
    (received, release, server, client)
}

#[test]
fn missing_foreign_and_duplicate_session_ack_refuse_before_held_body_or_absence() {
    let session = format!("sid_{}", "a".repeat(64));
    let foreign = format!("sid_{}", "b".repeat(64));
    for status in [200, 404] {
        for (acknowledgement, expected) in [
            (String::new(), "FARMD_SESSION_ACK_MISSING"),
            (
                format!("x-bullet-session-id: {foreign}\r\n"),
                "FARMD_SESSION_ACK_MISMATCH",
            ),
            (
                format!("x-bullet-session-id: {session}\r\nX-Bullet-Session-Id: {session}\r\n"),
                "FARMD_SESSION_ACK_AMBIGUOUS",
            ),
            (
                format!("x-bullet-session-id: {session}, {session}\r\n"),
                "FARMD_SESSION_ACK_MISMATCH",
            ),
            (
                "x-bullet-session-id: \r\n".into(),
                "FARMD_SESSION_ACK_MISMATCH",
            ),
        ] {
            let (received, release, server, client) =
                held_session_response(status, acknowledgement, "PRIVATE_BODY_NOT_JSON");
            let early = received.recv_timeout(Duration::from_secs(2));
            release.send(()).unwrap();
            server.join().unwrap();
            client.join().unwrap();
            let error = early
                .expect("session refusal must precede body release")
                .err()
                .unwrap();
            assert_eq!(error, expected);
            assert!(!error.contains("PRIVATE_BODY"));
        }
    }
}

#[test]
fn matching_session_ack_allows_body_and_owner_bound_not_found() {
    for status in [200, 404] {
        let acknowledgement = format!("x-bullet-session-id: sid_{}\r\n", "a".repeat(64));
        let (received, release, server, client) =
            held_session_response(status, acknowledgement, r#"{"subject":"exact-request"}"#);
        let before_release = received.recv_timeout(Duration::from_millis(100));
        release.send(()).unwrap();
        server.join().unwrap();
        client.join().unwrap();
        assert!(matches!(
            before_release,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        let response = received
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(response.status, status);
        assert_eq!(response.body, json!({"subject":"exact-request"}));
    }
}
