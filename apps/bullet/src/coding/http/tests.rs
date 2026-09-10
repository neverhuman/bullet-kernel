use super::*;
use std::io::Write;
use std::net::TcpListener;

fn serve(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; 4096];
        socket.read(&mut bytes).unwrap();
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
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 4096);
        }
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
