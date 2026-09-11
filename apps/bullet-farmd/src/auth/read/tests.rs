use super::*;
use crate::auth::secret_digest;
use bullet_adapters::SqliteLedger;
use bullet_application::operator_sessions::{
    BootstrapRegistration, OperatorSessionStore, SessionIssue,
};
use futures_util::StreamExt;
use std::{collections::VecDeque, time::Duration};

const ORIGIN: &str = "http://127.0.0.1:7420";
fn issue(store: &mut SqliteLedger, seed: &str, lifetime_seconds: u32) -> (HeaderMap, SessionIssue) {
    let bearer = format!("ses_{}", Digest::of(seed.as_bytes()).to_hex());
    let bootstrap_digest = Digest::of(format!("bootstrap:{seed}").as_bytes());
    store
        .register_operator_bootstrap(&BootstrapRegistration {
            digest: bootstrap_digest,
            proposed_operator_id: format!("opr_{}", Digest::of(b"operator").to_hex()),
            origin: ORIGIN.into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    let request = SessionIssue {
        bootstrap_digest,
        session_id: format!("sid_{}", Digest::of(seed.as_bytes()).to_hex()),
        bearer_digest: secret_digest("session", &bearer),
        csrf_digest: Digest::of(seed.as_bytes()),
        origin: ORIGIN.into(),
        lifetime_seconds,
    };
    store.exchange_operator_bootstrap(&request).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("bullet_session={bearer}").parse().unwrap(),
    );
    (headers, request)
}
fn private_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().unwrap()
}
fn buffered() -> VecDeque<bullet_application::LedgerEvent> {
    VecDeque::from([bullet_application::LedgerEvent {
        seq: 1,
        at: "2026-09-10T00:00:00Z".into(),
        kind: "private".into(),
        body: "private event".into(),
        event_id: None,
        stream_id: None,
        sequence: Some(1),
        causation_id: None,
        correlation_id: None,
        authority_token_hash: None,
    }])
}

#[tokio::test]
async fn event_stream_stops_before_buffered_events_after_expiry_or_revocation() {
    let directory = private_directory();
    let path = directory.path().join("auth.sqlite");
    let mut independent = SqliteLedger::open(&path).unwrap();
    for expires in [false, true] {
        let (headers, request) = issue(
            &mut independent,
            if expires { "expired" } else { "revoked" },
            if expires { 2 } else { 600 },
        );
        // Reopening the daemon retains a permit for a persisted session.
        let (_, state) = crate::api::daemon(&path, None, ORIGIN.into(), None).unwrap();
        let permit = ReadPermit::issue(&*state.auth.lock().await, &headers)
            .unwrap_or_else(|_| panic!("persisted session"));
        if expires {
            tokio::time::sleep(Duration::from_millis(2100)).await;
        } else {
            independent
                .revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN)
                .unwrap();
        }
        assert!(!permit.is_current(&*state.auth.lock().await));
        let stream = crate::api::event_stream(state, 0, buffered(), permit);
        futures_util::pin_mut!(stream);
        assert!(
            stream.next().await.is_none(),
            "buffered private events cannot escape lost authority"
        );
    }
}

#[tokio::test]
async fn idle_stream_observes_external_revocation_without_revoking_another_client() {
    let directory = private_directory();
    let path = directory.path().join("auth.sqlite");
    let mut independent = SqliteLedger::open(&path).unwrap();
    let (first, request) = issue(&mut independent, "first", 600);
    let (_, state) = crate::api::daemon(&path, None, ORIGIN.into(), None).unwrap();
    let permit = ReadPermit::issue(&*state.auth.lock().await, &first)
        .unwrap_or_else(|_| panic!("persisted session"));
    let (second, _) = issue(&mut independent, "second", 600);
    assert!(
        permit.is_current(&*state.auth.lock().await),
        "new client does not replace first client"
    );
    let second_permit = ReadPermit::issue(&*state.auth.lock().await, &second)
        .unwrap_or_else(|_| panic!("second client"));
    let stream = crate::api::event_stream(state.clone(), 0, VecDeque::new(), permit);
    futures_util::pin_mut!(stream);
    let next = stream.next();
    futures_util::pin_mut!(next);
    assert!(futures_util::poll!(&mut next).is_pending());
    independent
        .revoke_operator_session(request.bearer_digest, request.csrf_digest, ORIGIN)
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), next)
        .await
        .expect("idle recheck")
        .is_none());
    assert!(second_permit.is_current(&*state.auth.lock().await));
}

#[tokio::test]
async fn scoped_reads_acknowledge_the_exact_session_and_refuse_cookie_replacement() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Server(tokio::task::JoinHandle<()>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    async fn request(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        headers: &HeaderMap,
    ) -> String {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let headers = headers.iter().map(|(key, value)| format!("{key}: {}\r\n", value.to_str().unwrap())).collect::<String>();
            socket.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                assert!(response.len() < 16_384, "bounded response headers");
                response.push(socket.read_u8().await.unwrap());
            }
            let mut response = String::from_utf8(response).unwrap();
            // An SSE response is intentionally unending. Inspect its real HTTP
            // opening acknowledgement, then detach this test client.
            if !(path == "/api/v1/events" && response.starts_with("HTTP/1.1 200")) {
                socket.take(16_384).read_to_string(&mut response).await.unwrap();
            }
            response
        }).await.expect("bounded HTTP response")
    }
    let directory = private_directory();
    let path = directory.path().join("auth.sqlite");
    let mut store = SqliteLedger::open(&path).unwrap();
    let (first, original) = issue(&mut store, "view-owner", 600);
    let (second, replacement) = issue(&mut store, "replacement-cookie", 600);
    let (router, _) = crate::api::daemon(&path, None, ORIGIN.into(), None).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    for expected in [None, Some(original.session_id.as_str())] {
        let mut headers = first.clone();
        if let Some(expected) = expected {
            headers.insert("x-bullet-expected-session", expected.parse().unwrap());
        }
        let response = request(addr, "GET", "/api/v1/conversations", &headers).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        let response_headers = response.split_once("\r\n\r\n").unwrap().0;
        assert!(
            response_headers.contains(&format!("x-bullet-session-id: {}\r\n", original.session_id))
        );
        assert!(response_headers.contains("cache-control: no-store"));
    }
    let missing = format!(
        "/api/v1/commands/cmd_{}",
        Digest::of(b"missing-command").to_hex()
    );
    for (method, path, status) in [
        ("GET", missing.as_str(), "404"),
        ("GET", "/api/v1/commands/invalid", "400"),
        ("HEAD", "/api/v1/conversations", "200"),
        ("GET", "/api/v1/events", "200"),
    ] {
        let mut headers = first.clone();
        headers.insert(
            "x-bullet-expected-session",
            original.session_id.parse().unwrap(),
        );
        let response = request(addr, method, path, &headers).await;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{method} {path}: {response}"
        );
        let (response_headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            response_headers.contains(&format!("x-bullet-session-id: {}\r\n", original.session_id))
        );
        assert!(response_headers.contains("cache-control: no-store"));
        if method == "HEAD" {
            assert!(body.is_empty());
        }
        if status == "404" {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(body).unwrap()["code"],
                "NOT_FOUND"
            );
        }
        // A valid cookie for a different session must fail before the command
        // absence or stream response can authorize recovery in the old owner.
        let mut replaced = second.clone();
        replaced.insert(
            "x-bullet-expected-session",
            original.session_id.parse().unwrap(),
        );
        let response = request(addr, method, path, &replaced).await;
        assert!(response.starts_with("HTTP/1.1 403"));
        assert!(!response.contains("x-bullet-session-id:"));
    }
    for expected in [original.session_id.as_str(), "", "sid_invalid"] {
        let mut headers = second.clone();
        headers.insert("x-bullet-expected-session", expected.parse().unwrap());
        let response = request(addr, "GET", "/api/v1/conversations", &headers).await;
        assert!(response.starts_with("HTTP/1.1 403"));
        assert!(!response.contains("x-bullet-session-id:"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(response.split_once("\r\n\r\n").unwrap().1)
                .unwrap()["code"],
            "SESSION_CHANGED"
        );
    }
    let mut headers = second;
    headers.append(
        "x-bullet-expected-session",
        replacement.session_id.parse().unwrap(),
    );
    headers.append(
        "x-bullet-expected-session",
        replacement.session_id.parse().unwrap(),
    );
    let response = request(addr, "GET", "/api/v1/conversations", &headers).await;
    assert!(response.starts_with("HTTP/1.1 401"));
    assert!(!response.contains("x-bullet-session-id:"));
    server.0.abort();
    while !server.0.is_finished() {
        tokio::task::yield_now().await;
    }
}
