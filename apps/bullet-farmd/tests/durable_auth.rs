//! Real local HTTP with synthetic auth fixtures; no provider credentials.
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::operator_sessions::{
    BootstrapRegistration, OperatorSessionStore, SessionIssue,
};
use bullet_domain::Digest;
use serde_json::{json, Value};
use std::{net::SocketAddr, path::Path};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

const ORIGIN: &str = "http://127.0.0.1:7420";
const FIRST: &str = "boot_1111111111111111111111111111111111111111111111111111111111111111";
const SECOND: &str = "boot_2222222222222222222222222222222222222222222222222222222222222222";
struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(path: &Path, token: Option<&str>) -> Self {
        let (router, _) = bullet_farmd::api::daemon(path, token, ORIGIN.into(), None).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { addr, task }
    }
    async fn stop(self) {
        self.task.abort();
        assert!(self.task.await.unwrap_err().is_cancelled());
    }
}
async fn open(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> BufReader<TcpStream> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    BufReader::new(stream)
}
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut stream = open(addr, method, path, headers, body).await;
    let mut response = String::new();
    timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
fn status(response: &str) -> u16 {
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}
fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
}
fn body(response: &str) -> Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}
async fn bootstrap(addr: SocketAddr, token: &str) -> (String, String) {
    let response = request(
        addr,
        "POST",
        "/api/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        &json!({"bootstrap_token":token}).to_string(),
    )
    .await;
    assert_eq!(status(&response), 200);
    assert_eq!(header(&response, "cache-control"), Some("no-store"));
    (
        header(&response, "set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into(),
        body(&response)["csrf_token"].as_str().unwrap().into(),
    )
}
async fn session(addr: SocketAddr, cookie: &str) -> Value {
    let response = request(
        addr,
        "GET",
        "/api/v1/auth/session",
        &[("Cookie", cookie)],
        "",
    )
    .await;
    assert_eq!(status(&response), 200);
    assert_eq!(header(&response, "cache-control"), Some("no-store"));
    let value = body(&response);
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "expires_at",
            "issued_at",
            "operator_id",
            "session_id",
            "status"
        ]
    );
    assert_eq!(value["status"], "AUTHENTICATED");
    assert!(value["operator_id"].as_str().unwrap().starts_with("opr_"));
    assert!(value["session_id"].as_str().unwrap().starts_with("sid_"));
    for field in ["issued_at", "expires_at"] {
        chrono::DateTime::parse_from_rfc3339(value[field].as_str().unwrap()).unwrap();
    }
    value
}

#[tokio::test]
async fn sessions_survive_restart_and_self_revocation_preserves_another_client() {
    let directory = support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    let first = Server::start(&path, Some(FIRST)).await;
    let (cookie_one, csrf_one) = bootstrap(first.addr, FIRST).await;
    let one = session(first.addr, &cookie_one).await;
    first.stop().await;
    let same = Server::start(&path, Some(FIRST)).await;
    assert_eq!(session(same.addr, &cookie_one).await, one);
    let consumed = request(
        same.addr,
        "POST",
        "/api/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        &json!({"bootstrap_token":FIRST}).to_string(),
    )
    .await;
    assert_eq!(status(&consumed), 401);
    assert_eq!(body(&consumed)["code"], "BOOTSTRAP_CONSUMED");
    same.stop().await;
    let second = Server::start(&path, Some(SECOND)).await;
    let (cookie_two, csrf_two) = bootstrap(second.addr, SECOND).await;
    let two = session(second.addr, &cookie_two).await;
    assert_eq!(one["operator_id"], two["operator_id"]);
    assert_ne!(one["session_id"], two["session_id"]);
    assert_eq!(session(second.addr, &cookie_one).await, one);
    for (headers, data, expected) in [
        (
            vec![("Origin", ORIGIN), ("Cookie", cookie_one.as_str())],
            "{}",
            403,
        ),
        (
            vec![
                ("Origin", ORIGIN),
                ("Cookie", cookie_one.as_str()),
                ("X-Bullet-CSRF", csrf_two.as_str()),
            ],
            "{}",
            403,
        ),
        (
            vec![
                ("Origin", "https://attacker.invalid"),
                ("Cookie", cookie_one.as_str()),
                ("X-Bullet-CSRF", csrf_one.as_str()),
            ],
            "{}",
            403,
        ),
        (
            vec![
                ("Cookie", cookie_one.as_str()),
                ("X-Bullet-CSRF", csrf_one.as_str()),
            ],
            "{}",
            403,
        ),
        (
            vec![
                ("Origin", ORIGIN),
                ("Cookie", cookie_one.as_str()),
                ("X-Bullet-CSRF", csrf_one.as_str()),
            ],
            "{\"session_id\":\"other\"}",
            400,
        ),
        (
            vec![
                ("Origin", ORIGIN),
                ("Cookie", cookie_one.as_str()),
                ("X-Bullet-CSRF", csrf_one.as_str()),
            ],
            "null",
            400,
        ),
    ] {
        assert_eq!(
            status(&request(second.addr, "POST", "/api/v1/auth/revoke", &headers, data).await),
            expected
        );
        assert_eq!(session(second.addr, &cookie_one).await, one);
    }
    let response = request(
        second.addr,
        "POST",
        "/api/v1/auth/revoke",
        &[
            ("Origin", ORIGIN),
            ("Cookie", &cookie_one),
            ("X-Bullet-CSRF", &csrf_one),
        ],
        "{}",
    )
    .await;
    assert_eq!(status(&response), 200);
    assert_eq!(header(&response, "cache-control"), Some("no-store"));
    assert!(header(&response, "set-cookie")
        .unwrap()
        .contains("Max-Age=0"));
    let revoked = body(&response);
    assert_eq!(revoked["status"], "REVOKED");
    assert_eq!(revoked["session_id"], one["session_id"]);
    assert_eq!(revoked["operator_id"], one["operator_id"]);
    assert_eq!(revoked.as_object().unwrap().len(), 4);
    chrono::DateTime::parse_from_rfc3339(revoked["revoked_at"].as_str().unwrap()).unwrap();
    assert_eq!(session(second.addr, &cookie_two).await, two);
    second.stop().await;
    let restarted = Server::start(&path, None).await;
    assert_eq!(session(restarted.addr, &cookie_two).await, two);
    for path in [
        "/api/v1/auth/session",
        "/api/v1/operator-snapshot",
        "/api/v1/events?after=0",
    ] {
        assert_eq!(
            status(&request(restarted.addr, "GET", path, &[("Cookie", &cookie_one)], "").await),
            401
        );
        assert_eq!(
            status(&request(restarted.addr, "GET", path, &[], "").await),
            401
        );
    }
    assert_eq!(
        status(
            &request(
                restarted.addr,
                "POST",
                "/api/v1/auth/revoke",
                &[("Origin", ORIGIN)],
                "{}"
            )
            .await
        ),
        401
    );
    assert_eq!(
        status(
            &request(
                restarted.addr,
                "POST",
                "/api/v1/auth/revoke",
                &[
                    ("Origin", ORIGIN),
                    ("Cookie", &cookie_one),
                    ("X-Bullet-CSRF", &csrf_one)
                ],
                "{}"
            )
            .await
        ),
        401
    );
    restarted.stop().await;
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in [
            FIRST,
            SECOND,
            cookie_one.split_once('=').unwrap().1,
            &csrf_one,
            cookie_two.split_once('=').unwrap().1,
            &csrf_two,
        ] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "raw auth secret persisted"
            );
        }
    }
}

#[tokio::test]
async fn live_sse_closes_after_revocation_from_an_independent_daemon() {
    let directory = support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    let first = Server::start(&path, Some(FIRST)).await;
    let (cookie, csrf) = bootstrap(first.addr, FIRST).await;
    let second = Server::start(&path, None).await;
    let mut stream = open(
        first.addr,
        "GET",
        "/api/v1/events?after=0",
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    timeout(Duration::from_secs(2), async {
        loop {
            let mut line = String::new();
            assert!(stream.read_line(&mut line).await.unwrap() > 0);
            if line.starts_with(": connected") {
                break;
            }
        }
    })
    .await
    .unwrap();
    let response = request(
        second.addr,
        "POST",
        "/api/v1/auth/revoke",
        &[
            ("Origin", ORIGIN),
            ("Cookie", &cookie),
            ("X-Bullet-CSRF", &csrf),
        ],
        "{}",
    )
    .await;
    assert_eq!(status(&response), 200);
    let mut tail = String::new();
    timeout(Duration::from_secs(2), stream.read_to_string(&mut tail))
        .await
        .expect("open stream observes cross-daemon revocation")
        .unwrap();
    assert!(!tail.contains("data:"));
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn expired_persisted_cookie_is_refused_after_restart() {
    let directory = support::private_tempdir();
    let path = directory.path().join("auth.sqlite");
    let bearer = format!("ses_{}", "a".repeat(64));
    let cookie = format!("bullet_session={bearer}");
    let mut store = SqliteLedger::open(&path).unwrap();
    let digest = Digest::of(b"expiry");
    store
        .register_operator_bootstrap(&BootstrapRegistration {
            digest,
            proposed_operator_id: format!("opr_{}", "b".repeat(64)),
            origin: ORIGIN.into(),
            lifetime_seconds: 600,
        })
        .unwrap();
    store
        .exchange_operator_bootstrap(&SessionIssue {
            bootstrap_digest: digest,
            session_id: format!("sid_{}", "c".repeat(64)),
            bearer_digest: Digest::of(format!("bullet-farmd.session.v1\0{bearer}").as_bytes()),
            csrf_digest: Digest::of(b"csrf"),
            origin: ORIGIN.into(),
            lifetime_seconds: 1,
        })
        .unwrap();
    drop(store);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let server = Server::start(&path, None).await;
    for path in ["/api/v1/auth/session", "/api/v1/events?after=0"] {
        assert_eq!(
            status(&request(server.addr, "GET", path, &[("Cookie", &cookie)], "").await),
            401
        );
    }
    server.stop().await;
}
