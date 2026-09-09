//! Embedded-Portal HTTP proofs. Without the feature this file is empty and the
//! daemon mounts no static route at all.
#![cfg(feature = "embedded-portal")]

mod support;

use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const BOOTSTRAP: &str = "boot_1111111111111111111111111111111111111111111111111111111111111111";

async fn serve(router: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    addr
}

async fn start(db: &Path) -> SocketAddr {
    serve(bullet_farmd::api::router(db).expect("router")).await
}

/// One raw request; the response is returned verbatim so header bytes are
/// asserted as sent.
async fn raw(addr: SocketAddr, method: &str, path: &str, headers: &str) -> String {
    raw_json(addr, method, path, headers, "").await
}

/// One raw request carrying an exact JSON body.
async fn raw_json(addr: SocketAddr, method: &str, path: &str, headers: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let content_type = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/json\r\n".to_string()
    };
    let length = body.len();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}{content_type}Content-Length: {length}\r\nConnection: close\r\n\r\n{body}"
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut buffer = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut buffer))
        .await
        .expect("response before timeout")
        .expect("read");
    String::from_utf8_lossy(&buffer).to_string()
}

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(": "))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn json(response: &str) -> Value {
    serde_json::from_str(body(response)).expect("json body")
}

/// The first `/assets/...` reference in the served entry point.
fn first_asset(index: &str) -> String {
    let rest = &index[index.find("/assets/").expect("asset reference")..];
    let end = rest.find(['"', '\'']).expect("quoted reference");
    rest[..end].to_string()
}

#[tokio::test]
async fn the_entry_point_is_served_from_the_api_origin_without_a_session() {
    let directory = support::private_tempdir();
    let addr = start(&directory.path().join("ledger.sqlite")).await;
    for path in ["/", "/index.html"] {
        let response = raw(addr, "GET", path, "").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{path}: {response}");
        assert_eq!(
            header(&response, "content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            header(&response, "cache-control"),
            Some("no-cache, no-store, must-revalidate")
        );
        assert_eq!(header(&response, "x-content-type-options"), Some("nosniff"));
        assert!(header(&response, "content-security-policy")
            .expect("policy")
            .starts_with("default-src 'self'"));
        assert!(body(&response).contains("<div id=\"root\">"), "{path}");
    }
}

#[tokio::test]
async fn content_hashed_assets_are_immutable_and_carry_their_manifest_digest() {
    let directory = support::private_tempdir();
    let addr = start(&directory.path().join("ledger.sqlite")).await;
    let index = raw(addr, "GET", "/", "").await;
    let asset = first_asset(body(&index));
    let response = raw(addr, "GET", &asset, "").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{asset}: {response}");
    assert_eq!(
        header(&response, "cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    let etag = header(&response, "etag").expect("etag");
    let digest = etag
        .trim_matches('"')
        .strip_prefix("blake3-")
        .expect("digest-derived etag");
    assert_eq!(
        blake3::hash(body(&response).as_bytes())
            .to_hex()
            .to_string(),
        digest,
        "the served bytes are the bytes the manifest bound"
    );
}

#[tokio::test]
async fn an_unknown_static_path_still_answers_the_typed_api_refusal() {
    let directory = support::private_tempdir();
    let addr = start(&directory.path().join("ledger.sqlite")).await;
    for path in ["/assets/absent.js", "/assets/", "/not-a-route"] {
        let response = raw(addr, "GET", path, "").await;
        assert!(response.starts_with("HTTP/1.1 404"), "{path}: {response}");
        assert_eq!(json(&response)["code"], "NOT_FOUND", "{path}");
    }
}

#[tokio::test]
async fn health_names_the_embedded_bundle_subject() {
    let directory = support::private_tempdir();
    let addr = start(&directory.path().join("ledger.sqlite")).await;
    let response = raw(addr, "GET", "/health", "").await;
    let health = json(&response);
    assert_eq!(health["status"], "ok");
    let portal = health["portal"].as_str().expect("portal subject");
    assert!(portal.starts_with("blake3:"), "{portal}");
    assert_eq!(portal.len(), "blake3:".len() + 64);
}

#[tokio::test]
async fn same_origin_serving_does_not_weaken_bootstrap_origin_or_session_rules() {
    let directory = support::private_tempdir();
    let db = directory.path().join("ledger.sqlite");
    let origin = "http://127.0.0.1:7420";
    let router = bullet_farmd::api::router_with_bootstrap(&db, BOOTSTRAP, origin.to_string())
        .expect("router");
    let addr = serve(router).await;

    let served = raw(addr, "GET", "/", "").await;
    assert!(served.starts_with("HTTP/1.1 200"), "{served}");

    let exchange = format!("{{\"bootstrap_token\":\"{BOOTSTRAP}\"}}");
    let foreign = raw_json(
        addr,
        "POST",
        "/api/v1/auth/bootstrap",
        "Origin: http://127.0.0.1:5999\r\n",
        &exchange,
    )
    .await;
    assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
    assert_eq!(json(&foreign)["code"], "ORIGIN_DENIED");

    let originless = raw_json(addr, "POST", "/api/v1/auth/bootstrap", "", &exchange).await;
    assert_eq!(json(&originless)["code"], "ORIGIN_REQUIRED");

    let unauthenticated = raw(
        addr,
        "POST",
        "/api/v1/commands",
        &format!("Origin: {origin}\r\n"),
    )
    .await;
    assert!(
        unauthenticated.starts_with("HTTP/1.1 401"),
        "{unauthenticated}"
    );
    assert_eq!(json(&unauthenticated)["code"], "SESSION_REQUIRED");
}
