//! A test client with a session obtained through the production HTTP bootstrap.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

pub const ORIGIN: &str = "http://127.0.0.1:7420";
pub const BOOTSTRAP: &str = "boot_0000000000000000000000000000000000000000000000000000000000000000";

pub struct Client {
    pub addr: SocketAddr,
    pub cookie: String,
}

pub async fn serve(app: axum::Router) -> Client {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    let body = serde_json::json!({"bootstrap_token": BOOTSTRAP}).to_string();
    let mut stream = TcpStream::connect(addr).await.expect("connect bootstrap");
    stream.write_all(format!(
        "POST /api/v1/auth/bootstrap HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    ).as_bytes()).await.expect("send bootstrap");
    let mut response = String::new();
    timeout(
        Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .expect("bootstrap timeout")
    .expect("read bootstrap");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let cookie = response
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("set-cookie")
                .then(|| value.trim().split(';').next().unwrap().to_string())
        })
        .expect("session cookie");
    Client { addr, cookie }
}
