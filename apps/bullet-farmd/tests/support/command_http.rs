//! Explicit synthetic authentication fixtures over owned local HTTP listeners.
use serde_json::{json, Value};
use std::{net::SocketAddr, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
pub const ORIGIN: &str = "http://127.0.0.1:7420";
pub const BOOT: &str = "boot_1111111111111111111111111111111111111111111111111111111111111111";
pub struct Server {
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    pub async fn start(path: &Path, token: Option<&str>) -> Self {
        let (app, _) = bullet_farmd::api::daemon(path, token, ORIGIN.into(), None).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { addr, task }
    }
    pub async fn stop(self) {
        self.task.abort();
        assert!(self.task.await.unwrap_err().is_cancelled());
    }
}
pub async fn open(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
    declared: usize,
) -> BufReader<TcpStream> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let headers: String = headers
        .iter()
        .map(|(key, value)| format!("{key}: {value}\r\n"))
        .collect();
    stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {declared}\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
    BufReader::new(stream)
}
pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut stream = open(addr, method, path, headers, body, body.len()).await;
    let mut response = String::new();
    timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
pub fn status(response: &str) -> u16 {
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}
pub fn body(response: &str) -> Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}
pub fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
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
pub async fn bootstrap(addr: SocketAddr) -> (String, String) {
    let response = request(
        addr,
        "POST",
        "/api/v1/auth/bootstrap",
        &[("Origin", ORIGIN)],
        &json!({"bootstrap_token":BOOT}).to_string(),
    )
    .await;
    assert_eq!(status(&response), 200);
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
pub fn envelope(key: &str) -> String {
    json!({"idempotency_key":key,"kind":"run_demo","payload":{}}).to_string()
}
pub fn check_snapshot(response: &str) -> Value {
    assert_eq!(status(response), 200);
    assert_eq!(header(response, "cache-control"), Some("no-store"));
    let value = body(response);
    assert_eq!(
        header(response, "x-bullet-as-of-sequence")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        value["as_of_sequence"].as_u64().unwrap()
    );
    assert_eq!(value["source"], "bullet-kernel/sqlite-ledger");
    value
}
