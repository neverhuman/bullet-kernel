//! Host-side allow-listing HTTP CONNECT proxy on std threads.
//!
//! The proxy binds `127.0.0.1:<ephemeral>` and accepts only `CONNECT
//! host:port`. It decides against the policy before resolving or connecting
//! anything, answers `403` for every refusal, logs each decision, and caps
//! concurrent tunnels and idle time. It starts *disarmed*: admitted targets
//! answer `503` (decision still logged as `allow`) until [`Proxy::arm`], so
//! in-namespace probes never open a real upstream connection.

use crate::allowlist::{Decision as PolicyDecision, EgressPolicy};
use crate::decisions::{Decision, DecisionLog};
use crate::error::{EgressCode, EgressError};
use crate::request::{parse_connect_target, RequestError};
use crate::tunnel::{connect_upstream, read_head, relay, respond, TunnelGuard};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Resource bounds for the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyLimits {
    /// Maximum simultaneously open tunnels.
    pub max_tunnels: usize,
    /// Time allowed for a client to send its request head.
    pub header_timeout: Duration,
    /// Time allowed to connect upstream after an allow decision.
    pub connect_timeout: Duration,
    /// Idle time (no bytes either way) after which a tunnel closes.
    pub idle_timeout: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_tunnels: 32,
            header_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// State shared by the acceptor and every connection thread.
pub(crate) struct Shared {
    policy: EgressPolicy,
    log: Arc<DecisionLog>,
    pub(crate) limits: ProxyLimits,
    armed: AtomicBool,
    shutdown: AtomicBool,
    pub(crate) tunnels: AtomicUsize,
}

/// Running proxy. Dropping it stops the acceptor.
pub struct Proxy {
    addr: SocketAddr,
    shared: Arc<Shared>,
    acceptor: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Bind `127.0.0.1:0` and start accepting, disarmed.
    ///
    /// # Errors
    ///
    /// `EGRESS_PROXY_FAILED` when the socket or thread cannot be created.
    pub fn start(
        policy: EgressPolicy,
        log: Arc<DecisionLog>,
        limits: ProxyLimits,
    ) -> Result<Self, EgressError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|err| EgressError::new(EgressCode::ProxyFailed, format!("bind: {err}")))?;
        let addr = listener
            .local_addr()
            .map_err(|err| EgressError::new(EgressCode::ProxyFailed, format!("addr: {err}")))?;
        let shared = Arc::new(Shared {
            policy,
            log,
            limits,
            armed: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            tunnels: AtomicUsize::new(0),
        });
        let worker = Arc::clone(&shared);
        let acceptor = thread::Builder::new()
            .name("bf-egress-proxy".into())
            .spawn(move || accept_loop(&listener, &worker))
            .map_err(|err| EgressError::new(EgressCode::ProxyFailed, format!("thread: {err}")))?;
        Ok(Self {
            addr,
            shared,
            acceptor: Some(acceptor),
        })
    }

    /// Bound port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Bound address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Allow admitted targets to open real upstream connections.
    pub fn arm(&self) {
        self.shared.armed.store(true, Ordering::SeqCst);
    }

    /// Whether upstream connections are enabled.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.shared.armed.load(Ordering::SeqCst)
    }

    /// Currently open tunnels.
    #[must_use]
    pub fn active_tunnels(&self) -> usize {
        self.shared.tunnels.load(Ordering::SeqCst)
    }

    /// Stop accepting. Open tunnels finish on EOF or idle timeout.
    pub fn shutdown(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.acceptor.take() {
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
            let _ = handle.join();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for conn in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        match conn {
            Ok(stream) => {
                let worker = Arc::clone(shared);
                let _ = thread::Builder::new()
                    .name("bf-egress-conn".into())
                    .spawn(move || serve(&worker, stream));
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn serve(shared: &Shared, mut client: TcpStream) {
    let limits = shared.limits;
    let _ = client.set_read_timeout(Some(limits.header_timeout));
    let _ = client.set_write_timeout(Some(limits.header_timeout));
    let _ = client.set_nodelay(true);
    let (head, leftover) = match read_head(&mut client) {
        Ok(parsed) => parsed,
        Err(err) => {
            let status = err.status();
            shared
                .log
                .record("", Decision::Malformed, &err.reason(), status);
            let allow = matches!(err, RequestError::MethodNotAllowed(_));
            let _ = respond(
                &mut client,
                status,
                if allow { "Allow: CONNECT\r\n" } else { "" },
            );
            return;
        }
    };
    let target = match parse_connect_target(&head.target) {
        Ok(target) => target,
        Err(reason) => {
            shared.log.record(
                &head.target,
                Decision::Deny,
                &format!("target:{reason}"),
                403,
            );
            let _ = respond(&mut client, 403, "");
            return;
        }
    };
    let target_text = target.to_string();
    if let PolicyDecision::Deny(reason) = shared.policy.decide(&target) {
        shared.log.record(&target_text, Decision::Deny, reason, 403);
        let _ = respond(&mut client, 403, "");
        return;
    }
    if !shared.armed.load(Ordering::SeqCst) {
        shared
            .log
            .record(&target_text, Decision::Allow, "disarmed", 503);
        let _ = respond(
            &mut client,
            503,
            "X-Bullet-Egress: allowlist-accepted; upstream-disarmed\r\n",
        );
        return;
    }
    let Some(_guard) = TunnelGuard::acquire(shared) else {
        shared
            .log
            .record(&target_text, Decision::Limit, "tunnel-limit", 503);
        let _ = respond(&mut client, 503, "X-Bullet-Egress: tunnel-limit\r\n");
        return;
    };
    let mut upstream = match connect_upstream(&target, limits.connect_timeout) {
        Ok(stream) => stream,
        Err(reason) => {
            shared
                .log
                .record(&target_text, Decision::Allow, &reason, 502);
            let _ = respond(&mut client, 502, "");
            return;
        }
    };
    shared
        .log
        .record(&target_text, Decision::Allow, "tunnel", 200);
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
    {
        return;
    }
    if !leftover.is_empty() && upstream.write_all(&leftover).is_err() {
        return;
    }
    relay(client, upstream, limits.idle_timeout);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::Instant;

    fn start(
        policy: EgressPolicy,
        limits: ProxyLimits,
    ) -> (Proxy, Arc<DecisionLog>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log =
            Arc::new(DecisionLog::open(&dir.path().join("d.jsonl"), policy.provider()).unwrap());
        let proxy = Proxy::start(policy, Arc::clone(&log), limits).unwrap();
        (proxy, log, dir)
    }

    /// Send `raw`, read the response head byte-wise, return its status line.
    fn request(addr: SocketAddr, raw: &[u8]) -> (String, TcpStream) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(raw).unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap() == 1 {
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        (text.lines().next().unwrap_or_default().to_string(), stream)
    }

    fn echo_server() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut stream = stream;
                    let mut buf = [0u8; 64];
                    while let Ok(n @ 1..) = stream.read(&mut buf) {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn disarmed_proxy_decides_without_connecting_anywhere() {
        let (proxy, log, _dir) = start(
            EgressPolicy::for_provider("claude").unwrap(),
            ProxyLimits::default(),
        );
        let addr = proxy.addr();
        assert!(!proxy.is_armed());
        let cases: [(&[u8], &str); 5] = [
            (
                b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 403 Forbidden",
            ),
            (
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n\r\n",
                "HTTP/1.1 503 Service Unavailable",
            ),
            (
                b"GET http://api.anthropic.com/ HTTP/1.1\r\n\r\n",
                "HTTP/1.1 405 Method Not Allowed",
            ),
            (
                b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 403 Forbidden",
            ),
            (
                b"CONNECT api.anthropic.com:80 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 403 Forbidden",
            ),
        ];
        for (raw, status) in cases {
            assert_eq!(request(addr, raw).0, status, "{raw:?}");
        }
        let oversized = format!("CONNECT {}:443 HTTP/1.1\r\n\r\n", "a".repeat(5000));
        assert_eq!(
            request(addr, oversized.as_bytes()).0,
            "HTTP/1.1 431 Request Header Fields Too Large"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while log.recent().len() < 6 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let recent = log.recent();
        let summary: Vec<(Decision, &str, u16)> = recent
            .iter()
            .map(|r| (r.decision, r.reason.as_str(), r.status))
            .collect();
        assert_eq!(
            summary,
            vec![
                (Decision::Deny, "host-not-allowlisted", 403),
                (Decision::Allow, "disarmed", 503),
                (Decision::Malformed, "method-not-allowed:GET", 405),
                (Decision::Deny, "target:ipv4-literal", 403),
                (Decision::Deny, "port-not-allowed", 403),
                (Decision::Malformed, "oversized:request-line", 431),
            ]
        );
        assert_eq!(recent[1].target, "api.anthropic.com:443");
    }

    #[test]
    fn armed_proxy_tunnels_bytes_and_enforces_the_tunnel_limit() {
        let port = echo_server();
        let policy = EgressPolicy::custom("echo", ["localhost"], [port]).unwrap();
        let limits = ProxyLimits {
            max_tunnels: 1,
            ..ProxyLimits::default()
        };
        let (proxy, log, _dir) = start(policy, limits);
        proxy.arm();
        let connect = format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n");
        let (status, mut tunnel) = request(proxy.addr(), connect.as_bytes());
        assert_eq!(status, "HTTP/1.1 200 Connection established");
        tunnel.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        tunnel.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        assert_eq!(proxy.active_tunnels(), 1);
        let (status, _) = request(proxy.addr(), connect.as_bytes());
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable");
        assert!(log.recent().iter().any(|r| r.decision == Decision::Limit));
        drop(tunnel);
        let deadline = Instant::now() + Duration::from_secs(5);
        while proxy.active_tunnels() != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(proxy.active_tunnels(), 0);
        assert!(log
            .recent()
            .iter()
            .any(|r| r.decision == Decision::Allow && r.reason == "tunnel" && r.status == 200));
    }

    #[test]
    fn upstream_failure_is_502_with_allow_logged() {
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let policy = EgressPolicy::custom("dead", ["localhost"], [port]).unwrap();
        let (proxy, log, _dir) = start(policy, ProxyLimits::default());
        proxy.arm();
        let connect = format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n");
        assert_eq!(
            request(proxy.addr(), connect.as_bytes()).0,
            "HTTP/1.1 502 Bad Gateway"
        );
        let recent = log.recent();
        assert_eq!(recent.len(), 1);
        assert_eq!(
            (recent[0].decision, recent[0].status),
            (Decision::Allow, 502)
        );
        assert!(
            recent[0].reason.starts_with("upstream-connect:"),
            "{}",
            recent[0].reason
        );
    }

    #[test]
    fn header_timeout_closes_silent_clients() {
        let limits = ProxyLimits {
            header_timeout: Duration::from_millis(300),
            ..ProxyLimits::default()
        };
        let (proxy, log, _dir) = start(EgressPolicy::for_provider("codex").unwrap(), limits);
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 400 Bad Request"));
        assert!(log
            .recent()
            .iter()
            .any(|r| r.decision == Decision::Malformed && r.reason.starts_with("io:")));
    }
}
