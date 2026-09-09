//! Bounded Kernel-minted Unix lease transport; public lease routes stay absent.
use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{KernelLeaseTransport, SignedAcquireBody};
use bullet_application::{
    materialize_plan, CommandRequest, ComponentCommandCompletionV1, Ledger, PlanInput,
};
use bullet_domain::{RunnerId, TaskClass};
use bullet_farmd::api;
use bullet_farmd::lease_transport_rpc::{
    serve, serve_with_bounds, LeasePeerRegistry, RegisteredRunnerPeer, TransportBounds,
    TransportRefusal, LEASE_TRANSPORT_FRAME_TOO_LARGE, LEASE_TRANSPORT_OVERLOADED,
    LEASE_TRANSPORT_READ_DEADLINE, LEASE_TRANSPORT_SESSION_DEADLINE,
};
use bullet_runner_core::signed_lease_rpc::ExpectedLeaseServer;
use bullet_runner_core::{AcquireRequest, LeaseClient, SignedLeaseRpcClient};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

/// Hard ceiling on any single wait in these tests.
const WAIT: Duration = Duration::from_secs(4);
const NEXT_READY: &[u8] = b"{\"id\":2,\"method\":\"next_ready\"}\n";
#[cfg(all(feature = "test-seams", debug_assertions))]
#[path = "lease_transport_rpc/synthetic_selection.rs"]
mod synthetic_selection;
fn seeded_db(path: &Path) -> SignedAcquireBody {
    let mut ledger = SqliteLedger::open(path).expect("open");
    let now = "2026-01-01T00:00:00.000Z";
    let graph = materialize_plan(
        &mut ledger,
        "signed-lease",
        &PlanInput {
            title: "signed lease".into(),
            objective: "kernel mint then acquire".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        now,
    )
    .expect("plan");
    ledger
        .submit_command(
            &CommandRequest::new("uds-command-dispatch", "run_demo", &serde_json::json!({}))
                .expect("command"),
        )
        .expect("submit command");
    SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("signed-runner"),
        runner_epoch: 1,
        idempotency_key: "acquire-once".into(),
        ttl_seconds: 15,
    }
}

/// Seeded ledger, daemon state, and a registry admitting this process' UID.
fn fixture(
    root: &Path,
) -> (
    SignedAcquireBody,
    api::SharedState,
    Arc<LeasePeerRegistry>,
    u32,
    u32,
) {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).expect("0700");
    let db = root.join("ledger.sqlite");
    let body = seeded_db(&db);
    let (_router, state) =
        api::daemon(&db, None, "http://127.0.0.1:7420".into(), None).expect("daemon");
    let self_meta = std::fs::metadata("/proc/self").expect("self");
    let (uid, gid) = (self_meta.uid(), self_meta.gid());
    let peer = RegisteredRunnerPeer::new(body.runner_id.clone(), body.runner_epoch, uid);
    let registry = Arc::new(LeasePeerRegistry::new(uid, gid, [peer]).expect("registry"));
    (body, state, registry, uid, gid)
}

struct Daemon {
    _root: tempfile::TempDir,
    socket: PathBuf,
    body: SignedAcquireBody,
    uid: u32,
    gid: u32,
}

impl Daemon {
    async fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket).await.expect("connect")
    }

    /// Send this runner's hello and return whatever frame answers it.
    async fn hello(&self, stream: &mut UnixStream) -> serde_json::Value {
        assert!(send(stream, hello_line(&self.body.runner_id).as_bytes()).await);
        read_frame(stream).await.expect("hello reply")
    }

    /// Connect and complete the hello; the ack is asserted `ok`.
    async fn session(&self) -> UnixStream {
        let mut stream = self.connect().await;
        let ack = self.hello(&mut stream).await;
        assert_eq!(ack["ok"], true, "{ack}");
        stream
    }

    fn client(&self) -> SignedLeaseRpcClient {
        SignedLeaseRpcClient::new_admitted(
            self.socket.clone(),
            self.body.runner_id.clone(),
            self.body.runner_epoch,
            ExpectedLeaseServer::new(self.uid, self.gid),
        )
        .with_recovery_file(self._root.path().join("runner-recovery.json"))
        .expect("durable runner recovery")
    }
}

fn hello_line(runner: &RunnerId) -> String {
    format!(
        "{{\"proto\":\"bullet-farm.lease-transport.rpc.v1\",\"runner_id\":\"{runner}\",\"runner_epoch\":1}}\n"
    )
}

/// Spin a daemon on a temp socket; `None` serves under the default bounds.
async fn daemon(bounds: Option<TransportBounds>) -> Daemon {
    let root = tempfile::tempdir().expect("tempdir");
    let (body, state, registry, uid, gid) = fixture(root.path());
    let socket_root = root.path().join("socket");
    std::fs::create_dir(&socket_root).expect("socket directory");
    std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o710)).expect("0710");
    let socket = socket_root.join("lease.sock");
    let transport = Arc::new(KernelLeaseTransport::generate().expect("key"));
    let path = socket.clone();
    let server = tokio::spawn(async move {
        match bounds {
            Some(bounds) => serve_with_bounds(path, state, transport, registry, bounds).await,
            None => serve(path, state, transport, registry).await,
        }
    });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        socket.exists() && !server.is_finished(),
        "socket never bound"
    );
    Daemon {
        _root: root,
        socket,
        body,
        uid,
        gid,
    }
}

fn acquire_request(body: &SignedAcquireBody) -> AcquireRequest {
    AcquireRequest {
        work_package_id: body.work_package_id.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        idempotency_key: body.idempotency_key.clone(),
        ttl_seconds: body.ttl_seconds,
    }
}

async fn send(stream: &mut UnixStream, bytes: &[u8]) -> bool {
    stream.write_all(bytes).await.is_ok()
}

/// Deliver `bytes` one 1-byte write at a time, `gap` apart, giving up after
/// `budget` or once the peer stops accepting writes.
async fn drip(stream: &mut UnixStream, bytes: &[u8], gap: Duration, budget: Duration) {
    let started = Instant::now();
    for byte in bytes {
        if !send(stream, &[*byte]).await || started.elapsed() > budget {
            break;
        }
        tokio::time::sleep(gap).await;
    }
}

/// One newline-terminated JSON frame, or `None` at EOF. Never waits > `WAIT`.
async fn read_frame(stream: &mut UnixStream) -> Option<serde_json::Value> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match timeout(WAIT, stream.read(&mut byte))
            .await
            .expect("read hung")
        {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        if byte[0] == b'\n' {
            return Some(serde_json::from_slice(&buf).expect("frame json"));
        }
        buf.push(byte[0]);
    }
}

/// Assert the peer is cut with exactly `code`.
async fn cut(stream: &mut UnixStream, code: &str) {
    assert_eq!(refusal_then_eof(stream).await, code);
}

/// The reason code of the next frame (an `id`-less error), then EOF.
async fn refusal_then_eof(stream: &mut UnixStream) -> String {
    let frame = read_frame(stream)
        .await
        .expect("typed refusal before close");
    assert!(frame["id"].is_null(), "{frame}");
    let code = frame["error"]["code"].as_str().expect("code").to_string();
    assert!(
        read_frame(stream).await.is_none(),
        "still open after {code}"
    );
    code
}

fn within(started: Instant, min_ms: u64, max_ms: u64) {
    let elapsed = started.elapsed();
    let ok = elapsed >= Duration::from_millis(min_ms) && elapsed < Duration::from_millis(max_ms);
    assert!(ok, "{elapsed:?} outside [{min_ms} ms, {max_ms} ms)");
}

fn tight(read_ms: u64, session_ms: u64) -> TransportBounds {
    TransportBounds {
        read_deadline: Duration::from_millis(read_ms),
        session_deadline: Duration::from_millis(session_ms),
        ..TransportBounds::defaults()
    }
}

#[tokio::test]
async fn unsigned_runner_acquires_through_unix_socket() {
    let daemon = daemon(None).await;
    let grant = daemon
        .client()
        .acquire(&acquire_request(&daemon.body))
        .await
        .expect("acquire");
    assert_eq!(grant.lease.fence, 1);
    let mut probe = daemon.connect().await;
    let ack = daemon.hello(&mut probe).await;
    assert_eq!(ack["ok"], true);
    assert_eq!(ack["peer_uid"].as_u64(), Some(u64::from(daemon.uid)));
    assert!(ack["socket_dev"].as_u64().is_some());
    assert!(ack["socket_ino"].as_u64().is_some());
    assert_ne!(ack["listener_dev"].as_u64(), Some(0));
    assert_ne!(ack["listener_ino"].as_u64(), Some(0));

    let mut spoof = daemon.connect().await;
    let line = hello_line(&RunnerId::from_seed("unregistered"));
    assert!(send(&mut spoof, line.as_bytes()).await);
    let refusal = read_frame(&mut spoof).await.expect("refusal");
    assert_eq!(
        refusal["error"]["code"],
        "LEASE_TRANSPORT_PEER_UNREGISTERED"
    );
}

#[tokio::test]
async fn registered_peer_claims_reads_back_and_settles_without_http() {
    let daemon = daemon(None).await;
    let client = daemon.client();
    let claimed = client
        .claim_command_dispatch()
        .await
        .expect("claim over peer-authenticated UDS")
        .expect("pending command");
    assert_eq!(claimed.request.kind, "run_demo");
    assert_eq!(claimed.runner_id, daemon.body.runner_id);
    assert_eq!(claimed.runner_epoch, daemon.body.runner_epoch);
    assert_eq!(
        client
            .readback_command_dispatch()
            .await
            .expect("read back lost claim response"),
        Some(claimed.clone())
    );
    let completion = ComponentCommandCompletionV1::new(
        &claimed,
        bullet_domain::Digest::of(b"retained component receipt"),
    )
    .expect("strict component completion");
    let settled = client
        .settle_component_command_dispatch(&claimed.claim_id, &completion)
        .await
        .expect("settle through authenticated UDS");
    assert_eq!(settled.phase, bullet_domain::CommandPhase::Unknown);
    assert!(settled
        .response
        .as_deref()
        .is_some_and(|body| body.contains("COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE")));
    assert!(client
        .claim_command_dispatch()
        .await
        .expect("queue empty")
        .is_none());
}

#[tokio::test]
async fn slowloris_half_hello_is_cut_with_the_read_deadline() {
    let daemon = daemon(Some(tight(200, 3_000))).await;
    let started = Instant::now();
    let mut stream = daemon.connect().await;
    let line = hello_line(&daemon.body.runner_id);
    assert!(send(&mut stream, &line.as_bytes()[..line.len() / 2]).await);
    cut(&mut stream, LEASE_TRANSPORT_READ_DEADLINE).await;
    within(started, 200, 3_000);
}

#[tokio::test]
async fn trickled_request_is_cut_with_the_read_deadline() {
    let daemon = daemon(Some(tight(200, 3_000))).await;
    let mut stream = daemon.session().await;
    let started = Instant::now();
    // One byte every 50 ms never completes the frame within 200 ms: the
    // deadline bounds the frame, not the gap between bytes.
    let (gap, budget) = (Duration::from_millis(50), Duration::from_millis(700));
    drip(&mut stream, NEXT_READY, gap, budget).await;
    cut(&mut stream, LEASE_TRANSPORT_READ_DEADLINE).await;
    within(started, 200, 3_000);
}

#[tokio::test]
async fn frame_in_one_byte_writes_completes_under_the_read_deadline() {
    let daemon = daemon(Some(tight(1_000, 3_000))).await;
    let mut stream = daemon.session().await;
    let started = Instant::now();
    let (gap, budget) = (Duration::from_millis(10), Duration::from_millis(900));
    drip(&mut stream, NEXT_READY, gap, budget).await;
    let reply = read_frame(&mut stream).await.expect("reply");
    assert_eq!(reply["id"], 2, "{reply}");
    assert!(reply.get("result").is_some(), "{reply}");
    within(started, 10 * (NEXT_READY.len() as u64 - 1), 1_000);
}

#[tokio::test]
async fn active_session_past_the_session_deadline_is_cut() {
    let daemon = daemon(Some(tight(1_000, 500))).await;
    let started = Instant::now();
    let mut stream = daemon.session().await;
    let mut served = 0u64;
    let code = loop {
        let request = format!("{{\"id\":{served},\"method\":\"next_ready\"}}\n");
        if !send(&mut stream, request.as_bytes()).await {
            break refusal_then_eof(&mut stream).await;
        }
        let frame = read_frame(&mut stream).await.expect("reply or refusal");
        if frame["id"].is_null() {
            let code = frame["error"]["code"].as_str().expect("code").to_string();
            assert!(read_frame(&mut stream).await.is_none(), "still open");
            break code;
        }
        assert_eq!(frame["id"], served, "{frame}");
        served += 1;
        tokio::time::sleep(Duration::from_millis(40)).await;
    };
    assert_eq!(code, LEASE_TRANSPORT_SESSION_DEADLINE);
    assert!(served > 0, "no request was served before the cut");
    within(started, 500, 3_000);
}

#[tokio::test]
async fn oversized_request_is_refused_before_the_read_deadline() {
    let bounds = TransportBounds {
        max_line_bytes: 512,
        ..tight(2_000, 4_000)
    };
    let daemon = daemon(Some(bounds)).await;
    let mut stream = daemon.session().await;
    let started = Instant::now();
    let mut frame = b"{\"id\":1,\"method\":\"".to_vec();
    frame.resize(513, b'a');
    send(&mut stream, &frame).await;
    cut(&mut stream, LEASE_TRANSPORT_FRAME_TOO_LARGE).await;
    within(started, 0, 1_000);
    // Exactly the limit, newline-terminated, is still read and dispatched.
    let mut stream = daemon.session().await;
    let mut frame = b"{\"id\":7,\"method\":\"".to_vec();
    frame.resize(510, b'a');
    frame.extend_from_slice(b"\"}\n");
    assert_eq!(frame.len(), 513, "512 content bytes plus the newline");
    assert!(send(&mut stream, &frame).await);
    let reply = read_frame(&mut stream).await.expect("reply");
    assert_eq!(reply["id"], 7, "{reply}");
    assert_eq!(reply["error"]["code"], "LEASE_TRANSPORT_INVALID");
}

#[tokio::test]
async fn oversized_hello_is_refused_before_the_read_deadline() {
    let daemon = daemon(Some(tight(2_000, 4_000))).await;
    let mut stream = daemon.connect().await;
    let started = Instant::now();
    send(&mut stream, &vec![b'{'; 4_097]).await;
    cut(&mut stream, LEASE_TRANSPORT_FRAME_TOO_LARGE).await;
    within(started, 0, 1_000);
}

#[tokio::test]
async fn accept_bound_refuses_the_extra_peer_and_readmits_after_a_release() {
    let bounds = TransportBounds {
        max_in_flight_sessions: 2,
        ..tight(2_000, 4_000)
    };
    let daemon = daemon(Some(bounds)).await;
    let first = daemon.session().await;
    let mut second = daemon.session().await;
    let mut third = daemon.connect().await;
    cut(&mut third, LEASE_TRANSPORT_OVERLOADED).await;
    // The admitted sessions keep working while the extra peer was refused.
    assert!(send(&mut second, NEXT_READY).await);
    let reply = read_frame(&mut second).await.expect("reply");
    assert_eq!(reply["id"], 2, "{reply}");
    assert!(reply.get("result").is_some(), "{reply}");
    drop(first);
    let started = Instant::now();
    let mut admitted = false;
    while started.elapsed() < WAIT {
        let mut fourth = daemon.connect().await;
        let frame = daemon.hello(&mut fourth).await;
        if frame["ok"] == true {
            admitted = true;
            break;
        }
        assert_eq!(
            frame["error"]["code"], LEASE_TRANSPORT_OVERLOADED,
            "{frame}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(admitted, "slot never released after the first peer closed");
}

#[tokio::test]
async fn legitimate_client_is_unaffected_by_bounds() {
    let bounds = TransportBounds {
        max_in_flight_sessions: 4,
        ..tight(1_000, 3_000)
    };
    let daemon = daemon(Some(bounds)).await;
    let client = daemon.client();
    let request = acquire_request(&daemon.body);
    let grant = client.acquire(&request).await.expect("acquire");
    assert_eq!(grant.lease.fence, 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let again = client.acquire(&request).await.expect("idempotent acquire");
    assert_eq!(again.lease.fence, 1);
    assert!(client.next_ready().await.is_ok());
}

#[tokio::test]
async fn zero_bounds_are_refused_before_bind() {
    let root = tempfile::tempdir().expect("tempdir");
    let (_body, state, registry, _, _) = fixture(root.path());
    let socket = root.path().join("lease.sock");
    let defaults = TransportBounds::defaults();
    let mut zeroed = [("read_deadline", defaults); 4];
    zeroed[0].1.read_deadline = Duration::ZERO;
    zeroed[1] = ("session_deadline", defaults);
    zeroed[1].1.session_deadline = Duration::ZERO;
    zeroed[2] = ("max_line_bytes", defaults);
    zeroed[2].1.max_line_bytes = 0;
    zeroed[3] = ("max_in_flight_sessions", defaults);
    zeroed[3].1.max_in_flight_sessions = 0;
    for (field, bounds) in zeroed {
        assert_ne!(bounds, defaults, "{field} case did not zero anything");
        let server = serve_with_bounds(
            socket.clone(),
            state.clone(),
            Arc::new(KernelLeaseTransport::generate().expect("key")),
            Arc::clone(&registry),
            bounds,
        );
        let error = timeout(WAIT, server)
            .await
            .expect("refuses immediately")
            .expect_err("zero bound admitted");
        assert_eq!(
            TransportRefusal::from_io(&error),
            Some(&TransportRefusal::BoundsInvalid { field }),
            "{error}"
        );
        assert!(!socket.exists(), "bound a socket under a zero {field}");
    }
    assert_eq!(defaults.read_deadline, Duration::from_secs(5));
    assert_eq!(defaults.session_deadline, Duration::from_secs(30));
    assert_eq!(defaults.max_line_bytes, 65_536);
    assert_eq!(defaults.max_in_flight_sessions, 64);
}

#[path = "lease_transport_rpc/persistence.rs"]
mod persistence;
