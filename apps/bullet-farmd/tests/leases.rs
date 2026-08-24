//! Lease API tests over a real served socket, including the stale paths,
//! plus the runner's `HttpLeaseClient` against the same server so the wire
//! contract is proven from both sides.

use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, Ledger, PlanInput};
use bullet_domain::{AttemptId, AttemptState, RunnerId, TaskClass, WorkPackageId};
use bullet_runner_core::{
    AcquireRequest, HeartbeatCall, HttpLeaseClient, LeaseClient, ReleaseCall,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

fn seed_graph(db: &Path, seed: &str) -> String {
    let mut ledger = SqliteLedger::open(db).expect("open ledger");
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "lease api".into(),
            objective: "objective".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("plan");
    graph.packages[0].id.to_string()
}

async fn start(db: &Path) -> SocketAddr {
    let app = bullet_farmd::api::router(db).expect("router");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

async fn request(addr: SocketAddr, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let payload = body.map(Value::to_string).unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes()).await.expect("write head");
    stream
        .write_all(payload.as_bytes())
        .await
        .expect("write body");
    let mut buf = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .expect("response before timeout")
        .expect("read");
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let raw_body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, decode_body(&raw_body))
}

fn decode_body(body: &str) -> Value {
    if body.trim().is_empty() {
        return Value::Null;
    }
    if let Ok(value) = serde_json::from_str(body) {
        return value;
    }
    let unchunked: String = body
        .lines()
        .filter(|line| !line.trim().is_empty() && u64::from_str_radix(line.trim(), 16).is_err())
        .collect();
    serde_json::from_str(&unchunked).expect("json body")
}

fn acquire_body(wp: &str, runner: &RunnerId, key: &str) -> Value {
    json!({
        "work_package_id": wp,
        "runner_id": runner.as_str(),
        "runner_epoch": 1,
        "idempotency_key": key,
        "ttl_seconds": 60,
    })
}

#[tokio::test]
async fn ready_acquire_heartbeat_release_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("ledger.sqlite");
    let wp = seed_graph(&db, "lease-rt");
    let addr = start(&db).await;

    let (status, ready) = request(addr, "GET", "/v1/ready", None).await;
    assert_eq!(status, 200);
    assert_eq!(ready["work_package_id"], wp);

    let runner = RunnerId::from_seed("rt");
    let body = acquire_body(&wp, &runner, "lease-rt-1");
    let (status, grant) = request(addr, "POST", "/v1/leases/acquire", Some(&body)).await;
    assert_eq!(status, 200, "{grant}");
    assert_eq!(grant["attempt"]["fence"], 1);
    assert_eq!(grant["attempt"]["state"], "starting");
    assert_eq!(grant["authority_token"]["attempt_fence"], 1);
    assert_eq!(grant["lease"]["runner_id"], runner.as_str());

    // Same key replays the stored grant.
    let (status, replay) = request(addr, "POST", "/v1/leases/acquire", Some(&body)).await;
    assert_eq!(status, 200);
    assert_eq!(replay["attempt"]["id"], grant["attempt"]["id"]);

    // A different key while leased is a typed conflict.
    let mut second = body.clone();
    second["idempotency_key"] = json!("lease-rt-2");
    let (status, problem) = request(addr, "POST", "/v1/leases/acquire", Some(&second)).await;
    assert_eq!(status, 409);
    assert_eq!(
        problem["code"], "GRAPH_CONFLICT",
        "leased package is no longer ready"
    );

    let (status, _) = request(addr, "GET", "/v1/ready", None).await;
    assert_eq!(status, 404, "leased package leaves the queue");

    let heartbeat = json!({
        "variant_id": grant["lease"]["variant_id"],
        "attempt_id": grant["lease"]["attempt_id"],
        "fence": 1,
        "runner_id": runner.as_str(),
        "runner_epoch": 1,
        "workspace_nonce": grant["lease"]["workspace_nonce"],
        "ttl_seconds": 60,
    });
    let (status, _) = request(addr, "POST", "/v1/leases/heartbeat", Some(&heartbeat)).await;
    assert_eq!(status, 204);

    for state in ["running", "preparing"] {
        let advance = json!({ "attempt_id": grant["attempt"]["id"], "state": state });
        let (status, _) = request(addr, "POST", "/v1/attempts/advance", Some(&advance)).await;
        assert_eq!(status, 204, "{state}");
    }
    let release = json!({ "attempt_id": grant["attempt"]["id"], "outcome": "succeeded" });
    let (status, _) = request(addr, "POST", "/v1/leases/release", Some(&release)).await;
    assert_eq!(status, 204);
    // Idempotent replay of the release.
    let (status, _) = request(addr, "POST", "/v1/leases/release", Some(&release)).await;
    assert_eq!(status, 204);
    let (status, _) = request(addr, "GET", "/v1/ready", None).await;
    assert_eq!(
        status, 404,
        "succeeded without requeue stays out of the queue"
    );
}

#[tokio::test]
async fn stale_paths_are_typed_conflicts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("ledger.sqlite");
    let wp = seed_graph(&db, "lease-stale");
    let addr = start(&db).await;
    let runner = RunnerId::from_seed("stale");
    let body = acquire_body(&wp, &runner, "lease-stale-1");
    let (status, grant) = request(addr, "POST", "/v1/leases/acquire", Some(&body)).await;
    assert_eq!(status, 200);

    // Wrong fence: six-column match fails, zero rows, typed stale.
    let stale = json!({
        "variant_id": grant["lease"]["variant_id"],
        "attempt_id": grant["lease"]["attempt_id"],
        "fence": 2,
        "runner_id": runner.as_str(),
        "runner_epoch": 1,
        "workspace_nonce": grant["lease"]["workspace_nonce"],
    });
    let (status, problem) = request(addr, "POST", "/v1/leases/heartbeat", Some(&stale)).await;
    assert_eq!(status, 409);
    assert_eq!(problem["code"], "STALE_AUTHORITY");

    // Expire the lease behind the server's back, then a previously valid
    // heartbeat matches zero rows.
    let mut side = SqliteLedger::open(&db).expect("second connection");
    let expired = side
        .expire_leases("9999-01-01T00:00:00.000Z")
        .expect("expire");
    assert_eq!(expired.len(), 1);
    let valid = json!({
        "variant_id": grant["lease"]["variant_id"],
        "attempt_id": grant["lease"]["attempt_id"],
        "fence": 1,
        "runner_id": runner.as_str(),
        "runner_epoch": 1,
        "workspace_nonce": grant["lease"]["workspace_nonce"],
    });
    let (status, problem) = request(addr, "POST", "/v1/leases/heartbeat", Some(&valid)).await;
    assert_eq!(status, 409);
    assert_eq!(problem["code"], "STALE_AUTHORITY");

    // Releasing an attempt that never existed is 404; releasing the crashed
    // attempt into a live state is a 400 invalid transition.
    let missing = json!({
        "attempt_id": AttemptId::from_seed("never").as_str(),
        "outcome": "failed",
    });
    let (status, problem) = request(addr, "POST", "/v1/leases/release", Some(&missing)).await;
    assert_eq!(status, 404);
    assert_eq!(problem["code"], "NOT_FOUND");
    let live = json!({ "attempt_id": grant["attempt"]["id"], "outcome": "running" });
    let (status, problem) = request(addr, "POST", "/v1/leases/release", Some(&live)).await;
    assert_eq!(status, 400);
    assert_eq!(problem["code"], "INVALID_TRANSITION");
}

#[tokio::test]
async fn invalid_and_unknown_requests_are_problem_details() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("ledger.sqlite");
    seed_graph(&db, "lease-bad");
    let addr = start(&db).await;
    let bad = json!({
        "work_package_id": "not-an-id",
        "runner_id": RunnerId::from_seed("bad").as_str(),
        "runner_epoch": 1,
        "idempotency_key": "k",
    });
    let (status, problem) = request(addr, "POST", "/v1/leases/acquire", Some(&bad)).await;
    assert_eq!(status, 400);
    assert_eq!(problem["code"], "INVALID_ID");
    let unknown = json!({
        "work_package_id": WorkPackageId::from_seed("missing").as_str(),
        "runner_id": RunnerId::from_seed("bad").as_str(),
        "runner_epoch": 1,
        "idempotency_key": "k",
    });
    let (status, problem) = request(addr, "POST", "/v1/leases/acquire", Some(&unknown)).await;
    assert_eq!(status, 404);
    assert_eq!(problem["code"], "NOT_FOUND");
    let advance = json!({
        "attempt_id": AttemptId::from_seed("never").as_str(),
        "state": "flying",
    });
    let (status, problem) = request(addr, "POST", "/v1/attempts/advance", Some(&advance)).await;
    assert_eq!(status, 400);
    assert_eq!(problem["code"], "UNKNOWN_STATE");
}

#[tokio::test]
async fn http_lease_client_speaks_the_same_contract() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("ledger.sqlite");
    let wp = seed_graph(&db, "lease-client");
    let addr = start(&db).await;
    let client = HttpLeaseClient::new(&format!("http://{addr}")).expect("client");

    let ready = client
        .next_ready()
        .await
        .expect("ready call")
        .expect("one ready row");
    assert_eq!(ready.work_package_id, wp);

    let grant = client
        .acquire(&AcquireRequest {
            work_package_id: WorkPackageId::parse(&wp).expect("wp id"),
            runner_id: RunnerId::from_seed("client"),
            runner_epoch: 1,
            idempotency_key: "lease-client-1".into(),
            ttl_seconds: 60,
        })
        .await
        .expect("acquire");
    assert_eq!(grant.attempt.fence, 1);
    assert_eq!(grant.authority_token.attempt_fence, 1);

    client
        .heartbeat(&HeartbeatCall::for_grant(&grant, 60))
        .await
        .expect("heartbeat");
    let mut stale = HeartbeatCall::for_grant(&grant, 60);
    stale.fence = 99;
    let err = client.heartbeat(&stale).await.expect_err("stale fence");
    assert!(err.is_stale(), "{err}");

    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .expect("running");
    client
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await
        .expect("preparing");
    client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Succeeded,
            requeue: false,
        })
        .await
        .expect("release");
    assert!(client.next_ready().await.expect("ready").is_none());
}
