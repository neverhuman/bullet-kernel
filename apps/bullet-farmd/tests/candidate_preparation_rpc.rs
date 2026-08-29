use bullet_adapters::SqliteLedger;
use bullet_application::candidate_preparation::{
    execution_toolchain_digest, CandidatePreparationSigningKey, CandidatePreparationSource,
    CandidatePreparationStore, ExecutionEnvelopeV1, ExecutionToolV1,
};
use bullet_application::{materialize_plan, LeaseService, Ledger, PlanInput};
use bullet_domain::{Attempt, RunnerId, TaskClass};
use bullet_farmd::api;
use bullet_farmd::lease_transport_rpc::{
    serve, serve_with_candidate, serve_with_candidate_and_bounds, LeasePeerRegistry,
    RegisteredRunnerPeer, TransportBounds, LEASE_TRANSPORT_FRAME_TOO_LARGE,
};
use bullet_harness_core::decode_signed_candidate_preparation_grant;
use bullet_runner_core::{
    CandidatePreparationRpcClient, ExpectedLeaseServer, SignedLeaseRpcClient,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(4);
const PROTO: &str = "bullet-farm.lease-transport.rpc.v1";

struct Fixture {
    _root: tempfile::TempDir,
    db: PathBuf,
    attempt: Attempt,
    requests: Vec<String>,
    key: Arc<CandidatePreparationSigningKey>,
    uid: u32,
    gid: u32,
}

impl Fixture {
    fn new(seed: &str) -> Self {
        let mut builder = tempfile::Builder::new();
        builder.permissions(std::fs::Permissions::from_mode(0o700));
        let root = builder.tempdir().expect("private root");
        let db = root.path().join("candidate.sqlite3");
        let mut ledger = SqliteLedger::open(&db).expect("open");
        let graph = materialize_plan(
            &mut ledger,
            seed,
            &PlanInput {
                title: "Candidate UDS".into(),
                objective: "issue only from preregistered truth".into(),
                packages: vec![("prepare".into(), TaskClass::BoundedBugFix)],
            },
            &LeaseService::rfc3339(Utc::now()),
        )
        .expect("plan");
        let (attempt, _, _) =
            LeaseService::acquire(&mut ledger, &graph, 0, seed, 15).expect("lease");
        let requests = ['1', '2', '3']
            .into_iter()
            .map(|suffix| {
                ledger
                    .register_candidate_preparation_source(&source(&attempt, suffix))
                    .expect("preregister source")
                    .request_digest
            })
            .collect();
        drop(ledger);
        let self_meta = std::fs::metadata("/proc/self").expect("self metadata");
        Self {
            _root: root,
            db,
            attempt,
            requests,
            key: Arc::new(
                CandidatePreparationSigningKey::generate("kernel-local", "candidate-preparation-1")
                    .expect("Candidate key"),
            ),
            uid: self_meta.uid(),
            gid: self_meta.gid(),
        }
    }

    fn registry(
        &self,
        peers: impl IntoIterator<Item = RegisteredRunnerPeer>,
    ) -> Arc<LeasePeerRegistry> {
        Arc::new(LeasePeerRegistry::new(self.uid, self.gid, peers).expect("peer registry"))
    }

    fn admitted_registry(&self) -> Arc<LeasePeerRegistry> {
        self.registry([RegisteredRunnerPeer::new(
            self.attempt.runner_id.clone(),
            self.attempt.runner_epoch,
            self.uid,
        )])
    }

    async fn start(
        &self,
        name: &str,
        registry: Arc<LeasePeerRegistry>,
        candidate_key: Option<Arc<CandidatePreparationSigningKey>>,
        bounds: Option<TransportBounds>,
    ) -> Server {
        let socket_root = self._root.path().join(name);
        std::fs::create_dir(&socket_root).expect("socket root");
        std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o710))
            .expect("socket root mode");
        let socket = socket_root.join("workload.sock");
        let (_, state) =
            api::daemon(&self.db, None, "http://127.0.0.1:7420".into(), None).expect("farmd state");
        let transport = Arc::new(
            bullet_application::lease_transport::KernelLeaseTransport::generate()
                .expect("lease key"),
        );
        let path = socket.clone();
        let task = tokio::spawn(async move {
            match (candidate_key, bounds) {
                (Some(key), Some(bounds)) => {
                    serve_with_candidate_and_bounds(path, state, transport, registry, key, bounds)
                        .await
                }
                (Some(key), None) => {
                    serve_with_candidate(path, state, transport, registry, key).await
                }
                (None, _) => serve(path, state, transport, registry).await,
            }
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(socket.exists() && !task.is_finished(), "socket never bound");
        Server {
            socket,
            task: Some(task),
        }
    }
}

struct Server {
    socket: PathBuf,
    task: Option<JoinHandle<Result<(), std::io::Error>>>,
}

impl Server {
    async fn stop(mut self) {
        let task = self.task.take().expect("server task");
        task.abort();
        let _ = task.await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn source(attempt: &Attempt, suffix: char) -> CandidatePreparationSource {
    let tools = vec![ExecutionToolV1 {
        schema_version: "v1alpha1".into(),
        tool_id: id("etl", suffix),
        role: "git".into(),
        executable_path: "/usr/bin/git".into(),
        executable_digest: "a".repeat(64),
        descriptor_digest: "b".repeat(64),
        version: "2.45.2".into(),
    }];
    let now = u64::try_from(Utc::now().timestamp_millis()).expect("positive time");
    CandidatePreparationSource {
        schema_version: "v1alpha1".into(),
        attempt_id: attempt.id.clone(),
        root_change: true,
        change_id: id("chg", suffix),
        parent_candidate_ids: vec![],
        execution_envelope: ExecutionEnvelopeV1 {
            schema_version: "v1alpha1".into(),
            execution_envelope_id: id("exe", suffix),
            issuer: "bullet-kernel".into(),
            key_id: "execution-1".into(),
            signing_purpose: "execution-envelope-signing".into(),
            claims_domain: "execution.envelope.v1alpha1".into(),
            runner_id: attempt.runner_id.to_string(),
            runner_epoch: attempt.runner_epoch,
            provider: "simulator".into(),
            model: "deterministic".into(),
            adapter: "simulator-v1".into(),
            provider_profile_id: id("prf", suffix),
            platform: "linux-x86_64".into(),
            containment_profile_id: id("ctp", suffix),
            environment_digest: "c".repeat(64),
            toolchain_digest: execution_toolchain_digest(&tools).expect("toolchain digest"),
            sandbox_image_digest: "d".repeat(64),
            tools,
            authority_epoch: 1,
            freeze_generation: 0,
            issued_at_unix_ms: now.saturating_sub(1_000),
            expires_at_unix_ms: now + 14_000,
        },
        ttl_ms: 5_000,
    }
}

fn id(prefix: &str, suffix: char) -> String {
    format!("{prefix}_{}", suffix.to_string().repeat(64))
}

fn request(method: &str, attempt: &Attempt, digest: &str) -> Value {
    json!({
        "id": 7,
        "method": method,
        "params": {"attempt_id": attempt.id, "request_digest": digest}
    })
}

async fn connect(socket: &Path, runner: &RunnerId, epoch: u64) -> (UnixStream, Value) {
    let mut stream = UnixStream::connect(socket).await.expect("connect");
    write_line(
        &mut stream,
        &json!({"proto": PROTO, "runner_id": runner, "runner_epoch": epoch}),
    )
    .await;
    let ack = read_frame(&mut stream).await.expect("hello reply");
    (stream, ack)
}

async fn call(socket: &Path, runner: &RunnerId, epoch: u64, value: &Value) -> Value {
    let (mut stream, ack) = connect(socket, runner, epoch).await;
    assert_eq!(ack["ok"], true, "{ack}");
    write_line(&mut stream, value).await;
    read_frame(&mut stream).await.expect("RPC reply")
}

async fn candidate_call(fixture: &Fixture, server: &Server, method: &str, digest: &str) -> Value {
    call(
        &server.socket,
        &fixture.attempt.runner_id,
        fixture.attempt.runner_epoch,
        &request(method, &fixture.attempt, digest),
    )
    .await
}

async fn write_line(stream: &mut UnixStream, value: &Value) {
    let mut bytes = serde_json::to_vec(value).expect("encode");
    bytes.push(b'\n');
    stream.write_all(&bytes).await.expect("write");
}

async fn read_frame(stream: &mut UnixStream) -> Option<Value> {
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match timeout(WAIT, stream.read(&mut byte))
            .await
            .expect("read hung")
        {
            Ok(0) | Err(_) => return None,
            Ok(_) if byte[0] == b'\n' => {
                return Some(serde_json::from_slice(&frame).expect("JSON frame"));
            }
            Ok(_) => frame.push(byte[0]),
        }
    }
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().expect("error code")
}

fn durable_counts(db: &Path) -> (usize, usize) {
    let ledger = SqliteLedger::open(db).expect("inspect ledger");
    let events = ledger
        .list_events()
        .expect("events")
        .into_iter()
        .filter(|event| event.kind == "candidate_preparation_grant_issued")
        .count();
    let outbox = ledger
        .outbox_all()
        .expect("outbox")
        .into_iter()
        .filter(|item| item.kind == "candidate_verification_requested")
        .count();
    (events, outbox)
}

#[tokio::test]
async fn exact_prepare_replay_readback_and_restart_share_one_durable_carrier() {
    let fixture = Fixture::new("candidate-uds-replay");
    let server = fixture
        .start(
            "first",
            fixture.admitted_registry(),
            Some(Arc::clone(&fixture.key)),
            None,
        )
        .await;
    let digest = &fixture.requests[0];
    assert_eq!(
        code(&candidate_call(&fixture, &server, "candidate_readback", digest).await),
        "CANDIDATE_PREPARATION_GRANT_NOT_FOUND"
    );
    let first = candidate_call(&fixture, &server, "candidate_prepare", digest).await;
    let client = SignedLeaseRpcClient::new_admitted(
        &server.socket,
        fixture.attempt.runner_id.clone(),
        fixture.attempt.runner_epoch,
        ExpectedLeaseServer::new(fixture.uid, fixture.gid),
    );
    let replay = client
        .candidate_prepare(&fixture.attempt.id, digest)
        .await
        .expect("Runner replay");
    assert_eq!(
        client.candidate_readback(&replay).await.expect("readback"),
        replay
    );
    let result = first["result"].as_object().expect("result object");
    assert_eq!(result.len(), 6, "response has no derived authority fields");
    assert_eq!(result["schema_version"], "v1alpha1");
    assert_eq!(result["request_digest"], *digest);
    assert_eq!(result["attempt_id"], fixture.attempt.id.as_str());
    let carrier = first["result"]["signed_grant_canonical_json"]
        .as_str()
        .expect("signed carrier");
    let signed = decode_signed_candidate_preparation_grant(carrier.as_bytes()).expect("canonical");
    assert_eq!(replay.signed_grant_canonical_json(), carrier);
    assert_eq!(signed.issuer, "kernel-local");
    assert_eq!(signed.key_id, "candidate-preparation-1");
    assert_eq!(durable_counts(&fixture.db), (1, 1));
    server.stop().await;

    let restarted = fixture
        .start(
            "restart",
            fixture.admitted_registry(),
            Some(Arc::clone(&fixture.key)),
            None,
        )
        .await;
    let after_restart = candidate_call(&fixture, &restarted, "candidate_readback", digest).await;
    assert_eq!(after_restart, first);
    assert_eq!(durable_counts(&fixture.db), (1, 1));
}

#[tokio::test]
async fn wrong_subject_and_stale_authority_refuse_before_new_or_replayed_grant() {
    let fixture = Fixture::new("candidate-uds-authority");
    let other = RunnerId::from_seed("other-runner");
    let registry = fixture.registry([
        RegisteredRunnerPeer::new(
            fixture.attempt.runner_id.clone(),
            fixture.attempt.runner_epoch,
            fixture.uid,
        ),
        RegisteredRunnerPeer::new(other.clone(), fixture.attempt.runner_epoch, fixture.uid),
    ]);
    let server = fixture
        .start("authority", registry, Some(Arc::clone(&fixture.key)), None)
        .await;
    let second = request("candidate_prepare", &fixture.attempt, &fixture.requests[1]);
    assert_eq!(
        code(
            &call(
                &server.socket,
                &other,
                fixture.attempt.runner_epoch,
                &second
            )
            .await
        ),
        "CANDIDATE_PREPARATION_REFUSED"
    );
    let first = request("candidate_prepare", &fixture.attempt, &fixture.requests[0]);
    assert!(call(
        &server.socket,
        &fixture.attempt.runner_id,
        fixture.attempt.runner_epoch,
        &first,
    )
    .await["result"]
        .is_object());
    rusqlite::Connection::open(&fixture.db)
        .expect("authority connection")
        .execute(
            "UPDATE authority_revisions SET authority_epoch = 2 WHERE singleton = 1",
            [],
        )
        .expect("advance authority");
    for value in [first, second] {
        let response = call(
            &server.socket,
            &fixture.attempt.runner_id,
            fixture.attempt.runner_epoch,
            &value,
        )
        .await;
        assert_eq!(code(&response), "CANDIDATE_PREPARATION_REFUSED");
    }
    assert_eq!(durable_counts(&fixture.db), (1, 1));
}

#[tokio::test]
async fn fixture_route_unknown_fields_wrong_peer_and_oversized_frames_fail_closed() {
    let fixture = Fixture::new("candidate-uds-hostile");
    let absent = fixture
        .start("absent", fixture.admitted_registry(), None, None)
        .await;
    let valid = request("candidate_prepare", &fixture.attempt, &fixture.requests[0]);
    assert_eq!(
        code(&candidate_call(&fixture, &absent, "candidate_prepare", &fixture.requests[0]).await),
        "LEASE_TRANSPORT_INVALID"
    );

    let wrong_uid = fixture.registry([RegisteredRunnerPeer::new(
        fixture.attempt.runner_id.clone(),
        fixture.attempt.runner_epoch,
        fixture.uid.saturating_add(1),
    )]);
    let wrong = fixture
        .start(
            "wrong-peer",
            wrong_uid,
            Some(Arc::clone(&fixture.key)),
            None,
        )
        .await;
    let (_, refusal) = connect(
        &wrong.socket,
        &fixture.attempt.runner_id,
        fixture.attempt.runner_epoch,
    )
    .await;
    assert_eq!(code(&refusal), "LEASE_TRANSPORT_PEER_UNREGISTERED");

    let strict = fixture
        .start(
            "strict",
            fixture.admitted_registry(),
            Some(Arc::clone(&fixture.key)),
            Some(TransportBounds {
                max_line_bytes: 512,
                ..TransportBounds::defaults()
            }),
        )
        .await;
    let mut unknown = valid.clone();
    unknown["params"]["authority_epoch"] = json!(1);
    assert_eq!(
        code(
            &call(
                &strict.socket,
                &fixture.attempt.runner_id,
                fixture.attempt.runner_epoch,
                &unknown,
            )
            .await
        ),
        "CANDIDATE_PREPARATION_REQUEST_INVALID"
    );
    let registration = json!({"id": 9, "method": "candidate_register", "params": {}});
    assert_eq!(
        code(
            &call(
                &strict.socket,
                &fixture.attempt.runner_id,
                fixture.attempt.runner_epoch,
                &registration,
            )
            .await
        ),
        "CANDIDATE_PREPARATION_REQUEST_INVALID"
    );
    let (mut stream, ack) = connect(
        &strict.socket,
        &fixture.attempt.runner_id,
        fixture.attempt.runner_epoch,
    )
    .await;
    assert_eq!(ack["ok"], true);
    stream
        .write_all(&vec![b'x'; 513])
        .await
        .expect("oversized write");
    let refusal = read_frame(&mut stream).await.expect("typed frame refusal");
    assert_eq!(code(&refusal), LEASE_TRANSPORT_FRAME_TOO_LARGE);
    assert!(read_frame(&mut stream).await.is_none());
    assert_eq!(durable_counts(&fixture.db), (0, 0));
}
