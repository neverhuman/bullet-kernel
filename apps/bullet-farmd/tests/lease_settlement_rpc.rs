//! Real farmd UDS restart proof for durable Runner terminal settlement.

use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{
    AdvanceSettlementRequest, KernelLeaseTransport, LeaseSettlementRequest,
    ReleaseSettlementRequest, SignedAcquireBody,
};
use bullet_application::{materialize_plan, Ledger, PlanInput};
use bullet_domain::{AttemptState, RunnerId, TaskClass};
use bullet_farmd::api;
use bullet_farmd::lease_transport_rpc::{serve, LeasePeerRegistry, RegisteredRunnerPeer};
use bullet_runner_core::signed_lease_rpc::ExpectedLeaseServer;
use bullet_runner_core::{
    AcquireGrant, AcquireRequest, LeaseClient, ReleaseCall, SignedLeaseRpcClient,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn seed(db: &Path) -> SignedAcquireBody {
    let mut ledger = SqliteLedger::open(db).expect("open seed database");
    let graph = materialize_plan(
        &mut ledger,
        "settlement-restart",
        &PlanInput {
            title: "settlement restart".into(),
            objective: "prove exact terminal recovery".into(),
            packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .expect("materialize plan");
    SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("settlement-restart-runner"),
        runner_epoch: 11,
        idempotency_key: "settlement-restart-acquire".into(),
        ttl_seconds: 15,
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

fn advance_request(
    body: &SignedAcquireBody,
    grant: &AcquireGrant,
    expected_state: AttemptState,
    target_state: AttemptState,
) -> LeaseSettlementRequest {
    LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
        acquire_request_digest: body.request_digest().expect("acquire digest"),
        work_package_id: body.work_package_id.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        idempotency_key: body.idempotency_key.clone(),
        variant_id: grant.attempt.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        attempt_fence: grant.attempt.fence,
        expected_state,
        target_state,
    })
}

fn release_request(
    body: &SignedAcquireBody,
    grant: &AcquireGrant,
    expected_state: AttemptState,
    final_state: AttemptState,
) -> LeaseSettlementRequest {
    LeaseSettlementRequest::Release(ReleaseSettlementRequest {
        acquire_request_digest: body.request_digest().expect("acquire digest"),
        work_package_id: body.work_package_id.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        idempotency_key: body.idempotency_key.clone(),
        variant_id: grant.attempt.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        attempt_fence: grant.attempt.fence,
        expected_state,
        final_state,
        requeue: false,
    })
}

async fn start(
    socket: &Path,
    db: &Path,
    transport: Arc<KernelLeaseTransport>,
    registry: Arc<LeasePeerRegistry>,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    let (_router, state) =
        api::daemon(db, None, "http://127.0.0.1:7420".into(), None).expect("daemon state");
    let path = socket.to_path_buf();
    let task = tokio::spawn(async move { serve(path, state, transport, registry).await });
    for _ in 0..200 {
        if socket.exists() && !task.is_finished() {
            return task;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("farmd UDS did not bind");
}

fn client(socket: &Path, body: &SignedAcquireBody, recovery: PathBuf) -> SignedLeaseRpcClient {
    let metadata = std::fs::metadata(socket).expect("socket metadata");
    SignedLeaseRpcClient::new_admitted(
        socket,
        body.runner_id.clone(),
        body.runner_epoch,
        ExpectedLeaseServer::new(metadata.uid(), metadata.gid()),
    )
    .with_recovery_file(recovery)
    .expect("load durable recovery")
}

async fn stop(task: tokio::task::JoinHandle<std::io::Result<()>>, socket: &Path) {
    task.abort();
    let error = task.await.expect_err("aborted listener must not complete");
    assert!(error.is_cancelled());
    if socket.exists() {
        std::fs::remove_file(socket).expect("remove stopped socket");
    }
}

async fn settle_without_reading_response(
    socket: &Path,
    body: &SignedAcquireBody,
    request: &LeaseSettlementRequest,
) {
    let stream = UnixStream::connect(socket).await.expect("raw UDS connect");
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let hello = serde_json::json!({
        "proto": "bullet-farm.lease-transport.rpc.v1",
        "runner_id": body.runner_id.as_str(),
        "runner_epoch": body.runner_epoch,
    });
    write
        .write_all(&[serde_json::to_vec(&hello).unwrap(), vec![b'\n']].concat())
        .await
        .expect("raw hello");
    let mut ack = String::new();
    reader.read_line(&mut ack).await.expect("hello ack");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ack).unwrap()["ok"],
        true
    );
    let call = serde_json::json!({"id": 91, "method": "settle", "params": request});
    write
        .write_all(&[serde_json::to_vec(&call).unwrap(), vec![b'\n']].concat())
        .await
        .expect("raw settle request");
    write.flush().await.expect("flush raw settle");
    drop(write);
    drop(reader);
}

async fn wait_for_settlement(db: &Path, settlement_id: &str) {
    for _ in 0..200 {
        let mut ledger = SqliteLedger::open(db).expect("poll SQLite truth");
        let found = ledger
            .with_lease_transport(|transaction| {
                Ok::<_, bullet_application::LedgerError>(
                    transaction
                        .get_transport_settlement(settlement_id)?
                        .is_some(),
                )
            })
            .expect("poll settlement row");
        if found {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("settlement row did not commit after response close");
}

#[tokio::test]
async fn restart_reconciles_pending_settlement_and_sqlite_truth() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).expect("0700");
    let db = root.path().join("ledger.sqlite");
    let recovery = root.path().join("runner-recovery.json");
    let socket_root = root.path().join("socket");
    std::fs::create_dir(&socket_root).expect("socket directory");
    std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o710)).expect("0710");
    let socket = socket_root.join("lease.sock");
    let body = seed(&db);
    let self_meta = std::fs::metadata("/proc/self").expect("self identity");
    let registry = Arc::new(
        LeasePeerRegistry::new(
            self_meta.uid(),
            self_meta.gid(),
            [RegisteredRunnerPeer::new(
                body.runner_id.clone(),
                body.runner_epoch,
                self_meta.uid(),
            )],
        )
        .expect("peer registry"),
    );
    let transport = Arc::new(KernelLeaseTransport::generate().expect("transport key"));
    let first = start(&socket, &db, Arc::clone(&transport), Arc::clone(&registry)).await;
    let first_client = client(&socket, &body, recovery.clone());
    let grant = first_client
        .acquire(&acquire_request(&body))
        .await
        .expect("acquire through real UDS");
    first_client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .expect("first settlement");
    stop(first, &socket).await;

    let unknown = first_client
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await
        .expect_err("stopped listener cannot resolve a persisted request");
    assert_eq!(unknown.reason_code(), "ADVANCE_OUTCOME_UNKNOWN");
    drop(first_client);

    let second = start(&socket, &db, Arc::clone(&transport), Arc::clone(&registry)).await;
    let restarted = client(&socket, &body, recovery.clone());
    restarted
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await
        .expect("restart readback, one settle, final readback");
    let release = ReleaseCall {
        attempt_id: grant.attempt.id.clone(),
        outcome: AttemptState::Failed,
        requeue: false,
    };
    stop(second, &socket).await;

    let release_unknown = restarted
        .release(&release)
        .await
        .expect_err("stopped listener leaves exact release pending");
    assert_eq!(release_unknown.reason_code(), "RELEASE_OUTCOME_UNKNOWN");
    drop(restarted);
    let released = release_request(&body, &grant, AttemptState::Preparing, AttemptState::Failed);
    let release_id = released.settlement_id().expect("release settlement id");
    let third = start(&socket, &db, Arc::clone(&transport), Arc::clone(&registry)).await;
    settle_without_reading_response(&socket, &body, &released).await;
    wait_for_settlement(&db, &release_id).await;
    stop(third, &socket).await;

    let fourth = start(&socket, &db, Arc::clone(&transport), Arc::clone(&registry)).await;
    let final_client = client(&socket, &body, recovery);
    final_client
        .release(&release)
        .await
        .expect("restart resolves committed row by historical readback");
    stop(fourth, &socket).await;

    let running = advance_request(&body, &grant, AttemptState::Starting, AttemptState::Running);
    let preparing = advance_request(
        &body,
        &grant,
        AttemptState::Running,
        AttemptState::Preparing,
    );
    let ids = [running, preparing, released].map(|request| request.settlement_id().unwrap());
    let mut ledger = SqliteLedger::open(&db).expect("reopen SQLite truth");
    ledger
        .with_lease_transport(|transaction| {
            for id in &ids {
                assert!(
                    transaction.get_transport_settlement(id)?.is_some(),
                    "missing {id}"
                );
            }
            Ok::<(), bullet_application::LedgerError>(())
        })
        .expect("settlement rows");
    let attempt = ledger
        .get_attempt(&grant.attempt.id)
        .expect("attempt read")
        .expect("attempt row");
    assert_eq!(attempt.state, AttemptState::Failed);
    assert!(ledger
        .get_lease(&grant.attempt.variant_id)
        .expect("lease read")
        .is_none());
    let events = ledger.list_events().expect("events");
    for id in ids {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "lease_transport_settled" && event.body == id)
                .count(),
            1,
            "settlement must append exactly one event"
        );
    }
}
