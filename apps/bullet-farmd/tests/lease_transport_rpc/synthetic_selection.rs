use super::*;
use bullet_application::lease_transport::SyntheticSelectedAcquireBody;
use bullet_application::materialize_synthetic_selection;
use bullet_application::store::ProjectionReader;
use bullet_domain::{AttemptState, Digest, VariantId};
use bullet_runner_core::ReleaseCall;

struct SelectedDaemon {
    _root: tempfile::TempDir,
    db: PathBuf,
    socket: PathBuf,
    selected: [SyntheticSelectedAcquireBody; 2],
    uid: u32,
    gid: u32,
}

impl SelectedDaemon {
    fn client(&self, lane: usize) -> SignedLeaseRpcClient {
        let body = self.selected[lane].inner();
        SignedLeaseRpcClient::new_admitted(
            &self.socket,
            body.runner_id.clone(),
            body.runner_epoch,
            ExpectedLeaseServer::new(self.uid, self.gid),
        )
        .with_recovery_file(self._root.path().join(format!("lane-{lane}-recovery.json")))
        .unwrap()
    }
}

async fn selected_daemon() -> SelectedDaemon {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = root.path().join("selected.sqlite3");
    let mut ledger = SqliteLedger::open(&db).unwrap();
    let graph = materialize_synthetic_selection(
        &mut ledger,
        "farmd-selected-uds",
        &PlanInput {
            title: "farmd selected UDS".into(),
            objective: "A terminal settlement precedes B acquire".into(),
            packages: vec![("one".into(), TaskClass::BoundedBugFix)],
        },
        "2026-01-01T00:00:00.000Z",
    )
    .unwrap();
    drop(ledger);
    let selected = [0, 1].map(|lane| {
        SyntheticSelectedAcquireBody::new(
            Digest::of(b"farmd-selected-plan"),
            graph.packages[0].id.clone(),
            RunnerId::from_seed(&format!("farmd-selected-runner-{lane}")),
            1,
            graph.variants[lane].id.clone(),
            15,
        )
        .unwrap()
    });
    let (_router, state) = api::daemon(&db, None, "http://127.0.0.1:7420".into(), None).unwrap();
    let identity = std::fs::metadata("/proc/self").unwrap();
    let (uid, gid) = (identity.uid(), identity.gid());
    let peers = selected.each_ref().map(|request| {
        RegisteredRunnerPeer::new(
            request.inner().runner_id.clone(),
            request.inner().runner_epoch,
            uid,
        )
    });
    let registry = Arc::new(LeasePeerRegistry::new(uid, gid, peers).unwrap());
    let socket_root = root.path().join("socket");
    std::fs::create_dir(&socket_root).unwrap();
    std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o710)).unwrap();
    let socket = socket_root.join("lease.sock");
    let path = socket.clone();
    let transport = Arc::new(KernelLeaseTransport::generate().unwrap());
    tokio::spawn(async move { serve(path, state, transport, registry).await });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(socket.exists());
    SelectedDaemon {
        _root: root,
        db,
        socket,
        selected,
        uid,
        gid,
    }
}

fn ordinary(request: &SyntheticSelectedAcquireBody) -> AcquireRequest {
    let body = request.inner();
    AcquireRequest {
        work_package_id: body.work_package_id.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        idempotency_key: body.idempotency_key.clone(),
        ttl_seconds: body.ttl_seconds,
    }
}

#[tokio::test]
async fn selected_uds_closes_ordinary_ambiguity_and_orders_two_fence_one_lanes() {
    let daemon = selected_daemon().await;
    let client_a = daemon.client(0);
    let ordinary_error = client_a
        .acquire(&ordinary(&daemon.selected[0]))
        .await
        .unwrap_err();
    assert!(matches!(
        ordinary_error,
        bullet_runner_core::RunnerError::Lease { .. }
    ));
    assert!(SqliteLedger::open(&daemon.db)
        .unwrap()
        .list_leases()
        .unwrap()
        .is_empty());

    let grant_a = client_a
        .acquire_synthetic_selected(&daemon.selected[0])
        .await
        .unwrap();
    assert_eq!(
        grant_a.attempt.variant_id,
        *daemon.selected[0].selected_variant_id()
    );
    assert_eq!(grant_a.attempt.fence, 1);
    assert_eq!(
        client_a
            .acquire_synthetic_selected(&daemon.selected[0])
            .await
            .unwrap()
            .attempt
            .id,
        grant_a.attempt.id
    );
    drop(client_a);
    let restarted_a = daemon.client(0);
    assert_eq!(
        restarted_a
            .acquire_synthetic_selected(&daemon.selected[0])
            .await
            .unwrap()
            .attempt
            .id,
        grant_a.attempt.id
    );
    restarted_a
        .release(&ReleaseCall {
            attempt_id: grant_a.attempt.id.clone(),
            outcome: AttemptState::Superseded,
            requeue: true,
        })
        .await
        .unwrap();

    let client_b = daemon.client(1);
    let grant_b = client_b
        .acquire_synthetic_selected(&daemon.selected[1])
        .await
        .unwrap();
    assert_eq!(
        grant_b.attempt.variant_id,
        *daemon.selected[1].selected_variant_id()
    );
    assert_eq!(grant_b.attempt.fence, 1);
    assert_ne!(grant_a.attempt.id, grant_b.attempt.id);

    let ledger = SqliteLedger::open(&daemon.db).unwrap();
    assert_eq!(
        ledger
            .get_attempt(&grant_a.attempt.id)
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Superseded
    );
    assert_eq!(ledger.list_leases().unwrap().len(), 1);
    assert_eq!(
        ledger.list_leases().unwrap()[0].variant_id,
        grant_b.attempt.variant_id
    );
}

#[tokio::test]
async fn selected_rpc_refuses_foreign_variant_and_hello_without_mutation() {
    let daemon = selected_daemon().await;
    let mut value = serde_json::to_value(&daemon.selected[0]).unwrap();
    value["selected_variant_id"] = serde_json::json!(VariantId::from_seed("foreign"));
    let mut stream = UnixStream::connect(&daemon.socket).await.unwrap();
    let ack = daemon_hello(&daemon, &mut stream, 0).await;
    assert_eq!(ack["ok"], true);
    let frame = serde_json::json!({
        "id": 1,
        "method": "synthetic_acquire_selected_variant",
        "params": value,
    });
    assert!(send(&mut stream, format!("{frame}\n").as_bytes()).await);
    assert_eq!(
        read_frame(&mut stream).await.unwrap()["error"]["code"],
        "LEASE_TRANSPORT_INVALID"
    );

    let mut wrong_hello = UnixStream::connect(&daemon.socket).await.unwrap();
    let foreign = RunnerId::from_seed("foreign-hello");
    assert!(send(&mut wrong_hello, hello_line(&foreign).as_bytes()).await);
    assert_ne!(read_frame(&mut wrong_hello).await.unwrap()["ok"], true);
    assert!(SqliteLedger::open(&daemon.db)
        .unwrap()
        .list_leases()
        .unwrap()
        .is_empty());
}

async fn daemon_hello(
    daemon: &SelectedDaemon,
    stream: &mut UnixStream,
    lane: usize,
) -> serde_json::Value {
    let runner = &daemon.selected[lane].inner().runner_id;
    assert!(send(stream, hello_line(runner).as_bytes()).await);
    read_frame(stream).await.unwrap()
}
