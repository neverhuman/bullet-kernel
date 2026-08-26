//! Kernel-minted Unix lease transport. Public `/api/v1/leases/*` stay absent.

use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{KernelLeaseTransport, SignedAcquireBody};
use bullet_application::{materialize_plan, PlanInput};
use bullet_domain::{RunnerId, TaskClass};
use bullet_farmd::api;
use bullet_farmd::lease_transport_rpc;
use bullet_farmd::lease_transport_rpc::{LeasePeerRegistry, RegisteredRunnerPeer};
use bullet_runner_core::signed_lease_rpc::ExpectedLeaseServer;
use bullet_runner_core::{AcquireRequest, LeaseClient, SignedLeaseRpcClient};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Arc;
use std::time::Duration;

fn seeded_db(path: &std::path::Path) -> SignedAcquireBody {
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
    SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("signed-runner"),
        runner_epoch: 1,
        idempotency_key: "acquire-once".into(),
        ttl_seconds: 15,
    }
}

#[tokio::test]
async fn unsigned_runner_acquires_through_unix_socket() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).expect("0700");
    let db = root.path().join("ledger.sqlite");
    let socket_root = root.path().join("socket");
    std::fs::create_dir(&socket_root).expect("socket directory");
    std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o710)).expect("0710");
    let socket = socket_root.join("lease.sock");
    let body = seeded_db(&db);
    let (router, state) =
        api::daemon(&db, None, "http://127.0.0.1:7420".into(), None).expect("daemon");
    let transport = Arc::new(KernelLeaseTransport::generate().expect("key"));
    let self_meta = std::fs::metadata("/proc/self").expect("self");
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
        .expect("registry"),
    );
    tokio::spawn(lease_transport_rpc::serve(
        socket.clone(),
        state,
        transport,
        registry,
    ));
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let client = SignedLeaseRpcClient::new_admitted(
        socket.clone(),
        body.runner_id.clone(),
        body.runner_epoch,
        ExpectedLeaseServer::new(self_meta.uid(), self_meta.gid()),
    );
    let grant = client
        .acquire(&AcquireRequest {
            work_package_id: body.work_package_id.clone(),
            runner_id: body.runner_id.clone(),
            runner_epoch: body.runner_epoch,
            idempotency_key: body.idempotency_key.clone(),
            ttl_seconds: body.ttl_seconds,
        })
        .await
        .expect("acquire");
    assert_eq!(grant.lease.fence, 1);
    let mut probe = tokio::net::UnixStream::connect(&socket)
        .await
        .expect("peer probe");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    probe
        .write_all(
            format!(
                "{{\"proto\":\"bullet-farm.lease-transport.rpc.v1\",\"runner_id\":\"{}\",\"runner_epoch\":1}}\n",
                body.runner_id
            )
            .as_bytes(),
        )
        .await
        .expect("hello");
    let mut hello = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        probe.read_exact(&mut byte).await.expect("read");
        if byte[0] == b'\n' {
            break;
        }
        hello.push(byte[0]);
    }
    let ack: serde_json::Value = serde_json::from_slice(&hello).expect("ack");
    assert_eq!(ack["ok"], true);
    assert_eq!(
        ack["peer_uid"].as_u64().expect("peer uid"),
        u64::from(std::fs::metadata("/proc/self").expect("self").uid())
    );
    assert!(ack["socket_dev"].as_u64().is_some());
    assert!(ack["socket_ino"].as_u64().is_some());
    assert_ne!(ack["listener_dev"].as_u64(), Some(0));
    assert_ne!(ack["listener_ino"].as_u64(), Some(0));

    let mut spoof = tokio::net::UnixStream::connect(&socket)
        .await
        .expect("spoof probe");
    spoof
        .write_all(
            format!(
                "{{\"proto\":\"bullet-farm.lease-transport.rpc.v1\",\"runner_id\":\"{}\",\"runner_epoch\":1}}\n",
                RunnerId::from_seed("unregistered")
            )
            .as_bytes(),
        )
        .await
        .expect("spoof hello");
    let mut refused = Vec::new();
    loop {
        spoof.read_exact(&mut byte).await.expect("read refusal");
        if byte[0] == b'\n' {
            break;
        }
        refused.push(byte[0]);
    }
    let refusal: serde_json::Value = serde_json::from_slice(&refused).expect("refusal");
    assert_eq!(
        refusal["error"]["code"],
        "LEASE_TRANSPORT_PEER_UNREGISTERED"
    );
    let _ = router;
}

#[tokio::test]
async fn sqlite_readback_survives_reopen_with_same_kernel_key() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).expect("0700");
    let db = root.path().join("ledger.sqlite");
    let body = seeded_db(&db);
    let transport = KernelLeaseTransport::generate().expect("key");
    let now = 1_700_000_000_000;
    {
        let mut ledger = SqliteLedger::open(&db).expect("open");
        transport.acquire(&mut ledger, &body, now).expect("acquire");
    }
    let mut ledger = SqliteLedger::open(&db).expect("reopen");
    let grant = transport
        .readback(&mut ledger, &body, now + 1)
        .expect("readback");
    assert_eq!(grant.lease.fence, 1);
}

#[tokio::test]
async fn public_http_has_no_lease_routes() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).expect("0700");
    let db = root.path().join("ledger.sqlite");
    drop(SqliteLedger::open(&db).expect("open"));
    let app = api::router(&db).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(b"POST /api/v1/leases/acquire HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        .await
        .expect("write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read");
    let response = String::from_utf8_lossy(&bytes);
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}
