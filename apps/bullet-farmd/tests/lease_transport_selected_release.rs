#![cfg(not(debug_assertions))]

//! Release binary with `test-seams` still has no selected-Variant method.

use bullet_adapters::SqliteLedger;
use bullet_application::store::ProjectionReader;
use bullet_application::{materialize_plan, PlanInput};
use bullet_domain::{RunnerId, TaskClass};
use bullet_farmd::api;
use bullet_farmd::lease_transport_rpc::{serve, LeasePeerRegistry, RegisteredRunnerPeer};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn read_frame(stream: &mut UnixStream) -> serde_json::Value {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
        if byte[0] == b'\n' {
            return serde_json::from_slice(&bytes).unwrap();
        }
        bytes.push(byte[0]);
    }
}

#[tokio::test]
async fn release_feature_refuses_selected_method_before_ledger_mutation() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = root.path().join("release-selected.sqlite3");
    let runner = RunnerId::from_seed("release-selected-runner");
    let mut ledger = SqliteLedger::open(&db).unwrap();
    let at = "2026-01-01T00:00:00.000Z";
    materialize_plan(
        &mut ledger,
        "release-selected",
        &PlanInput {
            title: "release selected refusal".into(),
            objective: "compile out component-only method".into(),
            packages: vec![("one".into(), TaskClass::BoundedBugFix)],
        },
        at,
    )
    .unwrap();
    drop(ledger);
    let (_router, state) = api::daemon(&db, None, "http://127.0.0.1:7420".into(), None).unwrap();
    let identity = std::fs::metadata("/proc/self").unwrap();
    let (uid, gid) = (identity.uid(), identity.gid());
    let registry = Arc::new(
        LeasePeerRegistry::new(
            uid,
            gid,
            [RegisteredRunnerPeer::new(runner.clone(), 1, uid)],
        )
        .unwrap(),
    );
    let socket_root = root.path().join("socket");
    std::fs::create_dir(&socket_root).unwrap();
    std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o710)).unwrap();
    let socket = socket_root.join("lease.sock");
    let path = socket.clone();
    tokio::spawn(async move {
        serve(
            path,
            state,
            Arc::new(
                bullet_application::lease_transport::KernelLeaseTransport::generate().unwrap(),
            ),
            registry,
        )
        .await
    });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let hello = serde_json::json!({
        "proto": "bullet-farm.lease-transport.rpc.v1",
        "runner_id": runner,
        "runner_epoch": 1,
    });
    stream
        .write_all(format!("{hello}\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(read_frame(&mut stream).await["ok"], true);
    let request = serde_json::json!({
        "id": 1,
        "method": "synthetic_acquire_selected_variant",
        "params": {},
    });
    stream
        .write_all(format!("{request}\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut stream).await["error"]["code"],
        "LEASE_TRANSPORT_INVALID"
    );
    assert!(SqliteLedger::open(&db)
        .unwrap()
        .list_leases()
        .unwrap()
        .is_empty());
}
