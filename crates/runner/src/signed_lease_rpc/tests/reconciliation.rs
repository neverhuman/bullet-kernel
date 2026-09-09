use super::super::*;
use bullet_application::lease_transport::SignedAcquireBody;
use bullet_application::{
    materialize_plan, LeaseRequest, LeaseService, Ledger, MemoryLedger, PlanInput,
};
use bullet_domain::{Digest, TaskClass, WorkspaceId};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Clone)]
pub(super) enum Reply {
    Grant(Box<AcquireGrant>),
    GrantThenExposeRecovery(Box<AcquireGrant>, PathBuf),
    Settlement(Box<bullet_application::lease_transport::LeaseSettlementRecord>),
    SettlementThenExposeRecovery(
        Box<bullet_application::lease_transport::LeaseSettlementRecord>,
        PathBuf,
    ),
    Refuse(&'static str),
    HeartbeatTtl(i64),
    Close,
}

pub(super) fn fixture() -> (AcquireRequest, AcquireGrant) {
    let mut ledger = MemoryLedger::new();
    let now = ledger.simulation_time();
    let plan = PlanInput {
        title: "acquire reconciliation".into(),
        objective: "recover one exact active grant".into(),
        packages: vec![("one".into(), TaskClass::MechanicalCodeEdit)],
    };
    let graph = materialize_plan(&mut ledger, "reconcile", &plan, &now).unwrap();
    let request = AcquireRequest {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed("reconciliation-runner"),
        runner_epoch: 9,
        idempotency_key: "reconciliation-key".into(),
        ttl_seconds: 7,
    };
    let workspace_nonce = *Digest::of(request.idempotency_key.as_bytes()).as_bytes();
    let lease_request = LeaseRequest {
        idempotency_key: request.idempotency_key.clone(),
        mission_id: graph.mission.id.clone(),
        variant_id: graph.variants[0].id.clone(),
        attempt_seed: request.idempotency_key.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        workspace_id: WorkspaceId::from_seed(&request.idempotency_key),
        workspace_nonce,
        scope_revision: 1,
        context_revision: 1,
        ttl_seconds: request.ttl_seconds,
    };
    let acquired = ledger.acquire_lease(&lease_request).unwrap();
    let authority_token = LeaseService::token_for(&graph, &acquired.attempt).unwrap();
    let grant = AcquireGrant {
        attempt: acquired.attempt,
        authority_token,
        lease: acquired.lease,
    };
    (request, grant)
}

pub(super) async fn server(
    listener: tokio::net::UnixListener,
    socket: PathBuf,
    script: Vec<(&'static str, Reply)>,
) {
    let metadata = std::fs::metadata(socket).unwrap();
    for (method, reply) in script {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _: serde_json::Value = read_json(&mut stream).await.unwrap();
        write_line(
            &mut stream,
            &serde_json::json!({
                "ok": true,
                "proto": PROTO,
                "peer_uid": metadata.uid(),
                "peer_gid": metadata.gid(),
                "peer_pid": std::process::id(),
                "socket_dev": metadata.dev(),
                "socket_ino": metadata.ino(),
                "listener_dev": metadata.dev(),
                "listener_ino": metadata.ino(),
            }),
        )
        .await
        .unwrap();
        let request: serde_json::Value = read_json(&mut stream).await.unwrap();
        assert_eq!(request["method"], method);
        match reply {
            Reply::Grant(grant) => {
                write_line(&mut stream, &serde_json::json!({"id": 1, "result": grant}))
                    .await
                    .unwrap();
            }
            Reply::GrantThenExposeRecovery(grant, parent) => {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
                write_line(&mut stream, &serde_json::json!({"id": 1, "result": grant}))
                    .await
                    .unwrap();
            }
            Reply::Settlement(record) => {
                write_line(&mut stream, &serde_json::json!({"id": 1, "result": record}))
                    .await
                    .unwrap();
            }
            Reply::SettlementThenExposeRecovery(record, parent) => {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
                write_line(&mut stream, &serde_json::json!({"id": 1, "result": record}))
                    .await
                    .unwrap();
            }
            Reply::Refuse(code) => {
                write_line(
                    &mut stream,
                    &serde_json::json!({
                        "id": 1,
                        "error": {"code": code, "message": "scripted refusal"}
                    }),
                )
                .await
                .unwrap();
            }
            Reply::HeartbeatTtl(ttl_seconds) => {
                assert_eq!(request["params"]["call"]["ttl_seconds"], ttl_seconds);
                write_line(&mut stream, &serde_json::json!({"id": 1, "result": null}))
                    .await
                    .unwrap();
            }
            Reply::Close => {}
        }
    }
}

pub(super) fn admitted(
    root: &Path,
    request: &AcquireRequest,
) -> (SignedLeaseRpcClient, tokio::net::UnixListener, PathBuf) {
    let socket = root.join("lease.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).unwrap();
    let metadata = std::fs::metadata(&socket).unwrap();
    let client = SignedLeaseRpcClient::new_admitted(
        &socket,
        request.runner_id.clone(),
        request.runner_epoch,
        ExpectedLeaseServer::new(metadata.uid(), metadata.gid()),
    )
    .with_recovery_file(root.join("recovery.json"))
    .unwrap();
    (client, listener, socket)
}

#[tokio::test]
async fn response_loss_after_commit_is_recovered_by_active_readback() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Close),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
        ],
    ));
    let recovered = client.acquire(&request).await.unwrap();
    assert_eq!(recovered.attempt.id, grant.attempt.id);
    task.await.unwrap();
}

#[tokio::test]
async fn grant_publication_failure_never_returns_acquire_authority() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            (
                "readback_active",
                Reply::GrantThenExposeRecovery(Box::new(grant), root.path().to_path_buf()),
            ),
        ],
    ));
    let error = client.acquire(&request).await.unwrap_err();
    assert_eq!(error.reason_code(), "ACQUIRE_OUTCOME_UNKNOWN");
    task.await.unwrap();
}

#[tokio::test]
async fn typed_postcommit_error_is_reconciled_before_forgetting_intent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Refuse("ENCODING")),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
        ],
    ));
    assert_eq!(
        client.acquire(&request).await.unwrap().attempt.id,
        grant.attempt.id
    );
    task.await.unwrap();
}

#[tokio::test]
async fn typed_precommit_refusal_requires_authoritative_absence_and_is_not_replayed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, _) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Refuse("NOT_FOUND")),
            (
                "readback_active",
                Reply::Refuse("LEASE_TRANSPORT_GRANT_ABSENT"),
            ),
        ],
    ));
    let error = client.acquire(&request).await.unwrap_err();
    assert!(matches!(error, RunnerError::Lease { ref code, .. } if code == "NOT_FOUND"));
    task.await.unwrap();
}

#[tokio::test]
async fn graph_resolution_unknown_retains_intent_and_never_authorizes_replay() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, _) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Refuse("NOT_FOUND")),
            ("readback_active", Reply::Refuse("LEASE_TRANSPORT_UNKNOWN")),
        ],
    ));
    let error = client.acquire(&request).await.unwrap_err();
    assert_eq!(error.reason_code(), "ACQUIRE_OUTCOME_UNKNOWN");
    task.await.unwrap();

    let journal = load_recovery(
        &root.path().join("recovery.json"),
        &request.runner_id,
        request.runner_epoch,
    )
    .unwrap();
    assert!(journal
        .intent_for(&AttemptId::from_seed(&request.idempotency_key))
        .is_some());
}

#[tokio::test]
async fn restarted_client_uses_active_readback_without_a_second_acquire() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let body = SignedAcquireBody {
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        ttl_seconds: request.ttl_seconds,
    };
    let _ = client.reserve_intent(body).unwrap();
    drop(client);
    let metadata = std::fs::metadata(&socket).unwrap();
    let restarted = SignedLeaseRpcClient::new_admitted(
        &socket,
        request.runner_id.clone(),
        request.runner_epoch,
        ExpectedLeaseServer::new(metadata.uid(), metadata.gid()),
    )
    .with_recovery_file(root.path().join("recovery.json"))
    .unwrap();
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![("readback_active", Reply::Grant(Box::new(grant.clone())))],
    ));
    assert_eq!(
        restarted.acquire(&request).await.unwrap().attempt.id,
        grant.attempt.id
    );
    task.await.unwrap();
}

#[tokio::test]
async fn authoritative_absence_allows_one_exact_replay_then_active_readback() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let body = SignedAcquireBody {
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        ttl_seconds: request.ttl_seconds,
    };
    let _ = client.reserve_intent(body).unwrap();
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            (
                "readback_active",
                Reply::Refuse("LEASE_TRANSPORT_GRANT_ABSENT"),
            ),
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
        ],
    ));
    assert_eq!(
        client.acquire(&request).await.unwrap().attempt.id,
        grant.attempt.id
    );
    task.await.unwrap();
}

#[tokio::test]
async fn unresolved_response_and_readback_are_typed_unknown() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, _) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![("acquire", Reply::Close), ("readback_active", Reply::Close)],
    ));
    let error = client.acquire(&request).await.unwrap_err();
    assert_eq!(error.reason_code(), "ACQUIRE_OUTCOME_UNKNOWN");
    task.await.unwrap();
}

#[tokio::test]
async fn unresolved_post_replay_readback_is_typed_unknown() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, _) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let body = SignedAcquireBody {
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        ttl_seconds: request.ttl_seconds,
    };
    let _ = client.reserve_intent(body).unwrap();
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            (
                "readback_active",
                Reply::Refuse("LEASE_TRANSPORT_GRANT_ABSENT"),
            ),
            ("acquire", Reply::Close),
            ("readback_active", Reply::Close),
        ],
    ));
    let error = client.acquire(&request).await.unwrap_err();
    assert_eq!(error.reason_code(), "ACQUIRE_OUTCOME_UNKNOWN");
    task.await.unwrap();
}

#[tokio::test]
async fn drifted_active_grant_is_typed_unknown() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, mut grant) = fixture();
    grant.lease.ttl_seconds = 15;
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Close),
            ("readback_active", Reply::Grant(Box::new(grant))),
        ],
    ));
    let error = client.acquire(&request).await.unwrap_err();
    assert_eq!(error.reason_code(), "ACQUIRE_OUTCOME_UNKNOWN");
    task.await.unwrap();
}

#[tokio::test]
async fn heartbeat_uses_the_durable_original_ttl_not_caller_drift() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let body = SignedAcquireBody {
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        ttl_seconds: request.ttl_seconds,
    };
    let _ = client.reserve_intent(body).unwrap();
    let mut heartbeat = HeartbeatCall::for_grant(&grant).unwrap();
    heartbeat.ttl_seconds = 15;
    assert_ne!(heartbeat.ttl_seconds, request.ttl_seconds);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![("heartbeat", Reply::HeartbeatTtl(request.ttl_seconds))],
    ));
    client.heartbeat(&heartbeat).await.unwrap();
    task.await.unwrap();
}
