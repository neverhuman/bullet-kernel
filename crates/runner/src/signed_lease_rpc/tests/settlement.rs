use super::super::*;
use super::reconciliation::{admitted, fixture, server, Reply};
use bullet_application::lease_transport::{
    AdvanceSettlementRequest, LeaseSettlementOutcome, LeaseSettlementRecord,
    LeaseSettlementRequest, ReleaseSettlementRequest, SignedAcquireBody,
    LEASE_SETTLEMENT_RECORD_VERSION,
};
use bullet_harness_core::launch_grant::workspace_nonce_digest;
use bullet_harness_core::lease_transport::{LeaseIncarnationClaims, LeaseSubjectClaims};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn acquire_body(request: &AcquireRequest) -> SignedAcquireBody {
    SignedAcquireBody {
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        ttl_seconds: request.ttl_seconds,
    }
}

pub(super) fn advance_request(
    request: &AcquireRequest,
    grant: &AcquireGrant,
    target_state: AttemptState,
) -> LeaseSettlementRequest {
    LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
        acquire_request_digest: acquire_body(request).request_digest().unwrap(),
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        variant_id: grant.attempt.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        attempt_fence: grant.attempt.fence,
        expected_state: grant.attempt.state,
        target_state,
    })
}

fn release_request(
    request: &AcquireRequest,
    grant: &AcquireGrant,
    final_state: AttemptState,
) -> LeaseSettlementRequest {
    LeaseSettlementRequest::Release(ReleaseSettlementRequest {
        acquire_request_digest: acquire_body(request).request_digest().unwrap(),
        work_package_id: request.work_package_id.clone(),
        runner_id: request.runner_id.clone(),
        runner_epoch: request.runner_epoch,
        idempotency_key: request.idempotency_key.clone(),
        variant_id: grant.attempt.variant_id.clone(),
        attempt_id: grant.attempt.id.clone(),
        attempt_fence: grant.attempt.fence,
        expected_state: grant.attempt.state,
        final_state,
        requeue: false,
    })
}

pub(super) fn record(
    request: LeaseSettlementRequest,
    mut attempt: bullet_domain::Attempt,
) -> LeaseSettlementRecord {
    let operation = match &request {
        LeaseSettlementRequest::Advance(body) => {
            attempt.state = body.target_state;
            LeaseSettlementOutcome::Advanced(attempt)
        }
        LeaseSettlementRequest::Release(body) => {
            attempt.state = body.final_state;
            LeaseSettlementOutcome::Released(attempt)
        }
    };
    let request_digest = request.digest().unwrap();
    let incarnation = LeaseIncarnationClaims {
        variant_id: attempt_for(&operation).variant_id.to_string(),
        attempt_id: attempt_for(&operation).id.to_string(),
        fence: attempt_for(&operation).fence,
        scope_revision: attempt_for(&operation).scope_revision,
        context_revision: attempt_for(&operation).context_revision,
    };
    let record = LeaseSettlementRecord {
        version: LEASE_SETTLEMENT_RECORD_VERSION.into(),
        settlement_id: format!("lts_{request_digest}"),
        request_digest,
        request,
        subject: LeaseSubjectClaims {
            workspace_id: attempt_for(&operation).workspace_id.to_string(),
            workspace_generation: 1,
            workspace_nonce_digest: workspace_nonce_digest(
                &attempt_for(&operation).workspace_nonce,
            )
            .unwrap(),
            scope_digest: "2".repeat(64),
            policy_generation: 1,
            freeze_generation: 0,
            graph_revision: 1,
            routing_generation: 1,
            authority_epoch: 1,
            incarnation: Some(incarnation),
        },
        outcome: operation,
    };
    record.encode().unwrap();
    record
}

fn attempt_for(outcome: &LeaseSettlementOutcome) -> &bullet_domain::Attempt {
    match outcome {
        LeaseSettlementOutcome::Advanced(attempt) | LeaseSettlementOutcome::Released(attempt) => {
            attempt
        }
    }
}

pub(super) fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[tokio::test]
async fn advance_close_absence_replay_and_readback_converge() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = advance_request(&request, &grant, AttemptState::Running);
    let expected = record(terminal, grant.attempt.clone());
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            (
                "settlement_readback",
                Reply::Refuse("LEASE_TRANSPORT_SETTLEMENT_ABSENT"),
            ),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Settlement(Box::new(expected))),
        ],
    ));
    client.acquire(&request).await.unwrap();
    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap();
    task.await.unwrap();
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("recovery.json")).unwrap()).unwrap();
    assert!(journal["settlements"].as_object().unwrap().is_empty());
    assert_eq!(journal["completed"].as_object().unwrap().len(), 1);
    let intent = &journal["intents"][grant.attempt.id.as_str()];
    assert_eq!(intent["grant"]["attempt"]["state"], "starting");
    assert_eq!(intent["current_attempt"]["state"], "running");
}

#[tokio::test]
async fn restart_reads_back_pending_advance_before_any_replay() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = advance_request(&request, &grant, AttemptState::Running);
    let expected = record(terminal, grant.attempt.clone());
    let (client, listener, socket) = admitted(root.path(), &request);
    let first = tokio::spawn(server(
        listener,
        socket.clone(),
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Close),
        ],
    ));
    client.acquire(&request).await.unwrap();
    let error = client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), "ADVANCE_OUTCOME_UNKNOWN");
    first.await.unwrap();
    drop(client);

    std::fs::remove_file(&socket).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).unwrap();
    let metadata = std::fs::metadata(&socket).unwrap();
    let restarted = SignedLeaseRpcClient::new_admitted(
        &socket,
        request.runner_id.clone(),
        request.runner_epoch,
        ExpectedLeaseServer::new(metadata.uid(), metadata.gid()),
    )
    .with_recovery_file(root.path().join("recovery.json"))
    .unwrap();
    let second = tokio::spawn(server(
        listener,
        socket,
        vec![("settlement_readback", Reply::Settlement(Box::new(expected)))],
    ));
    restarted
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap();
    second.await.unwrap();
}

#[tokio::test]
async fn release_unknown_is_distinct_and_retains_exact_request() {
    let root = private_root();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Close),
        ],
    ));
    client.acquire(&request).await.unwrap();
    let error = client
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id,
            outcome: AttemptState::Failed,
            requeue: false,
        })
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), "RELEASE_OUTCOME_UNKNOWN");
    task.await.unwrap();
    let journal = std::fs::read_to_string(root.path().join("recovery.json")).unwrap();
    assert!(journal.contains("final_state"));
    assert!(journal.contains("acquire_request_digest"));
}

#[tokio::test]
async fn typed_refusal_plus_authoritative_absence_clears_without_replay() {
    let root = private_root();
    let (request, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Refuse("INVALID_TRANSITION")),
            (
                "settlement_readback",
                Reply::Refuse("LEASE_TRANSPORT_SETTLEMENT_ABSENT"),
            ),
        ],
    ));
    client.acquire(&request).await.unwrap();
    let error = client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap_err();
    assert!(matches!(error, RunnerError::Lease { ref code, .. } if code == "INVALID_TRANSITION"));
    task.await.unwrap();
    let journal = std::fs::read_to_string(root.path().join("recovery.json")).unwrap();
    assert!(!journal.contains("target_state"));
}

#[tokio::test]
async fn wrong_record_is_unknown_retains_pending_and_conflicts_before_socket() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = advance_request(&request, &grant, AttemptState::Running);
    let mut wrong = record(terminal, grant.attempt.clone());
    wrong.settlement_id = format!("lts_{}", "0".repeat(64));
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket.clone(),
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Settlement(Box::new(wrong))),
        ],
    ));
    client.acquire(&request).await.unwrap();
    let error = client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), "ADVANCE_OUTCOME_UNKNOWN");
    task.await.unwrap();
    std::fs::remove_file(socket).unwrap();

    let conflict = client
        .advance(&grant.attempt.id, AttemptState::Preparing)
        .await
        .unwrap_err();
    assert!(
        matches!(conflict, RunnerError::Lease { ref code, .. } if code == "IDEMPOTENCY_CONFLICT")
    );
    let journal = std::fs::read_to_string(root.path().join("recovery.json")).unwrap();
    assert!(journal.contains("target_state"));
}

#[tokio::test]
async fn restart_absence_allows_one_settle_then_exact_readback() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = advance_request(&request, &grant, AttemptState::Running);
    let expected = record(terminal, grant.attempt.clone());
    let (client, listener, socket) = admitted(root.path(), &request);
    let first = tokio::spawn(server(
        listener,
        socket.clone(),
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Close),
        ],
    ));
    client.acquire(&request).await.unwrap();
    assert_eq!(
        client
            .advance(&grant.attempt.id, AttemptState::Running)
            .await
            .unwrap_err()
            .reason_code(),
        "ADVANCE_OUTCOME_UNKNOWN"
    );
    first.await.unwrap();
    drop(client);

    std::fs::remove_file(&socket).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).unwrap();
    let metadata = std::fs::metadata(&socket).unwrap();
    let restarted = SignedLeaseRpcClient::new_admitted(
        &socket,
        request.runner_id.clone(),
        request.runner_epoch,
        ExpectedLeaseServer::new(metadata.uid(), metadata.gid()),
    )
    .with_recovery_file(root.path().join("recovery.json"))
    .unwrap();
    let second = tokio::spawn(server(
        listener,
        socket,
        vec![
            (
                "settlement_readback",
                Reply::Refuse("LEASE_TRANSPORT_SETTLEMENT_ABSENT"),
            ),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Settlement(Box::new(expected))),
        ],
    ));
    restarted
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap();
    second.await.unwrap();
}

#[tokio::test]
async fn completed_advance_duplicate_returns_without_socket() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = advance_request(&request, &grant, AttemptState::Running);
    let expected = record(terminal, grant.attempt.clone());
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket.clone(),
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Settlement(Box::new(expected))),
        ],
    ));
    client.acquire(&request).await.unwrap();
    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap();
    task.await.unwrap();
    std::fs::remove_file(socket).unwrap();
    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap();
}

#[tokio::test]
async fn release_record_retires_intent_and_duplicate_needs_no_socket() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = release_request(&request, &grant, AttemptState::Failed);
    let expected = record(terminal, grant.attempt.clone());
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket.clone(),
        vec![
            ("acquire", Reply::Grant(Box::new(grant.clone()))),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
            ("settle", Reply::Close),
            ("settlement_readback", Reply::Settlement(Box::new(expected))),
        ],
    ));
    client.acquire(&request).await.unwrap();
    let call = ReleaseCall {
        attempt_id: grant.attempt.id.clone(),
        outcome: AttemptState::Failed,
        requeue: false,
    };
    client.release(&call).await.unwrap();
    task.await.unwrap();
    std::fs::remove_file(socket).unwrap();
    client.release(&call).await.unwrap();

    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("recovery.json")).unwrap()).unwrap();
    assert!(journal["intents"].as_object().unwrap().is_empty());
    assert!(journal["settlements"].as_object().unwrap().is_empty());
    assert_eq!(journal["completed"].as_object().unwrap().len(), 1);
}
