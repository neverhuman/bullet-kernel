use super::super::*;
use super::reconciliation::{admitted, fixture, server, Reply};
use super::settlement::{advance_request, private_root, record};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[tokio::test]
async fn shaped_subject_drift_is_unknown_and_retains_pending_request() {
    let root = private_root();
    let (request, grant) = fixture();
    let terminal = advance_request(&request, &grant, AttemptState::Running);
    let mut wrong = record(terminal, grant.attempt.clone());
    wrong
        .subject
        .incarnation
        .as_mut()
        .expect("incarnation")
        .fence += 1;
    wrong.encode().expect("shape-valid drifted record");
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
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
    let journal = std::fs::read_to_string(root.path().join("recovery.json")).unwrap();
    assert!(journal.contains("target_state"));
}

#[tokio::test]
async fn typed_settle_refusal_with_committed_record_resolves_success() {
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
            ("settle", Reply::Refuse("INVALID_TRANSITION")),
            ("settlement_readback", Reply::Settlement(Box::new(expected))),
        ],
    ));
    client.acquire(&request).await.unwrap();
    client
        .advance(&grant.attempt.id, AttemptState::Running)
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn completion_publication_failure_retains_pending_and_restart_converges() {
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
            (
                "settlement_readback",
                Reply::SettlementThenExposeRecovery(
                    Box::new(expected.clone()),
                    root.path().to_path_buf(),
                ),
            ),
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

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
