use super::reconciliation::{admitted, server, Reply};
use super::*;
use bullet_application::lease_transport::SyntheticSelectedAcquireBody;
use bullet_application::{
    materialize_synthetic_selection, LeaseRequest, LeaseService, Ledger, MemoryLedger, PlanInput,
};
use bullet_domain::{Digest, TaskClass, WorkspaceId};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tokio::time::{timeout, Duration};

fn fixture() -> (AcquireRequest, SyntheticSelectedAcquireBody, AcquireGrant) {
    let mut ledger = MemoryLedger::new();
    let at = ledger.simulation_time();
    let graph = materialize_synthetic_selection(
        &mut ledger,
        "runner-selected-recovery",
        &PlanInput {
            title: "selected recovery".into(),
            objective: "persist the selected method and Variant".into(),
            packages: vec![("one".into(), TaskClass::BoundedBugFix)],
        },
        &at,
    )
    .unwrap();
    let selected = SyntheticSelectedAcquireBody::new(
        Digest::of(b"runner-selected-plan"),
        graph.packages[0].id.clone(),
        RunnerId::from_seed("runner-selected"),
        3,
        graph.variants[0].id.clone(),
        7,
    )
    .unwrap();
    let body = selected.inner();
    let acquired = ledger
        .acquire_lease(&LeaseRequest {
            idempotency_key: body.idempotency_key.clone(),
            mission_id: graph.mission.id.clone(),
            variant_id: selected.selected_variant_id().clone(),
            attempt_seed: body.idempotency_key.clone(),
            runner_id: body.runner_id.clone(),
            runner_epoch: body.runner_epoch,
            workspace_id: WorkspaceId::from_seed(&body.idempotency_key),
            workspace_nonce: *Digest::of(body.idempotency_key.as_bytes()).as_bytes(),
            scope_revision: 1,
            context_revision: 1,
            ttl_seconds: body.ttl_seconds,
        })
        .unwrap();
    let grant = AcquireGrant {
        authority_token: LeaseService::token_for(&graph, &acquired.attempt).unwrap(),
        attempt: acquired.attempt,
        lease: acquired.lease,
    };
    let request = AcquireRequest {
        work_package_id: body.work_package_id.clone(),
        runner_id: body.runner_id.clone(),
        runner_epoch: body.runner_epoch,
        idempotency_key: body.idempotency_key.clone(),
        ttl_seconds: body.ttl_seconds,
    };
    (request, selected, grant)
}

fn restart(root: &Path, socket: &Path, request: &AcquireRequest) -> SignedLeaseRpcClient {
    let metadata = std::fs::metadata(socket).unwrap();
    SignedLeaseRpcClient::new_admitted(
        socket,
        request.runner_id.clone(),
        request.runner_epoch,
        ExpectedLeaseServer::new(metadata.uid(), metadata.gid()),
    )
    .with_recovery_file(root.join("recovery.json"))
    .unwrap()
}

#[test]
fn durable_acquire_tag_refuses_both_method_collisions() {
    let (request, selected, _) = fixture();
    let selected_intent = AcquireIntent::synthetic(selected.clone()).unwrap();
    let ordinary_intent = AcquireIntent::ordinary(selected.inner().clone());
    for (first, second) in [
        (selected_intent.clone(), ordinary_intent.clone()),
        (ordinary_intent, selected_intent),
    ] {
        let mut journal = RecoveryJournal::new(request.runner_id.clone(), request.runner_epoch);
        assert!(journal.reserve_intent(first).unwrap());
        let error = journal.reserve_intent(second).unwrap_err();
        assert!(
            matches!(error, RunnerError::Lease { ref code, .. } if code == "IDEMPOTENCY_CONFLICT")
        );
    }
}

#[tokio::test]
async fn selected_response_loss_recovers_only_the_expected_variant() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, selected, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            ("synthetic_acquire_selected_variant", Reply::Close),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
        ],
    ));
    let recovered = client.acquire_synthetic_selected(&selected).await.unwrap();
    assert_eq!(
        recovered.attempt.variant_id,
        *selected.selected_variant_id()
    );
    task.await.unwrap();
}

#[tokio::test]
async fn durable_selected_tag_blocks_ordinary_restart_before_socket() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, selected, _) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    client
        .reserve_tagged_intent(AcquireIntent::synthetic(selected).unwrap())
        .unwrap();
    drop(client);
    let restarted = restart(root.path(), &socket, &request);
    let error = restarted.acquire(&request).await.unwrap_err();
    assert!(matches!(error, RunnerError::Lease { ref code, .. } if code == "IDEMPOTENCY_CONFLICT"));
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "method mismatch must refuse before a socket write"
    );
}

#[tokio::test]
async fn selected_restart_replays_selected_method_after_authoritative_absence() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, selected, grant) = fixture();
    let (client, listener, socket) = admitted(root.path(), &request);
    client
        .reserve_tagged_intent(AcquireIntent::synthetic(selected.clone()).unwrap())
        .unwrap();
    drop(client);
    let restarted = restart(root.path(), &socket, &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            (
                "readback_active",
                Reply::Refuse("LEASE_TRANSPORT_GRANT_ABSENT"),
            ),
            (
                "synthetic_acquire_selected_variant",
                Reply::Grant(Box::new(grant.clone())),
            ),
            ("readback_active", Reply::Grant(Box::new(grant.clone()))),
        ],
    ));
    assert_eq!(
        restarted
            .acquire_synthetic_selected(&selected)
            .await
            .unwrap()
            .attempt
            .id,
        grant.attempt.id
    );
    task.await.unwrap();
}

#[tokio::test]
async fn wrong_variant_readback_is_unknown_and_retains_selected_intent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (request, selected, mut grant) = fixture();
    let wrong = bullet_domain::VariantId::from_seed("wrong-selected-variant");
    grant.attempt.variant_id = wrong.clone();
    grant.lease.variant_id = wrong.clone();
    grant.authority_token.variant_id = wrong;
    let (client, listener, socket) = admitted(root.path(), &request);
    let task = tokio::spawn(server(
        listener,
        socket,
        vec![
            (
                "synthetic_acquire_selected_variant",
                Reply::Grant(Box::new(grant.clone())),
            ),
            ("readback_active", Reply::Grant(Box::new(grant))),
        ],
    ));
    let error = client
        .acquire_synthetic_selected(&selected)
        .await
        .unwrap_err();
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
