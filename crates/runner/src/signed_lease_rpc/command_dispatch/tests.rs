use crate::signed_lease_rpc::{
    read_json, write_line, ExpectedLeaseServer, SignedLeaseRpcClient, PROTO, SOCKET_MODE,
};
use bullet_application::{CommandDispatchClaim, CommandRequest};
use bullet_domain::{CommandId, Digest, RunnerId};
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn bind(root: &Path) -> (PathBuf, tokio::net::UnixListener, ExpectedLeaseServer) {
    let socket = root.join("command-dispatch.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind fake Kernel");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    let metadata = std::fs::metadata(&socket).expect("socket metadata");
    let expected = ExpectedLeaseServer::new(metadata.uid(), metadata.gid());
    (socket, listener, expected)
}

async fn hello(stream: &mut tokio::net::UnixStream, metadata: &std::fs::Metadata) {
    let request: Value = read_json(stream).await.expect("hello");
    assert_eq!(request["proto"], PROTO);
    write_line(
        stream,
        &json!({
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
    .expect("hello ack");
}

fn claim(runner: &RunnerId, epoch: u64) -> CommandDispatchClaim {
    let request = CommandRequest::new("rpc-command", "run_demo", &json!({})).unwrap();
    CommandDispatchClaim {
        schema_version: "bullet.command-dispatch-claim.v1".into(),
        claim_id: format!("dcl_{}", "a".repeat(64)),
        command_id: request.id(),
        outbox_sequence: 1,
        request_digest: request.digest(),
        request,
        runner_id: runner.clone(),
        runner_epoch: epoch,
        authority_epoch: 1,
        freeze_generation: 0,
        restore_epoch: 0,
        disposition: bullet_application::CommandDispatchDisposition::Claimed,
        completion_digest: None,
        claimed_at: "2026-08-27T13:00:00.000Z".into(),
        updated_at: "2026-08-27T13:00:00.000Z".into(),
    }
}

#[tokio::test]
async fn claim_response_loss_uses_same_incarnation_durable_readback() {
    let root = tempfile::tempdir().expect("tempdir");
    let (socket, listener, expected_server) = bind(root.path());
    let runner = RunnerId::from_seed("command-rpc-runner");
    let expected = claim(&runner, 7);
    let metadata = std::fs::metadata(&socket).unwrap();
    let server = tokio::spawn({
        let expected = expected.clone();
        async move {
            let (mut lost, _) = listener.accept().await.unwrap();
            hello(&mut lost, &metadata).await;
            let request: Value = read_json(&mut lost).await.unwrap();
            assert_eq!(request["method"], "command_claim");
            assert_eq!(request["params"], json!({}));
            drop(lost);

            let (mut readback, _) = listener.accept().await.unwrap();
            hello(&mut readback, &metadata).await;
            let request: Value = read_json(&mut readback).await.unwrap();
            assert_eq!(request["method"], "command_readback");
            assert_eq!(request["params"], json!({}));
            write_line(&mut readback, &json!({"id": 1, "result": expected}))
                .await
                .unwrap();
        }
    });
    let client = SignedLeaseRpcClient::new_admitted(&socket, runner.clone(), 7, expected_server);
    assert!(client.claim_command_dispatch().await.is_err());
    assert_eq!(
        client.readback_command_dispatch().await.unwrap(),
        Some(expected)
    );
    server.await.unwrap();
}

#[tokio::test]
async fn command_dispatch_client_refuses_recursive_response_or_subject_drift() {
    for mutation in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let (socket, listener, expected_server) = bind(root.path());
        let runner = RunnerId::from_seed("command-rpc-hostile");
        let metadata = std::fs::metadata(&socket).unwrap();
        let mut result = serde_json::to_value(claim(&runner, 3)).unwrap();
        match mutation {
            0 => result["unknown"] = json!(true),
            1 => result["runner_epoch"] = json!(4),
            _ => result["command_id"] = json!(CommandId::from_seed("wrong-command")),
        }
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            hello(&mut stream, &metadata).await;
            let request: Value = read_json(&mut stream).await.unwrap();
            assert_eq!(request["method"], "command_claim");
            write_line(&mut stream, &json!({"id": 1, "result": result}))
                .await
                .unwrap();
        });
        let client = SignedLeaseRpcClient::new_admitted(&socket, runner, 3, expected_server);
        assert_eq!(
            client
                .claim_command_dispatch()
                .await
                .expect_err("hostile claim")
                .reason_code(),
            "PROTOCOL_ERROR"
        );
        server.await.unwrap();
    }
}

#[test]
fn completion_constructor_binds_claim_and_keeps_eligibility_false() {
    let runner = RunnerId::from_seed("command-completion-runner");
    let claim = claim(&runner, 1);
    let completion = bullet_application::ComponentCommandCompletionV1::new(
        &claim,
        Digest::of(b"component receipt"),
    )
    .unwrap();
    assert_eq!(completion.command_id, claim.command_id);
    assert_eq!(completion.request_digest, claim.request_digest);
    assert!(!completion.transaction_gate_eligible);
    assert!(!completion.independent_evidence_eligible);
}
