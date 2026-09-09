use super::*;
use crate::signed_lease_rpc::{
    read_json, write_line, ExpectedLeaseServer, SignedLeaseRpcClient, PROTO, SOCKET_MODE,
};
use bullet_domain::RunnerId;
use bullet_harness_core::candidate_preparation::{
    candidate_preparation_envelope_digest, canonical_candidate_preparation_json,
    SignedCandidatePreparationGrantV1,
};
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

struct Exchange {
    method: &'static str,
    attempt_id: String,
    request_digest: String,
    result: Value,
}

fn bind(root: &Path) -> (PathBuf, tokio::net::UnixListener, ExpectedLeaseServer) {
    let socket = root.join("candidate-rpc.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind fake Kernel");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    let metadata = std::fs::metadata(&socket).expect("socket metadata");
    let expected = ExpectedLeaseServer::new(metadata.uid(), metadata.gid());
    (socket, listener, expected)
}

fn serve(
    socket: &Path,
    listener: tokio::net::UnixListener,
    exchanges: Vec<Exchange>,
) -> tokio::task::JoinHandle<()> {
    let metadata = std::fs::metadata(socket).expect("socket metadata");
    tokio::spawn(async move {
        for exchange in exchanges {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let hello: Value = read_json(&mut stream).await.expect("hello");
            assert_eq!(hello["proto"], PROTO);
            write_line(
                &mut stream,
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
            let request: Value = read_json(&mut stream).await.expect("request");
            assert_eq!(request["id"], 1);
            assert_eq!(request["method"], exchange.method);
            assert_eq!(request["params"]["attempt_id"], exchange.attempt_id);
            assert_eq!(request["params"]["request_digest"], exchange.request_digest);
            assert_eq!(
                request["params"].as_object().expect("params").len(),
                2,
                "Candidate request must remain recursively closed"
            );
            write_line(&mut stream, &json!({"id": 1, "result": exchange.result}))
                .await
                .expect("response");
        }
    })
}

fn signed(seed: &str) -> (String, String) {
    let signed = SignedCandidatePreparationGrantV1 {
        schema_version: "v1alpha1".into(),
        issuer: "bullet-kernel-local".into(),
        key_id: format!("candidate-key-{seed}"),
        paseto: format!("v4.public.{seed}"),
    };
    let canonical = String::from_utf8(
        canonical_candidate_preparation_json(&signed).expect("canonical signed grant"),
    )
    .expect("UTF-8");
    let digest = candidate_preparation_envelope_digest(&signed).expect("envelope digest");
    (canonical, digest)
}

fn response(attempt_id: &AttemptId, request_digest: &str, seed: char) -> Value {
    let (signed_grant_canonical_json, envelope_digest) = signed(&seed.to_string());
    json!({
        "schema_version": "v1alpha1",
        "request_digest": request_digest,
        "attempt_id": attempt_id.as_str(),
        "candidate_preparation_grant_id": format!("cpg_{}", seed.to_string().repeat(64)),
        "signed_grant_canonical_json": signed_grant_canonical_json,
        "envelope_digest": envelope_digest,
    })
}

async fn prepare_once(result: Value) -> Result<CandidatePreparationGrant, RunnerError> {
    let root = tempfile::tempdir().expect("tempdir");
    let (socket, listener, expected_server) = bind(root.path());
    let attempt_id = AttemptId::from_seed("candidate-rpc-attempt");
    let request_digest = "a".repeat(64);
    let server = serve(
        &socket,
        listener,
        vec![Exchange {
            method: "candidate_prepare",
            attempt_id: attempt_id.to_string(),
            request_digest: request_digest.clone(),
            result,
        }],
    );
    let client = SignedLeaseRpcClient::new_admitted(
        &socket,
        RunnerId::from_seed("candidate-rpc-runner"),
        7,
        expected_server,
    );
    let outcome = client.candidate_prepare(&attempt_id, &request_digest).await;
    server.await.expect("fake Kernel");
    outcome
}

#[tokio::test]
async fn prepare_and_exact_readback_use_the_admitted_transport() {
    let root = tempfile::tempdir().expect("tempdir");
    let (socket, listener, expected_server) = bind(root.path());
    let attempt_id = AttemptId::from_seed("candidate-rpc-success");
    let request_digest = "a".repeat(64);
    let result = response(&attempt_id, &request_digest, '1');
    let server = serve(
        &socket,
        listener,
        vec![
            Exchange {
                method: "candidate_prepare",
                attempt_id: attempt_id.to_string(),
                request_digest: request_digest.clone(),
                result: result.clone(),
            },
            Exchange {
                method: "candidate_readback",
                attempt_id: attempt_id.to_string(),
                request_digest: request_digest.clone(),
                result,
            },
        ],
    );
    let client = SignedLeaseRpcClient::new_admitted(
        &socket,
        RunnerId::from_seed("candidate-rpc-runner"),
        7,
        expected_server,
    );
    let prepared = client
        .candidate_prepare(&attempt_id, &request_digest)
        .await
        .expect("prepare");
    assert_eq!(prepared.attempt_id(), &attempt_id);
    assert_eq!(prepared.request_digest(), request_digest);
    assert_eq!(prepared.candidate_preparation_grant_id().len(), 68);
    assert_eq!(prepared.envelope_digest().len(), 64);
    assert_eq!(prepared.signed_grant().schema_version, "v1alpha1");
    assert!(prepared.signed_grant_canonical_json().starts_with('{'));
    assert_eq!(
        client
            .candidate_readback(&prepared)
            .await
            .expect("readback"),
        prepared
    );
    server.await.expect("fake Kernel");
}

#[tokio::test]
async fn recursively_malformed_responses_refuse() {
    let attempt_id = AttemptId::from_seed("candidate-rpc-attempt");
    let request_digest = "a".repeat(64);

    let mut unknown_outer = response(&attempt_id, &request_digest, '1');
    unknown_outer["unknown"] = json!(true);
    assert_eq!(
        prepare_once(unknown_outer)
            .await
            .expect_err("unknown outer field")
            .reason_code(),
        "PROTOCOL_ERROR"
    );

    let mut unknown_signed = response(&attempt_id, &request_digest, '1');
    unknown_signed["signed_grant_canonical_json"] = json!(concat!(
        "{\"issuer\":\"bullet-kernel-local\",",
        "\"key_id\":\"candidate-key-1\",",
        "\"paseto\":\"v4.public.1\",",
        "\"schema_version\":\"v1alpha1\",\"unknown\":true}"
    ));
    assert_eq!(
        prepare_once(unknown_signed)
            .await
            .expect_err("unknown signed field")
            .reason_code(),
        "PROTOCOL_ERROR"
    );

    let mut noncanonical_signed = response(&attempt_id, &request_digest, '1');
    noncanonical_signed["signed_grant_canonical_json"] = json!(concat!(
        "{\"schema_version\":\"v1alpha1\",",
        "\"issuer\":\"bullet-kernel-local\",",
        "\"key_id\":\"candidate-key-1\",",
        "\"paseto\":\"v4.public.1\"}"
    ));
    assert_eq!(
        prepare_once(noncanonical_signed)
            .await
            .expect_err("noncanonical signed grant")
            .reason_code(),
        "PROTOCOL_ERROR"
    );

    let mut wrong_envelope = response(&attempt_id, &request_digest, '1');
    wrong_envelope["envelope_digest"] = json!("f".repeat(64));
    assert_eq!(
        prepare_once(wrong_envelope)
            .await
            .expect_err("unbound envelope digest")
            .reason_code(),
        "PROTOCOL_ERROR"
    );
}

#[tokio::test]
async fn same_attempt_wrong_digest_response_refuses() {
    let attempt_id = AttemptId::from_seed("candidate-rpc-attempt");
    let result = response(&attempt_id, &"b".repeat(64), '1');
    let error = prepare_once(result)
        .await
        .expect_err("wrong response digest");
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert!(error.to_string().contains("Attempt/digest"));
}

#[tokio::test]
async fn readback_rejects_wrong_digest_and_same_subject_grant_drift() {
    for readback in [
        response(
            &AttemptId::from_seed("candidate-rpc-readback"),
            &"b".repeat(64),
            '1',
        ),
        response(
            &AttemptId::from_seed("candidate-rpc-readback"),
            &"a".repeat(64),
            '2',
        ),
    ] {
        let root = tempfile::tempdir().expect("tempdir");
        let (socket, listener, expected_server) = bind(root.path());
        let attempt_id = AttemptId::from_seed("candidate-rpc-readback");
        let request_digest = "a".repeat(64);
        let server = serve(
            &socket,
            listener,
            vec![
                Exchange {
                    method: "candidate_prepare",
                    attempt_id: attempt_id.to_string(),
                    request_digest: request_digest.clone(),
                    result: response(&attempt_id, &request_digest, '1'),
                },
                Exchange {
                    method: "candidate_readback",
                    attempt_id: attempt_id.to_string(),
                    request_digest: request_digest.clone(),
                    result: readback,
                },
            ],
        );
        let client = SignedLeaseRpcClient::new_admitted(
            &socket,
            RunnerId::from_seed("candidate-rpc-runner"),
            7,
            expected_server,
        );
        let prepared = client
            .candidate_prepare(&attempt_id, &request_digest)
            .await
            .expect("prepare");
        assert_eq!(
            client
                .candidate_readback(&prepared)
                .await
                .expect_err("drifted readback")
                .reason_code(),
            "PROTOCOL_ERROR"
        );
        server.await.expect("fake Kernel");
    }
}

#[tokio::test]
async fn malformed_request_digest_refuses_before_socket_access() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing = root.path().join("missing.sock");
    let client = SignedLeaseRpcClient::new_admitted(
        &missing,
        RunnerId::from_seed("candidate-rpc-runner"),
        7,
        ExpectedLeaseServer::new(0, 0),
    );
    let error = client
        .candidate_prepare(
            &AttemptId::from_seed("candidate-rpc-attempt"),
            &"A".repeat(64),
        )
        .await
        .expect_err("uppercase digest");
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
    assert!(!missing.exists());
}
