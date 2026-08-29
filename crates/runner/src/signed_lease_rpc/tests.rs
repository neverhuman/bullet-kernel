use super::*;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use tokio::time::{timeout, Duration};

#[path = "tests/reconciliation.rs"]
mod reconciliation;
#[path = "tests/recovery.rs"]
mod recovery;
#[path = "tests/settlement.rs"]
mod settlement;
#[path = "tests/settlement_completion.rs"]
mod settlement_completion;
#[cfg(all(feature = "test-seams", debug_assertions))]
#[path = "tests/synthetic_selection.rs"]
mod synthetic_selection;

fn ids(path: &Path) -> ExpectedLeaseServer {
    let meta = std::fs::metadata(path).expect("metadata");
    ExpectedLeaseServer::new(meta.uid(), meta.gid())
}

fn client(path: &Path, expected: ExpectedLeaseServer) -> SignedLeaseRpcClient {
    SignedLeaseRpcClient::new_admitted(path, RunnerId::from_seed("peer-test"), 1, expected)
}

#[tokio::test]
async fn fake_server_cannot_receive_a_command_without_exact_hello_binding() {
    let root = tempfile::tempdir().expect("tempdir");
    let socket = root.path().join("fake.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind fake");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    let expected = ids(&socket);
    let meta = std::fs::metadata(&socket).expect("socket metadata");
    let fake = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _: serde_json::Value = read_json(&mut stream).await.expect("hello");
        write_line(
            &mut stream,
            &serde_json::json!({
                "ok": true,
                "proto": PROTO,
                "peer_uid": meta.uid(),
                "peer_gid": meta.gid(),
                "peer_pid": 1,
                "socket_dev": meta.dev(),
                "socket_ino": meta.ino().wrapping_add(1),
                "listener_dev": 1,
                "listener_ino": 1,
            }),
        )
        .await
        .expect("fake ack");
        let read = timeout(
            Duration::from_secs(1),
            read_json::<serde_json::Value>(&mut stream),
        )
        .await;
        assert!(
            !matches!(read, Ok(Ok(_))),
            "no command may follow an unbound hello"
        );
    });
    let error = client(&socket, expected)
        .next_ready()
        .await
        .expect_err("fake hello must refuse");
    assert!(error.to_string().contains("hello"));
    fake.await.expect("fake task");
}

#[tokio::test]
async fn path_replacement_between_admission_and_connect_is_detected() {
    let root = tempfile::tempdir().expect("tempdir");
    let socket = root.path().join("lease.sock");
    let original = tokio::net::UnixListener::bind(&socket).expect("original");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    let expected = ids(&socket);
    let client = client(&socket, expected);
    let admitted = client.admit_socket().expect("admit original");
    std::fs::remove_file(&socket).expect("unlink isolated socket");
    let replacement = tokio::net::UnixListener::bind(&socket).expect("replacement");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    let stream = UnixStream::connect(&socket)
        .await
        .expect("connect replacement");
    let error = client
        .authenticate_connected_server(&stream, admitted)
        .expect_err("replacement must refuse");
    assert!(error.to_string().contains("identity changed"));
    drop(original);
    drop(replacement);
}

#[test]
fn socket_path_mode_owner_group_and_symlink_are_exact() {
    let root = tempfile::tempdir().expect("tempdir");
    let actual = ids(root.path());
    let relative = Path::new("relative-peercred-test.sock");
    assert!(client(relative, actual).admit_socket().is_err());
    assert!(
        !relative.exists(),
        "client refusal must not create a socket"
    );
    let missing = root.path().join("missing.sock");
    assert!(client(&missing, actual).admit_socket().is_err());
    assert!(!missing.exists(), "client refusal must not create a socket");
    let socket = root.path().join("lease.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    let actual = ids(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).expect("0600");
    assert!(client(&socket, actual).admit_socket().is_err());
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    assert!(client(
        &socket,
        ExpectedLeaseServer::new(actual.uid.wrapping_add(1), actual.socket_gid)
    )
    .admit_socket()
    .is_err());
    assert!(client(
        &socket,
        ExpectedLeaseServer::new(actual.uid, actual.socket_gid.wrapping_add(1))
    )
    .admit_socket()
    .is_err());
    drop(listener);
    std::fs::remove_file(&socket).expect("remove isolated socket");
    symlink(root.path().join("missing"), &socket).expect("symlink");
    assert!(client(&socket, actual).admit_socket().is_err());
}

#[test]
fn unconfigured_and_wrong_expected_server_identity_refuse() {
    let root = tempfile::tempdir().expect("tempdir");
    let socket = root.path().join("lease.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(SOCKET_MODE)).expect("0660");
    let actual = ids(&socket);
    let unconfigured = SignedLeaseRpcClient::new(&socket, RunnerId::from_seed("unconfigured"), 1);
    assert!(unconfigured.admit_socket().is_err());
    let expected = ExpectedLeaseServer::new(actual.uid.wrapping_add(1), actual.socket_gid);
    assert!(client(&socket, expected).admit_socket().is_err());
    assert!(validate_server_uid(actual.uid, actual.uid.wrapping_add(1)).is_err());
    drop(listener);
}
