use super::*;

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
    stream
        .write_all(b"POST /api/v1/leases/acquire HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        .await
        .expect("write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read");
    let response = String::from_utf8_lossy(&bytes);
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}
