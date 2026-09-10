#[tokio::test]
async fn missing_command_reconciliation_is_typed_not_found_without_mutation() {
    let directory = support::private_tempdir();
    let server = start(&directory.path().join("worker.sqlite")).await;
    let bearer = format!("Bearer {WORKER}");
    let missing_id = format!("cmd_{}", "f".repeat(64));
    let missing_path = format!("/internal/v1/commands/{missing_id}/reconcile");
    let hidden = request(&server, "POST", &missing_path, &[], None).await;
    assert_eq!(hidden.status, 401, "{}", hidden.text);
    assert_eq!(hidden.body["code"], "WORKER_AUTHORITY_REQUIRED");
    let missing = request(
        &server,
        "POST",
        &missing_path,
        &[("Authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(missing.status, 410, "{}", missing.text);
    assert_eq!(
        header(&missing, "content-type").as_deref(),
        Some("application/problem+json")
    );
    assert_eq!(missing.body["status"], 410);
    assert_eq!(missing.body["code"], "WORKLOAD_API_UDS_REQUIRED");
    assert_eq!(missing.body["retryable"], false);
    assert_eq!(
        missing.body["type"],
        "https://bullet.farm/problems/workload-api-uds-required"
    );
    assert!(missing.body["repair"]
        .as_str()
        .is_some_and(|repair| repair.contains("Unix")));
    let connection = Connection::open(&server.db).expect("open missing ledger");
    for table in ["commands", "outbox", "events"] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count missing-command truth");
        assert_eq!(count, 0, "missing reconciliation mutated {table}");
    }
}

#[tokio::test]
async fn only_independent_worker_authority_can_reconcile_and_replay() {
    let directory = support::private_tempdir();
    let server = start(&directory.path().join("worker.sqlite")).await;
    let (cookie, csrf) = bootstrap(&server).await;
    let admitted = request(
        &server,
        "POST",
        "/api/v1/commands",
        &command_headers(&cookie, &csrf),
        Some(&json!({"idempotency_key":"worker-http","kind":"run_demo","payload":{}})),
    )
    .await;
    assert_eq!(admitted.status, 202);
    let id = admitted.body["id"].as_str().expect("id");
    let path = format!("/internal/v1/commands/{id}/reconcile");
    let bearer = format!("Bearer {WORKER}");
    for (headers, code) in [
        (vec![], "WORKER_AUTHORITY_REQUIRED"),
        (
            vec![("Authorization", "Bearer wrk_invalid")],
            "WORKER_AUTHORITY_INVALID",
        ),
        (
            vec![("Cookie", cookie.as_str())],
            "WORKER_AUTHORITY_REQUIRED",
        ),
        (
            vec![
                ("Authorization", bearer.as_str()),
                ("Authorization", bearer.as_str()),
            ],
            "WORKER_AUTHORITY_INVALID",
        ),
    ] {
        let denied = request(&server, "POST", &path, &headers, None).await;
        assert_eq!(denied.status, 401, "{}", denied.text);
        assert_eq!(denied.body["code"], code);
    }
    let pending = request(
        &server,
        "GET",
        &format!("/api/v1/commands/{id}"),
        &[("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(pending.body["status"], "PENDING");

    let settled = request(&server, "POST", &path, &[("Authorization", &bearer)], None).await;
    assert_eq!(settled.status, 410, "{}", settled.text);
    assert_eq!(settled.body["code"], "WORKLOAD_API_UDS_REQUIRED");
    let replay = request(&server, "POST", &path, &[("Authorization", &bearer)], None).await;
    assert_eq!(replay.status, 410);
    for field in ["code", "status", "detail", "repair", "retryable", "type"] {
        assert_eq!(replay.body[field], settled.body[field]);
    }
    let projected = request(
        &server,
        "GET",
        &format!("/api/v1/commands/{id}"),
        &[("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(projected.body["status"], "PENDING");
    assert_eq!(projected.body["result"], Value::Null);
    let connection = Connection::open(&server.db).expect("open");
    let reconciled: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind = 'command_reconciled' AND correlation_id = ?1",
            params![id],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(reconciled, 0);
}
