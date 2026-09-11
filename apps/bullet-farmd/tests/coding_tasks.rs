//! Authenticated task intent over real local HTTP; component fixtures, no providers.
#[path = "support/command_http.rs"]
mod http;
mod support;
use bullet_adapters::SqliteLedger;
use bullet_application::coding_tasks::{coding_run_id, RunCodingTaskPayload};
use bullet_application::{
    CommandDispatchStore, CommandRequest, ComponentCommandCompletionV1, Ledger,
};
use bullet_domain::{Digest, RunnerId};
use http::*;
use serde_json::{json, Value};
use tokio::time::{timeout, Duration};

fn coding(key: &str) -> String {
    json!({"idempotency_key":key,"kind":"run_coding","payload":{
        "schema_version":"bullet.run-coding.v2",
        "task":{"title":"Preserve task intent","objective":"Survive response loss",
            "repository_id":format!("rep_{}","ab".repeat(32)),"base_commit":"ab".repeat(20),
            "scope_paths":["src/lib.rs"],"acceptance_criteria":["Retry returns original task"],
            "gate_ids":[format!("gat_{}","cd".repeat(32))],"dependencies":[],
            "budget":{"max_invocations":1,"max_cost_microusd":1000},"deadline_unix_ms":4_102_444_800_000u64},
        "selection":{"account_id":"fixture-account","provider":"claude","model":"fixture-model","effort":null}
    }}).to_string()
}
fn effects(ledger: &SqliteLedger) -> (usize, usize) {
    (
        ledger.list_events().unwrap().len(),
        ledger.outbox_all().unwrap().len(),
    )
}

#[tokio::test]
async fn coding_reads_and_submission_enforce_session_origin_csrf_and_closed_intent() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let ledger = SqliteLedger::open(&path).unwrap();
    let before = effects(&ledger);
    let body = coding("auth");
    for (headers, expected) in [
        (vec![], "ORIGIN_REQUIRED"),
        (vec![("Origin", ORIGIN)], "SESSION_REQUIRED"),
        (
            vec![("Cookie", cookie.as_str()), ("Origin", ORIGIN)],
            "CSRF_REQUIRED",
        ),
        (
            vec![
                ("Cookie", cookie.as_str()),
                ("Origin", "http://example.invalid"),
                ("X-Bullet-CSRF", csrf.as_str()),
            ],
            "ORIGIN_DENIED",
        ),
    ] {
        let response = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
        assert_eq!(http::body(&response)["code"], expected);
        assert_eq!(effects(&ledger), before);
    }
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let mut invalid: Value = serde_json::from_str(&body).unwrap();
    invalid["payload"]["allocated_run"] = json!(RunnerId::from_seed("caller-authority").as_str());
    let refused = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &invalid.to_string(),
    )
    .await;
    assert_eq!(status(&refused), 400);
    assert_eq!(effects(&ledger), before);
    let accepted = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&accepted), 202);
    let id = http::body(&accepted)["id"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/commands/{id}/coding");
    let anonymous = request(server.addr, "GET", &url, &[], "").await;
    assert_eq!(status(&anonymous), 401);
    assert_eq!(http::body(&anonymous)["code"], "SESSION_REQUIRED");
    let snapshot = check_snapshot(&request(server.addr, "GET", &url, &headers, "").await);
    assert_eq!(snapshot["data"]["command"], http::body(&accepted));
    assert_eq!(
        snapshot["data"]["task"],
        serde_json::from_str::<Value>(&body).unwrap()["payload"]["task"]
    );
    assert!(
        snapshot["data"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|blocker| blocker["code"] != "CODING_BINDING_ADMISSION_UNAVAILABLE"),
        "admitted v2 tasks bind nonce and quota: {}",
        snapshot["data"]["blockers"]
    );
    let demo = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &envelope("demo"),
    )
    .await;
    let url = format!(
        "/api/v1/commands/{}/coding",
        http::body(&demo)["id"].as_str().unwrap()
    );
    assert_eq!(
        status(&request(server.addr, "GET", &url, &headers, "").await),
        404
    );
    server.stop().await;
}

#[tokio::test]
async fn new_legacy_authority_shape_is_explicitly_retired_without_any_effect() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let ledger = SqliteLedger::open(&path).unwrap();
    let before = effects(&ledger);
    let legacy=json!({"idempotency_key":"retired","kind":"run_coding","payload":{
        "account_id":"fixture-account","provider":"claude","model":"fixture-model",
        "expected_revision":1,"launch_nonce":"ab".repeat(32),"quota_reservation":format!("rsv_{}","cd".repeat(32)),
        "quota_units":3,"allocated_run":RunnerId::from_seed("fixture-run").as_str()}}).to_string();
    let response = request(
        server.addr,
        "POST",
        "/api/v1/commands",
        &[
            ("Cookie", &cookie),
            ("Origin", ORIGIN),
            ("X-Bullet-CSRF", &csrf),
        ],
        &legacy,
    )
    .await;
    assert_eq!(status(&response), 409);
    assert_eq!(
        body(&response)["code"],
        "RUN_CODING_LEGACY_AUTHORITY_SHAPE_RETIRED"
    );
    assert_eq!(effects(&ledger), before);
    assert!(ledger.get_command("retired").unwrap().is_none());
    server.stop().await;
}

#[tokio::test]
async fn task_response_loss_restart_discovery_and_exact_retry_keep_server_subjects() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let ledger = SqliteLedger::open(&path).unwrap();
    let body = coding("lost");
    drop(
        open(
            server.addr,
            "POST",
            "/api/v1/commands",
            &headers,
            "{",
            body.len(),
        )
        .await,
    );
    tokio::task::yield_now().await;
    assert!(ledger.get_command("lost").unwrap().is_none());
    let unread = open(
        server.addr,
        "POST",
        "/api/v1/commands",
        &headers,
        &body,
        body.len(),
    )
    .await;
    timeout(Duration::from_secs(5), async {
        while ledger.get_command("lost").unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(unread);
    let original = ledger.get_command("lost").unwrap().unwrap();
    let before = effects(&ledger);
    let decoded: Value = serde_json::from_str(&body).unwrap();
    let payload = RunCodingTaskPayload::parse(&decoded["payload"].to_string()).unwrap();
    let expected = CommandRequest::new("lost", "run_coding", &payload).unwrap();
    assert_eq!(original.id, expected.id());
    server.stop().await;
    drop(ledger);
    let server = Server::start(&path, None).await;
    let discovery =
        check_snapshot(&request(server.addr, "GET", "/api/v1/commands", &headers, "").await);
    assert_eq!(discovery["data"]["commands"].as_array().unwrap().len(), 1);
    let retry = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&retry), 202);
    assert_eq!(http::body(&retry)["status"], "PENDING");
    let url = format!("/api/v1/commands/{}/coding", original.id);
    let snapshot = check_snapshot(&request(server.addr, "GET", &url, &headers, "").await);
    assert_eq!(snapshot["data"]["run_id"], coding_run_id(&expected.id()));
    assert_eq!(snapshot["data"]["command"], http::body(&retry));
    assert_eq!(snapshot["as_of_sequence"], discovery["as_of_sequence"]);
    assert_eq!(snapshot["data"]["task"], decoded["payload"]["task"]);
    assert_eq!(effects(&SqliteLedger::open(&path).unwrap()), before);
    server.stop().await;
}

#[tokio::test]
async fn v2_http_dispatch_settles_one_failure_and_refuses_a_second_spawn() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let body = coding("stack-d1");
    let accepted = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&accepted), 202);
    let id = http::body(&accepted)["id"].as_str().unwrap().to_owned();
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let runner = RunnerId::from_seed("d1-fake-worker");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-11T00:00:00.000Z")
        .unwrap()
        .unwrap();
    assert_eq!(claim.command_id.as_str(), id);
    assert!(
        bullet_application::coding_tasks::task_payload(&claim.request)
            .unwrap()
            .is_some()
    );
    let receipt =
        ComponentCommandCompletionV1::new(&claim, Digest::of(b"d1-fake-failure")).unwrap();
    ledger
        .settle_component_command_dispatch(
            &claim.claim_id,
            &runner,
            1,
            &receipt,
            "2026-09-11T00:00:01.000Z",
        )
        .unwrap();
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-11T00:00:02.000Z")
        .unwrap()
        .is_none());
    let retry = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&retry), 202);
    assert_eq!(http::body(&retry)["id"], id);
    assert_eq!(http::body(&retry)["status"], "UNKNOWN");
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-11T00:00:03.000Z")
        .unwrap()
        .is_none());
    let snapshot = check_snapshot(
        &request(
            server.addr,
            "GET",
            &format!("/api/v1/commands/{id}/coding"),
            &headers,
            "",
        )
        .await,
    );
    assert_ne!(snapshot["data"]["command"]["status"], "VERIFIED");
    assert_eq!(snapshot["data"]["command"]["id"], id);
    server.stop().await;
}

fn sibling_bin(name: &str) -> Option<std::path::PathBuf> {
    let farmd = std::path::PathBuf::from(env!("CARGO_BIN_EXE_bullet-farmd"));
    let candidate = farmd.with_file_name(name);
    candidate.is_file().then_some(candidate)
}

fn write_stub(dir: &std::path::Path) -> std::path::PathBuf {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let stub = dir.join("signed-in-stub");
    let proposal = format!(
        r#"{{"schema_version":1,"proposal_id":"cnt_{a}","producing_attempt_id":"atm_{b}","base_checkpoint_id":"ckp_{c}","base_checkpoint_digest":"{d}","operations":[{{"path":"PONG.txt","preimage":{{"kind":"absent"}},"mutation":{{"kind":"write","content_utf8":"PONG\n"}}}}],"gate_ids":["gat_{g}"]}}"#,
        a = "1".repeat(64),
        b = "2".repeat(64),
        c = "3".repeat(64),
        d = "4".repeat(64),
        g = "8".repeat(64),
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o700)
        .open(&stub)
        .unwrap();
    write!(file, "#!/bin/sh\nprintf '%s\\n' '{proposal}'\nexit 1\n").unwrap();
    stub
}

#[tokio::test]
async fn v2_http_then_real_runner_stub_retains_failure_and_refuses_a_second_spawn() {
    let dir = support::private_tempdir();
    let path = dir.path().join("coding.sqlite");
    let server = Server::start(&path, Some(BOOT)).await;
    let (cookie, csrf) = bootstrap(server.addr).await;
    let headers = [
        ("Cookie", cookie.as_str()),
        ("Origin", ORIGIN),
        ("X-Bullet-CSRF", csrf.as_str()),
    ];
    let body = coding("stack-d1-runner");
    let accepted = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&accepted), 202);
    let id = http::body(&accepted)["id"].as_str().unwrap().to_owned();
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let runner = RunnerId::from_seed("d1-real-runner");
    let claim = ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-11T00:00:00.000Z")
        .unwrap()
        .unwrap();
    assert_eq!(claim.command_id.as_str(), id);
    let runner_bin = sibling_bin("bullet-runner").expect(
        "COMMAND_RUNNER_BIN_ABSENT: build bullet-runner in the same target as bullet-farmd",
    );
    let stub = write_stub(dir.path());
    let workspace = dir.path().join("workspace");
    let source = dir.path().join("source.git");
    let preserve = dir.path().join("preserve");
    let key = dir.path().join("candidate.key");
    let recovery = dir.path().join("lease.recovery");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&preserve).unwrap();
    std::fs::write(&key, []).unwrap();
    std::fs::write(&recovery, []).unwrap();
    let output = std::process::Command::new(&runner_bin)
        .args([
            "--provider",
            "codex",
            "--model",
            "fixture-model",
            "--signed-in-executable",
        ])
        .arg(&stub)
        .args([
            "--runner-id",
            claim.runner_id.as_str(),
            "--work-package-id",
            &bullet_domain::WorkPackageId::from_seed("d1-real-runner").to_string(),
            "--candidate-request-digest",
            &claim.request.digest().to_hex(),
            "--candidate-verification-key",
        ])
        .arg(&key)
        .arg("--workspace-root")
        .arg(&workspace)
        .arg("--source-repo")
        .arg(&source)
        .args(["--base-sha", &"ab".repeat(20)])
        .arg("--preservation-destination")
        .arg(&preserve)
        .args([
            "--objective",
            "Survive response loss",
            "--gate-id",
            &format!("gat_{}", "cd".repeat(32)),
            "--scope",
            "src/lib.rs",
            "--idempotency-key",
            "stack-d1-runner",
            "--lease-recovery",
        ])
        .arg(&recovery)
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("sim"),
        "real runner stub path must not name the simulator: {combined}"
    );
    assert_ne!(output.status.code(), Some(0));
    let receipt =
        ComponentCommandCompletionV1::new(&claim, Digest::of(&output.stderr)).unwrap();
    ledger
        .settle_component_command_dispatch(
            &claim.claim_id,
            &runner,
            1,
            &receipt,
            "2026-09-11T00:00:01.000Z",
        )
        .unwrap();
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-11T00:00:02.000Z")
        .unwrap()
        .is_none());
    let retry = request(server.addr, "POST", "/api/v1/commands", &headers, &body).await;
    assert_eq!(status(&retry), 202);
    assert_eq!(http::body(&retry)["id"], id);
    assert_eq!(http::body(&retry)["status"], "UNKNOWN");
    assert!(ledger
        .claim_next_command_dispatch(&runner, 1, "2026-09-11T00:00:03.000Z")
        .unwrap()
        .is_none());
    server.stop().await;
}
