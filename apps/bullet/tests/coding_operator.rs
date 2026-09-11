//! Actual CLI and actual daemon, with isolated task intent and no provider execution.
#![cfg(target_os = "linux")]
use bullet_adapters::SqliteLedger;
use bullet_application::Ledger;
use serde_json::{json, Value};
use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, process::Stdio};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    time::{timeout, Duration},
};

async fn invoke(state: &Path, args: &[&str], input: Option<&str>) -> std::process::Output {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_bullet"))
        .args(args)
        .arg("--state-dir")
        .arg(state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .await
            .unwrap();
    }
    drop(child.stdin.take());
    let output = timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in ["boot_", "ses_", "csrf_", "bullet_session="] {
            assert!(!text.contains(secret), "CLI disclosed credential material");
        }
    }
    output
}
fn accepted(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
async fn serve(
    path: &Path,
    address: Option<SocketAddr>,
    bootstrap: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(address.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let token = format!("boot_{}", "1".repeat(64));
    let (app, _) = bullet_farmd::api::daemon(
        path,
        bootstrap.then_some(token.as_str()),
        format!("http://{address}"),
        None,
    )
    .unwrap();
    let task = tokio::spawn(async move {
        axum_serve(listener, app).await;
    });
    (address, task)
}
async fn axum_serve(listener: TcpListener, app: axum::Router) {
    axum::serve(listener, app).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_task_submission_retry_and_discovery_share_the_daemons_durable_subjects() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let database = dir.path().join("ledger.sqlite");
    let state = dir.path().join("operator");
    let (address, server) = serve(&database, None, true).await;
    let endpoint = format!("http://{address}");
    let login = invoke(
        &state,
        &[
            "auth", "login", "--stdin", "--farmd", &endpoint, "--origin", &endpoint,
        ],
        Some(&format!("boot_{}\n", "1".repeat(64))),
    )
    .await;
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let task = json!({"title":"Exercise real operator wiring","objective":"Persist exact task intent through daemon restart",
        "repository_id":format!("rep_{}","ab".repeat(32)),"base_commit":"ab".repeat(20),"scope_paths":["src/lib.rs"],
        "acceptance_criteria":["Restart preserves task and run identities"],"gate_ids":[format!("gat_{}","cd".repeat(32))],
        "dependencies":[],"budget":{"max_invocations":1,"max_cost_microusd":1000},"deadline_unix_ms":4_102_444_800_000u64});
    let task_file = dir.path().join("task.json");
    std::fs::write(&task_file, task.to_string()).unwrap();
    let submitted = accepted(
        invoke(
            &state,
            &[
                "coding",
                "submit",
                "--task",
                task_file.to_str().unwrap(),
                "--account",
                "fixture-account",
                "--provider",
                "codex",
                "--model",
                "fixture-model",
                "--effort",
                "high",
                "--idempotency-key",
                "cli-daemon-task",
                "--json",
            ],
            None,
        )
        .await,
    );
    let id = submitted["id"].as_str().unwrap();
    let original = accepted(invoke(&state, &["coding", "task", id, "--json"], None).await);
    assert_eq!(original["data"]["task"], task);
    assert_eq!(original["data"]["command"], submitted);
    assert_eq!(original["data"]["selection"]["effort"], "high");
    assert!(
        original["data"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|blocker| blocker["code"] != "CODING_BINDING_ADMISSION_UNAVAILABLE"),
        "admitted v2 tasks bind nonce and quota: {}",
        original["data"]["blockers"]
    );
    let ledger = SqliteLedger::open(&database).unwrap();
    let counts = (
        ledger.list_events().unwrap().len(),
        ledger.outbox_all().unwrap().len(),
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let (_, server) = serve(&database, Some(address), false).await;
    assert_eq!(
        accepted(invoke(&state, &["coding", "retry", id, "--json"], None).await),
        submitted
    );
    let restarted = accepted(invoke(&state, &["coding", "task", id, "--json"], None).await);
    assert_eq!(restarted["data"], original["data"]);
    assert_eq!(restarted["as_of_sequence"], original["as_of_sequence"]);
    std::fs::remove_file(state.join(format!("{id}.json"))).unwrap();
    let history = accepted(invoke(&state, &["coding", "list", "--json"], None).await);
    assert_eq!(history["data"]["commands"], json!([submitted]));
    assert_eq!(
        accepted(invoke(&state, &["coding", "task", id, "--json"], None).await)["data"],
        original["data"]
    );
    let refused = invoke(&state, &["coding", "retry", id, "--json"], None).await;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("COMMAND_JOURNAL_REQUIRED"));
    assert_eq!(
        (
            ledger.list_events().unwrap().len(),
            ledger.outbox_all().unwrap().len()
        ),
        counts
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
