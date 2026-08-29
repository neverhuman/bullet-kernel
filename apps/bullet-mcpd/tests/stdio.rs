mod support;

use bullet_adapters::SqliteLedger;
use bullet_application::Ledger;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn stdio_lifecycle_reads_real_farmd_and_forbidden_tools_do_not_mutate() {
    let temporary = support::private_tempdir();
    let database = temporary.path().join("ledger.sqlite");
    let app = bullet_farmd::api::router(&database).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let farmd = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut child = spawn(&format!("http://{address}"));
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    initialize(&mut stdin, &mut stdout).await;

    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )
    .await;
    let listed = receive(&mut stdout).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: BTreeSet<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 8);
    assert!(names.contains("bullet_missions"));
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["destructiveHint"], false);
    }

    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bullet_missions","arguments":{}}}),
    )
    .await;
    let projection = receive(&mut stdout).await;
    assert_eq!(projection["id"], 3);
    assert_eq!(
        projection["result"]["structuredContent"]["source"], "bullet-kernel/sqlite-ledger",
        "{projection}"
    );
    assert!(projection["result"]["structuredContent"]["as_of_sequence"].is_u64());
    assert_eq!(projection["result"]["isError"], false);

    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bullet_submit_command","arguments":{"kind":"run_demo"}}}),
    )
    .await;
    let refused = receive(&mut stdout).await;
    assert_eq!(refused["id"], 4);
    assert!(refused.get("error").is_some() || refused["result"]["isError"] == true);

    drop(stdin);
    wait(&mut child).await;
    let mut trailing_stdout = String::new();
    tokio::time::timeout(IO_TIMEOUT, stdout.read_to_string(&mut trailing_stdout))
        .await
        .expect("bounded stdout drain")
        .unwrap();
    assert!(
        trailing_stdout.is_empty(),
        "stdout contained a non-request protocol fragment or diagnostic: {trailing_stdout:?}"
    );
    farmd.abort();

    let ledger = SqliteLedger::open(&database).unwrap();
    assert!(ledger.list_events().unwrap().is_empty());
    assert!(ledger.outbox_all().unwrap().is_empty());
}

#[tokio::test]
async fn oversized_stdio_frame_closes_the_server() {
    let mut child = spawn("http://127.0.0.1:9");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&vec![b'x'; 1024 * 1024 + 1]).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    drop(stdin);
    let status = tokio::time::timeout(IO_TIMEOUT, child.wait())
        .await
        .expect("bounded shutdown")
        .unwrap();
    assert!(!status.success());
}

fn spawn(farmd_url: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_bullet-mcpd"))
        .arg("--farmd-url")
        .arg(farmd_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn initialize(stdin: &mut ChildStdin, stdout: &mut BufReader<ChildStdout>) {
    send(
        stdin,
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":"2025-11-25",
                "capabilities":{},
                "clientInfo":{"name":"bullet-mcp-test","version":"1"}
            }
        }),
    )
    .await;
    let initialized = receive(stdout).await;
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["serverInfo"]["name"], "bullet-mcpd");
    send(
        stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
}

async fn send(stdin: &mut ChildStdin, value: Value) {
    let line = serde_json::to_string(&value).unwrap();
    tokio::time::timeout(IO_TIMEOUT, async {
        stdin.write_all(line.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        stdin.flush().await.unwrap();
    })
    .await
    .expect("bounded write");
}

async fn receive(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    tokio::time::timeout(IO_TIMEOUT, stdout.read_line(&mut line))
        .await
        .expect("bounded read")
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

async fn wait(child: &mut Child) {
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("server did not stop after stdin EOF")
        .unwrap();
    assert!(status.success(), "server exit: {status}");
}
