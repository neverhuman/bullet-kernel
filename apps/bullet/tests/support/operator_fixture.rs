//! Synthetic HTTP/credential fixture for component tests only.
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub malformed: Arc<AtomicBool>,
    pub reads: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

pub fn subject() -> String {
    format!("mis_{}", "1".repeat(64))
}

impl Fixture {
    pub fn start() -> Self {
        Self::start_with_gate(Arc::new(AtomicBool::new(false)))
    }
    pub fn start_with_gate(gate: Arc<AtomicBool>) -> Self {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let cookie = format!("bullet_session=ses_{}", "a".repeat(64));
        let creds = json!({"schema_version":1,"farmd":origin,"origin":origin,
            "cookie":cookie,"csrf":format!("csrf_{}", "b".repeat(64))});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("session.json"))
            .unwrap();
        file.write_all(creds.to_string().as_bytes()).unwrap();
        file.sync_all().unwrap();
        let malformed = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (bad, count, end) = (malformed.clone(), reads.clone(), stop.clone());
        let worker = std::thread::spawn(move || {
            while !end.load(Ordering::SeqCst) {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept failed: {e}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                    assert!(bytes.len() < 16_384);
                }
                let request = String::from_utf8(bytes).unwrap();
                let snapshot_get =
                    request.starts_with("GET /api/v1/operator-snapshot HTTP/1.1\r\n");
                let commands_get = request.starts_with("GET /api/v1/commands HTTP/1.1\r\n");
                assert!(
                    snapshot_get || commands_get,
                    "TUI must only read the snapshot or command list, including detach"
                );
                let headers = request.to_ascii_lowercase();
                assert!(headers.contains(&format!("\r\ncookie: {cookie}\r\n")));
                assert!(headers.contains(&format!("\r\norigin: {origin}\r\n")));
                count.fetch_add(1, Ordering::SeqCst);
                while gate.load(Ordering::SeqCst) && !end.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if end.load(Ordering::SeqCst) {
                    break;
                }
                let body = if commands_get {
                    r#"{"data":{"commands":[]}}"#.into()
                } else if bad.load(Ordering::SeqCst) {
                    "{}".into()
                } else {
                    snapshot()
                };
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Bullet-As-Of-Sequence: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            directory,
            malformed,
            reads,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn snapshot() -> String {
    let id = |prefix| format!("{prefix}_{}", "1".repeat(64));
    let mission = json!({"id":subject(),"organization_id":id("org"),"repository_id":id("rep"),
        "acceptance_contract_id":id("acc"),"title":"Synthetic PTY mission","objective":"component regression","state":"draft"});
    json!({"as_of_sequence":0,"observed_at":"2026-09-10T00:00:00Z","source":"bullet-kernel/sqlite-ledger",
        "data":{"missions":[mission],"graphs":[{"mission":mission,"packages":[],"fence":null}],
        "outbox":{"items":[]},"ready":null,"fleet":{"authority_time":"2026-09-10T00:00:00Z","leases":[],"ready_queue":[]},
        "sessions":{"attempts":[],"state_counts":[]},"context_lineage":{"capsules":[]},
        "merge_rail":{"candidates":[],"effects":[],"intents":[],"receipts":[],"intent_state_counts":[]},
        "quality_lab":{"evidence":[],"outcome_counts":[]},"audit":{"latest_sequence":0,"tail_window":64,"events":[]}}}).to_string()
}
