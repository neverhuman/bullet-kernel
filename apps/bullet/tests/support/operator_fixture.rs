//! Synthetic HTTP/credential fixture for component tests only.
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub path: String,
    pub expected_session: Option<String>,
}

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub malformed: Arc<AtomicBool>,
    pub reads: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<ReadRequest>>>,
    // Only operator_tui exercises this switch; other integration binaries share the fixture.
    #[allow(dead_code)]
    pub command_refusal: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

pub fn subject() -> String {
    format!("mis_{}", "1".repeat(64))
}

impl Fixture {
    // Mission tests verify each discovery/projection pair; UI suites keep their gates.
    #[allow(dead_code)]
    pub fn requests(&self) -> Vec<ReadRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn start() -> Self {
        Self::start_with_gate(Arc::new(AtomicBool::new(false)))
    }
    pub fn start_with_gate(gate: Arc<AtomicBool>) -> Self {
        Self::start_with_gate_and_refusal(gate, Arc::new(AtomicU16::new(0)))
    }
    pub fn start_with_gate_and_refusal(gate: Arc<AtomicBool>, refusal: Arc<AtomicU16>) -> Self {
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
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed_requests = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let command_refusal = Arc::new(AtomicU16::new(0));
        let command_failure = command_refusal.clone();
        let (bad, count, end) = (malformed.clone(), reads.clone(), stop.clone());
        let worker = std::thread::spawn(move || {
            'accept: while !end.load(Ordering::SeqCst) {
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
                    if let Err(error) = socket.read_exact(&mut byte) {
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                        ) {
                            continue 'accept;
                        }
                        panic!("fixture request read failed: {error}");
                    }
                    bytes.push(byte[0]);
                    assert!(bytes.len() < 16_384);
                }
                let request = String::from_utf8(bytes).unwrap();
                let commands = request.starts_with("GET /api/v1/commands HTTP/1.1\r\n");
                let discovery = request.starts_with("GET /api/v1/auth/session HTTP/1.1\r\n");
                assert!(
                    discovery || commands || request.starts_with("GET /api/v1/operator-snapshot HTTP/1.1\r\n"),
                    "TUI must only observe its authenticated session and read snapshots, including detach"
                );
                let values = |name: &str| {
                    request
                        .split("\r\n")
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .filter_map(|(key, value)| {
                            key.eq_ignore_ascii_case(name).then_some(value.trim())
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(values("cookie"), vec![cookie.as_str()]);
                assert_eq!(values("origin"), vec![origin.as_str()]);
                let session_id = format!("sid_{}", "c".repeat(64));
                assert_eq!(
                    values("x-bullet-expected-session"),
                    if discovery {
                        vec![]
                    } else {
                        vec![session_id.as_str()]
                    }
                );
                // Record actual validated request subjects before any response gate.
                // Client success separately requires the matching response acknowledgement.
                let mut observations = observed_requests.lock().unwrap();
                assert!(observations.len() < 1024, "fixture request bound exceeded");
                observations.push(ReadRequest {
                    path: request.split_whitespace().nth(1).unwrap().into(),
                    expected_session: values("x-bullet-expected-session")
                        .first()
                        .map(|value| (*value).into()),
                });
                drop(observations);
                count.fetch_add(1, Ordering::SeqCst);
                while gate.load(Ordering::SeqCst) && !end.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if end.load(Ordering::SeqCst) {
                    break;
                }
                // Inject projection refusal after a valid session observation.
                // This is synthetic UI error recovery, not live session revocation.
                let requested_status = if discovery {
                    0
                } else if commands && command_failure.load(Ordering::SeqCst) != 0 {
                    command_failure.load(Ordering::SeqCst)
                } else {
                    refusal.load(Ordering::SeqCst)
                };
                let status = match requested_status {
                    0 => "200 OK",
                    401 => "401 Unauthorized",
                    403 => "403 Forbidden",
                    500 => "500 Internal Server Error",
                    other => panic!("unsupported fixture refusal: {other}"),
                };
                let body = if discovery {
                    json!({"status":"AUTHENTICATED","operator_id":format!("opr_{}", "1".repeat(64)),
                        "session_id":session_id,"issued_at":"2026-09-10T00:00:00Z",
                        "expires_at":"2026-09-10T08:00:00Z"})
                    .to_string()
                } else if bad.load(Ordering::SeqCst) || status != "200 OK" {
                    "{}".into()
                } else if commands {
                    json!({"data":{"commands":[{"id":format!("cmd_{}", "2".repeat(64)),
                        "status":"PENDING","kind":"run_coding","payload_digest":"3".repeat(64),"result":null}],
                        "next_after":null},"as_of_sequence":9,"observed_at":"2026-09-11T00:00:00Z",
                        "source":"bullet-kernel/sqlite-ledger"}).to_string()
                } else {
                    snapshot()
                };
                let sequence = if commands { 9 } else { 0 };
                let response = format!("HTTP/1.1 {status}\r\nX-Bullet-Session-Id: {session_id}\r\nContent-Type: application/json\r\nX-Bullet-As-Of-Sequence: {sequence}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                // Detaching a console may close its socket during this write.
                // Keep serving the remaining clients; protocol checks above
                // still fail loudly for invalid or unauthorized requests.
                if let Err(error) = socket.write_all(response.as_bytes()) {
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) {
                        panic!("fixture response write failed: {error}");
                    }
                }
            }
        });
        Self {
            directory,
            malformed,
            reads,
            requests,
            command_refusal,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            match self.requests.try_lock() {
                Ok(requests) => eprintln!("validated synthetic fixture requests: {requests:?}"),
                Err(_) => {
                    eprintln!("synthetic fixture request diagnostics unavailable during unwind")
                }
            }
        }
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
