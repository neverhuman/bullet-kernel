//! Bounded loopback server and synthetic credentials, never production state.
use anyhow::{bail, ensure, Result};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub gate: Arc<AtomicBool>,
    pub status: Arc<AtomicU16>,
    pub reads: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    errors: Arc<Mutex<Vec<String>>>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn start(blocked: bool) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("btw-state-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let cookie = format!("bullet_session=ses_{}", "a".repeat(64));
        let credentials = json!({"schema_version":1,"farmd":origin,"origin":origin,
            "cookie":cookie,"csrf":format!("csrf_{}","b".repeat(64))});
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(directory.path().join("session.json"))?;
        file.write_all(credentials.to_string().as_bytes())?;
        file.sync_all()?;
        let gate = Arc::new(AtomicBool::new(blocked));
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(AtomicU16::new(200));
        let reads = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let (hold, end, response, count, failures) = (
            gate.clone(),
            stop.clone(),
            status.clone(),
            reads.clone(),
            errors.clone(),
        );
        let worker = std::thread::spawn(move || {
            let mut connections = Vec::new();
            while !end.load(Ordering::SeqCst) {
                let (stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => {
                        failures.lock().unwrap().push(error.to_string());
                        break;
                    }
                };
                if connections.len() >= 64 {
                    failures
                        .lock()
                        .unwrap()
                        .push("FIXTURE_CONNECTION_LIMIT".into());
                    break;
                }
                let (hold, end, response, count, failures, origin, cookie) = (
                    hold.clone(),
                    end.clone(),
                    response.clone(),
                    count.clone(),
                    failures.clone(),
                    origin.clone(),
                    cookie.clone(),
                );
                connections.push(std::thread::spawn(move || {
                    if let Err(error) =
                        serve(stream, &hold, &end, &response, &count, &origin, &cookie)
                    {
                        failures.lock().unwrap().push(format!("{error:#}"));
                    }
                }));
            }
            for thread in connections {
                if thread.join().is_err() {
                    failures
                        .lock()
                        .unwrap()
                        .push("FIXTURE_THREAD_PANICKED".into());
                }
            }
        });
        Ok(Self {
            directory,
            gate,
            status,
            reads,
            stop,
            errors,
            worker: Some(worker),
        })
    }

    pub fn lock_credentials(&self) -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(self.directory.path().join(".auth.lock"))?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(file)
    }

    pub fn credentials(&self, present: bool) -> Result<()> {
        let (old, new) = if present {
            ("retained-session", "session.json")
        } else {
            ("session.json", "retained-session")
        };
        std::fs::rename(
            self.directory.path().join(old),
            self.directory.path().join(new),
        )?;
        Ok(())
    }

    fn settle(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                self.errors
                    .lock()
                    .unwrap()
                    .push("FIXTURE_JOIN_FAILED".into());
            }
        }
        let errors = self.errors.lock().unwrap();
        crate::session::record_cleanup(json!({"kind":"http_fixture_settled",
            "reads":self.reads.load(Ordering::SeqCst),"errors":*errors,"threads_joined":true}));
        ensure!(errors.is_empty(), "FIXTURE_FAILURE: {}", errors.join("; "));
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.settle()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.worker.is_some() {
            if let Err(error) = self.settle() {
                crate::session::record_cleanup(
                    json!({"kind":"http_fixture_failed_during_cleanup","error":format!("{error:#}")}),
                );
            }
        }
    }
}

fn serve(
    mut stream: TcpStream,
    gate: &AtomicBool,
    stop: &AtomicBool,
    status: &AtomicU16,
    reads: &AtomicUsize,
    origin: &str,
    cookie: &str,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        bytes.push(byte[0]);
        ensure!(bytes.len() < 16384, "FIXTURE_HEADER_LIMIT");
    }
    let request = String::from_utf8(bytes)?;
    let commands = request.starts_with("GET /api/v1/commands HTTP/1.1\r\n");
    let discovery = request.starts_with("GET /api/v1/auth/session HTTP/1.1\r\n");
    ensure!(
        discovery || commands || request.starts_with("GET /api/v1/operator-snapshot HTTP/1.1\r\n"),
        "MUTATION_OR_UNEXPECTED_READ"
    );
    let values = |name: &str| {
        request
            .split("\r\n")
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .filter_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.trim()))
            .collect::<Vec<_>>()
    };
    ensure!(values("cookie") == vec![cookie], "FIXTURE_COOKIE_MISMATCH");
    ensure!(values("origin") == vec![origin], "FIXTURE_ORIGIN_MISMATCH");
    let session_id = format!("sid_{}", "c".repeat(64));
    ensure!(
        values("x-bullet-expected-session")
            == if discovery {
                vec![]
            } else {
                vec![session_id.as_str()]
            },
        "FIXTURE_EXPECTED_SESSION_MISMATCH"
    );
    reads.fetch_add(1, Ordering::SeqCst);
    while gate.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(2));
    }
    if stop.load(Ordering::SeqCst) {
        return Ok(());
    }
    let sequence = if commands { 9 } else { 0 };
    // Status injection exercises UI refusal recovery after authenticated discovery;
    // it does not establish actual server-side session revocation.
    let (status, body) = if discovery {
        (
            "200 OK",
            json!({"status":"AUTHENTICATED","operator_id":format!("opr_{}", "1".repeat(64)),
            "session_id":session_id,"issued_at":"2026-09-10T00:00:00Z",
            "expires_at":"2026-09-10T08:00:00Z"})
            .to_string(),
        )
    } else {
        match status.load(Ordering::SeqCst) {
            200 => ("200 OK", if commands { submissions() } else { snapshot() }),
            401 => ("401 Unauthorized", "{}".into()),
            403 => ("403 Forbidden", "{}".into()),
            _ => bail!("FIXTURE_STATUS_INVALID"),
        }
    };
    // A detached client may close its socket while the response is withheld.
    // Delivery loss is expected here; the request above was fully validated.
    let _ = write!(stream, "HTTP/1.1 {status}\r\nX-Bullet-Session-Id: {session_id}\r\nContent-Type: application/json\r\nX-Bullet-As-Of-Sequence: {sequence}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    Ok(())
}

fn snapshot() -> String {
    let id = |prefix| format!("{prefix}_{}", "1".repeat(64));
    let mission = json!({"id":id("mis"),"organization_id":id("org"),"repository_id":id("rep"),
        "acceptance_contract_id":id("acc"),"title":"Synthetic Tuiwright mission","objective":"component regression","state":"draft"});
    json!({"as_of_sequence":0,"observed_at":"2026-09-10T00:00:00Z","source":"bullet-kernel/sqlite-ledger",
        "data":{"missions":[mission],"graphs":[{"mission":mission,"packages":[],"fence":null}],
        "outbox":{"items":[]},"ready":null,"fleet":{"authority_time":"2026-09-10T00:00:00Z","leases":[],"ready_queue":[]},
        "sessions":{"attempts":[],"state_counts":[]},"context_lineage":{"capsules":[]},
        "merge_rail":{"candidates":[],"effects":[],"intents":[],"receipts":[],"intent_state_counts":[]},
        "quality_lab":{"evidence":[],"outcome_counts":[]},"audit":{"latest_sequence":0,"tail_window":64,"events":[]}}}).to_string()
}

// This independently observed submission has no durable execution relationships.
// Its watermark must never be borrowed for the operator snapshot above.
fn submissions() -> String {
    json!({"as_of_sequence":9,"observed_at":"2026-09-11T00:00:00Z",
        "source":"bullet-kernel/sqlite-ledger",
        "data":{"commands":[{"id":format!("cmd_{}","2".repeat(64)),
            "status":"PENDING","kind":"run_coding","payload_digest":"3".repeat(64),
            "result":null}],"next_after":null}})
    .to_string()
}
