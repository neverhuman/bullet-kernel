use super::{flock, verify_filesystem, FlockOperation};
use crate::sqlite::{open, SqliteLedger};
use std::cell::RefCell;
use std::fs::{File, OpenOptions, Permissions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

const TEST: &str = "sqlite::migrations::tests::fresh_creation_records_exact_checksums_and_reopens";
const CHILD_PATH: &str = "BULLET_SQLITE_CUSTODY_CHILD_PATH";
const CHILD_MODE: &str = "BULLET_SQLITE_CUSTODY_CHILD_MODE";
const CHILD_READY: &str = "BULLET_SQLITE_CUSTODY_CHILD_READY";

type BeforeShared = Box<dyn FnOnce(&File)>;
thread_local! {
    static BEFORE_SHARED: RefCell<Option<BeforeShared>> = RefCell::new(None);
}

pub(super) fn before_shared(file: &File) {
    let hook = BEFORE_SHARED.with_borrow_mut(Option::take);
    if let Some(hook) = hook {
        hook(file);
    }
}

pub(in crate::sqlite::open::linux) fn assert_contract(directory: &Path) {
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        child(Path::new(&path));
    }
    let path = directory.join("custody.sqlite3");
    let first = SqliteLedger::open(&path).unwrap();
    let second = SqliteLedger::open(&path).expect("shared serving remains concurrent");
    probe(&path, "busy");
    drop(rusqlite::Connection::open(&path).unwrap());
    probe(&path, "busy");
    drop(first);
    probe(&path, "busy");
    drop(second);
    probe(&path, "free");

    let admitted = open::initialized(&path).unwrap();
    let duplicate = admitted.guard.inner.database.try_clone().unwrap();
    drop(admitted.connection);
    probe(&path, "busy");
    drop(admitted.guard);
    probe(&path, "busy");
    drop(duplicate);
    probe(&path, "free");

    let mut serving = Process::start("serving", &path);
    serving.wait_ready();
    probe(&path, "busy");
    serving.process.kill().unwrap();
    assert!(!serving.wait_done().success());
    probe(&path, "free");

    let mut exclusive = Process::start("exclusive", &path);
    exclusive.wait_ready();
    let before = snapshot(&path);
    for _ in 0..2 {
        let started = Instant::now();
        let error = match SqliteLedger::open(&path) {
            Ok(_) => panic!("serving ignored exclusive custody"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SQLITE_CUSTODY_BUSY"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(snapshot(&path), before, "busy refusal changed source files");
    }
    exclusive.process.stdin.take();
    assert!(exclusive.wait_done().success());
    drop(SqliteLedger::open(&path).expect("serving resumes after custody ends"));

    verify_creation_race(directory);
    verify_unsupported_filesystem();
}

fn verify_creation_race(directory: &Path) {
    let path = directory.join("creation-race.sqlite3");
    let custody = Rc::new(RefCell::new(None));
    let observed = Rc::clone(&custody);
    let child_path = path.clone();
    BEFORE_SHARED.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |file| {
            let metadata = file.metadata().unwrap();
            assert_eq!(metadata.len(), 0, "race must precede SQLite initialization");
            let mut exclusive = Process::start("exclusive", &child_path);
            exclusive.wait_ready();
            *observed.borrow_mut() = Some((exclusive, metadata.dev(), metadata.ino()));
        }));
    });
    let error = match SqliteLedger::open(&path) {
        Ok(_) => panic!("creation raced past exclusive custody"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("SQLITE_CUSTODY_BUSY"), "{error}");
    let (mut exclusive, device, inode) = custody.borrow_mut().take().expect("creation race ran");
    let retained = std::fs::metadata(&path).expect("busy creation must preserve peer-owned inode");
    assert_eq!(
        (retained.dev(), retained.ino(), retained.len()),
        (device, inode, 0)
    );
    assert_eq!(snapshot(&path), vec![(path.clone(), Vec::new())]);
    exclusive.process.stdin.take();
    assert!(exclusive.wait_done().success());
    drop(SqliteLedger::open(&path).expect("retained empty inode permits exact init retry"));
    let initialized = std::fs::metadata(&path).unwrap();
    assert_eq!((initialized.dev(), initialized.ino()), (device, inode));
}

fn verify_unsupported_filesystem() {
    for kind in [
        0,
        0x0102_1994,
        0x6969,
        0xff53_4d42,
        0xfe53_4d42,
        0x794c_7630,
        i128::MAX,
    ] {
        assert!(verify_filesystem(kind)
            .unwrap_err()
            .to_string()
            .contains("SQLITE_CUSTODY_FILESYSTEM_UNSUPPORTED"));
    }
    let directory = tempfile::Builder::new()
        .prefix("bullet-custody-refusal-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in("/dev/shm")
        .expect("Linux custody proof requires writable /dev/shm tmpfs");
    let path = directory.path().join("database.sqlite3");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    assert_eq!(
        rustix::fs::fstatfs(&file).unwrap().f_type,
        0x0102_1994,
        "Linux custody proof requires actual /dev/shm tmpfs"
    );
    let before = snapshot(&path);
    for _ in 0..2 {
        let error = match SqliteLedger::open(&path) {
            Ok(_) => panic!("unsupported tmpfs served"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("SQLITE_CUSTODY_FILESYSTEM_UNSUPPORTED"),
            "{error}"
        );
        assert_eq!(snapshot(&path), before);
    }
}

fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let subject = PathBuf::from(name);
        match std::fs::read(&subject) {
            Ok(bytes) => files.push((subject, bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => panic!("snapshot source: {error}"),
        }
    }
    files
}

fn child(path: &Path) -> ! {
    let mode = std::env::var(CHILD_MODE).unwrap();
    if mode == "serving" {
        let _ledger = SqliteLedger::open(path).unwrap();
        hold_until_eof();
    } else {
        let descriptor = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let locked = flock(&descriptor, FlockOperation::NonBlockingLockExclusive);
        match mode.as_str() {
            "busy" => assert_eq!(locked.unwrap_err(), rustix::io::Errno::WOULDBLOCK),
            "free" => locked.unwrap(),
            "exclusive" => {
                locked.unwrap();
                hold_until_eof();
            }
            _ => panic!("unknown custody child mode"),
        }
    }
    std::process::exit(0)
}

fn hold_until_eof() {
    std::fs::write(std::env::var_os(CHILD_READY).unwrap(), b"ready").unwrap();
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
}

fn probe(path: &Path, mode: &str) {
    let mut process = Process::start(mode, path);
    assert!(
        process.wait_done().success(),
        "cross-process custody probe: {mode}"
    );
}

struct Process {
    process: Child,
    ready: PathBuf,
    _control: tempfile::TempDir,
}

impl Process {
    fn start(mode: &str, path: &Path) -> Self {
        let control = crate::test_support::private_tempdir();
        let ready = control.path().join("ready");
        let process = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD_PATH, path)
            .env(CHILD_MODE, mode)
            .env(CHILD_READY, &ready)
            .env("TMPDIR", control.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self {
            process,
            ready,
            _control: control,
        }
    }

    fn wait_ready(&mut self) {
        let started = Instant::now();
        loop {
            if self.ready.exists() {
                return;
            }
            assert!(
                self.process.try_wait().unwrap().is_none(),
                "custody child died before ready"
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "custody child readiness timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_done(&mut self) -> ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "custody child exit timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.process.try_wait().ok().flatten().is_none() {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}
