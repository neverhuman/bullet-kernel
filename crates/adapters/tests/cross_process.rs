//! Cross-process authority races on one SQLite ledger.
//!
//! The in-process race suites prove the lease transaction against threads;
//! this suite proves it against operating-system processes, which is what a
//! crashed-and-restarted runner or a second farmd actually is. Each child is
//! this test binary re-executed in worker mode (no extra binary enters the
//! release archive). A file barrier releases every child at once.
//!
//! Contract under test (Wave 2 negative checks "concurrent acquire" and
//! "expiry boundary"): exactly one process acquires; every loser receives a
//! typed refusal, never a store failure; fences never repeat across waves;
//! an expired lease is reclaimed by another process at its own acquisition.

use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, LeaseService, NonceLedger, NonceState, PlanInput, StoredGraph,
};
use bullet_domain::{AttemptState, TaskClass};
use chrono::Utc;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[path = "cross_process/support.rs"]
mod support;
use support::{private_tempdir, wait_until, ChildSet};

const CHILD_DB: &str = "BULLET_TEST_RACE_CHILD_DB";
const CHILD_OUT: &str = "BULLET_TEST_RACE_CHILD_OUT";
const CHILD_SEED: &str = "BULLET_TEST_RACE_CHILD_SEED";
const CHILD_GO: &str = "BULLET_TEST_RACE_CHILD_GO";
const CHILD_RELEASE: &str = "BULLET_TEST_RACE_CHILD_RELEASE";
const CHILD_TTL: &str = "BULLET_TEST_RACE_CHILD_TTL";
const CHILD_RELEASE_GO: &str = "BULLET_TEST_RACE_CHILD_RELEASE_GO";
const CHILD_READY: &str = "BULLET_TEST_RACE_CHILD_READY";
const CHILD_NONCE_KEY: &str = "BULLET_TEST_RACE_CHILD_NONCE_KEY";
const CHILD_NONCE_DIGEST: &str = "BULLET_TEST_RACE_CHILD_NONCE_DIGEST";

const WORKER_ENV: [&str; 11] = [
    CHILD_DB,
    CHILD_OUT,
    CHILD_SEED,
    CHILD_GO,
    CHILD_RELEASE,
    CHILD_TTL,
    CHILD_RELEASE_GO,
    CHILD_READY,
    CHILD_NONCE_KEY,
    CHILD_NONCE_DIGEST,
    "RUST_BACKTRACE",
];

const GRAPH_SEED: &str = "cross-process-race";
const PROCESSES: usize = 8;

fn materialize(ledger: &mut SqliteLedger) -> StoredGraph {
    materialize_plan(
        ledger,
        GRAPH_SEED,
        &PlanInput {
            title: "cross-process race".into(),
            objective: "one writer per variant across processes".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        &LeaseService::rfc3339(Utc::now()),
    )
    .expect("materialize is idempotent by seed")
}

/// Worker mode. A normal harness invocation proves that no partial worker
/// channel leaked in from the host environment.
#[test]
fn child_acquire_worker_process() {
    let worker_fields = WORKER_ENV[..10]
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .count();
    if worker_fields == 0 {
        assert!(
            WORKER_ENV[..10]
                .iter()
                .all(|name| std::env::var_os(name).is_none()),
            "standalone invocation must not inherit a partial worker channel"
        );
        return;
    }
    assert!(
        worker_fields == 8 || worker_fields == 10,
        "worker channel must be complete, including both or neither nonce fields"
    );
    let db = std::env::var(CHILD_DB).expect("worker db");
    let out = PathBuf::from(std::env::var(CHILD_OUT).expect("worker output"));
    let seed = std::env::var(CHILD_SEED).expect("worker seed");
    let go = PathBuf::from(std::env::var(CHILD_GO).expect("worker barrier"));
    let release = match std::env::var(CHILD_RELEASE).as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        _ => panic!("worker release flag must be 0 or 1"),
    };
    let ttl: i64 = std::env::var(CHILD_TTL)
        .expect("worker ttl")
        .parse()
        .expect("worker ttl is an integer");

    let mut ledger = SqliteLedger::open(Path::new(&db)).expect("child opens the shared ledger");
    let graph = materialize(&mut ledger);
    let nonce = match (
        std::env::var(CHILD_NONCE_KEY).ok(),
        std::env::var(CHILD_NONCE_DIGEST).ok(),
    ) {
        (Some(key), Some(digest)) => Some((key, digest)),
        (None, None) => None,
        _ => panic!("worker nonce channel must contain both fields or neither"),
    };
    if let Some((key, digest)) = nonce.as_ref() {
        if let Err(error) = ledger.consume(key, digest) {
            std::fs::write(&out, format!("ERR {}", error.reason_code()))
                .expect("child records the nonce refusal");
            return;
        }
    }
    // Announce readiness exactly once, then wait for the parent to open the gate.
    std::fs::write(PathBuf::from(std::env::var(CHILD_READY).unwrap()), b"ready")
        .expect("child announces readiness");
    wait_until("parent acquisition barrier", || go.exists());
    let line = match LeaseService::acquire(&mut ledger, &graph, 0, &seed, ttl) {
        Ok((attempt, _token, grant)) => {
            let mut line = format!("OK {} {}", attempt.fence, attempt.id);
            if release {
                // Record the win first, then wait until the parent has seen every
                // sibling's outcome; releasing with requeue earlier would let a
                // sibling legitimately acquire the next fence inside this wave.
                std::fs::write(&out, &line).expect("child records its win");
                let release_go = PathBuf::from(std::env::var(CHILD_RELEASE_GO).unwrap());
                wait_until("parent release barrier", || release_go.exists());
                LeaseService::release(&mut ledger, &grant, AttemptState::Cancelled, true)
                    .expect("winner releases with requeue");
                line.push_str(" RELEASED");
            }
            line
        }
        Err(error) => format!("ERR {}", error.reason_code()),
    };
    std::fs::write(&out, line).expect("child records its outcome");
}

struct Outcome {
    winners: Vec<(u64, String)>,
    refusals: Vec<String>,
}

fn race(db: &Path, dir: &Path, wave: &str, count: usize, release: bool, ttl: i64) -> Outcome {
    race_with(db, dir, wave, count, release, ttl, None)
}

fn race_with(
    db: &Path,
    dir: &Path,
    wave: &str,
    count: usize,
    release: bool,
    ttl: i64,
    nonce: Option<(&str, &str)>,
) -> Outcome {
    let go = dir.join(format!("go-{wave}"));
    let release_go = dir.join(format!("release-go-{wave}"));
    let exe = std::env::current_exe().expect("test executable");
    let mut children = ChildSet::default();
    let mut outs = Vec::new();
    let mut readies = Vec::new();
    for index in 0..count {
        let out = dir.join(format!("out-{wave}-{index}"));
        let ready = dir.join(format!("ready-{wave}-{index}"));
        let mut command = Command::new(&exe);
        command.env_clear().env("RUST_BACKTRACE", "0");
        if let Some((key, digest)) = nonce {
            command
                .env(CHILD_NONCE_KEY, key)
                .env(CHILD_NONCE_DIGEST, digest);
        }
        command
            .args(["child_acquire_worker_process", "--exact", "--quiet"])
            .env(CHILD_DB, db)
            .env(CHILD_OUT, &out)
            .env(CHILD_SEED, format!("{wave}-attempt-{index}"))
            .env(CHILD_GO, &go)
            .env(CHILD_RELEASE, if release { "1" } else { "0" })
            .env(CHILD_TTL, ttl.to_string())
            .env(CHILD_RELEASE_GO, &release_go)
            .env(CHILD_READY, &ready);
        children.spawn(&mut command);
        outs.push(out);
        readies.push(ready);
    }
    // Exact ready count: every child that will race has announced itself (a
    // child refused at the nonce records its outcome instead and never races).
    wait_until("children to reach the acquisition barrier", || {
        readies
            .iter()
            .zip(&outs)
            .all(|(ready, out)| ready.exists() || out.exists())
    });
    std::fs::write(&go, b"go").expect("open barrier");
    if release {
        // Every child has recorded an outcome before any winner may release.
        wait_until("children to record acquisition outcomes", || {
            outs.iter().all(|out| out.exists())
        });
        std::fs::write(&release_go, b"go").expect("open release barrier");
    }
    for status in children.wait_all() {
        assert!(status.success(), "child process failed: {status}");
    }
    let mut outcome = Outcome {
        winners: Vec::new(),
        refusals: Vec::new(),
    };
    for out in outs {
        let line = std::fs::read_to_string(&out).expect("every child records an outcome");
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("OK") => {
                let fence: u64 = parts.next().unwrap().parse().unwrap();
                let attempt = parts.next().unwrap().to_string();
                if release {
                    assert_eq!(parts.next(), Some("RELEASED"));
                }
                outcome.winners.push((fence, attempt));
            }
            Some("ERR") => outcome.refusals.push(parts.next().unwrap().to_string()),
            other => panic!("malformed child outcome {other:?}: {line}"),
        }
    }
    outcome
}

fn active_lease_rows(db: &Path) -> Vec<(String, u64)> {
    let connection = Connection::open(db).expect("raw open");
    let mut statement = connection
        .prepare("SELECT attempt_id, fence FROM active_leases ORDER BY attempt_id")
        .expect("prepare");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })
        .expect("query");
    rows.map(|row| row.expect("row")).collect()
}

fn setup() -> (tempfile::TempDir, PathBuf) {
    let dir = private_tempdir();
    let db = dir.path().join("race.sqlite");
    let mut ledger = SqliteLedger::open(&db).expect("parent opens the ledger");
    let _graph = materialize(&mut ledger);
    (dir, db)
}

#[test]
fn exactly_one_process_wins_a_concurrent_acquire() {
    let (dir, db) = setup();
    let outcome = race(&db, dir.path(), "one", PROCESSES, false, 5);
    assert_eq!(
        outcome.winners.len(),
        1,
        "exactly one process may hold the lease"
    );
    assert_eq!(outcome.refusals.len(), PROCESSES - 1);
    for code in &outcome.refusals {
        assert!(
            code == "FENCE_REUSE" || code == "GRAPH_CONFLICT",
            "a loser must receive a typed lease refusal, never {code}"
        );
    }
    let rows = active_lease_rows(&db);
    assert_eq!(rows.len(), 1, "one active lease row");
    assert_eq!(rows[0].1, outcome.winners[0].0);
    assert_eq!(rows[0].0, outcome.winners[0].1);
    assert_eq!(outcome.winners[0].0, 1, "first fence on a fresh variant");
}

#[test]
fn fences_never_repeat_across_process_waves() {
    let (dir, db) = setup();
    let first = race(&db, dir.path(), "wave-a", PROCESSES, true, 5);
    let second = race(&db, dir.path(), "wave-b", PROCESSES, true, 5);
    assert_eq!(first.winners.len(), 1);
    assert_eq!(second.winners.len(), 1);
    let (fence_a, attempt_a) = &first.winners[0];
    let (fence_b, attempt_b) = &second.winners[0];
    assert!(
        fence_b > fence_a,
        "a later wave's fence is strictly greater"
    );
    assert_ne!(attempt_a, attempt_b);
    assert_eq!(*fence_a, 1);
    assert_eq!(*fence_b, 2);
    assert!(
        active_lease_rows(&db).is_empty(),
        "both winners released; no lease row survives"
    );
    let counter: u64 = Connection::open(&db)
        .expect("raw open")
        .query_row("SELECT MAX(fence) FROM attempts", [], |row| row.get(0))
        .expect("fence high-water");
    assert_eq!(counter, 2, "fence counter survives lease deletion");
}

#[test]
fn expired_lease_is_reclaimed_by_another_process() {
    let (dir, db) = setup();
    let first = race(&db, dir.path(), "holder", 1, false, 1);
    assert_eq!(first.winners.len(), 1);
    let (fence_a, attempt_a) = first.winners[0].clone();
    // The holder exited without releasing; nobody heartbeats it.
    std::thread::sleep(Duration::from_millis(2_500));
    let second = race(&db, dir.path(), "successor", 1, false, 5);
    assert_eq!(
        second.winners.len(),
        1,
        "a successor process reclaims the expired lease at its own acquisition"
    );
    let (fence_b, attempt_b) = second.winners[0].clone();
    assert!(fence_b > fence_a);
    assert_ne!(attempt_a, attempt_b);
    let rows = active_lease_rows(&db);
    assert_eq!(
        rows,
        vec![(attempt_b, fence_b)],
        "only the successor holds a lease"
    );
}

#[test]
fn consumed_nonce_replayed_from_another_process_is_refused() {
    let (dir, db) = setup();
    let key = "7".repeat(64);
    let digest = "c".repeat(64);
    SqliteLedger::open(&db)
        .expect("parent opens the ledger")
        .issue(&key, &digest)
        .expect("parent issues the one-use nonce");
    let first = race_with(
        &db,
        dir.path(),
        "nonce-a",
        1,
        false,
        5,
        Some((&key, &digest)),
    );
    assert_eq!(
        first.winners.len(),
        1,
        "the first consumer performs the protected mutation"
    );
    let replay = race_with(
        &db,
        dir.path(),
        "nonce-b",
        1,
        false,
        5,
        Some((&key, &digest)),
    );
    assert!(
        replay.winners.is_empty(),
        "a replayed consume never reaches the mutation"
    );
    assert_eq!(replay.refusals, vec!["NONCE_CONSUMED".to_string()]);
    let ledger = SqliteLedger::open(&db).expect("parent reopens the ledger");
    assert_eq!(
        ledger.state(&key).expect("state"),
        Some(NonceState::Consumed)
    );
    let rows = active_lease_rows(&db);
    assert_eq!(rows.len(), 1, "only the first consumer holds the lease");
    assert_eq!(rows[0].0, first.winners[0].1);
}
