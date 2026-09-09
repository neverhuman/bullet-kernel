//! The durable lease-transport grant row is the strict versioned
//! `LeaseGrantRecord` on both ledgers: acquire persists its canonical `encode`
//! bytes inside the acquire transaction, readback decodes them strictly, and
//! any row that is not exactly one canonical current record — a legacy bare
//! grant, an unknown version, an extra field, non-canonical bytes, a subject
//! without the seven authority fields, torn rows — is refused as
//! `STORE_FAILURE` with one fixed text that discloses nothing. There is no
//! fallback parser and no repair, and a refused acquire rolls back whole.

use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::{
    KernelLeaseTransport, LeaseGrantRecord, LEASE_GRANT_RECORD_VERSION,
};
use bullet_application::store::{LeaseTransportTxn, ProjectionReader};
use bullet_application::{
    materialize_plan, ActiveLease, Ledger, LedgerError, MemoryLedger, PlanInput, SignedAcquireBody,
    StoredGraph,
};
use bullet_domain::{Attempt, AttemptId, RunnerId, TaskClass, WorkPackageId, WorkPackageState};
use rusqlite::{params, Connection};
use std::collections::BTreeMap;
use std::path::PathBuf;

const AT: &str = "2026-01-01T00:00:00.000Z";
const NOW: u64 = 1_700_000_000_000;
const REFUSED: &str = "ledger: lease-transport grant record refused";
const DIFFERENT: &str = "ledger: lease-transport grant digest already records a different record";
const CONFLICT: &str = "IDEMPOTENCY_CONFLICT";
type BodyMutation = fn(&mut SignedAcquireBody, &WorkPackageId);

/// One ledger plus raw access to its opaque `grant_json` rows: the memory
/// ledger through its hostile-row seam, SQLite through a second connection.
/// Both bypass the port and its codec the way an older kernel or a corrupted
/// file would.
trait Fixture {
    type L: Ledger + ProjectionReader;
    fn ledger(&mut self) -> &mut Self::L;
    fn rows(&mut self) -> BTreeMap<String, String>;
    fn plant(&mut self, digest: &str, text: &str);
}

impl Fixture for MemoryLedger {
    type L = Self;

    fn ledger(&mut self) -> &mut Self {
        self
    }

    fn rows(&mut self) -> BTreeMap<String, String> {
        self.transport_grant_rows_mut().clone()
    }

    fn plant(&mut self, digest: &str, text: &str) {
        self.transport_grant_rows_mut()
            .insert(digest.to_string(), text.to_string());
    }
}

struct Sqlite {
    ledger: SqliteLedger,
    path: PathBuf,
    _directory: tempfile::TempDir,
}

impl Sqlite {
    fn open(name: &str) -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure tempdir mode");
        }
        let path = directory.path().join(format!("{name}.sqlite3"));
        let ledger = SqliteLedger::open(&path).expect("open");
        Self {
            ledger,
            path,
            _directory: directory,
        }
    }

    fn raw(&self) -> Connection {
        Connection::open(&self.path).expect("raw open")
    }
}

impl Fixture for Sqlite {
    type L = SqliteLedger;

    fn ledger(&mut self) -> &mut SqliteLedger {
        &mut self.ledger
    }

    fn rows(&mut self) -> BTreeMap<String, String> {
        let raw = self.raw();
        let mut statement = raw
            .prepare("SELECT idempotency_digest, grant_json FROM lease_transport_grants")
            .expect("prepare");
        let rows: BTreeMap<String, String> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        rows
    }

    fn plant(&mut self, digest: &str, text: &str) {
        self.raw()
            .execute(
                "INSERT OR REPLACE INTO lease_transport_grants
                 (idempotency_digest, grant_json, recorded_at) VALUES (?1, ?2, ?3)",
                params![digest, text, AT],
            )
            .expect("plant row");
    }
}

/// Two packages, so a changed `work_package_id` under the same key is a
/// conflict rather than an unknown package.
fn seed<L: Ledger>(ledger: &mut L, seed: &str, key: &str) -> (StoredGraph, SignedAcquireBody) {
    let plan = PlanInput {
        title: "strict grant record".into(),
        objective: "the durable row is the reconstruction".into(),
        packages: vec![
            ("one".into(), TaskClass::MechanicalCodeEdit),
            ("two".into(), TaskClass::MechanicalCodeEdit),
        ],
    };
    let graph = materialize_plan(ledger, seed, &plan, AT).expect("materialize");
    let body = SignedAcquireBody {
        work_package_id: graph.packages[0].id.clone(),
        runner_id: RunnerId::from_seed(seed),
        runner_epoch: 1,
        idempotency_key: key.into(),
        ttl_seconds: 15,
    };
    (graph, body)
}

fn in_txn<L: Ledger, T>(ledger: &mut L, f: impl FnOnce(&mut dyn LeaseTransportTxn) -> T) -> T {
    ledger
        .with_lease_transport(|txn| Ok::<T, LedgerError>(f(txn)))
        .expect("transaction commits")
}

/// The single durable row after one acquire: `(digest, grant_json)`.
fn only_row<F: Fixture>(fx: &mut F) -> (String, String) {
    let rows = fx.rows();
    assert_eq!(rows.len(), 1, "exactly one grant row: {rows:?}");
    rows.into_iter().next().expect("one row")
}

/// Everything a refused operation must leave untouched.
fn snapshot<L: Ledger + ProjectionReader>(
    ledger: &L,
    graph: &StoredGraph,
) -> (Vec<ActiveLease>, Vec<Attempt>, usize, usize) {
    (
        ledger.list_leases().expect("leases"),
        ledger.list_attempts(&graph.mission.id).expect("attempts"),
        ledger.list_events().expect("events").len(),
        ledger.ready_rows().expect("ready rows").len(),
    )
}

/// The digest the kernel stores under `key` and the bare-grant JSON the
/// pre-record port used to write, both taken from a probe ledger. The digest
/// is a pure function of the key, so it names the same row on any ledger.
fn legacy_row_for(key: &str) -> (String, String) {
    let mut probe = MemoryLedger::new();
    let (_, body) = seed(&mut probe, "digest-probe", key);
    let transport = KernelLeaseTransport::generate().expect("kernel key");
    let grant = transport
        .acquire(&mut probe, &body, NOW)
        .expect("probe acquire");
    let legacy = serde_json::to_string(&grant).expect("legacy bare grant");
    (only_row(&mut probe).0, legacy)
}

/// Delete `"field":<value>,` from a canonical document exactly once.
fn strip_field(text: &str, field: &str) -> String {
    let needle = format!("\"{field}\":");
    assert_eq!(text.matches(&needle).count(), 1, "{field} appears once");
    let start = text.find(&needle).expect("field");
    let end = start + text[start..].find(',').expect("field is not last") + 1;
    format!("{}{}", &text[..start], &text[end..])
}

fn refused(reason_code: &str, message: &str, case: &str) {
    assert_eq!(reason_code, "STORE_FAILURE", "{case}");
    assert_eq!(
        message, REFUSED,
        "{case}: nothing about the row is disclosed"
    );
}

fn durable_record_is_the_reconstruction<F: Fixture>(fx: &mut F, name: &str) {
    let (_graph, body) = seed(fx.ledger(), name, &format!("{name}-key"));
    let transport = KernelLeaseTransport::generate().expect("kernel key");
    let grant = transport.acquire(fx.ledger(), &body, NOW).expect("acquire");
    let (digest, text) = only_row(fx);
    let record = LeaseGrantRecord::decode(&text).expect("the durable row decodes strictly");
    assert_eq!(record.encode().expect("encode"), text, "canonical bytes");
    assert_eq!(record.version, LEASE_GRANT_RECORD_VERSION);
    assert_eq!(record.grant, grant);
    let request = &record.request;
    assert_eq!(request.idempotency_key, body.idempotency_key);
    assert_eq!(request.attempt_seed, body.idempotency_key);
    assert_eq!(request.runner_id, body.runner_id);
    assert_eq!(request.runner_epoch, body.runner_epoch);
    assert_eq!(request.ttl_seconds, body.ttl_seconds);
    assert_eq!(request.variant_id, grant.lease.variant_id);
    let authority = Ledger::current_authority(fx.ledger()).expect("authority row");
    let subject = &record.subject;
    assert_eq!(
        (
            subject.graph_revision,
            subject.routing_generation,
            subject.authority_epoch
        ),
        (
            authority.graph_revision(),
            authority.routing_generation(),
            authority.authority_epoch()
        ),
        "the seven-field subject binds the authority row"
    );
    assert_eq!(subject.workspace_id, request.workspace_id.as_str());
    assert!(subject.incarnation.is_none());

    let read = in_txn(fx.ledger(), |txn| txn.get_transport_grant(&digest));
    assert_eq!(read.expect("port read"), Some(record.clone()));
    let readback = transport.readback(fx.ledger(), &body, NOW + 1);
    assert_eq!(readback.expect("readback"), grant, "reconstruction agrees");
    let replay = transport.acquire(fx.ledger(), &body, NOW + 2);
    assert_eq!(replay.expect("replay"), grant);
    assert_eq!(fx.rows(), BTreeMap::from([(digest.clone(), text.clone())]));

    let mut different = record.clone();
    different.grant.lease.fence += 1;
    let (same, other) = in_txn(fx.ledger(), |txn| {
        (
            txn.put_transport_grant(&digest, &record),
            txn.put_transport_grant(&digest, &different),
        )
    });
    same.expect("the identical record is idempotent");
    let other = other.expect_err("a different record under the same digest");
    assert_eq!(other.reason_code(), "STORE_FAILURE");
    assert_eq!(other.to_string(), DIFFERENT);
    assert_eq!(fx.rows(), BTreeMap::from([(digest, text)]));
}

#[test]
fn memory_durable_record_is_the_reconstruction() {
    durable_record_is_the_reconstruction(&mut MemoryLedger::new(), "memory-record");
}

#[test]
fn sqlite_durable_record_is_the_reconstruction() {
    durable_record_is_the_reconstruction(&mut Sqlite::open("record"), "sqlite-record");
}

fn hostile_rows_are_refused_and_disclose_nothing<F: Fixture>(fx: &mut F, name: &str) {
    let (graph, body) = seed(fx.ledger(), name, &format!("{name}-key"));
    let transport = KernelLeaseTransport::generate().expect("kernel key");
    let grant = transport.acquire(fx.ledger(), &body, NOW).expect("acquire");
    let (digest, text) = only_row(fx);
    let record = LeaseGrantRecord::decode(&text).expect("current record");
    let mutated = |mutate: &dyn Fn(&mut LeaseGrantRecord)| {
        let mut hostile = record.clone();
        mutate(&mut hostile);
        hostile.encode().expect("encode")
    };
    let renamed = AttemptId::from_seed("attempt-and-lease-renamed-together");
    let other = graph.packages[1].id.clone();
    let cases = [
        (
            "legacy bare grant",
            serde_json::to_string(&grant).expect("bare grant"),
        ),
        (
            "unknown version",
            text.replace(LEASE_GRANT_RECORD_VERSION, "lease-transport-grant.v0"),
        ),
        (
            "extra field",
            text.replacen("{\"grant\":", "{\"a\":1,\"grant\":", 1),
        ),
        ("non-canonical bytes", text.replacen(',', ", ", 1)),
        (
            "subject without graph_revision",
            strip_field(&text, "graph_revision"),
        ),
        (
            "subject without routing_generation",
            strip_field(&text, "routing_generation"),
        ),
        (
            "subject without authority_epoch",
            strip_field(&text, "authority_epoch"),
        ),
        ("torn rows", mutated(&|r| r.grant.lease.fence += 1)),
        (
            "subject graph_revision zero",
            mutated(&|r| r.subject.graph_revision = 0),
        ),
        (
            "unrelated request digest",
            mutated(&|r| r.request_digest = "f".repeat(64)),
        ),
        (
            "attempt and lease id renamed together",
            mutated(&|r| {
                r.grant.attempt.id = renamed.clone();
                r.grant.lease.attempt_id = renamed.clone();
            }),
        ),
        (
            "attempt package changed",
            mutated(&|r| r.grant.attempt.work_package_id = other.clone()),
        ),
    ];
    let before = snapshot(fx.ledger(), &graph);
    assert_eq!(before.0, vec![grant.lease.clone()]);
    for (case, hostile) in cases {
        assert_ne!(hostile, text, "{case}");
        fx.plant(&digest, &hostile);
        let port = in_txn(fx.ledger(), |txn| txn.get_transport_grant(&digest));
        let port = port.expect_err(case);
        refused(port.reason_code(), &port.to_string(), case);
        let readback = transport.readback(fx.ledger(), &body, NOW + 1);
        let readback = readback.expect_err(case);
        refused(readback.reason_code(), &readback.to_string(), case);
        let replay = transport.acquire(fx.ledger(), &body, NOW + 2);
        let replay = replay.expect_err(case);
        refused(replay.reason_code(), &replay.to_string(), case);
        assert_eq!(snapshot(fx.ledger(), &graph), before, "{case}");
        let rows = BTreeMap::from([(digest.clone(), hostile.clone())]);
        assert_eq!(fx.rows(), rows, "{case}: no repair, no rewrite");
    }
    fx.plant(&digest, &text);
    let restored = transport.readback(fx.ledger(), &body, NOW + 3);
    assert_eq!(restored.expect("current record"), grant);
}

#[test]
fn memory_hostile_rows_are_refused_and_disclose_nothing() {
    hostile_rows_are_refused_and_disclose_nothing(&mut MemoryLedger::new(), "memory-hostile");
}

#[test]
fn sqlite_hostile_rows_are_refused_and_disclose_nothing() {
    hostile_rows_are_refused_and_disclose_nothing(&mut Sqlite::open("hostile"), "sqlite-hostile");
}

fn acquire_over_an_unreadable_row_rolls_back<F: Fixture>(fx: &mut F, name: &str) {
    let key = format!("{name}-key");
    let (graph, body) = seed(fx.ledger(), name, &key);
    let (digest, legacy) = legacy_row_for(&key);
    fx.plant(&digest, &legacy);
    let before = snapshot(fx.ledger(), &graph);
    assert!(before.0.is_empty() && before.1.is_empty());
    let transport = KernelLeaseTransport::generate().expect("kernel key");
    let acquire = transport.acquire(fx.ledger(), &body, NOW);
    let acquire = acquire.expect_err("acquire over a legacy row");
    refused(acquire.reason_code(), &acquire.to_string(), "acquire");
    let readback = transport.readback(fx.ledger(), &body, NOW + 1);
    let readback = readback.expect_err("readback of a legacy row");
    refused(readback.reason_code(), &readback.to_string(), "readback");
    assert_eq!(snapshot(fx.ledger(), &graph), before);
    let attempt = AttemptId::from_seed(&key);
    let package = body.work_package_id.clone();
    let (lease, stored, current) = in_txn(fx.ledger(), |txn| {
        (
            txn.get_lease(&attempt).expect("lease read"),
            txn.get_attempt(&attempt).expect("attempt read"),
            txn.resolve_package(&package).expect("package"),
        )
    });
    assert_eq!((lease, stored), (None, None));
    assert_eq!(current.package.state, WorkPackageState::Ready);
    assert_eq!(current.variant.fence_counter, 0);
    assert_eq!(fx.rows(), BTreeMap::from([(digest, legacy)]));

    let mut fresh = body.clone();
    fresh.idempotency_key = format!("{key}-fresh");
    let grant = transport.acquire(fx.ledger(), &fresh, NOW + 2);
    let grant = grant.expect("the package is still acquirable under a fresh key");
    assert_eq!(grant.lease.variant_id, current.variant.id);
    assert_eq!(fx.rows().len(), 2);
}

#[test]
fn memory_acquire_over_an_unreadable_row_rolls_back() {
    acquire_over_an_unreadable_row_rolls_back(&mut MemoryLedger::new(), "memory-rollback");
}

#[test]
fn sqlite_acquire_over_an_unreadable_row_rolls_back() {
    acquire_over_an_unreadable_row_rolls_back(&mut Sqlite::open("rollback"), "sqlite-rollback");
}

fn changed_body_under_the_same_key_is_a_conflict<F: Fixture>(fx: &mut F, name: &str) {
    let (graph, body) = seed(fx.ledger(), name, &format!("{name}-key"));
    let transport = KernelLeaseTransport::generate().expect("kernel key");
    let grant = transport.acquire(fx.ledger(), &body, NOW).expect("acquire");
    let (digest, text) = only_row(fx);
    let before = snapshot(fx.ledger(), &graph);
    let other = graph.packages[1].id.clone();
    let cases: [(&str, BodyMutation); 4] = [
        ("runner_id", |b, _| {
            b.runner_id = RunnerId::from_seed("intruder")
        }),
        ("runner_epoch", |b, _| b.runner_epoch += 1),
        ("ttl_seconds", |b, _| b.ttl_seconds = 5),
        ("work_package_id", |b, other| {
            b.work_package_id = other.clone()
        }),
    ];
    for (field, mutate) in cases {
        let mut hostile = body.clone();
        mutate(&mut hostile, &other);
        let readback = transport.readback(fx.ledger(), &hostile, NOW + 1);
        let readback = readback.expect_err(field);
        assert_eq!(readback.reason_code(), CONFLICT, "{field}");
        assert!(readback.to_string().contains(field), "{field}: {readback}");
        let acquire = transport.acquire(fx.ledger(), &hostile, NOW + 2);
        assert_eq!(acquire.expect_err(field).reason_code(), CONFLICT, "{field}");
        assert_eq!(snapshot(fx.ledger(), &graph), before, "{field}");
        let rows = BTreeMap::from([(digest.clone(), text.clone())]);
        assert_eq!(fx.rows(), rows, "{field}");
    }
    let own = transport.readback(fx.ledger(), &body, NOW + 3);
    assert_eq!(own.expect("own body"), grant);
}

#[test]
fn memory_changed_body_under_the_same_key_is_a_conflict() {
    changed_body_under_the_same_key_is_a_conflict(&mut MemoryLedger::new(), "memory-conflict");
}

#[test]
fn sqlite_changed_body_under_the_same_key_is_a_conflict() {
    changed_body_under_the_same_key_is_a_conflict(&mut Sqlite::open("conflict"), "sqlite-conflict");
}

/// Only SQLite can move the authority row (`authority_scope` is an adapter
/// path), so this behaviour is proved there: a record minted under a
/// superseded authority still decodes, but it no longer equals the current
/// reconstruction, so readback is the fixed refusal and a replay refuses to
/// overwrite the record.
#[test]
fn sqlite_record_under_a_superseded_authority_is_refused() {
    let mut fx = Sqlite::open("authority");
    let (graph, body) = seed(fx.ledger(), "sqlite-authority", "sqlite-authority-key");
    let transport = KernelLeaseTransport::generate().expect("kernel key");
    let grant = transport.acquire(fx.ledger(), &body, NOW).expect("acquire");
    let (digest, text) = only_row(&mut fx);
    let before = snapshot(fx.ledger(), &graph);
    fx.raw()
        .execute(
            "UPDATE authority_revisions SET authority_epoch = authority_epoch + 1
             WHERE singleton = 1",
            [],
        )
        .expect("move the authority");
    let readback = transport.readback(fx.ledger(), &body, NOW + 1);
    let readback = readback.expect_err("recorded under the previous authority");
    refused(readback.reason_code(), &readback.to_string(), "authority");
    let replay = transport.acquire(fx.ledger(), &body, NOW + 2);
    let replay = replay.expect_err("replay under the new authority");
    assert_eq!(replay.reason_code(), "STORE_FAILURE");
    assert_eq!(replay.to_string(), DIFFERENT);
    assert_eq!(snapshot(fx.ledger(), &graph), before);
    assert_eq!(fx.rows(), BTreeMap::from([(digest.clone(), text)]));
    let stored = in_txn(fx.ledger(), |txn| txn.get_transport_grant(&digest));
    let stored = stored.expect("port read").expect("row");
    assert_eq!(stored.grant, grant);
    let authority = Ledger::current_authority(fx.ledger()).expect("authority row");
    assert_eq!(
        stored.subject.authority_epoch + 1,
        authority.authority_epoch()
    );
}
