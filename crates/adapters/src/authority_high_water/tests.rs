#![cfg(target_os = "linux")]

use super::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;
use tempfile::TempDir;

const SERVING: RecoveryState = RecoveryState::Serving;
const RECOVERING: RecoveryState = RecoveryState::Recovering;

const fn hw(
    authority_epoch: u64,
    freeze_generation: u64,
    restore_epoch: u64,
    recovery: RecoveryState,
) -> AuthorityHighWaterValues {
    AuthorityHighWaterValues {
        authority_epoch,
        freeze_generation,
        restore_epoch,
        recovery,
    }
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    store: AuthorityHighWaterStore,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().expect("secure tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("0700");
        let path = directory.path().join("authority-high-water.json");
        let store = AuthorityHighWaterStore::new(&path).expect("store path");
        Self {
            _directory: directory,
            path,
            store,
        }
    }

    fn write_raw(&self, bytes: &[u8]) {
        fs::write(&self.path, bytes).expect("write hostile record");
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).expect("0600");
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(&self.path).expect("record bytes")
    }

    /// A fresh handle, as after a process restart.
    fn reload(&self) -> Option<AuthorityHighWaterV1> {
        AuthorityHighWaterStore::new(&self.path)
            .expect("reopen")
            .load()
            .expect("restart readback")
    }

    fn assert_corrupt_unrepaired(&self, bytes: &[u8]) {
        self.write_raw(bytes);
        assert_eq!(refusal(self.store.load()), "AUTHORITY_HIGH_WATER_CORRUPT");
        assert_eq!(
            refusal(self.store.advance(hw(9, 9, 9, SERVING))),
            "AUTHORITY_HIGH_WATER_CORRUPT"
        );
        assert_eq!(self.bytes(), bytes, "corrupt record must not be repaired");
    }
}

fn refusal<T>(result: Result<T, AuthorityHighWaterError>) -> &'static str {
    result
        .map(|_| ())
        .expect_err("refusal expected")
        .reason_code()
}

fn assert_record(record: &AuthorityHighWaterV1, values: AuthorityHighWaterValues) {
    assert_eq!(record.schema_version, AUTHORITY_HIGH_WATER_SCHEMA_VERSION);
    assert_eq!(record.values(), values);
    assert_eq!(record.checksum, checksum(values));
}

fn expected_bytes(values: AuthorityHighWaterValues) -> Vec<u8> {
    format!(
        "{{\"schema_version\":2,\"authority_epoch\":{},\"freeze_generation\":{},\"restore_epoch\":{},\"recovery\":\"{}\",\"checksum\":\"{}\"}}\n",
        values.authority_epoch,
        values.freeze_generation,
        values.restore_epoch,
        values.recovery.code(),
        checksum(values)
    )
    .into_bytes()
}

fn restart_idempotency_and_monotonic_refusal() {
    let fixture = Fixture::new();
    assert_eq!(fixture.store.load().expect("empty load"), None);
    let initial = fixture
        .store
        .advance(hw(1, 0, 0, SERVING))
        .expect("initialize");
    assert_record(&initial, hw(1, 0, 0, SERVING));
    let bytes = fixture.bytes();
    assert_eq!(fixture.reload(), Some(initial.clone()));

    let restarted = AuthorityHighWaterStore::new(&fixture.path).expect("reopen");
    let retried = restarted
        .advance(hw(1, 0, 0, SERVING))
        .expect("exact retry");
    assert_eq!(retried, initial);
    assert_eq!(fixture.bytes(), bytes);

    let current = hw(4, 3, 2, RECOVERING);
    let durable = restarted.advance(current).expect("advance all counters");
    assert_record(&durable, current);
    for requested in [
        hw(3, 3, 2, RECOVERING),
        hw(4, 2, 2, RECOVERING),
        hw(4, 3, 1, RECOVERING),
        hw(5, 4, 1, SERVING),
        hw(3, 4, 3, SERVING),
        hw(4, 3, 1, SERVING),
    ] {
        let before = fixture.bytes();
        let error = restarted.advance(requested).expect_err("rollback refused");
        assert_eq!(error.reason_code(), "AUTHORITY_HIGH_WATER_ROLLBACK");
        assert!(
            matches!(
                error,
                AuthorityHighWaterError::Rollback { current: reported, requested: refused }
                    if reported == current && refused == requested
            ),
            "typed rollback payload: {error}"
        );
        assert_eq!(fixture.bytes(), before, "refusal must not publish");
    }
    assert_eq!(fixture.reload(), Some(durable));
}

fn fault_and_response_loss_readback() {
    let fixture = Fixture::new();
    let initial = fixture
        .store
        .advance(hw(1, 0, 0, SERVING))
        .expect("initialize");
    let error = fixture
        .store
        .advance_with_fault(hw(2, 1, 1, RECOVERING), FaultPoint::BeforePublish)
        .expect_err("prepublication failure");
    assert_eq!(error.reason_code(), "AUTHORITY_HIGH_WATER_OPERATION_FAILED");
    assert_eq!(fixture.store.load().expect("old state"), Some(initial));

    let error = fixture
        .store
        .advance_with_fault(hw(2, 1, 1, RECOVERING), FaultPoint::AfterReadback)
        .expect_err("lost response");
    assert_eq!(error.reason_code(), "AUTHORITY_HIGH_WATER_RESPONSE_LOST");
    let durable = fixture.reload().expect("durable record");
    assert_record(&durable, hw(2, 1, 1, RECOVERING));
    let retried = fixture
        .store
        .advance(hw(2, 1, 1, RECOVERING))
        .expect("safe exact retry");
    assert_eq!(retried, durable);
}

fn independent_handles_serialize_without_regression() {
    let fixture = Fixture::new();
    fixture
        .store
        .advance(hw(1, 0, 0, SERVING))
        .expect("initialize");

    let held = fixture
        .store
        .locked_parent()
        .expect("hold cross-handle lock");
    let path = fixture.path.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let blocked = std::thread::spawn(move || {
        let store = AuthorityHighWaterStore::new(path).expect("second handle");
        started_tx.send(()).expect("started");
        done_tx
            .send(store.advance(hw(2, 1, 1, RECOVERING)))
            .expect("result");
    });
    started_rx.recv().expect("second handle started");
    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    drop(held);
    assert_record(
        &done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("unblocked result")
            .expect("unblocked advance"),
        hw(2, 1, 1, RECOVERING),
    );
    blocked.join().expect("blocked writer joined");

    let barrier = Arc::new(Barrier::new(3));
    let mut joins = Vec::new();
    for requested in [hw(3, 2, 1, SERVING), hw(4, 3, 2, RECOVERING)] {
        let path = fixture.path.clone();
        let barrier = Arc::clone(&barrier);
        joins.push(std::thread::spawn(move || {
            let store = AuthorityHighWaterStore::new(path).expect("parallel handle");
            barrier.wait();
            store.advance(requested)
        }));
    }
    barrier.wait();
    let results = joins
        .into_iter()
        .map(|join| join.join().expect("parallel writer joined"))
        .collect::<Vec<_>>();
    assert!(results.iter().any(|result| {
        result
            .as_ref()
            .is_ok_and(|record| record.values() == hw(4, 3, 2, RECOVERING))
    }));
    assert!(results.iter().all(|result| match result {
        Ok(_) => true,
        Err(error) => error.reason_code() == "AUTHORITY_HIGH_WATER_ROLLBACK",
    }));
    let final_record = fixture.reload().expect("record");
    assert_record(&final_record, hw(4, 3, 2, RECOVERING));
}

fn strict_corruption_and_bounds_refuse_without_repair() {
    for bytes in [b"{}".as_slice(), b"not-json".as_slice(), b"\n".as_slice()] {
        Fixture::new().assert_corrupt_unrepaired(bytes);
    }

    let valid = AuthorityHighWaterV1::from_values(hw(2, 1, 1, RECOVERING)).expect("valid record");
    for mutate in [
        |value: &mut serde_json::Value| value["schema_version"] = json!(1),
        |value: &mut serde_json::Value| value["schema_version"] = json!(3),
        |value: &mut serde_json::Value| value["checksum"] = json!("0".repeat(64)),
        |value: &mut serde_json::Value| value["unknown"] = json!(true),
        |value: &mut serde_json::Value| value["authority_epoch"] = json!(MAX_SAFE_INTEGER + 1),
        |value: &mut serde_json::Value| value["restore_epoch"] = json!(MAX_SAFE_INTEGER + 1),
        |value: &mut serde_json::Value| value["restore_epoch"] = json!(-1),
        |value: &mut serde_json::Value| value["restore_epoch"] = json!(0),
        |value: &mut serde_json::Value| value["recovery"] = json!("SERVING"),
        |value: &mut serde_json::Value| value["recovery"] = json!("recovering"),
        |value: &mut serde_json::Value| value["recovery"] = json!("UNKNOWN"),
        |value: &mut serde_json::Value| {
            value.as_object_mut().expect("object").remove("recovery");
        },
    ] {
        let mut value = serde_json::to_value(&valid).expect("record value");
        mutate(&mut value);
        Fixture::new().assert_corrupt_unrepaired(&serde_json::to_vec(&value).expect("JSON"));
    }

    // Valid checksum, invalid combination: RECOVERING without any restore.
    let recovering_without_restore = json!({
        "schema_version": AUTHORITY_HIGH_WATER_SCHEMA_VERSION,
        "authority_epoch": 2,
        "freeze_generation": 1,
        "restore_epoch": 0,
        "recovery": "RECOVERING",
        "checksum": checksum(hw(2, 1, 0, RECOVERING)),
    });
    Fixture::new()
        .assert_corrupt_unrepaired(&serde_json::to_vec(&recovering_without_restore).expect("JSON"));

    // A record written by the pre-extension schema is refused, never defaulted.
    let pre_extension = json!({
        "schema_version": 1,
        "authority_epoch": 2,
        "freeze_generation": 1,
        "checksum": "0".repeat(64),
    });
    Fixture::new().assert_corrupt_unrepaired(&serde_json::to_vec(&pre_extension).expect("JSON"));

    let full = expected_bytes(hw(2, 1, 1, RECOVERING));
    for cut in [1, full.len() / 2, full.len() - 3] {
        Fixture::new().assert_corrupt_unrepaired(&full[..cut]);
    }
    let oversized = vec![b'x'; usize::try_from(MAX_RECORD_BYTES + 1).unwrap()];
    Fixture::new().assert_corrupt_unrepaired(&oversized);
}

fn hostile_filesystem_subjects_refuse_without_following() {
    let fixture = Fixture::new();
    let target = fixture.path.with_extension("target");
    fs::write(&target, b"do-not-touch-record-target").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("0600");
    symlink(&target, &fixture.path).expect("record symlink");
    assert!(fixture.store.advance(hw(1, 0, 0, SERVING)).is_err());
    assert_eq!(
        fs::read(&target).expect("target bytes"),
        b"do-not-touch-record-target"
    );

    let fixture = Fixture::new();
    let lock_target = fixture.path.with_extension("lock-target");
    fs::write(&lock_target, b"do-not-touch-lock-target").expect("lock target");
    fs::set_permissions(&lock_target, fs::Permissions::from_mode(0o600)).expect("0600");
    symlink(&lock_target, fixture.store.lock_path()).expect("lock symlink");
    assert!(fixture.store.advance(hw(1, 0, 0, SERVING)).is_err());
    assert_eq!(
        fs::read(&lock_target).expect("lock target bytes"),
        b"do-not-touch-lock-target"
    );
    assert!(!fixture.path.exists());

    let fixture = Fixture::new();
    fs::create_dir(&fixture.path).expect("nonregular record");
    assert_eq!(
        refusal(fixture.store.load()),
        "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
    );

    for mode in [0o640, 0o666] {
        let fixture = Fixture::new();
        fixture.store.advance(hw(1, 0, 0, SERVING)).expect("record");
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode)).expect("mode");
        assert_eq!(
            refusal(fixture.store.load()),
            "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
        );
    }

    let fixture = Fixture::new();
    fixture.store.advance(hw(1, 0, 0, SERVING)).expect("record");
    fs::hard_link(&fixture.path, fixture.path.with_extension("hardlink")).expect("hardlink");
    assert_eq!(
        refusal(fixture.store.load()),
        "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
    );

    let outer = TempDir::new().expect("outer");
    let real = TempDir::new_in(outer.path()).expect("real parent");
    fs::set_permissions(real.path(), fs::Permissions::from_mode(0o700)).expect("0700");
    let linked_parent = outer.path().join("linked-parent");
    symlink(real.path(), &linked_parent).expect("parent symlink");
    let linked_store =
        AuthorityHighWaterStore::new(linked_parent.join("record.json")).expect("path");
    assert!(linked_store.advance(hw(1, 0, 0, SERVING)).is_err());
    assert!(linked_store.load().is_err());
    assert!(!real.path().join("record.json").exists());
    assert!(!real.path().join("record.json.lock").exists());

    for mode in [0o750, 0o777, 0o600] {
        let fixture = Fixture::new();
        let parent = fixture.path.parent().expect("parent");
        fs::set_permissions(parent, fs::Permissions::from_mode(mode)).expect("parent mode");
        assert_eq!(
            refusal(fixture.store.load()),
            "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
        );
        assert_eq!(
            refusal(fixture.store.advance(hw(1, 0, 0, SERVING))),
            "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
        );
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).expect("restore 0700");
        assert!(!fixture.path.exists());
    }
}

#[test]
fn external_authority_high_water_store_contract() {
    restart_idempotency_and_monotonic_refusal();
    fault_and_response_loss_readback();
    independent_handles_serialize_without_regression();
    strict_corruption_and_bounds_refuse_without_repair();
    hostile_filesystem_subjects_refuse_without_following();

    for path in ["relative.json", "/tmp/../tmp/high-water.json"] {
        let refused = refusal(AuthorityHighWaterStore::new(path));
        assert_eq!(refused, "AUTHORITY_HIGH_WATER_PATH_INVALID");
    }
}

#[test]
fn external_restore_epoch_and_recovery_posture_survive_restart() {
    let fixture = Fixture::new();
    let entered = hw(3, 1, 2, RECOVERING);
    let record = fixture.store.advance(entered).expect("record recovering");
    assert_record(&record, entered);
    assert_eq!(fixture.bytes(), expected_bytes(entered));
    assert_eq!(fixture.reload(), Some(record));

    let admitted = hw(3, 1, 2, SERVING);
    let record = fixture
        .store
        .advance(admitted)
        .expect("posture-only advance");
    assert_record(&record, admitted);
    assert_eq!(fixture.bytes(), expected_bytes(admitted));
    assert_eq!(fixture.reload(), Some(record.clone()));
    assert_eq!(
        fixture.store.advance(admitted).expect("exact retry"),
        record
    );
    assert_eq!(fixture.bytes(), expected_bytes(admitted));

    let next_restore = hw(4, 1, 3, RECOVERING);
    let record = fixture.store.advance(next_restore).expect("next restore");
    assert_record(&record, next_restore);
    assert_eq!(fixture.reload(), Some(record));
}

#[test]
fn external_restore_epoch_requests_are_validated_before_touching_storage() {
    let fixture = Fixture::new();
    for requested in [
        hw(0, 0, 0, SERVING),
        hw(1, 0, 0, RECOVERING),
        hw(MAX_SAFE_INTEGER + 1, 0, 0, SERVING),
        hw(1, MAX_SAFE_INTEGER + 1, 0, SERVING),
        hw(1, 0, MAX_SAFE_INTEGER + 1, SERVING),
    ] {
        let refused = refusal(fixture.store.advance(requested));
        assert_eq!(refused, "AUTHORITY_HIGH_WATER_CORRUPT");
    }
    assert!(!fixture.path.exists());
    assert!(!fixture.store.lock_path().exists());
    assert_eq!(fixture.store.load().expect("still empty"), None);
}

#[test]
fn recovery_state_codes_and_rollback_display_are_stable() {
    assert_eq!(SERVING.code(), "SERVING");
    assert_eq!(RECOVERING.code(), "RECOVERING");
    assert_eq!(
        serde_json::to_string(&RECOVERING).expect("encode"),
        "\"RECOVERING\""
    );
    assert_ne!(
        checksum(hw(1, 0, 1, SERVING)),
        checksum(hw(1, 0, 1, RECOVERING))
    );
    let error = AuthorityHighWaterError::Rollback {
        current: hw(4, 3, 2, RECOVERING),
        requested: hw(4, 3, 1, SERVING),
    };
    assert_eq!(
        error.to_string(),
        "AUTHORITY_HIGH_WATER_ROLLBACK: current=(authority_epoch=4,freeze_generation=3,restore_epoch=2,recovery=RECOVERING) requested=(authority_epoch=4,freeze_generation=3,restore_epoch=1,recovery=SERVING)"
    );
}
