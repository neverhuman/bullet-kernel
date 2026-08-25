#![cfg(target_os = "linux")]

use super::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;
use tempfile::TempDir;

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
}

fn assert_record(record: &AuthorityHighWaterV1, epoch: u64, generation: u64) {
    assert_eq!(record.schema_version, AUTHORITY_HIGH_WATER_SCHEMA_VERSION);
    assert_eq!(record.authority_epoch, epoch);
    assert_eq!(record.freeze_generation, generation);
    assert_eq!(record.checksum, checksum(epoch, generation));
}

fn restart_idempotency_and_monotonic_refusal() {
    let fixture = Fixture::new();
    assert_eq!(fixture.store.load().expect("empty load"), None);
    let initial = fixture.store.advance(1, 0).expect("initialize");
    assert_record(&initial, 1, 0);
    let bytes = fs::read(&fixture.path).expect("record bytes");

    let restarted = AuthorityHighWaterStore::new(&fixture.path).expect("reopen");
    assert_eq!(
        restarted.load().expect("restart readback"),
        Some(initial.clone())
    );
    assert_eq!(restarted.advance(1, 0).expect("exact retry"), initial);
    assert_eq!(fs::read(&fixture.path).expect("retry bytes"), bytes);

    let current = restarted.advance(4, 3).expect("advance both");
    for (epoch, generation) in [(3, 3), (4, 2), (5, 2), (3, 4)] {
        let before = fs::read(&fixture.path).expect("pre-refusal bytes");
        let error = restarted
            .advance(epoch, generation)
            .expect_err("rollback refused");
        assert_eq!(error.reason_code(), "AUTHORITY_HIGH_WATER_ROLLBACK");
        assert_eq!(fs::read(&fixture.path).expect("post-refusal bytes"), before);
    }
    assert_eq!(restarted.load().expect("monotonic readback"), Some(current));
}

fn fault_and_response_loss_readback() {
    let fixture = Fixture::new();
    let initial = fixture.store.advance(1, 0).expect("initialize");
    let error = fixture
        .store
        .advance_with_fault(2, 1, FaultPoint::BeforePublish)
        .expect_err("prepublication failure");
    assert_eq!(error.reason_code(), "AUTHORITY_HIGH_WATER_OPERATION_FAILED");
    assert_eq!(fixture.store.load().expect("old state"), Some(initial));

    let error = fixture
        .store
        .advance_with_fault(2, 1, FaultPoint::AfterReadback)
        .expect_err("lost response");
    assert_eq!(error.reason_code(), "AUTHORITY_HIGH_WATER_RESPONSE_LOST");
    let reopened = AuthorityHighWaterStore::new(&fixture.path).expect("reopen after response loss");
    let durable = reopened
        .load()
        .expect("response-loss readback")
        .expect("durable record");
    assert_record(&durable, 2, 1);
    assert_eq!(reopened.advance(2, 1).expect("safe exact retry"), durable);
}

fn independent_handles_serialize_without_regression() {
    let fixture = Fixture::new();
    fixture.store.advance(1, 0).expect("initialize");

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
        done_tx.send(store.advance(2, 1)).expect("result");
    });
    started_rx.recv().expect("second handle started");
    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    drop(held);
    assert_record(
        &done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("unblocked result")
            .expect("unblocked advance"),
        2,
        1,
    );
    blocked.join().expect("blocked writer joined");

    let barrier = Arc::new(Barrier::new(3));
    let mut joins = Vec::new();
    for (epoch, generation) in [(3, 2), (4, 3)] {
        let path = fixture.path.clone();
        let barrier = Arc::clone(&barrier);
        joins.push(std::thread::spawn(move || {
            let store = AuthorityHighWaterStore::new(path).expect("parallel handle");
            barrier.wait();
            store.advance(epoch, generation)
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
            .is_ok_and(|record| record.authority_epoch == 4 && record.freeze_generation == 3)
    }));
    let final_record = fixture
        .store
        .load()
        .expect("final readback")
        .expect("record");
    assert_record(&final_record, 4, 3);
}

fn strict_corruption_and_bounds_refuse_without_repair() {
    for bytes in [b"{}".as_slice(), b"not-json".as_slice()] {
        let fixture = Fixture::new();
        fixture.write_raw(bytes);
        let before = fs::read(&fixture.path).expect("corrupt bytes");
        assert_eq!(
            fixture
                .store
                .advance(2, 1)
                .expect_err("corrupt refusal")
                .reason_code(),
            "AUTHORITY_HIGH_WATER_CORRUPT"
        );
        assert_eq!(fs::read(&fixture.path).expect("unrepaired bytes"), before);
    }

    let valid = AuthorityHighWaterV1::from_values(2, 1).expect("valid record");
    for mutate in [
        |value: &mut serde_json::Value| value["schema_version"] = json!(2),
        |value: &mut serde_json::Value| value["checksum"] = json!("0".repeat(64)),
        |value: &mut serde_json::Value| value["unknown"] = json!(true),
        |value: &mut serde_json::Value| value["authority_epoch"] = json!(MAX_SAFE_INTEGER + 1),
    ] {
        let fixture = Fixture::new();
        let mut value = serde_json::to_value(&valid).expect("record value");
        mutate(&mut value);
        fixture.write_raw(&serde_json::to_vec(&value).expect("hostile JSON"));
        assert_eq!(
            fixture
                .store
                .load()
                .expect_err("strict refusal")
                .reason_code(),
            "AUTHORITY_HIGH_WATER_CORRUPT"
        );
    }

    let fixture = Fixture::new();
    fixture.write_raw(&vec![b'x'; usize::try_from(MAX_RECORD_BYTES + 1).unwrap()]);
    assert_eq!(
        fixture
            .store
            .load()
            .expect_err("bounded refusal")
            .reason_code(),
        "AUTHORITY_HIGH_WATER_CORRUPT"
    );
}

fn hostile_filesystem_subjects_refuse_without_following() {
    let fixture = Fixture::new();
    let target = fixture.path.with_extension("target");
    fs::write(&target, b"do-not-touch-record-target").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("0600");
    symlink(&target, &fixture.path).expect("record symlink");
    assert!(fixture.store.advance(1, 0).is_err());
    assert_eq!(
        fs::read(&target).expect("target bytes"),
        b"do-not-touch-record-target"
    );

    let fixture = Fixture::new();
    let lock_target = fixture.path.with_extension("lock-target");
    fs::write(&lock_target, b"do-not-touch-lock-target").expect("lock target");
    fs::set_permissions(&lock_target, fs::Permissions::from_mode(0o600)).expect("0600");
    symlink(&lock_target, fixture.store.lock_path()).expect("lock symlink");
    assert!(fixture.store.advance(1, 0).is_err());
    assert_eq!(
        fs::read(&lock_target).expect("lock target bytes"),
        b"do-not-touch-lock-target"
    );
    assert!(!fixture.path.exists());

    let fixture = Fixture::new();
    fs::create_dir(&fixture.path).expect("nonregular record");
    assert_eq!(
        fixture
            .store
            .load()
            .expect_err("nonregular refusal")
            .reason_code(),
        "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
    );

    let fixture = Fixture::new();
    fixture.store.advance(1, 0).expect("record");
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o640)).expect("0640");
    assert_eq!(
        fixture
            .store
            .load()
            .expect_err("mode refusal")
            .reason_code(),
        "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
    );

    let fixture = Fixture::new();
    fixture.store.advance(1, 0).expect("record");
    fs::hard_link(&fixture.path, fixture.path.with_extension("hardlink")).expect("hardlink");
    assert_eq!(
        fixture
            .store
            .load()
            .expect_err("link-count refusal")
            .reason_code(),
        "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
    );

    let outer = TempDir::new().expect("outer");
    let real = TempDir::new_in(outer.path()).expect("real parent");
    fs::set_permissions(real.path(), fs::Permissions::from_mode(0o700)).expect("0700");
    let linked_parent = outer.path().join("linked-parent");
    symlink(real.path(), &linked_parent).expect("parent symlink");
    let linked_store =
        AuthorityHighWaterStore::new(linked_parent.join("record.json")).expect("path");
    assert!(linked_store.advance(1, 0).is_err());
    assert!(!real.path().join("record.json").exists());

    let fixture = Fixture::new();
    fs::set_permissions(
        fixture.path.parent().expect("parent"),
        fs::Permissions::from_mode(0o750),
    )
    .expect("0750");
    assert_eq!(
        fixture
            .store
            .load()
            .expect_err("parent mode refusal")
            .reason_code(),
        "AUTHORITY_HIGH_WATER_ADMISSION_REFUSED"
    );
}

#[test]
fn external_authority_high_water_store_contract() {
    restart_idempotency_and_monotonic_refusal();
    fault_and_response_loss_readback();
    independent_handles_serialize_without_regression();
    strict_corruption_and_bounds_refuse_without_repair();
    hostile_filesystem_subjects_refuse_without_following();

    let relative = AuthorityHighWaterStore::new("relative.json").expect_err("relative refused");
    assert_eq!(relative.reason_code(), "AUTHORITY_HIGH_WATER_PATH_INVALID");
    let traversal =
        AuthorityHighWaterStore::new("/tmp/../tmp/high-water.json").expect_err("traversal refused");
    assert_eq!(traversal.reason_code(), "AUTHORITY_HIGH_WATER_PATH_INVALID");
}
