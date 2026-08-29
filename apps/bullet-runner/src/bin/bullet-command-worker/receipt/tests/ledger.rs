//! Hostiles for semantic retained-ledger admission.

use super::*;
use rusqlite::Connection;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

#[tokio::test]
async fn header_only_ledger_refuses_without_further_artifact_mutation() {
    let fixture = Fixture::new(false).await;
    let ledger = fixture.run.join("data/ledger.sqlite");
    std::fs::remove_file(&ledger).unwrap();
    ledger_fixture::write_header(&ledger);
    let before = snapshot(&fixture.run);
    assert_eq!(
        fixture.admit().unwrap_err().code(),
        "COMMAND_RECEIPT_INVALID"
    );
    assert_eq!(snapshot(&fixture.run), before);
}

#[tokio::test]
async fn semantic_ledger_substitutions_refuse_without_further_mutation() {
    let cases = [
        "UPDATE attempts SET state='failed' WHERE state='succeeded'",
        "INSERT INTO active_leases VALUES ('var_'||hex(randomblob(32)),'atm_'||hex(randomblob(32)),1,'run_'||hex(randomblob(32)),1,zeroblob(32),'now','later')",
        "UPDATE effect_intents SET attempt_id=(SELECT id FROM attempts WHERE state='succeeded')",
        "UPDATE effect_receipts SET adopted_after_unknown=0",
        "DELETE FROM events WHERE body LIKE '%DISPATCHING->OUTCOME_UNKNOWN'",
        "DELETE FROM lease_transport_settlements WHERE record_json LIKE '%\"final_state\":\"superseded\"%'",
        "UPDATE lease_transport_settlements SET record_json=replace(record_json,'\"state\":\"succeeded\"','\"state\":\"failed\"') WHERE record_json LIKE '%\"final_state\":\"succeeded\"%'",
    ];
    for sql in cases {
        let fixture = Fixture::new(false).await;
        let connection = Connection::open(fixture.run.join("data/ledger.sqlite")).unwrap();
        connection.execute(sql, []).unwrap();
        drop(connection);
        let before = snapshot(&fixture.run);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID",
            "accepted {sql}"
        );
        assert_eq!(snapshot(&fixture.run), before, "mutated after {sql}");
    }
}

#[tokio::test]
async fn sqlite_sidecars_refuse_without_mutation() {
    for suffix in ["-journal", "-wal", "-shm"] {
        let fixture = Fixture::new(false).await;
        let ledger = fixture.run.join("data/ledger.sqlite");
        let mut sidecar = ledger.as_os_str().to_os_string();
        sidecar.push(suffix);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(PathBuf::from(sidecar))
            .unwrap();
        let before = snapshot(&fixture.run);
        assert_eq!(
            fixture.admit().unwrap_err().code(),
            "COMMAND_RECEIPT_INVALID"
        );
        assert_eq!(snapshot(&fixture.run), before);
    }
}

#[tokio::test]
async fn transient_path_substitution_cannot_replace_descriptor_truth() {
    let fixture = Fixture::new(false).await;
    let ledger = fixture.run.join("data/ledger.sqlite");
    let backup = fixture.run.join("data/ledger.original");
    let substitute = fixture.run.join("data/ledger.substitute");
    std::fs::copy(&ledger, &substitute).unwrap();
    Connection::open(&substitute)
        .unwrap()
        .execute("UPDATE attempts SET state='failed'", [])
        .unwrap();
    let before = snapshot(&fixture.run);
    let expected = ledger.clone();
    artifacts::install_test_hook(move |path, stage| {
        assert_eq!(path, expected);
        match stage {
            "before_reads" => {
                std::fs::rename(path, &backup).unwrap();
                std::fs::rename(&substitute, path).unwrap();
            }
            "after_reads" => {
                std::fs::rename(path, &substitute).unwrap();
                std::fs::rename(&backup, path).unwrap();
            }
            _ => {}
        }
    });
    let result = fixture.admit();
    artifacts::clear_test_hook();
    result.unwrap();
    assert_eq!(snapshot(&fixture.run), before);
}

#[tokio::test]
async fn persistent_path_substitution_refuses_after_snapshot() {
    let fixture = Fixture::new(false).await;
    let ledger = fixture.run.join("data/ledger.sqlite");
    let backup = fixture.run.join("data/ledger.original");
    let substitute = fixture.run.join("data/ledger.substitute");
    std::fs::copy(&ledger, &substitute).unwrap();
    let expected = ledger.clone();
    let backup_hook = backup.clone();
    let substitute_hook = substitute.clone();
    artifacts::install_test_hook(move |path, stage| {
        assert_eq!(path, expected);
        if stage == "before_reads" {
            std::fs::rename(path, &backup_hook).unwrap();
            std::fs::rename(&substitute_hook, path).unwrap();
        }
    });
    let result = fixture.admit();
    artifacts::clear_test_hook();
    std::fs::rename(&ledger, &substitute).unwrap();
    std::fs::rename(&backup, &ledger).unwrap();
    assert_eq!(result.unwrap_err().code(), "COMMAND_RECEIPT_INVALID");
}

#[tokio::test]
async fn between_query_main_file_mutation_refuses() {
    let fixture = Fixture::new(false).await;
    let ledger = fixture.run.join("data/ledger.sqlite");
    let expected = ledger.clone();
    artifacts::install_test_hook(move |path, stage| {
        assert_eq!(path, expected);
        if stage == "between_queries" {
            let length = std::fs::metadata(path).unwrap().len();
            std::thread::sleep(Duration::from_millis(2));
            let mut file = OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(b"x").unwrap();
            file.set_len(length).unwrap();
            file.sync_data().unwrap();
        }
    });
    let result = fixture.admit();
    artifacts::clear_test_hook();
    assert_eq!(result.unwrap_err().code(), "COMMAND_RECEIPT_INVALID");
}

#[derive(Debug, Eq, PartialEq)]
struct Entry {
    path: String,
    mode: u32,
    inode: u64,
    bytes: Vec<u8>,
}

fn snapshot(root: &Path) -> Vec<Entry> {
    let mut entries = Vec::new();
    collect(root, root, &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn collect(root: &Path, path: &Path, entries: &mut Vec<Entry>) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    let bytes = if metadata.is_file() {
        std::fs::read(path).unwrap()
    } else if metadata.file_type().is_symlink() {
        std::fs::read_link(path)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec()
    } else {
        Vec::new()
    };
    entries.push(Entry {
        path: path.strip_prefix(root).unwrap().display().to_string(),
        mode: metadata.mode(),
        inode: metadata.ino(),
        bytes,
    });
    if metadata.is_dir() {
        let mut children = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            collect(root, &child, entries);
        }
    }
}
