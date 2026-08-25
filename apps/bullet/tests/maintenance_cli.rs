use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn backup_and_quarantined_restore_are_explicit_offline_commands() {
    let directory = TempDir::new().unwrap();
    let data = directory.path().join("data");
    let backup = directory.path().join("snapshot.sqlite");
    let receipt = directory.path().join("snapshot.receipt.json");
    let restored = directory.path().join("restored.sqlite");
    let binary = env!("CARGO_BIN_EXE_bullet");

    let init = Command::new(binary)
        .args(["farm", "init"])
        .env("BULLET_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let source = data.join("ledger.sqlite");

    let backed_up = Command::new(binary)
        .args(["farm", "backup", "--database"])
        .arg(&source)
        .arg("--output")
        .arg(&backup)
        .arg("--receipt")
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(
        backed_up.status.success(),
        "{}",
        String::from_utf8_lossy(&backed_up.stderr)
    );
    let receipt_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(receipt_json["integrity"], "PASS");

    let restored_run = Command::new(binary)
        .args(["farm", "restore", "--backup"])
        .arg(&backup)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--destination")
        .arg(&restored)
        .output()
        .unwrap();
    assert!(
        restored_run.status.success(),
        "{}",
        String::from_utf8_lossy(&restored_run.stderr)
    );
    assert!(String::from_utf8_lossy(&restored_run.stderr).contains("quarantined"));
    assert!(restored.exists());

    let before = fs::read(&restored).unwrap();
    let replay = Command::new(binary)
        .args(["farm", "restore", "--backup"])
        .arg(&backup)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--destination")
        .arg(&restored)
        .output()
        .unwrap();
    assert!(!replay.status.success());
    assert_eq!(fs::read(restored).unwrap(), before);
}
