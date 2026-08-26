use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::process::Command;
use tempfile::TempDir;

#[cfg(target_os = "linux")]
fn init_with_permissive_umask(binary: &str, data: &std::path::Path) -> std::process::Output {
    Command::new("/bin/sh")
        .args([
            "-c",
            "umask 0002; exec \"$1\" farm init",
            "bullet-farm-init",
        ])
        .arg(binary)
        .env("BULLET_DATA_DIR", data)
        .output()
        .unwrap()
}

#[test]
#[cfg(target_os = "linux")]
fn backup_and_quarantined_restore_are_explicit_offline_commands() {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let data = directory.path().join("data");
    let backup = directory.path().join("snapshot.sqlite");
    let receipt = directory.path().join("snapshot.receipt.json");
    let restored = directory.path().join("restored.sqlite");
    let binary = env!("CARGO_BIN_EXE_bullet");

    let init = init_with_permissive_umask(binary, &data);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert_eq!(fs::metadata(&data).unwrap().mode() & 0o7777, 0o700);
    let source = data.join("ledger.sqlite");

    let loose = directory.path().join("loose-data");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
    let repaired = init_with_permissive_umask(binary, &loose);
    assert!(
        repaired.status.success(),
        "{}",
        String::from_utf8_lossy(&repaired.stderr)
    );
    assert_eq!(fs::metadata(&loose).unwrap().mode() & 0o7777, 0o700);

    let target = directory.path().join("symlink-target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    let linked = directory.path().join("linked-data");
    symlink(&target, &linked).unwrap();
    let refused = init_with_permissive_umask(binary, &linked);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("without following links"));
    assert_eq!(fs::metadata(&target).unwrap().mode() & 0o7777, 0o755);
    assert!(!target.join("ledger.sqlite").exists());

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
