//! Operator key custody: 0700 directory, 0600 key, no symlink, no overwrite.

#![cfg(unix)]

use bullet_harness_core::launch_grant::{
    load_signing_key, signing_key_path, write_new_signing_key, LaunchGrantSigningKey,
    LAUNCH_GRANT_KEY_FILE,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

fn fresh_data_dir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap();
    (directory, path)
}

#[test]
fn keygen_creates_private_material_and_never_overwrites() {
    let (_guard, data_dir) = fresh_data_dir();
    let key = write_new_signing_key(&data_dir, "bullet-kernel", "launch-grant-alpha").unwrap();
    let path = signing_key_path(&data_dir);
    assert!(path.ends_with(LAUNCH_GRANT_KEY_FILE));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(data_dir.join("authority"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(fs::read(&path).unwrap().len(), 64);
    let loaded = load_signing_key(&data_dir, "bullet-kernel", "launch-grant-alpha").unwrap();
    assert_eq!(loaded.public_key_hex(), key.public_key_hex());
    assert_eq!(loaded.secret_bytes(), key.secret_bytes());
    let again =
        write_new_signing_key(&data_dir, "bullet-kernel", "launch-grant-alpha").unwrap_err();
    assert_eq!(again.reason_code(), "LAUNCH_GRANT_INVALID");
    assert!(again.to_string().contains("refusing to overwrite"));
    assert_eq!(fs::read(&path).unwrap(), key.secret_bytes());
    assert!(!format!("{key:?}").contains(&hex::encode(key.secret_bytes())));
}

#[test]
fn loose_mode_symlink_relative_and_short_keys_are_refused() {
    let (_guard, data_dir) = fresh_data_dir();
    write_new_signing_key(&data_dir, "bullet-kernel", "launch-grant-alpha").unwrap();
    let path = signing_key_path(&data_dir);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let loose = load_signing_key(&data_dir, "bullet-kernel", "launch-grant-alpha").unwrap_err();
    assert_eq!(loose.reason_code(), "LAUNCH_GRANT_INVALID");
    assert!(loose.to_string().contains("0600"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_signing_key(&data_dir, "bullet-kernel", "launch-grant-alpha").is_ok());

    let (_other_guard, other) = fresh_data_dir();
    fs::create_dir(other.join("authority")).unwrap();
    symlink(&path, signing_key_path(&other)).unwrap();
    let linked = load_signing_key(&other, "bullet-kernel", "launch-grant-alpha").unwrap_err();
    assert_eq!(linked.reason_code(), "LAUNCH_GRANT_INVALID");
    assert!(linked.to_string().contains("symlink"));

    let relative = load_signing_key(
        std::path::Path::new("relative/data"),
        "bullet-kernel",
        "launch-grant-alpha",
    )
    .unwrap_err();
    assert_eq!(relative.reason_code(), "LAUNCH_GRANT_INVALID");
    assert_eq!(
        write_new_signing_key(std::path::Path::new("relative"), "bullet-kernel", "k")
            .unwrap_err()
            .reason_code(),
        "LAUNCH_GRANT_INVALID"
    );

    let (_short_guard, short) = fresh_data_dir();
    fs::create_dir(short.join("authority")).unwrap();
    fs::write(signing_key_path(&short), [7_u8; 32]).unwrap();
    fs::set_permissions(signing_key_path(&short), fs::Permissions::from_mode(0o600)).unwrap();
    let truncated = load_signing_key(&short, "bullet-kernel", "launch-grant-alpha").unwrap_err();
    assert_eq!(truncated.reason_code(), "LAUNCH_GRANT_INVALID");

    let (_missing_guard, missing) = fresh_data_dir();
    let absent = load_signing_key(&missing, "bullet-kernel", "launch-grant-alpha").unwrap_err();
    assert_eq!(absent.reason_code(), "IO_FAILED");
}

#[test]
fn key_material_rules_are_exact() {
    assert!(LaunchGrantSigningKey::from_bytes("issuer", "key", &[0_u8; 64]).is_err());
    assert!(LaunchGrantSigningKey::from_bytes("issuer", "key", &[1_u8; 63]).is_err());
    assert!(LaunchGrantSigningKey::generate("bad issuer", "key").is_err());
    let generated = LaunchGrantSigningKey::generate("issuer", "key").unwrap();
    let other = LaunchGrantSigningKey::generate("issuer", "key").unwrap();
    assert_ne!(generated.public_key_hex(), other.public_key_hex());
    let verification = generated.verification_key().unwrap();
    assert_eq!(verification.public_key_hex(), generated.public_key_hex());
    assert_eq!(verification.issuer(), "issuer");
    assert_eq!(verification.key_id(), "key");
}
