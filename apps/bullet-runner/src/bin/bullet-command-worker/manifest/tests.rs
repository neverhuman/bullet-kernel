use super::*;
use std::os::unix::fs::{symlink, OpenOptionsExt};

fn digest(path: &Path) -> String {
    sha256_bytes(&std::fs::read(path).unwrap())
}

fn write_manifest(root: &Path, binary: &Path) -> PathBuf {
    let subject = BinarySubject {
        path: binary.into(),
        sha256: digest(binary),
    };
    let manifest = BinaryManifest {
        schema_version: MANIFEST_SCHEMA.into(),
        transaction_offline: subject.clone(),
        farmd: subject.clone(),
        runner: subject.clone(),
        gitd: subject.clone(),
        verifier: subject,
    };
    let path = root.join("manifest.json");
    let bytes = canonical_json(&manifest).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    path
}

#[test]
fn exact_manifest_copies_every_subject_to_a_sealed_image() {
    let root = tempfile::tempdir().unwrap();
    let binary = std::fs::canonicalize("/bin/true").unwrap();
    let admitted = AdmittedManifest::admit(&write_manifest(root.path(), &binary)).unwrap();
    assert_eq!(admitted.transaction_offline.sha256(), digest(&binary));
    assert!(admitted.transaction_offline.procfd_path().exists());
    assert!(lower_hex(admitted.sha256()));
}

#[test]
fn symlink_digest_drift_noncanonical_and_unknown_manifest_refuse() {
    let root = tempfile::tempdir().unwrap();
    let binary = std::fs::canonicalize("/bin/true").unwrap();
    let link = root.path().join("linked");
    symlink(&binary, &link).unwrap();
    let linked = write_manifest(root.path(), &link);
    assert_eq!(
        AdmittedManifest::admit(&linked).unwrap_err().code(),
        "BINARY_SUBJECT_ADMISSION_REFUSED"
    );

    let second = tempfile::tempdir().unwrap();
    let path = write_manifest(second.path(), &binary);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["transaction_offline"]["sha256"] = serde_json::json!("0".repeat(64));
    std::fs::write(&path, canonical_json(&value).unwrap()).unwrap();
    assert_eq!(
        AdmittedManifest::admit(&path).unwrap_err().code(),
        "BINARY_SUBJECT_ADMISSION_REFUSED"
    );

    value["unknown"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    assert_eq!(
        AdmittedManifest::admit(&path).unwrap_err().code(),
        "BINARY_MANIFEST_INVALID"
    );
}

#[test]
fn only_root_or_the_service_owner_is_trusted() {
    let own = rustix::process::geteuid().as_raw();
    assert!(trusted_owner(0));
    assert!(trusted_owner(own));
    let foreign = if own == 1 { 2 } else { 1 };
    assert!(!trusted_owner(foreign));
}
