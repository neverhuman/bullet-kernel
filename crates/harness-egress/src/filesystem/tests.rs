use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn only_proxy_composition_shares_the_existing_network_namespace() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let clone_directory = root.path().join("clone");
    let scratch_directory = root.path().join("scratch");
    fs::create_dir(&clone_directory).unwrap();
    fs::create_dir(&scratch_directory).unwrap();
    fs::set_permissions(&clone_directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&scratch_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = FilesystemSandboxProfileV0::new(
        admitted("/usr/bin/bwrap"),
        admitted("/usr/bin/false"),
        clone_directory,
        admitted("/etc/hosts"),
        admitted("/etc/ssl/certs/ca-certificates.crt"),
        vec![],
        scratch_directory,
    )
    .prepare()
    .unwrap();

    let direct = prepared.command_plan(&[]).unwrap();
    assert!(!has_argument(&direct, "--share-net"));
    drop(direct);

    let composed = prepared
        .command_plan_with_proxy(&[], Some("http://10.0.2.2:41000"))
        .unwrap();
    assert!(has_argument(&composed, "--share-net"));
    assert!(has_argument(&composed, "HTTPS_PROXY"));
    assert!(has_argument(&composed, "http://10.0.2.2:41000"));
}

fn admitted(path: &str) -> FilesystemFileV0 {
    let path = fs::canonicalize(path).unwrap();
    let digest = blake3::hash(&fs::read(&path).unwrap()).to_hex().to_string();
    FilesystemFileV0::new(path, digest)
}

fn has_argument(plan: &FilesystemCommandPlan<'_>, expected: &str) -> bool {
    plan.arguments().iter().any(|argument| argument == expected)
}
