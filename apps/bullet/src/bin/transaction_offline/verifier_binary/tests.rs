use super::*;
use std::fs::{self, hard_link};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

fn executable_fixture(directory: &Path, name: &str, source: &str) -> PathBuf {
    let path = directory.join(name);
    fs::copy(source, &path).expect("copy native executable");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod fixture");
    path
}

fn sha256(path: &Path) -> String {
    let mut file = File::open(path).expect("open fixture");
    sha256_and_count(&mut file).expect("hash fixture").0
}

fn admit_file(file: &File, digest: &str) -> Result<AdmittedVerifierFixture, String> {
    admit_inherited_fd(file.as_raw_fd(), digest)
}

fn sealed_executable(source: &str) -> (File, String) {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, Mode};
    let descriptor =
        memfd_create("sealed-verifier-source", MemfdFlags::ALLOW_SEALING).expect("memfd");
    let mut sealed = File::from(descriptor);
    std::io::copy(&mut File::open(source).expect("source"), &mut sealed).expect("copy source");
    rustix::fs::fchmod(&sealed, Mode::from_raw_mode(0o500)).expect("chmod sealed source");
    fcntl_add_seals(&sealed, mandatory_seals()).expect("seal source");
    sealed.seek(SeekFrom::Start(0)).expect("rewind source");
    let digest = sha256_and_count(&mut sealed).expect("hash sealed source").0;
    sealed.seek(SeekFrom::Start(0)).expect("rewind source");
    (sealed, digest)
}

#[test]
fn missing_malformed_and_release_subjects_refuse() {
    let unavailable = configured_for_build(false, None, None).unwrap_err();
    assert!(unavailable.contains("ADMISSION_REFUSED"));
    let missing_fd =
        configured_for_build(true, None, Some(OsString::from("0".repeat(64)))).unwrap_err();
    assert!(missing_fd.contains(FD_ENV));
    let missing_digest = configured_for_build(true, Some(OsString::from("3")), None).unwrap_err();
    assert!(missing_digest.contains(DIGEST_ENV));
    let malformed = configured_for_build(
        true,
        Some(OsString::from("3")),
        Some(OsString::from("A".repeat(64))),
    )
    .unwrap_err();
    assert!(malformed.contains("64 lowercase hexadecimal"));
    for invalid in ["/bin/false", "03", "-1", "2", "2147483648"] {
        let error = configured_for_build(
            true,
            Some(OsString::from(invalid)),
            Some(OsString::from("0".repeat(64))),
        )
        .unwrap_err();
        assert!(error.contains("descriptor"), "{invalid}: {error}");
    }
}

#[test]
fn closed_directory_non_executable_oversize_and_wrong_digest_refuse() {
    let directory = tempfile::tempdir().expect("tempdir");
    let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
    let digest = sha256(&executable);
    let file = File::open(&executable).expect("open fixture");
    assert!(admit_file(&file, &"0".repeat(64)).is_err());

    let closed_fd = file.as_raw_fd();
    drop(file);
    assert!(admit_inherited_fd(closed_fd, &digest).is_err());

    let directory_fd = File::open(directory.path()).expect("open directory");
    assert!(admit_file(&directory_fd, &digest).is_err());
    let (socket, _peer) = UnixStream::pair().expect("socket pair");
    assert!(admit_inherited_fd(socket.as_raw_fd(), &digest).is_err());

    let empty = directory.path().join("empty");
    File::create(&empty).expect("create empty fixture");
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).expect("chmod empty");
    assert!(admit_file(&File::open(&empty).expect("open empty"), &digest).is_err());

    let unlinked_path = executable_fixture(directory.path(), "unlinked", "/bin/sh");
    let unlinked = File::open(&unlinked_path).expect("open unlinked fixture");
    fs::remove_file(unlinked_path).expect("unlink retained fixture");
    assert!(admit_file(&unlinked, &digest).is_err());

    let unsealed_fd = rustix::fs::memfd_create(
        "unsealed-verifier-source",
        rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("memfd");
    let mut unsealed = File::from(unsealed_fd);
    std::io::copy(&mut File::open("/bin/sh").expect("source"), &mut unsealed).expect("copy source");
    rustix::fs::fchmod(&unsealed, rustix::fs::Mode::from_raw_mode(0o500)).expect("chmod");
    unsealed.seek(SeekFrom::Start(0)).expect("rewind");
    let unsealed_digest = sha256_and_count(&mut unsealed).expect("hash").0;
    assert!(admit_file(&unsealed, &unsealed_digest).is_err());

    let non_native = directory.path().join("non-native");
    fs::write(&non_native, b"not a native ELF executable").expect("write non-native fixture");
    fs::set_permissions(&non_native, fs::Permissions::from_mode(0o700))
        .expect("chmod non-native fixture");
    let non_native_file = File::open(&non_native).expect("open non-native fixture");
    assert!(admit_file(&non_native_file, &sha256(&non_native)).is_err());

    let non_executable = executable_fixture(directory.path(), "non-exec", "/bin/sh");
    fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o600))
        .expect("remove execute bit");
    let non_executable_file = File::open(&non_executable).expect("open non-executable");
    assert!(admit_file(&non_executable_file, &sha256(&non_executable)).is_err());

    let oversized = directory.path().join("oversized");
    let oversized_file = File::create(&oversized).expect("create oversized fixture");
    oversized_file
        .set_len(MAX_EXECUTABLE_BYTES + 1)
        .expect("make sparse oversized fixture");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o700))
        .expect("make oversized fixture executable");
    assert!(admit_file(&oversized_file, &digest).is_err());
}

#[test]
fn two_link_fixture_is_sealed_before_sibling_link_mutation() {
    let (sealed_source, sealed_digest) = sealed_executable("/bin/sh");
    assert_eq!(sealed_source.metadata().expect("metadata").nlink(), 0);
    admit_file(&sealed_source, &sealed_digest).expect("admit mandatory-sealed source");

    let directory = tempfile::tempdir().expect("tempdir");
    let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
    let linked = directory.path().join("cargo-linked-fixture");
    hard_link(&executable, &linked).expect("hardlink fixture");
    let digest = sha256(&executable);
    let mut inherited = File::open(&linked).expect("open inherited fixture");
    assert_eq!(inherited.metadata().expect("metadata").nlink(), 2);
    inherited
        .seek(SeekFrom::End(0))
        .expect("advance inherited source offset");
    let admitted = configured_for_build(
        true,
        Some(OsString::from(inherited.as_raw_fd().to_string())),
        Some(OsString::from(digest)),
    )
    .expect("admit two-link fixture through canonical fd grammar");
    fs::copy("/bin/false", &executable).expect("substitute source path");
    let marker = directory.path().join("sealed-ran");
    let status = Command::new(admitted.spawn_path().expect("sealed procfd"))
        .args(["-c", "printf sealed > \"$1\"", "bullet-fixture"])
        .arg(&marker)
        .status()
        .expect("spawn sealed image");
    assert!(status.success());
    assert_eq!(fs::read_to_string(marker).expect("marker"), "sealed");
}

#[test]
fn sibling_link_mutation_after_identity_binding_refuses() {
    let directory = tempfile::tempdir().expect("tempdir");
    let executable = executable_fixture(directory.path(), "fixture", "/bin/sh");
    let sibling = directory.path().join("sibling");
    hard_link(&executable, &sibling).expect("hardlink fixture");
    let digest = sha256(&executable);
    let inherited = File::open(&executable).expect("open inherited fixture");
    let error = admit_inherited_fd_with_hook(inherited.as_raw_fd(), &digest, || {
        fs::copy("/bin/false", &sibling).expect("mutate sibling link");
    })
    .unwrap_err();
    assert!(error.contains("changed while hashing"));
}
