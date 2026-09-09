use super::{decode_expected_passport, linux, InspectedProviderRuntimeV1, RuntimePassportError};
use crate::admission::ProviderProtocol;
use crate::runtime_passport::{
    ProviderRuntimePassportV1, RuntimeExecutionV1, RuntimeFileRoleV1, RuntimeFileV1,
    RuntimeLoaderV1,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Fixture {
    temporary: tempfile::TempDir,
    anchor: PathBuf,
    root_relative: PathBuf,
    root: PathBuf,
    bytes: Vec<u8>,
    id: String,
}

impl Fixture {
    fn new(provider: &str, protocol: ProviderProtocol, interpreted: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let anchor = temporary.path().to_path_buf();
        let root_relative = PathBuf::from("runtime");
        let root = anchor.join(&root_relative);
        let entrypoint = format!("bin/{provider}");
        let members = if interpreted {
            vec![
                (
                    entrypoint.clone(),
                    RuntimeFileRoleV1::Entrypoint,
                    0o555,
                    b"entrypoint".to_vec(),
                ),
                (
                    "bin/node".into(),
                    RuntimeFileRoleV1::Interpreter,
                    0o555,
                    b"interpreter".to_vec(),
                ),
                (
                    "lib/index.js".into(),
                    RuntimeFileRoleV1::Module,
                    0o444,
                    b"module".to_vec(),
                ),
            ]
        } else {
            vec![
                (
                    entrypoint.clone(),
                    RuntimeFileRoleV1::Entrypoint,
                    0o555,
                    b"entrypoint".to_vec(),
                ),
                (
                    "lib/ld.so".into(),
                    RuntimeFileRoleV1::Loader,
                    0o555,
                    b"loader".to_vec(),
                ),
                (
                    "lib/provider.so".into(),
                    RuntimeFileRoleV1::NativeLibrary,
                    0o444,
                    b"library".to_vec(),
                ),
            ]
        };
        let mut files = Vec::new();
        for (path, role, mode, contents) in &members {
            let destination = root.join(path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(&destination, contents).unwrap();
            fs::set_permissions(&destination, fs::Permissions::from_mode(*mode)).unwrap();
            files.push(RuntimeFileV1 {
                path: path.clone(),
                role: *role,
                mode: *mode,
                size: contents.len() as u64,
                blake3: blake3::hash(contents).to_hex().to_string(),
            });
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        freeze_directories(&root);
        let linked_digest = files
            .iter()
            .find(|file| {
                matches!(
                    file.role,
                    RuntimeFileRoleV1::Interpreter | RuntimeFileRoleV1::Loader
                )
            })
            .unwrap()
            .blake3
            .clone();
        let execution = if interpreted {
            RuntimeExecutionV1::Interpreted {
                interpreter_path: "bin/node".into(),
                interpreter_blake3: linked_digest,
                loader: RuntimeLoaderV1::Static,
            }
        } else {
            RuntimeExecutionV1::Native {
                loader: RuntimeLoaderV1::Dynamic {
                    path: "lib/ld.so".into(),
                    blake3: linked_digest,
                },
            }
        };
        let passport = ProviderRuntimePassportV1 {
            schema_version: 1,
            provider: provider.into(),
            protocol,
            version: "fixture-1".into(),
            deployment_root: format!("/usr/lib/bullet/providers/{provider}/fixture-1"),
            entrypoint,
            aggregate_file_count: files.len() as u32,
            aggregate_size_bytes: files.iter().map(|file| file.size).sum(),
            execution,
            files,
        };
        let bytes = passport.canonical_bytes().unwrap();
        let id = passport.passport_id().unwrap();
        Self {
            temporary,
            anchor,
            root_relative,
            root,
            bytes,
            id,
        }
    }

    fn inspect(&self) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        self.inspect_with(&mut |_, _| {})
    }

    fn inspect_with(
        &self,
        hook: &mut dyn FnMut(linux::HookPoint, &str),
    ) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        let (passport, id) = decode_expected_passport(&self.bytes, &self.id)?;
        linux::inspect_test_source(
            passport,
            id,
            &self.anchor,
            &self.root_relative,
            fs::metadata(&self.root).unwrap().uid(),
            hook,
        )
    }

    fn inspect_uid(&self, uid: u32) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        let (passport, id) = decode_expected_passport(&self.bytes, &self.id)?;
        linux::inspect_test_source(
            passport,
            id,
            &self.anchor,
            &self.root_relative,
            uid,
            &mut |_, _| {},
        )
    }

    fn inspect_id(&self, id: &str) -> Result<InspectedProviderRuntimeV1, RuntimePassportError> {
        let (passport, id) = decode_expected_passport(&self.bytes, id)?;
        linux::inspect_test_source(
            passport,
            id,
            &self.anchor,
            &self.root_relative,
            fs::metadata(&self.root).unwrap().uid(),
            &mut |_, _| {},
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        thaw_tree(self.temporary.path());
    }
}

fn freeze_directories(root: &Path) {
    let mut directories = vec![root.to_path_buf()];
    directories.extend([root.join("bin"), root.join("lib")]);
    for directory in directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
    }
}

fn thaw_tree(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                thaw_tree(&entry.path());
            }
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn replace_same(path: &Path, staging: &Path) {
    let contents = fs::read(path).unwrap();
    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    fs::write(staging, contents).unwrap();
    set_mode(staging, mode);
    set_mode(path.parent().unwrap(), 0o755);
    fs::rename(staging, path).unwrap();
    set_mode(path.parent().unwrap(), 0o555);
}

fn rewrite(path: &Path, contents: &[u8], mode: u32) {
    set_mode(path, 0o755);
    fs::write(path, contents).unwrap();
    set_mode(path, mode);
}

fn assert_code(result: Result<InspectedProviderRuntimeV1, RuntimePassportError>, expected: &str) {
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("hostile runtime was accepted"),
    };
    assert_eq!(error.reason_code(), expected, "{error}");
}

fn claude() -> Fixture {
    Fixture::new("claude", ProviderProtocol::ClaudeStreamJson, false)
}

#[test]
fn all_four_provider_filesystems_inspect_and_revalidate_without_execution() {
    let fixtures = [
        ("claude", ProviderProtocol::ClaudeStreamJson, false),
        ("codex", ProviderProtocol::CodexAppServerJsonl, false),
        ("cursor", ProviderProtocol::CursorAcp, true),
        (
            "agy",
            ProviderProtocol::AntigravityHeadlessStructured,
            false,
        ),
    ];
    for (provider, protocol, interpreted) in fixtures {
        let fixture = Fixture::new(provider, protocol, interpreted);
        let inspected = fixture.inspect().unwrap();
        assert_eq!(inspected.passport_id(), fixture.id);
        assert_eq!(inspected.entrypoint(), format!("bin/{provider}"));
        let observation = inspected.component_observation();
        assert_eq!(observation.passport_id, fixture.id);
        assert_eq!(observation.entrypoint, format!("bin/{provider}"));
        assert_eq!(observation.evidence_class, "COMPONENT_ONLY");
        inspected.revalidate().unwrap();
    }
}

#[test]
fn expected_id_is_bounded_and_checked_before_the_filesystem() {
    let fixture = claude();
    thaw_tree(&fixture.root);
    fs::remove_dir_all(&fixture.root).unwrap();
    assert_code(
        fixture.inspect_id(&format!("rtp_{}", "0".repeat(64))),
        "RUNTIME_PASSPORT_ID_MISMATCH",
    );
    assert_code(
        fixture.inspect_id(&"x".repeat(1_000_000)),
        "RUNTIME_PASSPORT_ID_MISMATCH",
    );
    assert_eq!(
        RuntimePassportError::PlatformUnsupported.reason_code(),
        "RUNTIME_PASSPORT_PLATFORM_UNSUPPORTED"
    );
}

#[test]
fn closed_manifest_refuses_missing_and_extra_entries() {
    let fixture = claude();
    let member = fixture.root.join("lib/provider.so");
    set_mode(member.parent().unwrap(), 0o755);
    fs::remove_file(&member).unwrap();
    set_mode(member.parent().unwrap(), 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = claude();
    set_mode(&fixture.root, 0o755);
    fs::write(fixture.root.join("extra"), b"extra").unwrap();
    set_mode(&fixture.root, 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = claude();
    set_mode(&fixture.root, 0o755);
    fs::create_dir(fixture.root.join("empty-extra")).unwrap();
    set_mode(&fixture.root.join("empty-extra"), 0o555);
    set_mode(&fixture.root, 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");
}

#[test]
fn symlinks_and_nonordinary_members_refuse() {
    let fixture = claude();
    let member = fixture.root.join("bin/claude");
    set_mode(member.parent().unwrap(), 0o755);
    fs::remove_file(&member).unwrap();
    symlink("../lib/ld.so", &member).unwrap();
    set_mode(member.parent().unwrap(), 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = claude();
    set_mode(&fixture.root, 0o755);
    set_mode(&fixture.root.join("lib"), 0o755);
    fs::remove_dir_all(fixture.root.join("lib")).unwrap();
    symlink("../outside-lib", fixture.root.join("lib")).unwrap();
    set_mode(&fixture.root, 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = claude();
    let member = fixture.root.join("lib/provider.so");
    set_mode(member.parent().unwrap(), 0o755);
    fs::remove_file(&member).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &member,
        rustix::fs::Mode::from_bits_retain(0o444),
    )
    .unwrap();
    set_mode(member.parent().unwrap(), 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_CUSTODY_INVALID");
}

#[test]
fn custody_refuses_links_owner_and_mutable_modes() {
    let fixture = claude();
    fs::hard_link(
        fixture.root.join("bin/claude"),
        fixture.anchor.join("second-link"),
    )
    .unwrap();
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_CUSTODY_INVALID");

    let fixture = claude();
    set_mode(&fixture.root.join("bin/claude"), 0o755);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_CUSTODY_INVALID");

    let fixture = claude();
    let uid = fs::metadata(&fixture.root).unwrap().uid();
    assert_code(
        fixture.inspect_uid(uid.saturating_add(1)),
        "RUNTIME_PASSPORT_CUSTODY_INVALID",
    );

    for relative in ["", "lib"] {
        let fixture = claude();
        set_mode(&fixture.root.join(relative), 0o755);
        assert_code(fixture.inspect(), "RUNTIME_PASSPORT_CUSTODY_INVALID");
    }
}

#[test]
fn size_digest_loader_and_interpreter_drift_refuse() {
    let fixture = claude();
    rewrite(&fixture.root.join("lib/provider.so"), b"larger!!", 0o444);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = claude();
    rewrite(&fixture.root.join("lib/provider.so"), b"LIBRARY", 0o444);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = claude();
    rewrite(&fixture.root.join("lib/ld.so"), b"LOADER", 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");

    let fixture = Fixture::new("cursor", ProviderProtocol::CursorAcp, true);
    rewrite(&fixture.root.join("bin/node"), b"INTERPRETER", 0o555);
    assert_code(fixture.inspect(), "RUNTIME_PASSPORT_MANIFEST_MISMATCH");
}

#[test]
fn deterministic_before_open_and_during_read_swaps_refuse() {
    for point in [linux::HookPoint::BeforeOpen, linux::HookPoint::DuringRead] {
        let fixture = claude();
        let target = fixture.root.join("bin/claude");
        let staging = fixture.anchor.join("replacement");
        let mut replaced = false;
        let mut hook = |observed, path: &str| {
            if !replaced && observed == point && path == "bin/claude" {
                replace_same(&target, &staging);
                replaced = true;
            }
        };
        assert_code(fixture.inspect_with(&mut hook), "RUNTIME_PASSPORT_CHANGED");
        assert!(replaced);
    }
}

#[test]
fn revalidation_refuses_restored_inode_and_named_path_changes() {
    let fixture = claude();
    let inspected = fixture.inspect().unwrap();
    let member = fixture.root.join("bin/claude");
    std::thread::sleep(Duration::from_millis(2));
    rewrite(&member, b"ENTRYPOINT", 0o555);
    rewrite(&member, b"entrypoint", 0o555);
    assert_eq!(
        inspected.revalidate().unwrap_err().reason_code(),
        "RUNTIME_PASSPORT_CHANGED"
    );

    let fixture = claude();
    let inspected = fixture.inspect().unwrap();
    replace_same(
        &fixture.root.join("bin/claude"),
        &fixture.anchor.join("replacement"),
    );
    assert_eq!(
        inspected.revalidate().unwrap_err().reason_code(),
        "RUNTIME_PASSPORT_CHANGED"
    );
}
