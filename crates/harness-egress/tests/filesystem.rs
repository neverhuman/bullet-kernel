//! Filesystem profile hostiles plus an optional credential-free local bwrap proof.

use bullet_harness_egress::{
    EgressCode, FilesystemFileV0, FilesystemRuntimeFileV0, FilesystemSandboxProfileV0,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    _root: tempfile::TempDir,
    bwrap: PathBuf,
    provider: PathBuf,
    clone_dir: PathBuf,
    schema: PathBuf,
    ca: PathBuf,
    runtime: PathBuf,
    scratch: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), 0o700);
        let clone_dir = root.path().join("clone");
        let scratch = root.path().join("scratch");
        fs::create_dir(&clone_dir).unwrap();
        fs::create_dir(&scratch).unwrap();
        set_mode(&clone_dir, 0o700);
        set_mode(&scratch, 0o700);
        let bwrap = required("/usr/bin/bwrap");
        let provider = required("/usr/bin/false");
        let schema = required("/etc/hosts");
        let ca = required("/etc/ssl/certs/ca-certificates.crt");
        let runtime = required("/usr/bin/busybox");
        Self {
            _root: root,
            bwrap,
            provider,
            clone_dir,
            schema,
            ca,
            runtime,
            scratch,
        }
    }

    fn profile(&self) -> FilesystemSandboxProfileV0 {
        FilesystemSandboxProfileV0::new(
            admitted(&self.bwrap),
            admitted(&self.provider),
            self.clone_dir.clone(),
            admitted(&self.schema),
            admitted(&self.ca),
            vec![FilesystemRuntimeFileV0::new(
                admitted(&self.runtime),
                "/runtime/bin/helper",
            )],
            self.scratch.clone(),
        )
    }
}

fn write_file(path: PathBuf, contents: &[u8], mode: u32) -> PathBuf {
    fs::write(&path, contents).unwrap();
    set_mode(&path, mode);
    path.canonicalize().unwrap()
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn admitted(path: &Path) -> FilesystemFileV0 {
    let bytes = fs::read(path).unwrap();
    FilesystemFileV0::new(path, blake3::hash(&bytes).to_hex().to_string())
}

fn assert_denied(result: Result<impl Sized, bullet_harness_egress::EgressError>) {
    match result {
        Ok(_) => panic!("profile unexpectedly admitted"),
        Err(error) => assert_eq!(error.code, EgressCode::FilesystemDenied),
    }
}

#[test]
fn closed_plan_uses_exact_descriptor_program_fixed_mounts_and_no_ambient_paths() {
    let fixture = Fixture::new();
    let prepared = fixture.profile().prepare().unwrap();
    let plan = prepared.command_plan(&["--version"]).unwrap();
    let program = plan.program().to_string_lossy();
    assert!(program.starts_with("/proc/self/fd/"));
    let args: Vec<String> = plan
        .arguments()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    for flag in [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--proc",
        "--dev",
        "--tmpfs",
        "--ro-bind-fd",
        "--bind-fd",
        "--chdir",
    ] {
        assert!(
            args.iter().any(|arg| arg == flag),
            "missing {flag}: {args:?}"
        );
    }
    assert!(!args.iter().any(|arg| arg == "--share-net"));
    for destination in [
        "/workspace",
        "/run/bullet/provider",
        "/run/bullet/proposal-schema.json",
        "/etc/ssl/certs/ca-certificates.crt",
        "/runtime/bin/helper",
        "/scratch",
    ] {
        assert!(
            args.iter().any(|arg| arg == destination),
            "missing {destination}: {args:?}"
        );
    }
    assert!(!args.iter().any(|arg| arg == "/home/ubuntu"));
    assert!(!args.windows(3).any(|window| {
        matches!(window[0].as_str(), "--ro-bind-fd" | "--bind-fd") && window[2] == "/"
    }));
    assert_eq!(args.last().map(String::as_str), Some("--version"));
}

#[test]
fn bare_paths_symlinks_hardlinks_and_mutable_files_are_refused() {
    let fixture = Fixture::new();
    let bare = FilesystemSandboxProfileV0::new(
        FilesystemFileV0::new("bwrap", "0".repeat(64)),
        admitted(&fixture.provider),
        fixture.clone_dir.clone(),
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(bare.prepare());

    let link = fixture._root.path().join("provider-link");
    symlink(&fixture.provider, &link).unwrap();
    let linked = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        FilesystemFileV0::new(&link, admitted(&fixture.provider).blake3()),
        fixture.clone_dir.clone(),
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(linked.prepare());

    let fake = write_file(fixture._root.path().join("fake-provider"), b"fake\n", 0o555);
    let hardlink = fixture._root.path().join("provider-hardlink");
    fs::hard_link(&fake, hardlink).unwrap();
    let hardlinked = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        admitted(&fake),
        fixture.clone_dir.clone(),
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(hardlinked.prepare());

    let mutable = write_file(fixture._root.path().join("mutable"), b"mutable\n", 0o755);
    let mutable_profile = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        admitted(&mutable),
        fixture.clone_dir.clone(),
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(mutable_profile.prepare());
}

#[test]
fn invalid_digest_and_nonallowlisted_environment_are_refused() {
    let fixture = Fixture::new();
    let wrong_digest = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        FilesystemFileV0::new(&fixture.provider, "0".repeat(64)),
        fixture.clone_dir.clone(),
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(wrong_digest.prepare());
    assert_denied(fixture.profile().with_environment("SECRET_TOKEN", "secret"));
    assert_denied(fixture.profile().with_environment("LANG", "en_US.UTF-8"));

    let oversized = fixture._root.path().join("oversized-schema");
    let file = fs::File::create(&oversized).unwrap();
    file.set_len(4 * 1024 * 1024 + 1).unwrap();
    drop(file);
    set_mode(&oversized, 0o444);
    let profile = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        admitted(&fixture.provider),
        fixture.clone_dir.clone(),
        FilesystemFileV0::new(&oversized, "0".repeat(64)),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(profile.prepare());
}

#[test]
fn duplicate_overlapping_and_outside_runtime_destinations_are_refused() {
    let fixture = Fixture::new();
    for destinations in [
        vec!["/runtime/bin/tool", "/runtime/bin/tool"],
        vec!["/usr/lib/tool", "/usr/lib/tool/data"],
        vec!["/etc/passwd", "/runtime/bin/tool"],
    ] {
        let runtime = destinations
            .into_iter()
            .map(|destination| {
                FilesystemRuntimeFileV0::new(admitted(&fixture.runtime), destination)
            })
            .collect();
        let profile = FilesystemSandboxProfileV0::new(
            admitted(&fixture.bwrap),
            admitted(&fixture.provider),
            fixture.clone_dir.clone(),
            admitted(&fixture.schema),
            admitted(&fixture.ca),
            runtime,
            fixture.scratch.clone(),
        );
        assert_denied(profile.prepare());
    }
}

#[test]
fn broad_host_directories_and_private_directory_aliases_are_refused() {
    let fixture = Fixture::new();
    for directory in [Path::new("/home/ubuntu"), Path::new("/home/ubuntu/bullet")] {
        if directory.exists() {
            let profile = FilesystemSandboxProfileV0::new(
                admitted(&fixture.bwrap),
                admitted(&fixture.provider),
                directory,
                admitted(&fixture.schema),
                admitted(&fixture.ca),
                vec![],
                fixture.scratch.clone(),
            );
            assert_denied(profile.prepare());
        }
    }
    let alias = fixture._root.path().join("clone-alias");
    symlink(&fixture.clone_dir, &alias).unwrap();
    let profile = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        admitted(&fixture.provider),
        alias,
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.scratch.clone(),
    );
    assert_denied(profile.prepare());

    let overlap = FilesystemSandboxProfileV0::new(
        admitted(&fixture.bwrap),
        admitted(&fixture.provider),
        fixture.clone_dir.clone(),
        admitted(&fixture.schema),
        admitted(&fixture.ca),
        vec![],
        fixture.clone_dir.clone(),
    );
    assert_denied(overlap.prepare());
}

#[test]
fn path_substitution_and_mode_drift_are_refused_before_plan_return() {
    let fixture = Fixture::new();
    let prepared = fixture.profile().prepare().unwrap();
    fs::rename(&fixture.clone_dir, fixture._root.path().join("old-clone")).unwrap();
    fs::create_dir(&fixture.clone_dir).unwrap();
    set_mode(&fixture.clone_dir, 0o700);
    let error = match prepared.command_plan(&[]) {
        Ok(_) => panic!("substituted clone unexpectedly admitted"),
        Err(error) => error,
    };
    assert_eq!(error.code, EgressCode::FilesystemChanged);

    let fixture = Fixture::new();
    let prepared = fixture.profile().prepare().unwrap();
    set_mode(&fixture.clone_dir, 0o500);
    let error = match prepared.command_plan(&[]) {
        Ok(_) => panic!("mode drift unexpectedly admitted"),
        Err(error) => error,
    };
    assert_eq!(error.code, EgressCode::FilesystemChanged);
}

#[test]
fn root_owned_static_subject_resists_post_plan_chmod_and_same_inode_rewrite() {
    if fs::metadata("/proc/self").unwrap().uid() == 0 {
        return;
    }
    let fixture = Fixture::new();
    let prepared = fixture.profile().prepare().unwrap();
    let first = prepared.command_plan(&[]).unwrap();
    drop(first);
    assert!(fs::set_permissions(&fixture.provider, fs::Permissions::from_mode(0o500)).is_err());
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(&fixture.provider)
        .is_err());
    prepared.command_plan(&[]).unwrap();
}

#[test]
fn prepared_home_binds_writable_copy_and_keeps_host_source_off_the_plan() {
    let fixture = Fixture::new();
    let home = fixture._root.path().join("provider-home");
    fs::create_dir(&home).unwrap();
    set_mode(&home, 0o700);
    let home = home.canonicalize().unwrap();
    write_file(home.join("oauth.json"), b"copy\n", 0o600);
    let host_source = write_file(
        fixture._root.path().join("host-oauth.json"),
        b"host\n",
        0o400,
    );
    let prepared = fixture
        .profile()
        .with_prepared_home(home.clone())
        .prepare()
        .unwrap();
    let plan = prepared.command_plan(&[]).unwrap();
    let args: Vec<String> = plan
        .arguments()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args
        .windows(3)
        .any(|window| { window[0] == "--bind-fd" && window[2] == "/home/bullet" }));
    assert!(!args
        .iter()
        .any(|arg| arg.contains(host_source.to_str().unwrap())));
    assert!(!args.iter().any(|arg| arg.contains(home.to_str().unwrap())));
}

#[test]
fn prepared_home_overlapping_clone_is_refused() {
    let fixture = Fixture::new();
    assert_denied(
        fixture
            .profile()
            .with_prepared_home(fixture.clone_dir.clone())
            .prepare(),
    );
}

#[test]
fn same_uid_credential_is_refused_pending_distinct_broker_custody() {
    let fixture = Fixture::new();
    let credential = write_file(fixture._root.path().join("credential"), b"fake\n", 0o400);
    assert_denied(
        fixture
            .profile()
            .with_brokered_credential(admitted(&credential))
            .prepare(),
    );
}

#[test]
fn local_bwrap_probe_if_available() {
    let Some(bwrap) = canonical_existing("/usr/bin/bwrap") else {
        return;
    };
    let Some(provider) = canonical_existing("/usr/bin/busybox") else {
        return;
    };
    let Some(ca_source) = canonical_existing("/etc/ssl/certs/ca-certificates.crt") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    set_mode(root.path(), 0o700);
    let clone_dir = root.path().join("clone");
    let scratch = root.path().join("scratch");
    fs::create_dir(&clone_dir).unwrap();
    fs::create_dir(&scratch).unwrap();
    set_mode(&clone_dir, 0o700);
    set_mode(&scratch, 0o700);
    write_file(clone_dir.join("input"), b"admitted\n", 0o444);
    let prepared = FilesystemSandboxProfileV0::new(
        admitted(&bwrap),
        admitted(&provider),
        clone_dir,
        admitted(Path::new("/etc/hosts")),
        admitted(&ca_source),
        vec![FilesystemRuntimeFileV0::new(
            admitted(&provider),
            "/runtime/bin/busybox",
        )],
        scratch.clone(),
    )
    .prepare()
    .unwrap();
    let host_secret = write_file(root.path().join("host-secret"), b"secret\n", 0o400);
    let held: Vec<_> = (0..64)
        .map(|_| fs::File::open(&host_secret).unwrap())
        .collect();
    let host_secret = host_secret.to_string_lossy().into_owned();
    let audit_plan = prepared.command_plan(&[]).unwrap();
    let mut admitted_fds: Vec<String> = audit_plan
        .arguments()
        .windows(2)
        .filter(|pair| matches!(pair[0].to_str(), Some("--ro-bind-fd" | "--bind-fd")))
        .filter_map(|pair| pair[1].to_str().map(str::to_string))
        .collect();
    admitted_fds.push(
        audit_plan
            .program()
            .to_str()
            .unwrap()
            .trim_start_matches("/proc/self/fd/")
            .to_string(),
    );
    assert!(!admitted_fds.is_empty());
    drop(audit_plan);
    admitted_fds.push(held.last().unwrap().as_raw_fd().to_string());
    let script = r#"set -u
IFS= read -r input < /workspace/input
[ "$input" = admitted ] || exit 10
IFS= read -r schema < /run/bullet/proposal-schema.json
[ -n "$schema" ] || exit 11
{ printf denied > /workspace/input; } 2>/dev/null && exit 20
{ printf denied > /run/bullet/proposal-schema.json; } 2>/dev/null && exit 21
printf writable > /scratch/result || exit 22
[ -w /home/bullet ] || exit 27
{ printf denied > /rogue; } 2>/dev/null && exit 28
{ printf denied > /etc/rogue; } 2>/dev/null && exit 29
{ printf denied > /run/rogue; } 2>/dev/null && exit 32
{ printf denied > /runtime/rogue; } 2>/dev/null && exit 33
[ ! -e /etc/passwd ] || exit 23
[ ! -e /home/ubuntu/.ssh ] || exit 24
[ ! -e /home/ubuntu/.claude ] || exit 25
[ ! -e "$1" ] || exit 26
if { IFS= read -r leaked < "$1"; } 2>/dev/null; then
  echo "host canary was readable: $leaked" >&2
  exit 34
fi
shift
for admitted_fd in "$@"; do
  if [ -e "/proc/self/fd/$admitted_fd" ]; then
    target=$(/runtime/bin/busybox readlink "/proc/self/fd/$admitted_fd")
    echo "leaked fd $admitted_fd -> $target" >&2
    exit 30
  fi
done
[ -z "${SECRET_TOKEN+x}" ] || exit 31"#;
    let mut provider_args = vec![
        "sh".to_string(),
        "-c".to_string(),
        script.to_string(),
        "sh".to_string(),
        host_secret,
    ];
    provider_args.extend(admitted_fds);
    let provider_args: Vec<&str> = provider_args.iter().map(String::as_str).collect();
    let plan = prepared.command_plan(&provider_args).unwrap();
    let output = Command::new(plan.program())
        .args(plan.arguments())
        .env_clear()
        .env("SECRET_TOKEN", "must-not-cross")
        .output()
        .unwrap();
    if !output.status.success() && namespace_unavailable(&output.stderr) {
        eprintln!("local Bubblewrap namespaces unavailable; capability-gated probe skipped");
        return;
    }
    assert!(
        output.status.success(),
        "status {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(scratch.join("result")).unwrap(),
        "writable"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("clone/input")).unwrap(),
        "admitted\n"
    );
    drop(held);
}

fn canonical_existing(path: &str) -> Option<PathBuf> {
    Path::new(path)
        .is_file()
        .then(|| Path::new(path).canonicalize().ok())
        .flatten()
}

fn required(path: &str) -> PathBuf {
    canonical_existing(path).unwrap_or_else(|| panic!("missing test subject {path}"))
}

#[test]
fn host_canary_read_succeeds_only_outside_containment() {
    let root = tempfile::tempdir().unwrap();
    set_mode(root.path(), 0o700);
    let canary = write_file(root.path().join("host-canary"), b"canary-secret\n", 0o400);
    assert_eq!(fs::read_to_string(&canary).unwrap(), "canary-secret\n");
}

#[test]
fn filesystem_command_composition_is_public_and_unavailable_is_typed() {
    assert_eq!(bullet_harness_egress::CONTAINMENT_UNAVAILABLE_EXIT, 78);
    let fixture = Fixture::new();
    let prepared = fixture.profile().prepare().unwrap();
    let plan = prepared.command_plan(&["--version"]).unwrap();
    let args: Vec<String> = plan
        .arguments()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args.iter().any(|arg| arg == "--unshare-all"));
    assert!(args
        .windows(3)
        .any(|window| { window[0] == "--ro-bind-fd" && window[2] == "/run/bullet/provider" }));
}

fn namespace_unavailable(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.contains("No permissions to create new namespace")
        || text.contains("Creating new namespace failed")
        || text.contains("Operation not permitted")
}
