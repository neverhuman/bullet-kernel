//! Verify the integrity of one offline transaction-component receipt.
//!
//! This binary never upgrades fixture output into Evidence or release truth.

use bullet_harness_core::launch_grant::{hash_canonical, is_lower_hex_64, validate_label};
use bullet_harness_core::transaction_proof::{
    verify_transaction_component, SignedTransactionComponent, TRANSACTION_COMPONENT_CLASS,
    TRANSACTION_COMPONENT_TRUST,
};
use clap::Parser;
use serde::Serialize;
use std::fmt;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 64;
const SUBJECT_DIGEST_DOMAIN: &str = "transaction-component.subject.v1alpha1";
const REFUSAL_CODE: &str = "TRANSACTION_COMPONENT_RECEIPT_REFUSED";

#[derive(Debug, Parser)]
#[command(name = "transaction_component_verify")]
struct Args {
    /// Absolute canonical path to the component receipt.
    #[arg(long)]
    receipt: PathBuf,
    /// Emit one compact JSON integrity observation.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct IntegrityObservation {
    evidence_class: &'static str,
    component_signing_trust: &'static str,
    verification_trust: &'static str,
    integrity: &'static str,
    transaction_gate_eligible: bool,
    release_profile_eligible: bool,
    subject_digest: String,
}

#[derive(Debug, Serialize)]
struct RefusalFrame<'a> {
    reason_code: &'static str,
    detail: &'a str,
}

#[derive(Debug)]
struct Refusal(String);

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => return refuse(&format!("command-line admission failed: {error}")),
    };
    match run(&args) {
        Ok(observation) => match write_json(io::stdout().lock(), &observation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => refuse(&format!("stdout write failed: {error}")),
        },
        Err(error) => refuse(&error.to_string()),
    }
}

fn run(args: &Args) -> Result<IntegrityObservation, Refusal> {
    if !args.json {
        return Err(refusal("--json is required"));
    }
    let bytes = read_receipt(&args.receipt)?;
    let proof: SignedTransactionComponent = serde_json::from_slice(&bytes)
        .map_err(|error| refusal(format!("receipt is not strict typed JSON: {error}")))?;

    validate_label("issuer", &proof.issuer).map_err(display_refusal)?;
    validate_label("key_id", &proof.key_id).map_err(display_refusal)?;
    if !is_lower_hex_64(&proof.public_hex) {
        return Err(refusal("public_hex must be 64 lowercase hexadecimal bytes"));
    }
    let subject = verify_transaction_component(&proof).map_err(display_refusal)?;
    let digest = hash_canonical(SUBJECT_DIGEST_DOMAIN, &subject).map_err(display_refusal)?;

    Ok(IntegrityObservation {
        evidence_class: TRANSACTION_COMPONENT_CLASS,
        component_signing_trust: TRANSACTION_COMPONENT_TRUST,
        verification_trust: "UNSIGNED_DIAGNOSTIC",
        integrity: "VERIFIED",
        transaction_gate_eligible: false,
        release_profile_eligible: false,
        subject_digest: format!("blake3:{digest}"),
    })
}

fn write_json(mut writer: impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value)?;
    writer.write_all(b"\n")
}

fn refuse(detail: &str) -> ExitCode {
    let frame = RefusalFrame {
        reason_code: REFUSAL_CODE,
        detail,
    };
    let _ = write_json(io::stderr().lock(), &frame);
    ExitCode::from(2)
}

fn display_refusal(error: impl fmt::Display) -> Refusal {
    refusal(error.to_string())
}

fn refusal(detail: impl Into<String>) -> Refusal {
    Refusal(detail.into())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "linux")]
impl FileIdentity {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_receipt(path: &Path) -> Result<Vec<u8>, Refusal> {
    validate_path(path)?;
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| refusal(format!("receipt canonicalization failed: {error}")))?;
    if canonical != path {
        return Err(refusal("receipt path must already be canonical"));
    }

    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| refusal(format!("root descriptor admission failed: {error}")))?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| refusal("receipt path must be absolute"))?;
    let open = || {
        rustix::fs::openat2(
            &root,
            relative,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(|error| refusal(format!("receipt descriptor admission failed: {error}")))
    };

    let mut file = open()?;
    let admitted = admit_regular(&file.metadata().map_err(display_refusal)?)?;
    admit_path_identity(path, admitted)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(display_refusal)?;
    if u64::try_from(bytes.len()).map_err(display_refusal)? != admitted.length {
        return Err(refusal("receipt length changed during bounded read"));
    }
    let after = admit_regular(&file.metadata().map_err(display_refusal)?)?;
    if after != admitted {
        return Err(refusal("receipt identity changed during bounded read"));
    }
    admit_path_identity(path, admitted)?;
    let reopened = open()?;
    if admit_regular(&reopened.metadata().map_err(display_refusal)?)? != admitted {
        return Err(refusal("receipt pathname changed after bounded read"));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn validate_path(path: &Path) -> Result<(), Refusal> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(refusal("receipt path must be bounded and absolute"));
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(refusal("receipt path must begin at the filesystem root"));
    }
    let mut count = 0_usize;
    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err(refusal("receipt path must not contain dot components"));
        }
        count += 1;
    }
    if count == 0 || count > MAX_PATH_COMPONENTS {
        return Err(refusal("receipt path has an invalid component count"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn admit_regular(metadata: &std::fs::Metadata) -> Result<FileIdentity, Refusal> {
    let identity = FileIdentity::from(metadata);
    if !metadata.is_file() || identity.links != 1 {
        return Err(refusal("receipt must be a single-link regular file"));
    }
    if identity.length == 0 || identity.length > MAX_RECEIPT_BYTES {
        return Err(refusal("receipt is empty or exceeds the 1 MiB bound"));
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn admit_path_identity(path: &Path, expected: FileIdentity) -> Result<(), Refusal> {
    let metadata = std::fs::symlink_metadata(path).map_err(display_refusal)?;
    if metadata.file_type().is_symlink() || FileIdentity::from(&metadata) != expected {
        return Err(refusal("receipt pathname does not identify its descriptor"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn read_receipt(_path: &Path) -> Result<Vec<u8>, Refusal> {
    Err(refusal(
        "transaction component receipt admission is available only on Linux",
    ))
}
