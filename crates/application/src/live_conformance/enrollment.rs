//! Operator provider enrollment (execution plan M3 / ENROLL-1): a spawn-free,
//! unsigned, operator-supplied INPUT that a real contained runtime probe
//! (PROBE-1b) consumes before the live-conformance `ADMISSION` step. The
//! adapters refuse `observe_runtime_conformance` with
//! `RUNTIME_PROBE_UNAVAILABLE` and `ADMISSION` precedes `MINT`/`VERIFY`, so
//! nothing here may execute a provider binary to learn about it; an operator
//! records what they verified out of band in
//! `<data-dir>/policy/enrollments/<provider>.json`.
//!
//! # Unsigned, and it grants nothing
//!
//! The record has no signature and authenticates no operator: an input, never
//! evidence, authority, or a credential. `enrolled_by` is free text its author
//! chose, not an identity anyone checked. Any actor that can write the data
//! directory as the runner uid — every agent, tool, and test sharing that uid
//! — can author a self-consistent enrollment for any executable it owns,
//! including one it just wrote, label it anything, and have this loader admit
//! it; `tests/enrollment.rs` does that on purpose, so the limit is visible
//! rather than implied. The record's only guarantees are self-consistency (a
//! bounded, strictly decoded record of this distinct class, read from a
//! regular 0600 file owned by this uid, whose provider, protocol, labels,
//! budget, and window are all in range with `now` inside that window) and
//! executable-byte agreement at load time (an absolute canonical regular
//! executable with no `0o022` bit on it or its parent, whose BLAKE3 over an
//! identity-checked fd equals `executable_blake3`). Neither says who wrote the
//! record; neither is custody. Binding an enrollment to operator authority
//! requires a signed envelope over these bytes, verified against an
//! `authority-signing` issuer key of the protected policy generation, authored
//! under a distinct service uid, with a monotonic enrollment generation and
//! revocation — ENROLL-2, operator-gated future work, not this lane.
//!
//! Fixture material is separated by record class, not by provenance, and
//! [`EnrolledProvider`] carries facts only. The tests prove exactly this much:
//! no committed artifact under `crates/application/tests/fixtures/` becomes an
//! enrollment, neither as the record (distinct `schema`, unknown fields
//! refused), nor as the enrolled executable (committed bytes and mode: no
//! execute bit), nor as `executable_blake3`, recomputed from executable bytes
//! no policy or key artifact supplies. That is a claim about record classes,
//! not about who authored anything, and [`FIXTURE_LABELS`] denylists the
//! identities those artifacts name: defence-in-depth, never a guarantee.
//!
//! # Residual race window, re-derived
//!
//! This crate depends on neither `libc` nor `rustix`, so no open here can
//! carry `O_NOFOLLOW`. Both subjects are read `lstat` → open → `fstat`,
//! comparing `dev`/`ino`/`len` and regular-file kind, with a `canonicalize`
//! between the `lstat` and the open inside `executable_digest`. Everything
//! that survives that, not only the symlink case: (1) a hard link to the very
//! same inode swapped over the final component matches `dev`/`ino`/`len`
//! exactly, being the same file; (2) a symlink installed after the `lstat` —
//! after `canonicalize`, for the executable — is still followed by the open
//! and passes whenever it resolves to that inode; (3) a different inode
//! reusing that inode number on the same device at the same length passes a
//! comparison that never reads content; (4) nothing re-`stat`s or re-hashes
//! after the read, so a writer on the same inode can change the bytes — and,
//! for the streamed executable digest, the length — mid-read: each digest
//! covers the bytes actually read, not the file the `lstat` saw; (5) the
//! `0o022` refusal `lstat`s the executable and `executable_digest` `lstat`s it
//! again, so a swap in between checks the mode on one inode and digests
//! another; and (6) no ancestor of the enrollment file is admitted at all,
//! neither its mode nor its owner, so custody rests on that file's own 0600
//! mode and uid alone and any uid that can write `policy/enrollments/` may
//! unlink and replace entries there, while only the executable's immediate
//! parent is checked, for `0o022` bits alone, never its owner and never a
//! grandparent. All six close together (`openat` with `O_NOFOLLOW`, a
//! post-read re-check, admitted ancestors) — a dependency decision above this
//! lane: PROBE-1b / ENROLL-2. None of them changes what an enrollment grants,
//! which is nothing.

use bullet_domain::ProfileId;
use bullet_harness_core::launch_grant::{is_lower_hex_64, MAX_SAFE_INTEGER};
use bullet_harness_core::strict_json::decode_strict_json;
use bullet_harness_core::{executable_digest, ProviderProtocol};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Exact `schema` value of an enrollment record.
pub const PROVIDER_ENROLLMENT_SCHEMA: &str = "bullet.provider-enrollment.v1";
/// Upper bound on an enrollment file.
pub const MAX_ENROLLMENT_BYTES: u64 = 64 * 1024;
/// Longest admitted validity window (90 days); re-enroll, never keep trusting.
pub const MAX_ENROLLMENT_WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// Largest admitted per-turn budget: 100 USD in micro-USD.
pub const MAX_BUDGET_MICRO_USD: u64 = 100_000_000;
/// Longest admitted `version`, `profile_id`, or `enrolled_by` label.
pub const MAX_LABEL_BYTES: usize = 128;

/// Enrollment provider name, admission wire name, and frozen V1 protocol,
/// mirroring `bullet_harness_core::admission::protocol::requirement`.
const PROVIDERS: [(&str, &str, ProviderProtocol); 4] = [
    ("claude", "claude", ProviderProtocol::ClaudeStreamJson),
    ("codex", "codex", ProviderProtocol::CodexAppServerJsonl),
    ("cursor", "cursor", ProviderProtocol::CursorAcp),
    (
        "antigravity",
        "agy",
        ProviderProtocol::AntigravityHeadlessStructured,
    ),
];

/// Fixture-only issuer/key labels (ADR 0005/0012): a denylist, not provenance.
const FIXTURE_LABELS: [&str; 4] = [
    "bullet-kernel-local",
    "authority-test-1",
    "bullet-farm-offline-policy",
    "release-signing-alpha",
];

/// Typed enrollment refusal; every variant refuses and none is `UNKNOWN`.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// No enrollment file exists for the provider.
    #[error("no enrollment at {path}")]
    Missing {
        /// Expected file location.
        path: String,
    },
    /// The file exists but is not a bounded, strict, complete enrollment.
    #[error("enrollment malformed: {reason}")]
    Malformed {
        /// Non-secret detail.
        reason: String,
    },
    /// The record does not describe the requested provider.
    #[error("enrollment provider mismatch: {reason}")]
    ProviderMismatch {
        /// Non-secret detail.
        reason: String,
    },
    /// The executable on disk is not the enrolled bytes.
    #[error("enrolled executable digest {expected} but observed {observed}")]
    ExecutableDigestMismatch {
        /// Digest recorded in the enrollment.
        expected: String,
        /// Digest recomputed from disk.
        observed: String,
    },
    /// The executable is not an admissible subject.
    #[error("enrolled executable invalid: {reason}")]
    ExecutableInvalid {
        /// Non-secret detail.
        reason: String,
    },
    /// The validity window is malformed or does not contain `now`.
    #[error("enrollment window invalid: {reason}")]
    WindowInvalid {
        /// Non-secret detail.
        reason: String,
    },
    /// The file violates custody policy (mode, owner, symlink, kind).
    #[error("enrollment file policy: {reason}")]
    FilePolicy {
        /// Non-secret detail.
        reason: String,
    },
}

impl EnrollmentError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "ENROLLMENT_MISSING",
            Self::Malformed { .. } => "ENROLLMENT_MALFORMED",
            Self::ProviderMismatch { .. } => "ENROLLMENT_PROVIDER_MISMATCH",
            Self::ExecutableDigestMismatch { .. } => "ENROLLMENT_EXECUTABLE_DIGEST_MISMATCH",
            Self::ExecutableInvalid { .. } => "ENROLLMENT_EXECUTABLE_INVALID",
            Self::WindowInvalid { .. } => "ENROLLMENT_WINDOW_INVALID",
            Self::FilePolicy { .. } => "ENROLLMENT_FILE_POLICY",
        }
    }
}

/// The on-disk enrollment record: unsigned, with unknown fields refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEnrollmentV1 {
    /// Exactly [`PROVIDER_ENROLLMENT_SCHEMA`].
    pub schema: String,
    /// `claude`, `codex`, `cursor`, or `antigravity`; must equal the file stem.
    pub provider: String,
    /// Absolute canonical executable path.
    pub executable: PathBuf,
    /// Lowercase hex BLAKE3 of the executable bytes as verified by the operator.
    pub executable_blake3: String,
    /// Frozen V1 protocol wire label (for example `claude_stream_json`).
    pub protocol: ProviderProtocol,
    /// Exact runtime version the operator observed.
    pub version: String,
    /// Kernel profile id (`prf_` + 64 lowercase hex).
    pub profile_id: String,
    /// Tightest per-turn cost cap in micro-USD (what dispatch consumes).
    pub budget_micro_usd_max: u64,
    /// Activation instant (inclusive), Unix milliseconds.
    pub valid_from_unix_ms: u64,
    /// Expiry instant (exclusive), Unix milliseconds.
    pub valid_until_unix_ms: u64,
    /// Free-text author label: unauthenticated, and never a fixture identity.
    pub enrolled_by: String,
}

/// A loaded, re-verified enrollment: unsigned operator assertions plus the two
/// facts re-proved at load. Constructed only by [`load_provider_enrollment`],
/// and deliberately no probe snapshot, observation, or admission value.
#[derive(Clone, Debug)]
pub struct EnrolledProvider {
    record: ProviderEnrollmentV1,
    enrollment_blake3: String,
    wire_provider: &'static str,
    profile_id: ProfileId,
}

impl EnrolledProvider {
    /// The validated, unsigned record.
    #[must_use]
    pub fn record(&self) -> &ProviderEnrollmentV1 {
        &self.record
    }

    /// BLAKE3 of the exact enrollment bytes, for receipts.
    #[must_use]
    pub fn enrollment_blake3(&self) -> &str {
        &self.enrollment_blake3
    }

    /// Admission/grant wire name (`agy` for `antigravity`).
    #[must_use]
    pub fn wire_provider(&self) -> &'static str {
        self.wire_provider
    }

    /// Parsed Kernel profile id.
    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    /// Per-turn cost cap in micro-USD.
    #[must_use]
    pub fn max_cost_micro_usd(&self) -> u64 {
        self.record.budget_micro_usd_max
    }
}

/// `<data-dir>/policy/enrollments/<provider>.json`.
#[must_use]
pub fn enrollment_path(data_dir: &Path, provider: &str) -> PathBuf {
    data_dir
        .join("policy")
        .join("enrollments")
        .join(format!("{provider}.json"))
}

/// Load and re-verify `provider`'s enrollment at `now_unix_ms`. The result
/// grants nothing; the module doc states what it does and does not prove.
///
/// # Errors
///
/// A typed [`EnrollmentError`]; see each variant.
pub fn load_provider_enrollment(
    data_dir: &Path,
    provider: &str,
    now_unix_ms: u64,
) -> Result<EnrolledProvider, EnrollmentError> {
    let (wire_provider, protocol) = provider_entry(provider)?;
    if !data_dir.is_absolute() {
        return Err(file_policy("data directory must be absolute"));
    }
    let path = enrollment_path(data_dir, provider);
    let bytes = read_regular_bounded(&path)?;
    let record = decode(&bytes)?;
    let profile_id = validate_record(&record, provider, protocol)?;
    check_window(&record, now_unix_ms)?;
    let observed = verify_executable(&record.executable)?;
    if observed != record.executable_blake3 {
        return Err(EnrollmentError::ExecutableDigestMismatch {
            expected: record.executable_blake3,
            observed,
        });
    }
    Ok(EnrolledProvider {
        record,
        enrollment_blake3: blake3::hash(&bytes).to_hex().to_string(),
        wire_provider,
        profile_id,
    })
}

fn provider_entry(provider: &str) -> Result<(&'static str, ProviderProtocol), EnrollmentError> {
    PROVIDERS
        .iter()
        .find(|(name, _, _)| *name == provider)
        .map(|(_, wire, protocol)| (*wire, *protocol))
        .ok_or_else(|| mismatch(&format!("{provider:?} is not an enrollable provider")))
}

/// The `policy_snapshot::load` read discipline plus operator-key custody (mode
/// 0600, owned by this process), which proves the runner uid authored these
/// bytes and never which operator. Residual window: see the module doc.
fn read_regular_bounded(path: &Path) -> Result<Vec<u8>, EnrollmentError> {
    let linkless = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(EnrollmentError::Missing {
                path: path.display().to_string(),
            });
        }
        Err(error) => return Err(file_policy(&format!("not readable: {error}"))),
    };
    if linkless.file_type().is_symlink() {
        return Err(file_policy("must not be a symlink"));
    }
    if !linkless.file_type().is_file() {
        return Err(file_policy("is not a regular file"));
    }
    if linkless.len() > MAX_ENROLLMENT_BYTES {
        return Err(malformed(&format!("exceeds {MAX_ENROLLMENT_BYTES} bytes")));
    }
    let file = std::fs::File::open(path).map_err(|error| file_policy(&format!("open: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| file_policy(&format!("inspect: {error}")))?;
    if !same_file(&linkless, &opened) {
        return Err(file_policy("identity changed while opening"));
    }
    check_custody(&opened)?;
    let mut bytes = Vec::new();
    file.take(MAX_ENROLLMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| file_policy(&format!("read: {error}")))?;
    if bytes.len() as u64 > MAX_ENROLLMENT_BYTES {
        return Err(malformed(&format!("exceeds {MAX_ENROLLMENT_BYTES} bytes")));
    }
    Ok(bytes)
}

fn same_file(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    opened.file_type().is_file()
        && before.dev() == opened.dev()
        && before.ino() == opened.ino()
        && before.len() == opened.len()
}

fn check_custody(opened: &std::fs::Metadata) -> Result<(), EnrollmentError> {
    if opened.permissions().mode() & 0o777 != 0o600 {
        return Err(file_policy("mode must be exactly 0600"));
    }
    if opened.uid() != current_uid() {
        return Err(file_policy("must be owned by the current user"));
    }
    Ok(())
}

/// Procfs owner; unreadable procfs yields a sentinel that fails custody closed.
fn current_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX)
}

fn decode(bytes: &[u8]) -> Result<ProviderEnrollmentV1, EnrollmentError> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| malformed(&format!("not UTF-8: {error}")))?;
    let value = decode_strict_json(text).map_err(|error| malformed(&error.to_string()))?;
    serde_json::from_value(value).map_err(|error| malformed(&error.to_string()))
}

fn validate_record(
    record: &ProviderEnrollmentV1,
    provider: &str,
    protocol: ProviderProtocol,
) -> Result<ProfileId, EnrollmentError> {
    if record.schema != PROVIDER_ENROLLMENT_SCHEMA {
        return Err(malformed(&format!(
            "schema must be {PROVIDER_ENROLLMENT_SCHEMA}, got {:?}",
            record.schema
        )));
    }
    if record.provider != provider {
        return Err(mismatch(&format!(
            "file is {provider}.json but the record enrolls {:?}",
            record.provider
        )));
    }
    if record.protocol != protocol {
        return Err(mismatch(&format!(
            "{} is not the frozen V1 protocol for {provider}",
            record.protocol.as_str()
        )));
    }
    check_label("version", &record.version)?;
    check_label("enrolled_by", &record.enrolled_by)?;
    let lowered = record.enrolled_by.to_ascii_lowercase();
    if FIXTURE_LABELS.contains(&lowered.as_str()) || lowered.contains("fixture") {
        return Err(malformed("enrolled_by names fixture-only material"));
    }
    let profile_id = ProfileId::parse(&record.profile_id)
        .map_err(|error| malformed(&format!("profile_id: {error}")))?;
    if !is_lower_hex_64(&record.executable_blake3) {
        return Err(malformed("executable_blake3 must be 64 lowercase hex"));
    }
    if record.budget_micro_usd_max == 0 || record.budget_micro_usd_max > MAX_BUDGET_MICRO_USD {
        return Err(malformed(&format!(
            "budget_micro_usd_max must be within 1..={MAX_BUDGET_MICRO_USD}"
        )));
    }
    if !record.executable.is_absolute() {
        return Err(executable_invalid("executable must be absolute"));
    }
    Ok(profile_id)
}

fn check_label(field: &str, value: &str) -> Result<(), EnrollmentError> {
    let graphic = value.bytes().all(|byte| byte.is_ascii_graphic());
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || !graphic {
        return Err(malformed(&format!(
            "{field} must be 1..={MAX_LABEL_BYTES} bytes of printable ASCII without whitespace"
        )));
    }
    Ok(())
}

/// Activation inclusive, expiry exclusive — the ADR 0012 instant semantics.
fn check_window(record: &ProviderEnrollmentV1, now_unix_ms: u64) -> Result<(), EnrollmentError> {
    let (from, until) = (record.valid_from_unix_ms, record.valid_until_unix_ms);
    if until > MAX_SAFE_INTEGER || from >= until {
        return Err(window(
            "valid_from_unix_ms must precede valid_until_unix_ms within the safe integer range",
        ));
    }
    if until - from > MAX_ENROLLMENT_WINDOW_MS {
        return Err(window(&format!(
            "window exceeds {MAX_ENROLLMENT_WINDOW_MS} ms"
        )));
    }
    if now_unix_ms < from {
        return Err(window(&format!(
            "not yet valid: now {now_unix_ms} < {from}"
        )));
    }
    if now_unix_ms >= until {
        return Err(window(&format!("expired: now {now_unix_ms} >= {until}")));
    }
    Ok(())
}

/// Refuse a group- or world-writable subject or immediate parent, then hash
/// through harness-core's fd-bound digest. Only that one parent is admitted,
/// and the module doc states the window both `lstat`/`fstat` pairs leave.
fn verify_executable(executable: &Path) -> Result<String, EnrollmentError> {
    let linkless = std::fs::symlink_metadata(executable)
        .map_err(|error| executable_invalid(&format!("metadata: {error}")))?;
    if linkless.permissions().mode() & 0o022 != 0 {
        return Err(executable_invalid("executable is group- or world-writable"));
    }
    let parent = executable
        .parent()
        .ok_or_else(|| executable_invalid("executable has no parent directory"))?;
    let parent_meta = std::fs::symlink_metadata(parent)
        .map_err(|error| executable_invalid(&format!("parent metadata: {error}")))?;
    if !parent_meta.file_type().is_dir() || parent_meta.permissions().mode() & 0o022 != 0 {
        return Err(executable_invalid(
            "executable parent must be a directory that is not group- or world-writable",
        ));
    }
    executable_digest(executable).map_err(|error| executable_invalid(&error.to_string()))
}

fn malformed(reason: &str) -> EnrollmentError {
    EnrollmentError::Malformed {
        reason: reason.to_string(),
    }
}

fn mismatch(reason: &str) -> EnrollmentError {
    EnrollmentError::ProviderMismatch {
        reason: reason.to_string(),
    }
}

fn window(reason: &str) -> EnrollmentError {
    EnrollmentError::WindowInvalid {
        reason: reason.to_string(),
    }
}

fn file_policy(reason: &str) -> EnrollmentError {
    EnrollmentError::FilePolicy {
        reason: reason.to_string(),
    }
}

fn executable_invalid(reason: &str) -> EnrollmentError {
    EnrollmentError::ExecutableInvalid {
        reason: reason.to_string(),
    }
}
