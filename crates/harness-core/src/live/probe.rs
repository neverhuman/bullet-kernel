//! Probe-only runtime observation: the honest, non-admitting precursor to
//! [`RuntimeConformanceObservation`](super::RuntimeConformanceObservation).
//!
//! A probe establishes only what a separately granted, contained execution of
//! the exact provider executable shows natively: which bytes ran (path, BLAKE3,
//! device/inode/size at spawn), with which argv, what version text they
//! printed, whether the frozen protocol handshake succeeded, which capabilities
//! the captured native output demonstrates, how the process exited, how long it
//! took, and which probe grant and containment receipt it ran under. It carries
//! no `PatchProposal`, no turn lifecycle, and no synthetic events, and there is
//! deliberately no `From`, `into_parts`, or constructor that turns it into a
//! conformance observation; see [`ProbeOutcome`](super::ProbeOutcome).

use crate::admission::{executable_digest, ProviderProtocol};
use crate::capability::Capability;
use crate::error::HarnessError;
use crate::launch_grant::{
    canonical_json, decode_canonical, hash_canonical, is_lower_hex_64, MAX_SAFE_INTEGER,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Frozen probe-observation schema.
pub const RUNTIME_PROBE_SCHEMA_VERSION: u32 = 1;
/// Digest domain for one canonical probe observation.
pub const RUNTIME_PROBE_DOMAIN: &str = "runtime-probe.observation.v1alpha1";
/// Maximum native stdout bytes one probe observation retains.
pub const MAX_PROBE_STDOUT_BYTES: usize = 16 * 1024;
/// Maximum bytes in the derived version string.
pub const MAX_PROBE_VERSION_BYTES: usize = 128;
/// Maximum argv entries; with `MAX_ARG_BYTES` the document stays under 64 KiB.
pub const MAX_PROBE_ARGV: usize = 32;
/// Maximum probe wall time in milliseconds.
pub const MAX_PROBE_WALL_MS: u64 = 120_000;
const MAX_ARG_BYTES: usize = 1_024;
const MAX_TOKEN_BYTES: usize = 128;
const MAX_PROVIDER_BYTES: usize = 16;
const MAX_REASON_BYTES: usize = 256;

/// Typed probe refusal. Every variant carries a stable reason code.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeProbeError {
    /// No adapter can produce a contained probe observation yet.
    #[error("runtime probe unavailable for {provider}")]
    Unavailable { provider: String },
    /// No probe grant evidence was supplied.
    #[error("runtime probe grant missing")]
    GrantMissing,
    /// The observation does not belong to the supplied grant.
    #[error("runtime probe grant mismatch on {field}")]
    GrantMismatch { field: &'static str },
    /// The grant expiry is at or before the checked instant.
    #[error("runtime probe grant expired at {expires_at_unix_ms}")]
    GrantExpired { expires_at_unix_ms: u64 },
    /// Native stdout exceeded the retained bound.
    #[error("runtime probe output exceeds {max} bytes")]
    OutputOversized { max: usize },
    /// The executable is not a bounded, canonical, executable regular file.
    #[error("runtime probe executable invalid: {reason}")]
    ExecutableInvalid { reason: String },
    /// A field violates the frozen probe contract.
    #[error("runtime probe observation malformed: {reason}")]
    Malformed { reason: String },
    /// A probe-only outcome was asked to serve as conformance evidence.
    #[error("runtime probe observation is not conformance evidence")]
    NotAdmissible,
}

impl RuntimeProbeError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "RUNTIME_PROBE_UNAVAILABLE",
            Self::GrantMissing => "RUNTIME_PROBE_GRANT_MISSING",
            Self::GrantMismatch { .. } => "RUNTIME_PROBE_GRANT_MISMATCH",
            Self::GrantExpired { .. } => "RUNTIME_PROBE_GRANT_EXPIRED",
            Self::OutputOversized { .. } => "RUNTIME_PROBE_OUTPUT_OVERSIZED",
            Self::ExecutableInvalid { .. } => "RUNTIME_PROBE_EXECUTABLE_INVALID",
            Self::Malformed { .. } => "RUNTIME_PROBE_MALFORMED",
            Self::NotAdmissible => "RUNTIME_PROBE_NOT_ADMISSIBLE",
        }
    }
}

/// Containment the probe grant requires of the execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentClass {
    /// Network egress is denied for the probe process tree.
    EgressDenied,
    /// The probe runs with no workspace mounted, read-only or otherwise.
    ReadOnlyWorkspaceAbsent,
}

/// Minimal opaque evidence of a granted probe execution. A later lane mints
/// and signs the underlying grant; this type only binds an observation to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeGrantEvidence {
    /// Digest of the probe grant.
    pub grant_blake3: String,
    /// Provider wire name the grant authorizes.
    pub provider: String,
    /// Exact executable bytes the grant authorizes.
    pub executable_blake3: String,
    /// Containment the grant requires.
    pub containment: ContainmentClass,
    /// Exclusive expiry instant.
    pub expires_at_unix_ms: u64,
}

impl ProbeGrantEvidence {
    /// Structural validation plus expiry: `RUNTIME_PROBE_MALFORMED` for a bad
    /// digest, provider, or expiry; `RUNTIME_PROBE_GRANT_EXPIRED` once
    /// `now_unix_ms` reaches the exclusive expiry.
    pub fn verify(&self, now_unix_ms: u64) -> Result<(), RuntimeProbeError> {
        hex_64("grant_blake3", &self.grant_blake3)?;
        hex_64("grant executable_blake3", &self.executable_blake3)?;
        validate_provider(&self.provider)?;
        let expiry = self.expires_at_unix_ms;
        let safe = expiry > 0 && expiry <= MAX_SAFE_INTEGER;
        ensure(safe, "grant expiry is outside the safe range")?;
        if now_unix_ms >= expiry {
            return Err(RuntimeProbeError::GrantExpired {
                expires_at_unix_ms: expiry,
            });
        }
        Ok(())
    }
}

/// Executable identity as observed immediately before spawn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    /// Absolute canonical path that was executed.
    pub path: String,
    /// BLAKE3 of the executable bytes.
    pub blake3: String,
    /// Device number from `stat`.
    pub device: u64,
    /// Inode number from `stat`.
    pub inode: u64,
    /// Size in bytes from `stat`.
    pub size: u64,
}

impl ExecutableIdentity {
    /// Hash and identify an exact canonical executable without executing it.
    /// `RUNTIME_PROBE_EXECUTABLE_INVALID` unless the path is a bounded,
    /// canonical, executable regular file whose identity holds while hashed.
    pub fn observe(path: &Path) -> Result<Self, RuntimeProbeError> {
        let before = stat_identity(path)?;
        let blake3 = executable_digest(path).map_err(|error| executable_invalid(&error))?;
        let (device, inode, size) = stat_identity(path)?;
        if before != (device, inode, size) {
            return Err(executable_invalid(&"identity changed while hashing"));
        }
        let text = path.to_str().ok_or_else(|| malformed("non-UTF-8 path"))?;
        let identity = Self {
            path: text.to_string(),
            blake3,
            device,
            inode,
            size,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), RuntimeProbeError> {
        let absolute = Path::new(&self.path).is_absolute() && self.path.len() <= MAX_ARG_BYTES;
        ensure(absolute, "executable path must be absolute and bounded")?;
        printable("executable path", &self.path)?;
        hex_64("executable blake3", &self.blake3)?;
        ensure(self.size > 0, "executable size must be non-zero")
    }
}

/// Result of the frozen protocol handshake, as parsed from native output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolHandshake {
    /// Claude stream-JSON hello completed.
    StreamJsonHelloOk,
    /// Codex App Server `initialize` completed.
    AppServerInitializeOk,
    /// Cursor ACP `initialize` completed.
    AcpInitializeOk,
    /// Antigravity headless structured-schema mode acknowledged.
    HeadlessStructuredOk,
    /// The runtime refused or failed the handshake.
    HandshakeRefused { reason: String },
}

impl ProtocolHandshake {
    /// Protocol the handshake demonstrated; `None` is never a pass.
    #[must_use]
    pub fn demonstrated_protocol(&self) -> Option<ProviderProtocol> {
        match self {
            Self::StreamJsonHelloOk => Some(ProviderProtocol::ClaudeStreamJson),
            Self::AppServerInitializeOk => Some(ProviderProtocol::CodexAppServerJsonl),
            Self::AcpInitializeOk => Some(ProviderProtocol::CursorAcp),
            Self::HeadlessStructuredOk => Some(ProviderProtocol::AntigravityHeadlessStructured),
            Self::HandshakeRefused { .. } => None,
        }
    }
}

/// How the probe process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeExit {
    /// Normal exit with a status code.
    Code { code: i32 },
    /// Terminated by a signal.
    Signal { signal: i32 },
}

/// One capability the native output demonstrates, with the exact token that
/// demonstrates it. The token must occur in the retained native stdout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCapability {
    /// Capability demonstrated.
    pub capability: Capability,
    /// Native output token that demonstrates it.
    pub native_token: String,
}

/// Raw facts a contained probe run captured. These are input, not evidence,
/// until [`RuntimeProbeObservation::from_native`] validates and seals them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeFacts {
    /// Provider wire name.
    pub provider: String,
    /// Executable identity taken immediately before spawn.
    pub executable: ExecutableIdentity,
    /// Exact argv used; `argv[0]` is the executable path.
    pub argv: Vec<String>,
    /// Exact native stdout captured, in order; see [`native_text`].
    pub native_stdout: String,
    /// Parsed handshake result.
    pub handshake: ProtocolHandshake,
    /// Capabilities the native output demonstrates, strictly ascending.
    pub capabilities: Vec<ObservedCapability>,
    /// Process exit.
    pub exit: ProbeExit,
    /// Wall time in milliseconds.
    pub wall_ms: u64,
    /// Spawn instant.
    pub observed_at_unix_ms: u64,
    /// Digest of the containment receipt the run produced.
    pub containment_receipt_blake3: String,
}

/// Bound and decode captured native stdout bytes: `RUNTIME_PROBE_OUTPUT_OVERSIZED`
/// beyond [`MAX_PROBE_STDOUT_BYTES`], `RUNTIME_PROBE_MALFORMED` unless strict UTF-8.
pub fn native_text(bytes: &[u8]) -> Result<String, RuntimeProbeError> {
    bounded_stdout(bytes.len())?;
    String::from_utf8(bytes.to_vec()).map_err(|_| malformed("native stdout is not strict UTF-8"))
}

/// Validated, grant-bound, proposal-free probe facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProbeObservation {
    schema_version: u32,
    facts: ProbeFacts,
    version: String,
    grant_blake3: String,
    containment: ContainmentClass,
}

impl RuntimeProbeObservation {
    /// Validate captured facts and bind them to the grant they ran under.
    /// Refuses typed for an invalid or expired grant, a provider or
    /// executable the grant does not cover, or any structural violation.
    pub fn from_native(
        facts: ProbeFacts,
        grant: &ProbeGrantEvidence,
        now_unix_ms: u64,
    ) -> Result<Self, RuntimeProbeError> {
        grant.verify(now_unix_ms)?;
        let version = derive_version(&facts.native_stdout)?;
        let observation = Self {
            schema_version: RUNTIME_PROBE_SCHEMA_VERSION,
            facts,
            version,
            grant_blake3: grant.grant_blake3.clone(),
            containment: grant.containment,
        };
        observation.validate()?;
        observation.verify_grant(Some(grant), now_unix_ms)?;
        Ok(observation)
    }

    /// Strictly decode one canonical observation and re-bind it to `grant`:
    /// `RUNTIME_PROBE_MALFORMED` for non-canonical, unknown-field, or
    /// structurally invalid bytes; grant refusals as in [`Self::from_native`].
    pub fn decode(
        bytes: &[u8],
        grant: &ProbeGrantEvidence,
        now_unix_ms: u64,
    ) -> Result<Self, RuntimeProbeError> {
        let observation: Self = decode_canonical(bytes).map_err(wire)?;
        observation.validate()?;
        observation.verify_grant(Some(grant), now_unix_ms)?;
        Ok(observation)
    }

    /// RFC 8785 canonical bytes; `RUNTIME_PROBE_MALFORMED` if encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, RuntimeProbeError> {
        canonical_json(self).map_err(wire)
    }

    /// Domain-separated digest of the canonical encoding.
    pub fn digest(&self) -> Result<String, RuntimeProbeError> {
        hash_canonical(RUNTIME_PROBE_DOMAIN, self).map_err(wire)
    }

    /// Re-check that this observation belongs to `grant` and is not expired:
    /// `RUNTIME_PROBE_GRANT_MISSING` for `None`, `RUNTIME_PROBE_GRANT_EXPIRED`,
    /// or `RUNTIME_PROBE_GRANT_MISMATCH` naming the first differing field.
    pub fn verify_grant(
        &self,
        grant: Option<&ProbeGrantEvidence>,
        now_unix_ms: u64,
    ) -> Result<(), RuntimeProbeError> {
        let grant = grant.ok_or(RuntimeProbeError::GrantMissing)?;
        grant.verify(now_unix_ms)?;
        let facts = &self.facts;
        let same_executable = facts.executable.blake3 == grant.executable_blake3;
        let fresh = facts.observed_at_unix_ms < grant.expires_at_unix_ms;
        let differs = [
            (self.grant_blake3 != grant.grant_blake3, "grant_blake3"),
            (facts.provider != grant.provider, "provider"),
            (!same_executable, "executable_blake3"),
            (self.containment != grant.containment, "containment"),
            (!fresh, "observed_at_unix_ms"),
        ];
        match differs.into_iter().find(|(differs, _)| *differs) {
            Some((_, field)) => Err(RuntimeProbeError::GrantMismatch { field }),
            None => Ok(()),
        }
    }

    /// The sealed facts.
    pub fn facts(&self) -> &ProbeFacts {
        &self.facts
    }

    /// Version string derived from the first non-empty native stdout line.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Digest of the probe grant this ran under.
    pub fn grant_blake3(&self) -> &str {
        &self.grant_blake3
    }

    /// Containment the grant required.
    pub fn containment(&self) -> ContainmentClass {
        self.containment
    }

    fn validate(&self) -> Result<(), RuntimeProbeError> {
        let facts = &self.facts;
        let schema = self.schema_version == RUNTIME_PROBE_SCHEMA_VERSION;
        ensure(schema, "unsupported probe schema_version")?;
        validate_provider(&facts.provider)?;
        facts.executable.validate()?;
        let argv_count = (1..=MAX_PROBE_ARGV).contains(&facts.argv.len());
        ensure(argv_count, "argv must contain 1..=32 entries")?;
        let argv0 = facts.argv[0] == facts.executable.path;
        ensure(argv0, "argv[0] must be the executable path")?;
        for argument in &facts.argv {
            bounded("argv entry", argument.len(), MAX_ARG_BYTES)?;
            printable("argv entry", argument)?;
        }
        bounded_stdout(facts.native_stdout.len())?;
        let clean = control_free(&facts.native_stdout, true);
        ensure(clean, "native stdout carries control characters")?;
        let derived = self.version == derive_version(&facts.native_stdout)?;
        ensure(derived, "version is not derived from native stdout")?;
        if let ProtocolHandshake::HandshakeRefused { reason } = &facts.handshake {
            bounded("handshake reason", reason.len(), MAX_REASON_BYTES)?;
            printable("handshake refusal reason", reason)?;
        }
        let count = facts.capabilities.len();
        bounded("capabilities", count, Capability::ALL.len())?;
        for (index, observed) in facts.capabilities.iter().enumerate() {
            let ascending =
                index == 0 || facts.capabilities[index - 1].capability < observed.capability;
            ensure(ascending, "capabilities must strictly ascend")?;
            let token = &observed.native_token;
            bounded("capability token", token.len(), MAX_TOKEN_BYTES)?;
            printable("capability token", token)?;
            let evidenced = facts.native_stdout.contains(token.as_str());
            ensure(evidenced, "capability token is absent from native stdout")?;
        }
        let wall_ok = facts.wall_ms <= MAX_PROBE_WALL_MS;
        ensure(wall_ok, "wall time exceeds the probe bound")?;
        let observed = facts.observed_at_unix_ms;
        let safe = observed > 0 && observed <= MAX_SAFE_INTEGER;
        ensure(safe, "observed_at_unix_ms is outside the safe range")?;
        hex_64("grant_blake3", &self.grant_blake3)?;
        let receipt = &facts.containment_receipt_blake3;
        hex_64("containment_receipt_blake3", receipt)
    }
}

fn derive_version(native_stdout: &str) -> Result<String, RuntimeProbeError> {
    let line = native_stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| malformed("native stdout carries no version line"))?;
    let ascii = line.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
    let ok = ascii && line.len() <= MAX_PROBE_VERSION_BYTES;
    ensure(ok, "version line must be bounded printable ASCII")?;
    Ok(line.to_string())
}

fn stat_identity(path: &Path) -> Result<(u64, u64, u64), RuntimeProbeError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| executable_invalid(&error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((metadata.dev(), metadata.ino(), metadata.len()))
    }
    #[cfg(not(unix))]
    Err(executable_invalid(&"probe execution is not certified here"))
}

fn bounded_stdout(len: usize) -> Result<(), RuntimeProbeError> {
    let max = MAX_PROBE_STDOUT_BYTES;
    (len <= max)
        .then_some(())
        .ok_or(RuntimeProbeError::OutputOversized { max })
}

fn control_free(value: &str, allow_newline: bool) -> bool {
    value
        .chars()
        .all(|c| !c.is_control() || (allow_newline && c == '\n'))
}

fn validate_provider(provider: &str) -> Result<(), RuntimeProbeError> {
    let lowercase = provider.bytes().all(|byte| byte.is_ascii_lowercase());
    let ok = lowercase && !provider.is_empty() && provider.len() <= MAX_PROVIDER_BYTES;
    ensure(ok, "provider must be a short lowercase wire name")
}

fn printable(name: &str, value: &str) -> Result<(), RuntimeProbeError> {
    let clean = !value.is_empty() && control_free(value, false);
    ensure(clean, &format!("{name} must be printable"))
}

fn bounded(name: &str, len: usize, max: usize) -> Result<(), RuntimeProbeError> {
    ensure(len <= max, &format!("{name} exceeds {max}"))
}

fn hex_64(name: &str, value: &str) -> Result<(), RuntimeProbeError> {
    ensure(is_lower_hex_64(value), &format!("{name} must be 64 hex"))
}

fn ensure(ok: bool, reason: &str) -> Result<(), RuntimeProbeError> {
    ok.then_some(()).ok_or_else(|| malformed(reason))
}

fn malformed(reason: &str) -> RuntimeProbeError {
    RuntimeProbeError::Malformed {
        reason: reason.to_string(),
    }
}

fn executable_invalid(reason: &dyn std::fmt::Display) -> RuntimeProbeError {
    RuntimeProbeError::ExecutableInvalid {
        reason: reason.to_string(),
    }
}

fn wire(error: HarnessError) -> RuntimeProbeError {
    malformed(&format!("canonical encoding: {error}"))
}
