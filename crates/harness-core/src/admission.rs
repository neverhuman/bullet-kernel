//! Central, fail-closed provider admission evaluation. It proves local
//! executable/probe/HOME/canary properties but deliberately cannot authorize
//! live dispatch without signed Kernel authority and audited egress isolation.

mod credentials;
mod mutation_permit;
mod protocol;
mod receipt;
mod signed;

use crate::adapter::HarnessDescriptor;
use crate::capability::{CapabilityMatrix, CapabilityState, PromotionStage};
use crate::error::HarnessError;
use crate::probe::{ProbeResult, ProfileRef};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use protocol::requirement;
use receipt::ReceiptInput;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub use crate::launch_grant::environment_digest;
pub use credentials::{CredentialGrant, CredentialReceipt, PreparedProviderHome};
pub use mutation_permit::{
    mutation_operation_audience, parse_mutation_operation, require_signed_mutation_permit,
    AuthorityAudience, MutationOperation, MutationPermitClaims, MutationPermitExpectation,
    MutationPermitSigningKey, MutationPermitVerificationKey, SignedMutationPermit,
    MAX_MUTATION_PERMIT_TTL_MS, MUTATION_PERMIT_IMPLICIT_ASSERTION, MUTATION_PERMIT_SCHEMA_VERSION,
};
pub use protocol::{ProtocolRequirement, ProviderProtocol};
pub use receipt::{
    AdmissionBlocker, CanarySecrets, ConformanceEvidence, ProviderConformanceReceipt,
};
pub use signed::{
    EgressIsolationEvidence, EgressIsolationRecord, EgressProbe, EgressProbeOutcome,
    SignedAuthorityRecord, REQUIRED_EGRESS_PROBES,
};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// Exact facts produced by an isolated runtime probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProbeSnapshot {
    /// Complete descriptor returned by this exact probed adapter build.
    pub descriptor: HarnessDescriptor,
    /// Absolute canonical executable path observed by the probe.
    pub executable: PathBuf,
    /// BLAKE3 digest of the probed executable bytes.
    pub executable_blake3: String,
    /// Protocol demonstrated by the runtime probe.
    pub protocol: ProviderProtocol,
    /// Effective provider profile plus the exact version.
    pub identity: ProbeResult,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
}

/// Immutable expected subject for one local admission evaluation.
#[derive(Clone, Debug)]
pub struct ProviderAdmissionPolicy {
    /// Provider wire name.
    pub provider: String,
    /// Exact absolute canonical executable path.
    pub executable: PathBuf,
    /// Expected executable digest.
    pub executable_blake3: String,
    /// Exact admitted version string.
    pub version: String,
    /// Exact admitted complete descriptor digest.
    pub descriptor_blake3: String,
    /// Authorized credential profile.
    pub profile: ProfileRef,
    /// Frozen V1 protocol. A caller cannot weaken the provider baseline.
    pub required_protocol: ProviderProtocol,
    /// Maximum runtime-probe age.
    pub max_probe_age_seconds: i64,
    /// Canonical directory under which the ephemeral HOME is created.
    pub runtime_root: PathBuf,
    /// Exact relative OAuth destination files admitted by policy.
    pub credential_targets: Vec<PathBuf>,
    /// Individually digest-bound OAuth files.
    pub credentials: Vec<CredentialGrant>,
}

/// Locally evaluated admission. It owns the ephemeral credential HOME and is
/// still non-dispatchable until a future signed/contained boundary replaces
/// the explicit blockers.
#[derive(Debug)]
pub struct ProviderAdmission {
    policy: ProviderAdmissionPolicy,
    probe: RuntimeProbeSnapshot,
    capability_blake3: String,
    descriptor_blake3: String,
    profile_blake3: String,
    environment_blake3: String,
    home: PreparedProviderHome,
    canaries: CanarySecrets,
    blockers: BTreeSet<AdmissionBlocker>,
    evaluated_at: DateTime<Utc>,
}

/// Final local conformance result plus the still-live ephemeral HOME.
#[derive(Debug)]
pub struct EvaluatedAdmission {
    receipt: ProviderConformanceReceipt,
    executable: PathBuf,
    home: PreparedProviderHome,
}

impl ProviderAdmission {
    /// Validate exact executable/probe/profile/capability facts and stage the
    /// minimum credential set. No provider process is invoked.
    ///
    /// # Errors
    ///
    /// Fails closed for any mismatch, stale probe, unsafe filesystem subject,
    /// weak canary, or credential staging failure.
    pub fn prepare<I>(
        policy: ProviderAdmissionPolicy,
        probe: RuntimeProbeSnapshot,
        inherited_env: I,
        canaries: CanarySecrets,
        evaluated_at: DateTime<Utc>,
    ) -> Result<Self, HarnessError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let required = requirement(&policy.provider)?;
        if policy.required_protocol != required.protocol {
            return Err(refused("policy weakens the frozen provider protocol"));
        }
        validate_digest(&policy.executable_blake3, "executable")?;
        validate_digest(&policy.descriptor_blake3, "descriptor")?;
        let executable_blake3 = executable_digest(&policy.executable)?;
        if executable_blake3 != policy.executable_blake3
            || probe.executable_blake3 != policy.executable_blake3
            || probe.executable != policy.executable
        {
            return Err(refused("runtime executable identity mismatch"));
        }
        let observed_version = match &probe.descriptor.version {
            bullet_domain::Observation::Value { value } => value,
            _ => return Err(refused("runtime descriptor version is not verified")),
        };
        if probe.descriptor.provider != policy.provider
            || observed_version != &policy.version
            || probe.identity.version != policy.version
        {
            return Err(refused("runtime provider/version mismatch"));
        }
        let executable_name = policy
            .executable
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| refused("provider executable has no UTF-8 file name"))?;
        if probe.descriptor.binary != executable_name
            || Path::new(&probe.descriptor.binary).components().count() != 1
        {
            return Err(refused("runtime descriptor binary identity mismatch"));
        }
        if probe.descriptor.stage < PromotionStage::ContractPass {
            return Err(refused("adapter has not reached contract-pass stage"));
        }
        let identity = probe
            .identity
            .verify(&policy.provider, &policy.profile.expected)?;
        if identity.provider != policy.provider {
            return Err(refused("runtime identity names a different provider"));
        }
        validate_probe_time(&probe, evaluated_at, policy.max_probe_age_seconds)?;
        let descriptor_blake3 = descriptor_digest(&probe.descriptor)?;
        if descriptor_blake3 != policy.descriptor_blake3 {
            return Err(refused("runtime descriptor mismatch"));
        }
        let capability_blake3 = capability_digest(&probe.descriptor.capabilities)?;

        let mut blockers = BTreeSet::from([
            AdmissionBlocker::SignedAuthorityUnavailable,
            AdmissionBlocker::EgressIsolationUnavailable,
        ]);
        if probe.protocol != required.protocol {
            blockers.insert(AdmissionBlocker::ProtocolNonconformant);
        }
        if required.capabilities.iter().any(|capability| {
            !matches!(
                probe.descriptor.capabilities.state(*capability),
                CapabilityState::Supported | CapabilityState::SupportedWithLimitations
            )
        }) {
            blockers.insert(AdmissionBlocker::CapabilityNonconformant);
        }
        let home = PreparedProviderHome::stage(
            &policy.runtime_root,
            &policy.credential_targets,
            &policy.credentials,
            inherited_env,
        )?;
        canaries.inspect_env(home.env())?;
        let profile_blake3 = serialized_digest(b"profile", &probe.identity)?;
        let environment_blake3 = serialized_digest(b"environment", &home.env())?;
        Ok(Self {
            policy,
            probe,
            capability_blake3,
            descriptor_blake3,
            profile_blake3,
            environment_blake3,
            home,
            canaries,
            blockers,
            evaluated_at,
        })
    }

    /// Validate output/event/proposal evidence and produce a receipt that
    /// preserves all live-dispatch blockers.
    ///
    /// # Errors
    ///
    /// Fails on canary exposure, malformed lifecycle events, or an invalid
    /// PatchProposal.
    pub fn finalize(
        self,
        evidence: ConformanceEvidence<'_>,
    ) -> Result<EvaluatedAdmission, HarnessError> {
        let commitments = evidence.validate(&self.policy.provider, &self.canaries)?;
        let executable = self.policy.executable.to_string_lossy().into_owned();
        let receipt = ProviderConformanceReceipt::from_input(ReceiptInput {
            provider: &self.policy.provider,
            executable: &executable,
            executable_blake3: &self.policy.executable_blake3,
            version: &self.policy.version,
            capability_blake3: &self.capability_blake3,
            descriptor_blake3: &self.descriptor_blake3,
            profile_id: self.policy.profile.profile_id.as_str(),
            profile_blake3: &self.profile_blake3,
            environment_blake3: &self.environment_blake3,
            current_protocol: self.probe.protocol,
            required_protocol: self.policy.required_protocol,
            probed_at: self.probe.observed_at,
            evaluated_at: self.evaluated_at,
            credentials: self.home.credential_receipts(),
            evidence: &commitments,
            blockers: &self.blockers,
        })?;
        Ok(EvaluatedAdmission {
            receipt,
            executable: self.policy.executable,
            home: self.home,
        })
    }
}

impl EvaluatedAdmission {
    /// Non-authoritative local conformance receipt.
    #[must_use]
    pub fn receipt(&self) -> &ProviderConformanceReceipt {
        &self.receipt
    }

    /// Exact admitted executable.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Exact child environment, including the ephemeral HOME.
    #[must_use]
    pub fn child_env(&self) -> &[(String, String)] {
        self.home.env()
    }

    /// Dispatch is possible only once every blocker has been cleared by its
    /// own evidence (`admit_signed`, `admit_egress`); the receipt is
    /// re-verified first so an altered receipt never dispatches.
    ///
    /// # Errors
    ///
    /// `PROVIDER_ADMISSION_BLOCKED` naming the first remaining blocker, or
    /// `ADMISSION_REFUSED` on a tampered receipt.
    pub fn require_dispatch(&self) -> Result<(), HarnessError> {
        self.receipt.verify()?;
        if self.receipt.blockers.is_empty() {
            return Ok(());
        }
        Err(HarnessError::AdmissionBlocked {
            blocker: self.receipt.first_blocker().to_string(),
        })
    }
}

/// Stable digest of an exact complete capability matrix.
///
/// # Errors
///
/// `ADMISSION_REFUSED` if serialization fails.
pub fn capability_digest(matrix: &CapabilityMatrix) -> Result<String, HarnessError> {
    let bytes = serde_json::to_vec(matrix)
        .map_err(|error| refused(&format!("capability matrix serialization failed: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bullet-provider-capabilities-v1\0");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

/// Stable digest of the complete descriptor returned by a runtime probe.
///
/// # Errors
///
/// `ADMISSION_REFUSED` if serialization fails.
pub fn descriptor_digest(descriptor: &HarnessDescriptor) -> Result<String, HarnessError> {
    serialized_digest(b"descriptor", descriptor)
}

/// Hash and validate an exact canonical executable.
///
/// # Errors
///
/// `ADMISSION_REFUSED` for a relative, symlinked, non-regular,
/// non-executable, oversized, or non-canonical path.
pub fn executable_digest(path: &Path) -> Result<String, HarnessError> {
    if !path.is_absolute() {
        return Err(refused("provider executable must be absolute"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| io("provider executable metadata", error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(refused(
            "provider executable must be a bounded regular file",
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| io("canonicalize provider executable", error))?;
    if canonical != path {
        return Err(refused("provider executable path is not canonical"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(refused("provider executable has no execute bit"));
        }
    }
    #[cfg(not(unix))]
    return Err(refused(
        "provider execution is not certified on this platform",
    ));

    let mut file = File::open(path).map_err(|error| io("open provider executable", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file
            .metadata()
            .map_err(|error| io("opened provider executable metadata", error))?;
        if metadata.dev() != opened.dev()
            || metadata.ino() != opened.ino()
            || metadata.len() != opened.len()
            || !opened.file_type().is_file()
        {
            return Err(refused(
                "provider executable identity changed while opening",
            ));
        }
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io("read provider executable", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_probe_time(
    probe: &RuntimeProbeSnapshot,
    now: DateTime<Utc>,
    max_age_seconds: i64,
) -> Result<(), HarnessError> {
    if max_age_seconds <= 0
        || probe.observed_at > now + ChronoDuration::seconds(5)
        || now - probe.observed_at > ChronoDuration::seconds(max_age_seconds)
    {
        return Err(refused("runtime probe is stale or from the future"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), HarnessError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused(&format!(
            "{label} digest must be 64 lowercase hex characters"
        )));
    }
    Ok(())
}

fn serialized_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, HarnessError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| refused(&format!("admission serialization failed: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bullet-provider-admission-v1\0");
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn refused(reason: &str) -> HarnessError {
    HarnessError::AdmissionRefused {
        reason: reason.to_string(),
    }
}

fn io(context: &str, error: std::io::Error) -> HarnessError {
    HarnessError::Io {
        context: context.to_string(),
        reason: error.to_string(),
    }
}
