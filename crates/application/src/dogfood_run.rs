//! Compose one read-only dogfood turn (ADR 0015).
//!
//! This is the production caller of `filesystem_command` and
//! `dispatch_dogfood_turn`. It never applies a proposal and never flips
//! `live_admission_enabled`.

use crate::dogfood::{write_receipt, DogfoodReadOnlyReceiptV0};
use crate::live_conformance::{enrollment_path, load_provider_enrollment};
use crate::policy_snapshot::{
    refuse_dogfood_binding_as_live, validate_dogfood_admission, DogfoodAudience, DogfoodBinding,
    DogfoodOperation, LoadedPolicy,
};
use bullet_harness_claude::dogfood::dispatch_dogfood_turn;
use bullet_harness_core::{
    inspect_provider_runtime, synthetic_uuid, CanarySecrets, CredentialGrant, LiveTurnRequest,
    PreparedProviderHome, ProviderRuntimePassportV1, RuntimeFileRoleV1, RUNTIME_DEPLOYMENT_PREFIX,
};
use bullet_harness_egress::filesystem::FilesystemRuntimeFileV0;
use bullet_harness_egress::{
    EgressPolicy, EgressSandbox, FilesystemFileV0, FilesystemSandboxProfileV0,
    CONTAINMENT_UNAVAILABLE_EXIT,
};
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Designed-neutral exit used for missing operator input and missing namespaces.
pub const DOGFOOD_NEUTRAL_EXIT: u8 = CONTAINMENT_UNAVAILABLE_EXIT;

/// One operator credential grant (host source never appears on the receipt).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSpec {
    /// Absolute source file.
    pub source: PathBuf,
    /// Relative destination under the staged HOME.
    pub target: PathBuf,
    /// Expected BLAKE3 of the source bytes.
    pub blake3: String,
}

/// Providers the dogfood compose recognizes. Only Claude has a dispatch
/// today; the other three refuse with a typed reason until their M2 lanes
/// land, so `--provider codex` fails closed instead of silently running the
/// wrong protocol.
pub const DOGFOOD_PROVIDERS: [&str; 4] = ["claude", "codex", "cursor", "antigravity"];

/// Operator inputs for one read-only dogfood compose.
#[derive(Clone, Debug)]
pub struct DogfoodReadOnlyOptions {
    /// Provider name from [`DOGFOOD_PROVIDERS`].
    pub provider: String,
    /// Absolute 0700 runtime data directory.
    pub data_dir: PathBuf,
    /// Absolute 0600 v1alpha2 policy.
    pub policy: PathBuf,
    /// Absolute `DogfoodBindingV1` JSON.
    pub binding: PathBuf,
    /// Absolute enrollment file: `<data-dir>/policy/enrollments/<provider>.json`.
    pub enrollment: PathBuf,
    /// Operator issuer label. Never `bullet-kernel` with `launch-grant-alpha`.
    pub issuer: String,
    /// Operator key id. `launch-grant-alpha` is refused.
    pub key_id: String,
    /// Absolute provider executable. Must match the enrollment.
    pub executable: PathBuf,
    /// Repeatable credential grants.
    pub credentials: Vec<CredentialSpec>,
    /// Absolute family working directory, bound read-only.
    pub workdir: PathBuf,
    /// Prompt. Missing is designed-neutral 78.
    pub prompt: Option<String>,
    /// Optional tighter USD cap; enrollment max still wins.
    pub max_budget_usd: Option<f64>,
    /// Create-once receipt path.
    pub receipt: PathBuf,
}

/// Terminal status of one compose attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DogfoodRunStatus {
    /// Valid 0600 receipt and one proposal. Exit 0.
    Succeeded {
        /// Receipt path.
        receipt: PathBuf,
        /// Proposal path.
        proposal: PathBuf,
    },
    /// Designed-neutral. Exit 78.
    Neutral {
        /// Stable reason code.
        code: &'static str,
        /// Non-secret detail.
        detail: String,
    },
}

/// Fail-closed compose error. Exit 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DogfoodRunError {
    /// Stable reason code.
    pub code: &'static str,
    /// Non-secret detail.
    pub detail: String,
}

impl std::fmt::Display for DogfoodRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for DogfoodRunError {}

/// Load, contain, dispatch, and write one create-once receipt. Never applies.
///
/// # Errors
///
/// Typed refusal for live admission, enrollment mismatch, overwrite, or spawn failure.
pub fn run_dogfood_read_only(
    options: DogfoodReadOnlyOptions,
) -> Result<DogfoodRunStatus, DogfoodRunError> {
    let prompt = match options.prompt.as_deref() {
        Some(prompt) if !prompt.is_empty() => prompt.to_owned(),
        _ => {
            return Ok(neutral(
                "DOGFOOD_PROMPT_MISSING",
                "prompt is required for a live turn",
            ));
        }
    };
    if !DOGFOOD_PROVIDERS.contains(&options.provider.as_str()) {
        return Err(failed(
            "DOGFOOD_PROVIDER_UNKNOWN",
            format!(
                "provider {:?} is not one of {DOGFOOD_PROVIDERS:?}",
                options.provider
            ),
        ));
    }
    if options.provider != "claude" {
        // Fail before any policy read, staging, or spend: the per-provider
        // dispatch (argv + transcript profile) for these lanes has not landed.
        // See DOGFOOD-MULTI-CLI-GATES.md M2-Codex / M2-Cursor / M2-Antigravity.
        return Err(failed(
            "DOGFOOD_PROVIDER_UNIMPLEMENTED",
            format!(
                "provider {:?} has no dogfood dispatch yet; only \"claude\" is wired",
                options.provider
            ),
        ));
    }
    refuse_launch_grant_alpha(&options.issuer, &options.key_id)?;
    require_absolute("data-dir", &options.data_dir)?;
    require_absolute("policy", &options.policy)?;
    require_absolute("binding", &options.binding)?;
    require_absolute("enrollment", &options.enrollment)?;
    require_absolute("executable", &options.executable)?;
    require_absolute("workdir", &options.workdir)?;
    require_absolute("receipt", &options.receipt)?;
    ensure_private_dir(&options.data_dir)?;

    let policy_bytes = match read_regular_0600(&options.policy) {
        Ok(bytes) => bytes,
        Err(error) if error.code == "DOGFOOD_POLICY_MISSING" => {
            return Ok(neutral(error.code, error.detail));
        }
        Err(error) => return Err(error),
    };
    let loaded = LoadedPolicy::from_bytes(&policy_bytes)
        .map_err(|error| failed("DOGFOOD_POLICY_INVALID", error.to_string()))?;
    if loaded.live_admission_enabled() {
        return Err(failed(
            "DOGFOOD_REFUSES_LIVE_ADMISSION",
            "dogfood admission refuses a general live binding",
        ));
    }
    let binding = load_binding(&options.binding)?;
    if refuse_dogfood_binding_as_live(&binding).is_ok() {
        return Err(failed(
            "LIVE_ADMISSION_REFUSES_DOGFOOD_BINDING",
            "dogfood binding must never satisfy live admission",
        ));
    }
    validate_dogfood_admission(loaded.snapshot(), &binding)
        .map_err(|error| failed("DOGFOOD_ADMISSION_REFUSED", error.to_string()))?;

    let expected_enrollment = enrollment_path(&options.data_dir, &options.provider);
    if options.enrollment != expected_enrollment {
        return Ok(neutral(
            "ENROLLMENT_PATH_MISMATCH",
            format!("enrollment must be {}", expected_enrollment.display()),
        ));
    }
    let now = unix_ms();
    let enrolled =
        load_provider_enrollment(&options.data_dir, &options.provider, now).map_err(|error| {
            if error.reason_code() == "ENROLLMENT_MISSING" {
                return DogfoodRunError {
                    code: "ENROLLMENT_MISSING",
                    detail: error.to_string(),
                };
            }
            failed(error.reason_code(), error.to_string())
        });
    let enrolled = match enrolled {
        Ok(enrolled) => enrolled,
        Err(error) if error.code == "ENROLLMENT_MISSING" => {
            return Ok(neutral(error.code, error.detail));
        }
        Err(error) => return Err(error),
    };
    if enrolled.record().executable != options.executable {
        return Err(failed(
            "ENROLLMENT_EXECUTABLE_MISMATCH",
            "CLI executable must equal the enrolled path",
        ));
    }
    let expected_digest = enrolled.record().executable_blake3.clone();
    let observed = file_blake3(&options.executable)?;
    if observed != expected_digest {
        return Err(failed(
            "ENROLLMENT_EXECUTABLE_DIGEST_MISMATCH",
            format!("enrolled {expected_digest} observed {observed}"),
        ));
    }

    let grants: Vec<CredentialGrant> = options
        .credentials
        .iter()
        .map(|spec| CredentialGrant {
            source: spec.source.clone(),
            target: spec.target.clone(),
            expected_blake3: spec.blake3.clone(),
        })
        .collect();
    let targets: Vec<PathBuf> = grants.iter().map(|grant| grant.target.clone()).collect();
    let runtime_root = options.data_dir.join("runtime");
    ensure_private_dir(&runtime_root)?;
    let home = PreparedProviderHome::stage(&runtime_root, &targets, &grants, std::env::vars())
        .map_err(|error| failed("DOGFOOD_HOME_STAGE", error.to_string()))?;
    for receipt in home.credential_receipts() {
        if receipt.target.contains('/')
            && receipt
                .target
                .contains(home.path().to_string_lossy().as_ref())
        {
            return Err(failed(
                "DOGFOOD_HOST_SOURCE_IN_RECEIPT",
                "credential receipt leaked a host path",
            ));
        }
    }

    let workdir = options
        .workdir
        .canonicalize()
        .map_err(|error| failed("DOGFOOD_WORKDIR", error.to_string()))?;
    if !workdir.is_dir() {
        return Ok(neutral(
            "DOGFOOD_WORKDIR_MISSING",
            "workdir must be an existing directory",
        ));
    }

    let max_cost_micro_usd =
        budget_micro_usd(options.max_budget_usd, enrolled.max_cost_micro_usd())?;
    let bubblewrap = match require_host_file("/usr/bin/bwrap") {
        Ok(path) => path,
        Err(error) if error.code == "CONTAINMENT_UNAVAILABLE" => {
            return Ok(neutral(error.code, error.detail));
        }
        Err(error) => return Err(error),
    };
    let ca_bundle = match require_host_file("/etc/ssl/certs/ca-certificates.crt") {
        Ok(path) => path,
        Err(error) if error.code == "CONTAINMENT_UNAVAILABLE" => {
            return Ok(neutral(error.code, error.detail));
        }
        Err(error) => return Err(error),
    };
    let schema_path = runtime_root.join("proposal-schema.json");
    let schema_bytes = bullet_harness_core::proposal::schema_source().as_bytes();
    write_0600(&schema_path, schema_bytes)?;
    // The schema's integrity is the compiled-in constant, not filesystem
    // custody: admit the digest of the constant bytes, so a swapped file is
    // refused by content rather than trusted by ownership.
    let schema_admitted = FilesystemFileV0::new(
        &schema_path,
        blake3::hash(schema_bytes).to_hex().to_string(),
    );
    let scratch = runtime_root.join(format!("scratch-{}", synthetic_uuid("scratch")));
    ensure_private_dir(&scratch)?;

    let passported = passported_runtime(&options.executable)?;
    let (runtime_files, provider_max_bytes) = match passported {
        Some(runtime) => (runtime.runtime_files, Some(runtime.provider_max_bytes)),
        None => (Vec::new(), None),
    };
    let mut profile = FilesystemSandboxProfileV0::new(
        host_file(&bubblewrap)?,
        host_file(&options.executable)?,
        workdir.clone(),
        schema_admitted,
        host_file(&ca_bundle)?,
        runtime_files,
        scratch,
    )
    .with_prepared_home(home.path());
    if let Some(bytes) = provider_max_bytes {
        profile = profile.with_provider_max_bytes(bytes);
    }
    let filesystem = profile
        .prepare()
        .map_err(|error| failed("DOGFOOD_FILESYSTEM", error.to_string()))?;

    let egress_dir = runtime_root.join(format!("egress-{}", synthetic_uuid("egress")));
    ensure_private_dir(&egress_dir)?;
    let policy = EgressPolicy::for_provider(&options.provider)
        .map_err(|error| failed("DOGFOOD_EGRESS_POLICY", error.to_string()))?;
    let sandbox = match EgressSandbox::prepare(policy, &egress_dir) {
        Ok(sandbox) => sandbox,
        Err(error) => {
            return Ok(neutral(
                "CONTAINMENT_UNAVAILABLE",
                format!("{error}; exit {DOGFOOD_NEUTRAL_EXIT}"),
            ));
        }
    };
    filesystem
        .command_plan(&[])
        .map_err(|error| failed("DOGFOOD_FILESYSTEM_PLAN", error.to_string()))?;

    let canaries = CanarySecrets::new(vec![synthetic_uuid("canary-one")])
        .map_err(|error| failed("DOGFOOD_CANARY", error.to_string()))?;
    let request = LiveTurnRequest {
        session_id: bullet_harness_core::AgentSessionId::new(synthetic_uuid("session")),
        invocation_id: bullet_harness_core::InvocationId::new(synthetic_uuid("invocation")),
        prompt,
        workdir: workdir.clone(),
        expected_runtime_version: enrolled.record().version.clone(),
        gate_ids: Vec::new(),
        max_cost_micro_usd,
        wall_timeout: Duration::from_secs(180),
        canaries: canaries.clone(),
    };
    // The child environment is composed INSIDE the bubblewrap plan via
    // --setenv (HOME=/home/bullet, PATH=/runtime/bin, TMPDIR, locale,
    // SSL_CERT_FILE, proxy variables), so ignoring the factory's env argument
    // is correct by design: the outer Command's env never reaches the child.
    // What must not be silent is a composition failure or a program
    // substitution -- record either and surface it as the typed error instead
    // of letting a /bin/false exit masquerade as a provider failure.
    let compose_error: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    let admitted_program = options.executable.to_string_lossy().into_owned();
    let factory = |program: &str, args: &[&str], _: &[(&str, &str)]| {
        if program != admitted_program {
            *compose_error.borrow_mut() = Some(format!(
                "dispatch requested {program:?} but the admitted provider is {admitted_program:?}"
            ));
            let mut command = Command::new("/bin/false");
            command.env_clear();
            return command;
        }
        match sandbox.filesystem_command(&filesystem, args) {
            Ok(command) => command,
            Err(error) => {
                *compose_error.borrow_mut() = Some(error.to_string());
                let mut command = Command::new("/bin/false");
                command.env_clear();
                command
            }
        }
    };
    let dispatched = dispatch_dogfood_turn(
        &options.executable,
        &expected_digest,
        &factory,
        &request,
        &enrolled.record().version,
        bullet_harness_egress::filesystem::CLONE_DESTINATION,
    );
    if let Some(detail) = compose_error.borrow_mut().take() {
        return Err(failed("DOGFOOD_CONTAINMENT_COMPOSE", detail));
    }
    let outcome = dispatched.map_err(|error| failed("DOGFOOD_DISPATCH", error.to_string()))?;

    let proposal_bytes = serde_json::to_vec(&outcome.proposal)
        .map_err(|error| failed("DOGFOOD_PROPOSAL", error.to_string()))?;
    let proposal_blake3 = blake3::hash(&proposal_bytes).to_hex().to_string();
    let proposal_path = options.receipt.with_extension("proposal.json");
    write_create_once_0600(&proposal_path, &proposal_bytes)?;

    let receipt = DogfoodReadOnlyReceiptV0 {
        schema_version: DogfoodReadOnlyReceiptV0::SCHEMA_VERSION.to_owned(),
        kind: DogfoodReadOnlyReceiptV0::KIND.to_owned(),
        class: DogfoodReadOnlyReceiptV0::CLASS.to_owned(),
        release_eligible: false,
        transaction_eligible: false,
        live_eligible: false,
        profile_eligible: false,
        candidate_eligible: false,
        scm_eligible: false,
        effect_eligible: false,
        verification_eligible: false,
        custody: DogfoodReadOnlyReceiptV0::CUSTODY.to_owned(),
        proposal_blake3,
        enrolled_runtime_version: enrolled.record().version.clone(),
        wall_ms: outcome.live.wall_ms,
        total_cost_micro_usd: outcome.live.total_cost_micro_usd,
    };
    write_receipt(&options.receipt, &receipt).map_err(|error| match error {
        crate::dogfood::DogfoodError::Refused("receipt overwrite is refused") => {
            failed("DOGFOOD_RECEIPT_EXISTS", "receipt overwrite is refused")
        }
        other => failed("DOGFOOD_RECEIPT", other.to_string()),
    })?;
    Ok(DogfoodRunStatus::Succeeded {
        receipt: options.receipt,
        proposal: proposal_path,
    })
}

fn refuse_launch_grant_alpha(issuer: &str, key_id: &str) -> Result<(), DogfoodRunError> {
    if key_id == "launch-grant-alpha"
        || (issuer == "bullet-kernel" && key_id.contains("launch-grant"))
    {
        return Err(failed(
            "DOGFOOD_REFUSES_LIVE_CONFORMANCE_KEY",
            "launch-grant-alpha is not a dogfood issuer key",
        ));
    }
    if issuer.is_empty() || key_id.is_empty() {
        return Ok(());
    }
    Ok(())
}

fn load_binding(path: &Path) -> Result<DogfoodBinding, DogfoodRunError> {
    let bytes = read_regular_file(path)?;
    let wire: WireBinding = serde_json::from_slice(&bytes)
        .map_err(|error| failed("INVALID_DOGFOOD_BINDING", error.to_string()))?;
    if wire.schema_version != "v1alpha1"
        || wire.audience != "dogfood-runner"
        || wire.operation != "read-only-propose"
    {
        return Err(failed(
            "INVALID_DOGFOOD_BINDING",
            "dogfood binding must be dogfood-runner / read-only-propose",
        ));
    }
    Ok(DogfoodBinding {
        schema_version: wire.schema_version,
        audience: DogfoodAudience::DogfoodRunner,
        operation: DogfoodOperation::ReadOnlyPropose,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    schema_version: String,
    audience: String,
    operation: String,
}

fn budget_micro_usd(requested: Option<f64>, enrolled_max: u64) -> Result<u64, DogfoodRunError> {
    let Some(usd) = requested else {
        return Ok(enrolled_max);
    };
    if !usd.is_finite() || usd <= 0.0 {
        return Err(failed(
            "DOGFOOD_BUDGET",
            "max-budget-usd must be a positive finite number",
        ));
    }
    let micro = (usd * 1_000_000.0).round() as u64;
    if micro > enrolled_max {
        return Err(failed(
            "DOGFOOD_BUDGET",
            "requested budget exceeds the enrolled cap",
        ));
    }
    Ok(micro)
}

fn require_absolute(name: &str, path: &Path) -> Result<(), DogfoodRunError> {
    if path.as_os_str().is_empty() {
        return Err(failed(
            "DOGFOOD_INPUT_MISSING",
            format!("{name} is required"),
        ));
    }
    if !path.is_absolute() {
        return Err(failed(
            "DOGFOOD_PATH_NOT_ABSOLUTE",
            format!("{name} must be absolute"),
        ));
    }
    Ok(())
}

fn require_host_file(path: &str) -> Result<PathBuf, DogfoodRunError> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err(failed(
            "CONTAINMENT_UNAVAILABLE",
            format!("{} is not available on this host", path.display()),
        ));
    }
    path.canonicalize()
        .map_err(|error| failed("DOGFOOD_HOST_FILE", error.to_string()))
}

fn host_file(path: &Path) -> Result<FilesystemFileV0, DogfoodRunError> {
    Ok(FilesystemFileV0::new(path, file_blake3(path)?))
}

fn file_blake3(path: &Path) -> Result<String, DogfoodRunError> {
    let bytes =
        fs::read(path).map_err(|error| failed("DOGFOOD_DIGEST", format!("{path:?}: {error}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn read_regular_0600(path: &Path) -> Result<Vec<u8>, DogfoodRunError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        failed(
            "DOGFOOD_POLICY_MISSING",
            format!("{} is not a file", path.display()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(failed(
            "DOGFOOD_POLICY_MISSING",
            "policy must be a regular file",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(failed("DOGFOOD_POLICY_MODE", "policy must be mode 0600"));
    }
    fs::read(path).map_err(|error| failed("DOGFOOD_POLICY_IO", error.to_string()))
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, DogfoodRunError> {
    fs::read(path).map_err(|_| DogfoodRunError {
        code: "DOGFOOD_BINDING_MISSING",
        detail: format!("{} is not a file", path.display()),
    })
}

/// Sandbox mount destinations a runtime file may bind to. Mirrors the egress
/// destination allowlist; files outside these prefixes (licenses, SBOMs,
/// schemas) are custody-verified by the inspector but never mounted.
const RUNTIME_DESTINATION_PREFIXES: [&str; 4] = ["/runtime/bin", "/lib", "/lib64", "/usr/lib"];

/// Facts a verified runtime passport contributes to the compose.
#[derive(Debug)]
struct PassportedRuntime {
    runtime_files: Vec<FilesystemRuntimeFileV0>,
    provider_max_bytes: u64,
}

/// When the executable lives under the frozen deployment prefix, a verified
/// passport is mandatory: it supplies the loader/library mounts a dynamic
/// provider needs (the bwrap base set deliberately binds no /lib or /usr) and
/// the exact provider size bound that replaces the blanket 64 MiB ceiling.
/// Outside the prefix nothing changes. The passport file lives beside the
/// immutable tree at `<deployment_root>.passport.json`.
fn passported_runtime(executable: &Path) -> Result<Option<PassportedRuntime>, DogfoodRunError> {
    let prefix = Path::new(RUNTIME_DEPLOYMENT_PREFIX);
    let Ok(relative) = executable.strip_prefix(prefix) else {
        return Ok(None);
    };
    let mut components = relative.components();
    let (Some(provider), Some(version)) = (components.next(), components.next()) else {
        return Err(failed(
            "DOGFOOD_PASSPORT_LAYOUT",
            "deployment executable must be <prefix>/<provider>/<version>/<entrypoint>",
        ));
    };
    let root = prefix.join(provider).join(version);
    let passport_path = root.with_extension("passport.json");
    let bytes = fs::read(&passport_path).map_err(|error| {
        failed(
            "DOGFOOD_PASSPORT_MISSING",
            format!("{}: {error}", passport_path.display()),
        )
    })?;
    let passport = ProviderRuntimePassportV1::decode(&bytes)
        .map_err(|error| failed("DOGFOOD_PASSPORT_INVALID", error.to_string()))?;
    let expected_id = passport
        .passport_id()
        .map_err(|error| failed("DOGFOOD_PASSPORT_INVALID", error.to_string()))?;
    let inspected = inspect_provider_runtime(&bytes, &expected_id)
        .map_err(|error| failed("DOGFOOD_PASSPORT_REFUSED", error.to_string()))?;
    let entrypoint = root.join(inspected.entrypoint());
    if entrypoint != executable {
        return Err(failed(
            "DOGFOOD_PASSPORT_ENTRYPOINT_MISMATCH",
            format!(
                "passport entrypoint {} is not the admitted executable {}",
                entrypoint.display(),
                executable.display()
            ),
        ));
    }
    let mut provider_max_bytes = None;
    let mut runtime_files = Vec::new();
    for file in &passport.files {
        if file.path == passport.entrypoint {
            provider_max_bytes = Some(file.size);
            continue;
        }
        if matches!(
            file.role,
            RuntimeFileRoleV1::License
                | RuntimeFileRoleV1::Sbom
                | RuntimeFileRoleV1::ProtocolSchema
        ) {
            continue;
        }
        let destination = format!("/{}", file.path);
        if !RUNTIME_DESTINATION_PREFIXES
            .iter()
            .any(|prefix| destination.starts_with(&format!("{prefix}/")))
        {
            continue;
        }
        runtime_files.push(FilesystemRuntimeFileV0::new(
            FilesystemFileV0::new(root.join(&file.path), file.blake3.clone()),
            destination,
        ));
    }
    let provider_max_bytes = provider_max_bytes.ok_or_else(|| {
        failed(
            "DOGFOOD_PASSPORT_INVALID",
            "passport manifest does not list its own entrypoint",
        )
    })?;
    Ok(Some(PassportedRuntime {
        runtime_files,
        provider_max_bytes,
    }))
}

fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), DogfoodRunError> {
    fs::write(path, bytes).map_err(|error| failed("DOGFOOD_IO", error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| failed("DOGFOOD_IO", error.to_string()))
}

/// Create-once 0600 write for run evidence. A rerun must never overwrite an
/// earlier run's artifact; the receipt already refuses overwrite and every
/// sibling artifact must hold the same line.
fn write_create_once_0600(path: &Path, bytes: &[u8]) -> Result<(), DogfoodRunError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                failed(
                    "DOGFOOD_ARTIFACT_EXISTS",
                    format!("{} already exists; evidence is create-once", path.display()),
                )
            } else {
                failed("DOGFOOD_IO", error.to_string())
            }
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed("DOGFOOD_IO", error.to_string()))
}

fn ensure_private_dir(path: &Path) -> Result<(), DogfoodRunError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|error| failed("DOGFOOD_DATA_DIR", error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| failed("DOGFOOD_DATA_DIR", error.to_string()))
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn failed(code: &'static str, detail: impl Into<String>) -> DogfoodRunError {
    DogfoodRunError {
        code,
        detail: detail.into(),
    }
}

fn neutral(code: &'static str, detail: impl Into<String>) -> DogfoodRunStatus {
    DogfoodRunStatus::Neutral {
        code,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        refuse_launch_grant_alpha, run_dogfood_read_only, DogfoodReadOnlyOptions, DogfoodRunStatus,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn options() -> DogfoodReadOnlyOptions {
        DogfoodReadOnlyOptions {
            provider: "claude".to_owned(),
            data_dir: PathBuf::from("/tmp/missing-dogfood-data"),
            policy: PathBuf::from("/tmp/missing-policy.json"),
            binding: PathBuf::from("/tmp/missing-binding.json"),
            enrollment: PathBuf::from("/tmp/missing-enrollment.json"),
            issuer: "operator-local".into(),
            key_id: "operator-runner-1".into(),
            executable: PathBuf::from("/usr/bin/true"),
            credentials: Vec::new(),
            workdir: PathBuf::from("/tmp"),
            prompt: Some("fix a stale sentence".into()),
            max_budget_usd: Some(0.25),
            receipt: PathBuf::from("/tmp/missing-receipt.json"),
        }
    }

    #[test]
    fn unknown_and_unimplemented_providers_refuse_before_any_staging() {
        // An unknown name is a typed refusal, never a silent claude fallback.
        let mut unknown = options();
        unknown.provider = "gemini".to_owned();
        let error = run_dogfood_read_only(unknown).expect_err("unknown provider must refuse");
        assert_eq!(error.code, "DOGFOOD_PROVIDER_UNKNOWN");

        // A known provider with no wired dispatch refuses with its own code,
        // before any policy read or staging: the options here point at paths
        // that do not exist, so reaching any later step would surface a
        // different code.
        for provider in ["codex", "cursor", "antigravity"] {
            let mut pending = options();
            pending.provider = provider.to_owned();
            let error =
                run_dogfood_read_only(pending).expect_err("unimplemented provider must refuse");
            assert_eq!(error.code, "DOGFOOD_PROVIDER_UNIMPLEMENTED", "{provider}");
        }
    }

    #[test]
    fn passported_runtime_is_none_outside_the_deployment_prefix_and_required_inside() {
        // Outside the frozen prefix, nothing changes: no passport is consulted.
        use std::path::Path;
        let outside = super::passported_runtime(Path::new("/usr/bin/true"))
            .expect("non-deployment path is fine");
        assert!(outside.is_none());

        // Inside the prefix, a missing passport is a typed refusal, never a
        // silent fall back to the 64 MiB unpassported path.
        let error = super::passported_runtime(Path::new(
            "/usr/lib/bullet/providers/claude/0.0.0-test-absent/bin/claude",
        ))
        .expect_err("deployment path without a passport must refuse");
        assert_eq!(error.code, "DOGFOOD_PASSPORT_MISSING");

        // A malformed layout under the prefix refuses with its own code.
        let error = super::passported_runtime(Path::new("/usr/lib/bullet/providers/claude"))
            .expect_err("prefix with no version segment must refuse");
        assert_eq!(error.code, "DOGFOOD_PASSPORT_LAYOUT");
    }

    #[test]
    fn run_evidence_is_create_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.proposal.json");
        super::write_create_once_0600(&path, b"{}").expect("first write");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "evidence must be owner-private");
        let error = super::write_create_once_0600(&path, b"{}")
            .expect_err("a rerun must never overwrite evidence");
        assert_eq!(error.code, "DOGFOOD_ARTIFACT_EXISTS");
    }

    #[test]
    fn launch_grant_alpha_is_refused() {
        assert!(refuse_launch_grant_alpha("bullet-kernel", "launch-grant-alpha").is_err());
        assert!(refuse_launch_grant_alpha("operator-local", "operator-runner-1").is_ok());
    }

    #[test]
    fn live_enabled_policy_fixture_is_refused() {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/policy-v1alpha2-live-enabled.json");
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("policy.json");
        std::fs::copy(&source, &policy).unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut options = options();
        options.policy = policy;
        options.prompt = Some("x".into());
        match run_dogfood_read_only(options) {
            Err(error) => assert_eq!(error.code, "DOGFOOD_REFUSES_LIVE_ADMISSION"),
            Ok(DogfoodRunStatus::Neutral { code, .. }) => {
                panic!("expected live refuse, got neutral {code}");
            }
            Ok(DogfoodRunStatus::Succeeded { .. }) => panic!("live policy must not compose"),
        }
    }

    #[test]
    fn missing_prompt_is_designed_neutral() {
        let mut options = options();
        options.prompt = None;
        match run_dogfood_read_only(options).unwrap() {
            DogfoodRunStatus::Neutral { code, .. } => assert_eq!(code, "DOGFOOD_PROMPT_MISSING"),
            other => panic!("expected neutral, got {other:?}"),
        }
    }
}
