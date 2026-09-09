//! Compose one read-only dogfood turn (ADR 0015).
//!
//! This is the production caller of `filesystem_command` and
//! `dispatch_dogfood_turn`. It never applies a proposal and never flips
//! `live_admission_enabled`.

use crate::dogfood::{
    write_receipt, write_refusal_record, DogfoodReadOnlyReceiptV0, DogfoodRefusalRecordV0,
};
use crate::live_conformance::{enrollment_path, load_provider_enrollment};
use crate::policy_snapshot::{
    refuse_dogfood_binding_as_live, validate_dogfood_admission, LoadedPolicy,
};
use bullet_domain::{gate_definition, parse_gate_ids};
use bullet_harness_claude::dogfood::dispatch_dogfood_turn;
use bullet_harness_core::{
    synthetic_uuid, CanarySecrets, CredentialGrant, LiveTurnRequest, PreparedProviderHome,
};
use bullet_harness_egress::{
    EgressPolicy, EgressSandbox, FilesystemFileV0, FilesystemSandboxProfileV0,
    CONTAINMENT_UNAVAILABLE_EXIT,
};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// Default wall-clock bound for one dogfood turn when the operator names none.
pub const DEFAULT_WALL_TIMEOUT_SECONDS: u64 = 180;

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
    /// Admitted sealed-catalog gate identifiers the turn's proposal must echo.
    /// Never empty: the transcript refuses an empty selection, so an empty set
    /// here would refuse the turn *after* the provider had already run.
    pub gate_ids: Vec<String>,
    /// Repeatable credential grants.
    pub credentials: Vec<CredentialSpec>,
    /// Absolute family working directory, bound read-only.
    pub workdir: PathBuf,
    /// Prompt. Missing is designed-neutral 78.
    pub prompt: Option<String>,
    /// Optional tighter USD cap; enrollment max still wins.
    pub max_budget_usd: Option<f64>,
    /// Optional wall-clock bound in seconds, bounded by the policy's
    /// `maximum_attempt_seconds`. `None` keeps the 180 s default.
    pub wall_timeout_secs: Option<u64>,
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
    let composed = match dispatch_dogfood_compose(&options)? {
        ComposedTurn::Neutral { code, detail } => return Ok(neutral(code, detail)),
        ComposedTurn::Dispatched(composed) => composed,
    };
    write_dogfood_evidence(&options, &composed)
}

/// A composed dogfood turn, or the designed-neutral reason it did not compose.
pub enum ComposedTurn {
    /// The provider ran and returned a validated proposal.
    Dispatched(Box<DispatchedTurn>),
    /// A missing prerequisite. Exit 78; nothing was spawned.
    Neutral {
        /// Stable reason code.
        code: &'static str,
        /// Non-secret detail.
        detail: String,
    },
}

/// One real provider turn plus the enrolled runtime it was bound to.
pub struct DispatchedTurn {
    /// The validated proposal and the observed turn facts.
    pub outcome: bullet_harness_claude::dogfood::DogfoodTurnOutcome,
    /// Exact enrolled runtime version the turn was admitted against.
    pub enrolled_runtime_version: String,
}

/// Designed-neutral composition outcome: nothing was spawned.
fn composed_neutral(code: &'static str, detail: impl Into<String>) -> ComposedTurn {
    ComposedTurn::Neutral {
        code,
        detail: detail.into(),
    }
}

/// Compose containment and run exactly one REAL provider turn.
///
/// This is the whole of [`run_dogfood_read_only`] except writing evidence, so a
/// `HarnessAdapter` can drive a real provider through the same admission the
/// CLI uses. It exists because the Runner accepted only `--provider sim`: the
/// dogfood dispatch was a free function no adapter could reach, which is the
/// only reason the real provider turn and the transaction loop never met.
///
/// # Errors
///
/// The same typed refusals as [`run_dogfood_read_only`].
pub fn dispatch_dogfood_compose(
    options: &DogfoodReadOnlyOptions,
) -> Result<ComposedTurn, DogfoodRunError> {
    let options = options.clone();
    let prompt = match options.prompt.as_deref() {
        Some(prompt) if !prompt.is_empty() => prompt.to_owned(),
        _ => {
            return Ok(composed_neutral(
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
    // Before any staging, containment, or spend: the transcript constructor
    // refuses an empty or unadmitted gate selection, and it runs only after the
    // provider process has been spawned and billed. Refuse here instead.
    let admitted_gate_ids = parse_gate_ids(&options.gate_ids)
        .map_err(|error| failed("DOGFOOD_GATE_IDS", error.to_string()))?;
    for gate_id in &admitted_gate_ids {
        if gate_definition(gate_id).is_none() {
            return Err(failed(
                "DOGFOOD_GATE_UNADMITTED",
                format!("gate {gate_id} is not in the sealed V1 catalog"),
            ));
        }
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
            return Ok(composed_neutral(error.code, error.detail));
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
    // The structural half ran in `from_bytes`; the activation window is a wall
    // -clock fact and was never checked on this path, so an expired or
    // not-yet-active policy composed a live turn.
    loaded
        .validate_at(unix_ms())
        .map_err(|error| failed("DOGFOOD_POLICY_NOT_ACTIVE", error.to_string()))?;
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
        return Ok(composed_neutral(
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
            return Ok(composed_neutral(error.code, error.detail));
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
        return Ok(composed_neutral(
            "DOGFOOD_WORKDIR_MISSING",
            "workdir must be an existing directory",
        ));
    }

    let max_cost_micro_usd =
        budget_micro_usd(options.max_budget_usd, enrolled.max_cost_micro_usd())?;
    let bubblewrap = match require_host_file("/usr/bin/bwrap") {
        Ok(path) => path,
        Err(error) if error.code == "CONTAINMENT_UNAVAILABLE" => {
            return Ok(composed_neutral(error.code, error.detail));
        }
        Err(error) => return Err(error),
    };
    let ca_bundle = match require_host_file("/etc/ssl/certs/ca-certificates.crt") {
        Ok(path) => path,
        Err(error) if error.code == "CONTAINMENT_UNAVAILABLE" => {
            return Ok(composed_neutral(error.code, error.detail));
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
            return Ok(composed_neutral(
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
    // The wall bound is a ratified policy fact, not a constant: a real
    // repository task does not finish in the 180 s that was hard-coded here,
    // and a turn killed by the wall is billed for nothing.
    let policy_max_seconds = loaded.snapshot().budget_policy.maximum_attempt_seconds;
    let wall_timeout_secs = match options.wall_timeout_secs {
        None => DEFAULT_WALL_TIMEOUT_SECONDS.min(policy_max_seconds),
        Some(requested) if requested == 0 || requested > policy_max_seconds => {
            return Err(failed(
                "DOGFOOD_WALL_TIMEOUT",
                format!(
                    "wall timeout {requested}s must be 1..={policy_max_seconds}s \
                     (policy budget_policy.maximum_attempt_seconds)"
                ),
            ));
        }
        Some(requested) => requested,
    };

    // Nothing else on this path tells the model which gate identifiers its
    // proposal must echo, and the transcript refuses a terminal whose
    // `gate_ids` differ from the admission. Without this the operator has to
    // paste the ids into the prompt by hand, and a turn that forgets them is
    // billed and then refused.
    let prompt = format!(
        "{prompt}\n\nWhen you return the PatchProposal, its `gate_ids` field must be \
         exactly this ordered list, copied verbatim: {gates}",
        gates = serde_json::to_string(&options.gate_ids)
            .map_err(|error| failed("DOGFOOD_GATE_IDS", error.to_string()))?
    );
    let request = LiveTurnRequest {
        session_id: bullet_harness_core::AgentSessionId::new(synthetic_uuid("session")),
        invocation_id: bullet_harness_core::InvocationId::new(synthetic_uuid("invocation")),
        prompt,
        workdir: workdir.clone(),
        expected_runtime_version: enrolled.record().version.clone(),
        gate_ids: options.gate_ids.clone(),
        max_cost_micro_usd,
        wall_timeout: Duration::from_secs(wall_timeout_secs),
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
    let outcome = match dispatched {
        Ok(outcome) => outcome,
        Err(error) => {
            // A refusal decided before the spawn cost nothing and needs no
            // record. A refusal after the turn ran was paid for: persist what
            // it did beside the receipt path so the spend is never silent.
            if let Some(observed) = error.observed() {
                let record = DogfoodRefusalRecordV0 {
                    schema_version: DogfoodRefusalRecordV0::SCHEMA_VERSION.to_owned(),
                    kind: DogfoodRefusalRecordV0::KIND.to_owned(),
                    code: "DOGFOOD_DISPATCH".to_owned(),
                    detail: error.error().to_string(),
                    enrolled_runtime_version: enrolled.record().version.clone(),
                    exit_code: observed.exit_code,
                    wall_ms: observed.wall_ms,
                    timed_out: observed.timed_out,
                    stdout_blake3: observed.stdout_blake3.clone(),
                    stderr_blake3: observed.stderr_blake3.clone(),
                    total_cost_micro_usd: observed.total_cost_micro_usd,
                };
                let refusal_path = options.receipt.with_extension("refused.json");
                // Opt-in diagnosis. A billed turn that the transcript refuses
                // leaves only digests, which cannot tell an operator WHY the
                // provider failed. When an absolute directory is named, the
                // captured streams are preserved create-once 0600 beside the
                // record. Off by default: the streams are provider output, not
                // receipt material, and nothing commits to them.
                if let Some(dir) = std::env::var_os("BULLET_DOGFOOD_CAPTURE_DIR") {
                    let dir = PathBuf::from(dir);
                    if dir.is_absolute() {
                        let stdout_path = dir.join("refused.stdout.jsonl");
                        let stderr_path = dir.join("refused.stderr.txt");
                        let stdout = observed.stdout_lines.join("\n");
                        let _ = write_create_once_0600(&stdout_path, stdout.as_bytes());
                        let _ = write_create_once_0600(&stderr_path, observed.stderr.as_bytes());
                    }
                }
                if let Err(write_error) = write_refusal_record(&refusal_path, &record) {
                    return Err(failed(
                        "DOGFOOD_REFUSAL_RECORD",
                        format!("{write_error} after {}", error.error()),
                    ));
                }
                return Err(failed(
                    "DOGFOOD_DISPATCH",
                    format!(
                        "{} (billed turn recorded at {})",
                        error.error(),
                        refusal_path.display()
                    ),
                ));
            }
            return Err(failed("DOGFOOD_DISPATCH", error.to_string()));
        }
    };

    Ok(ComposedTurn::Dispatched(Box::new(DispatchedTurn {
        outcome,
        enrolled_runtime_version: enrolled.record().version.clone(),
    })))
}

/// Write the create-once proposal and receipt for a composed turn.
fn write_dogfood_evidence(
    options: &DogfoodReadOnlyOptions,
    composed: &DispatchedTurn,
) -> Result<DogfoodRunStatus, DogfoodRunError> {
    let outcome = &composed.outcome;
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
        enrolled_runtime_version: composed.enrolled_runtime_version.clone(),
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
        receipt: options.receipt.clone(),
        proposal: proposal_path,
    })
}

#[path = "dogfood_run_host.rs"]
mod dogfood_run_host;
use dogfood_run_host::*;

#[cfg(test)]
#[path = "dogfood_run_tests.rs"]
mod tests;
