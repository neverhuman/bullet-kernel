//! The ordered provider-side + authority steps of the positive live path. Each
//! step records its own status; a step that never ran stays `NotRun`. The
//! probe is executable-digest + operator-attested identity (no provider is
//! spawned to probe); the only provider spawn is the single dispatched turn,
//! and it happens only after every blocker has been cleared by its own
//! evidence.

use super::{LiveConformanceOptions, ReceiptFields, StepFailure, StepSuccess};
use crate::launch_grant::{
    datetime_unix_ms, durable_lease_binding, LaunchGrantIssuer, LaunchGrantNonceStore,
    LaunchGrantRequest, LedgerLaunchGrantIssuer, StoreNonceLedger,
};
use crate::leases::LeaseService;
use crate::materializer::{materialize_plan, PlanInput};
use crate::policy_snapshot::LoadedPolicy;
use crate::records::StoredGraph;
use crate::store::{Ledger, LedgerError};
use bullet_domain::{Attempt, Observation, ProfileId, TaskClass};
use bullet_harness_core::launch_grant::{
    environment_digest, load_signing_key, verify_launch_grant, LaunchGrantExpectation,
    ProviderBinding, LAUNCH_GRANT_AUDIENCE,
};
use bullet_harness_core::{
    descriptor_digest, executable_digest, is_pong, AgentEvent, AgentEventKind, CanarySecrets,
    Capability, CapabilityState, CommandFactory, ConformanceEvidence, EgressBackend,
    EvaluatedAdmission, EventNormalizer, ExpectedProfile, HarnessDescriptor, HarnessError,
    LiveDispatcher, LiveStep, LiveTurnRequest, NativeMeta, PatchProposal, ProbeResult,
    ProfileIdentity, ProfileRef, PromotionStage, ProviderAdmission, ProviderAdmissionPolicy,
    ProviderProtocol, RuntimeProbeSnapshot, StepLog,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

/// Lexical gate id bound into the structured proposal contract (distinct from
/// the launch-grant `gat_` gate namespace).
pub const PROPOSAL_GATE_ID: &str = "bullet.conformance.pong";

/// Run the full ordered path. On success every step is `Pass` (or `PongMatch`
/// is `Failed` when the response was not `PONG`); on failure the offending
/// step is recorded and the rest stay `NotRun`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn run_steps<L>(
    data_dir: &Path,
    ledger: &mut L,
    policy: &LoadedPolicy,
    dispatcher: &dyn LiveDispatcher,
    egress: &dyn EgressBackend,
    options: &LiveConformanceOptions,
    now: DateTime<Utc>,
    log: &mut StepLog,
    fields: &mut ReceiptFields,
) -> Result<StepSuccess, StepFailure>
where
    L: Ledger + LaunchGrantNonceStore,
{
    // 1. POLICY — refuse before any key read, probe, namespace, or spawn.
    policy
        .require_live_admission()
        .map_err(|error| StepFailure::refusal(LiveStep::Policy, &error))?;
    fields.policy_snapshot_digest = Some(policy.digest().to_string());
    fields.policy_generation = Some(policy.generation());
    log.pass(LiveStep::Policy);

    // 2. OPERATOR KEY — load 0600 custody and confirm the policy admits it.
    let now_ms =
        datetime_unix_ms(now).map_err(|error| StepFailure::issue(LiveStep::OperatorKey, &error))?;
    let key = load_signing_key(data_dir, &options.issuer, &options.key_id)
        .map_err(|error| StepFailure::harness(LiveStep::OperatorKey, &error))?;
    let vkey = policy
        .authority_key_at(
            &options.issuer,
            &options.key_id,
            LAUNCH_GRANT_AUDIENCE,
            now_ms,
        )
        .map_err(|error| StepFailure::harness(LiveStep::OperatorKey, &error))?;
    if vkey.public_key_hex() != key.public_key_hex() {
        return Err(StepFailure::message(
            LiveStep::OperatorKey,
            "LAUNCH_GRANT_KEY_UNKNOWN",
            "operator key does not match the policy-admitted public key",
        ));
    }
    log.pass(LiveStep::OperatorKey);

    // 3. LEASE — materialize a conformance Mission/graph and take a durable lease.
    let (_graph, attempt) = materialize_and_lease(ledger, options, now)
        .map_err(|error| StepFailure::ledger(LiveStep::Lease, &error))?;
    log.pass(LiveStep::Lease);

    // 4. ADMISSION — local prepare/finalize from the runtime probe.
    let workdir = super::prepare_dir(
        &data_dir
            .join("live")
            .join(format!("work-{}", options.provider)),
    )
    .map_err(|error| StepFailure::harness(LiveStep::Admission, &error))?;
    let runtime_root = super::prepare_dir(&data_dir.join("live").join("home"))
        .map_err(|error| StepFailure::harness(LiveStep::Admission, &error))?;
    let canaries = CanarySecrets::new(options.canaries.clone())
        .map_err(|error| StepFailure::harness(LiveStep::Admission, &error))?;
    let admission = build_admission(dispatcher, options, &runtime_root, &canaries, now)
        .map_err(|error| StepFailure::harness(LiveStep::Admission, &error))?;
    let receipt = admission.receipt().clone();
    fields.executable_path = Some(receipt.executable.clone());
    fields.executable_blake3 = Some(receipt.executable_blake3.clone());
    log.pass(LiveStep::Admission);

    // 5. MINT — bind the durable lease and the evaluated provider facts.
    let egress_provider = egress_provider_name(&options.provider);
    let sandbox_manifest_digest = egress
        .sandbox_manifest_digest(egress_provider)
        .map_err(|error| StepFailure::harness(LiveStep::Mint, &error))?;
    let child_environment_digest = environment_digest(admission.child_env())
        .map_err(|error| StepFailure::harness(LiveStep::Mint, &error))?;
    let request = LaunchGrantRequest {
        attempt_id: attempt.id.clone(),
        provider: receipt.provider.clone(),
        adapter: options.adapter_label.clone(),
        provider_profile_id: receipt.profile_id.clone(),
        model: options.model.clone(),
        credential_generation: options.credential_generation,
        protocol: dispatcher.required_protocol().as_str().to_string(),
        executable_path: receipt.executable.clone(),
        executable_digest: receipt.executable_blake3.clone(),
        descriptor_digest: receipt.descriptor_blake3.clone(),
        capability_digest: receipt.capability_blake3.clone(),
        sandbox_manifest_digest,
        environment_digest: child_environment_digest,
        gate_ids: vec![grant_gate_id(&options.seed)],
        max_invocations: 1,
        max_wall_clock_ms: wall_ms(options.wall_timeout),
        max_cost_micro_usd: options.max_cost_micro_usd,
        ttl_ms: options.ttl_ms,
    };
    let grant = LedgerLaunchGrantIssuer::new(ledger, &key, policy.binding())
        .mint(&request, now)
        .map_err(|error| StepFailure::issue(LiveStep::Mint, &error))?;
    log.pass(LiveStep::Mint);

    // 6. VERIFY — re-observe the executable, bind the exact subject, spend the nonce.
    let fresh_digest = executable_digest(&options.executable)
        .map_err(|error| StepFailure::harness(LiveStep::VerifyGrant, &error))?;
    let lease_binding = durable_lease_binding(ledger, &attempt.id)
        .map_err(|error| StepFailure::issue(LiveStep::VerifyGrant, &error))?
        .binding;
    let expectation = LaunchGrantExpectation {
        now_unix_ms: now_ms,
        lease: lease_binding,
        provider: provider_binding(&request, dispatcher.required_protocol(), fresh_digest),
        policy: policy.binding(),
    };
    let verified = verify_launch_grant(&grant, &vkey, &expectation, &mut StoreNonceLedger(ledger))
        .map_err(|error| StepFailure::harness(LiveStep::VerifyGrant, &error))?;
    fields.grant_id = Some(verified.claims().grant_id.clone());
    fields.grant_envelope_digest = Some(verified.envelope_digest().to_string());
    log.pass(LiveStep::VerifyGrant);

    // 7. ADMIT SIGNED — clear SIGNED_ADMISSION_UNAVAILABLE.
    let admission = admission
        .admit_signed(verified)
        .map_err(|error| StepFailure::harness(LiveStep::AdmitSigned, &error))?;
    log.pass(LiveStep::AdmitSigned);

    // 8. EGRESS PREPARE — build and prove the containment boundary.
    let prepared = egress
        .prepare(egress_provider, &workdir)
        .map_err(|error| StepFailure::harness(LiveStep::EgressPrepare, &error))?;
    let evidence = prepared.evidence();
    fields.egress_receipt_digest = Some(evidence.receipt_digest.clone());
    fields.egress_ruleset_digest = Some(evidence.ruleset_digest.clone());
    fields.egress_allowlist_digest = Some(evidence.allowlist_digest.clone());
    log.pass(LiveStep::EgressPrepare);

    // 9. ADMIT EGRESS — clear EGRESS_ISOLATION_UNAVAILABLE.
    let admission = admission
        .admit_egress(evidence)
        .map_err(|error| StepFailure::harness(LiveStep::AdmitEgress, &error))?;
    log.pass(LiveStep::AdmitEgress);

    // 10. REQUIRE DISPATCH — the final chokepoint.
    admission
        .require_dispatch()
        .map_err(|error| StepFailure::harness(LiveStep::RequireDispatch, &error))?;
    log.pass(LiveStep::RequireDispatch);

    // 11. DISPATCH — exactly one read-only turn inside the egress boundary.
    let turn_request = LiveTurnRequest {
        session_id: bullet_harness_core::AgentSessionId::new(format!(
            "live-conformance-{}",
            options.provider
        )),
        invocation_id: bullet_harness_core::InvocationId::new(format!(
            "live-conformance-invocation-{}",
            options.provider
        )),
        prompt: bullet_harness_core::CONFORMANCE_PROMPT.to_string(),
        workdir,
        expected_runtime_version: dispatcher.observed_runtime_version().to_string(),
        gate_ids: vec![PROPOSAL_GATE_ID.to_string()],
        max_cost_micro_usd: options.max_cost_micro_usd,
        wall_timeout: options.wall_timeout,
        canaries,
    };
    let factory: &CommandFactory<'_> =
        &|program: &str, args: &[&str], env: &[(&str, &str)]| prepared.command(program, args, env);
    let turn = match dispatcher.dispatch_live_turn(&admission, factory, &turn_request) {
        Ok(turn) => turn,
        Err(error) if error.reason_code() == "SECRET_CANARY_EXPOSURE" => {
            return Err(StepFailure::harness(LiveStep::CanaryScan, &error));
        }
        Err(error) => return Err(StepFailure::harness(LiveStep::Dispatch, &error)),
    };
    log.pass(LiveStep::Dispatch);
    log.pass(LiveStep::CanaryScan);

    fields.response_text = Some(turn.response_text.clone());
    fields.cost_micro_usd = turn.total_cost_micro_usd;
    fields.duration_ms = Some(turn.wall_ms);
    fields.exit_code = turn.exit_code;
    fields.native_session_id = turn.native_session_id.clone();
    fields.events = turn.events.len() as u64;
    fields.stdout_blake3 = Some(turn.stdout_blake3.clone());
    fields.stderr_blake3 = Some(turn.stderr_blake3.clone());
    fields.events_blake3 = Some(turn.events_blake3.clone());

    // 12. PONG MATCH.
    let pong = is_pong(&turn.response_text);
    fields.pong_match = pong;
    if pong {
        log.pass(LiveStep::PongMatch);
    } else {
        log.record(
            LiveStep::PongMatch,
            bullet_harness_core::StepStatus::Failed,
            Some("response was not the single word PONG".to_string()),
        );
    }

    Ok(StepSuccess {
        pong_match: pong,
        grant,
        expectation,
        verification_key: vkey,
    })
}

fn materialize_and_lease<L: Ledger>(
    ledger: &mut L,
    options: &LiveConformanceOptions,
    now: DateTime<Utc>,
) -> Result<(StoredGraph, Attempt), LedgerError> {
    let now_str = LeaseService::rfc3339(now);
    let input = PlanInput {
        title: format!("live conformance: {}", options.provider),
        objective: "prove the positive signed launch-grant + egress dispatch path".into(),
        packages: vec![(
            "dispatch one conformance turn".into(),
            TaskClass::BoundedBugFix,
        )],
    };
    let graph = materialize_plan(ledger, &options.seed, &input, &now_str)?;
    let (attempt, _token, _grant) = LeaseService::acquire(ledger, &graph, 0, &options.seed, 15)?;
    Ok((graph, attempt))
}

fn build_admission(
    dispatcher: &dyn LiveDispatcher,
    options: &LiveConformanceOptions,
    runtime_root: &Path,
    canaries: &CanarySecrets,
    now: DateTime<Utc>,
) -> Result<EvaluatedAdmission, HarnessError> {
    let executable = options.executable.clone();
    let exe_digest = executable_digest(&executable)?;
    let protocol = dispatcher.required_protocol();
    let required = required_capabilities(protocol);
    let descriptor = probe_descriptor(dispatcher, &executable, &options.version, &required);
    let descriptor_blake3 = descriptor_digest(&descriptor)?;
    let expected = ExpectedProfile {
        email: Some(options.profile_email.clone()),
        account_id_prefix: None,
    };
    let policy = ProviderAdmissionPolicy {
        provider: options.provider.clone(),
        executable: executable.clone(),
        executable_blake3: exe_digest.clone(),
        version: options.version.clone(),
        descriptor_blake3,
        profile: ProfileRef {
            profile_id: ProfileId::from_seed(&options.provider),
            expected: expected.clone(),
        },
        required_protocol: protocol,
        max_probe_age_seconds: 300,
        runtime_root: runtime_root.to_path_buf(),
        credential_targets: vec![],
        credentials: vec![],
    };
    let identity = ProbeResult {
        profile: Observation::value(ProfileIdentity {
            provider: options.provider.clone(),
            email: expected.email,
            account_id: None,
            subscription: None,
            auth_method: Some("operator-attested".into()),
        }),
        version: options.version.clone(),
    };
    let probe = RuntimeProbeSnapshot {
        descriptor,
        executable,
        executable_blake3: exe_digest,
        protocol,
        identity,
        observed_at: now,
    };
    ProviderAdmission::prepare(policy, probe, std::env::vars(), canaries.clone(), now)?.finalize(
        ConformanceEvidence {
            stdout: b"",
            stderr: b"",
            events: &conformance_events(&options.provider),
            proposal: &conformance_proposal(),
        },
    )
}

fn probe_descriptor(
    dispatcher: &dyn LiveDispatcher,
    executable: &Path,
    version: &str,
    required: &[Capability],
) -> HarnessDescriptor {
    let mut descriptor = dispatcher.descriptor();
    descriptor.binary = executable
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    descriptor.version = Observation::value(version.to_string());
    descriptor.stage = PromotionStage::ContractPass;
    for capability in required {
        descriptor
            .capabilities
            .set(*capability, CapabilityState::Supported);
    }
    descriptor
}

/// Required capability set per protocol. Mirrors
/// `bullet_harness_core::admission::protocol::requirement`.
fn required_capabilities(protocol: ProviderProtocol) -> Vec<Capability> {
    match protocol {
        ProviderProtocol::AntigravityHeadlessStructured
        | ProviderProtocol::AntigravityHeadlessText => vec![
            Capability::StructuredOutputSchema,
            Capability::HeadlessMode,
            Capability::MultilinePrompt,
        ],
        _ => vec![
            Capability::StructuredEvents,
            Capability::StructuredOutputSchema,
            Capability::HeadlessMode,
            Capability::MultilinePrompt,
        ],
    }
}

fn conformance_events(provider: &str) -> Vec<AgentEvent> {
    let mut normalizer = EventNormalizer::new(
        bullet_harness_core::AgentSessionId::new("live-admission"),
        provider,
    );
    vec![
        normalizer.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none()),
        normalizer.accept(
            AgentEventKind::TurnCompleted,
            json!({}),
            &NativeMeta::none(),
        ),
    ]
}

fn conformance_proposal() -> PatchProposal {
    PatchProposal {
        intent_summary: "live conformance admission subject".into(),
        changes: vec![bullet_harness_core::FileChange {
            path: "PONG.txt".into(),
            op: bullet_harness_core::ChangeOp::Create,
            contents: Some("PONG\n".into()),
        }],
        gate_ids: vec![PROPOSAL_GATE_ID.to_string()],
        claims: vec![],
        uncertainties: vec![],
        done: true,
    }
}

fn provider_binding(
    request: &LaunchGrantRequest,
    protocol: ProviderProtocol,
    fresh_executable_digest: String,
) -> ProviderBinding {
    ProviderBinding {
        provider: request.provider.clone(),
        adapter: request.adapter.clone(),
        provider_profile_id: request.provider_profile_id.clone(),
        model: request.model.clone(),
        credential_generation: request.credential_generation,
        protocol,
        executable_path: request.executable_path.clone(),
        executable_digest: fresh_executable_digest,
        descriptor_digest: request.descriptor_digest.clone(),
        capability_digest: request.capability_digest.clone(),
        sandbox_manifest_digest: request.sandbox_manifest_digest.clone(),
        environment_digest: request.environment_digest.clone(),
    }
}

/// Egress uses `antigravity` where admission/grants use `agy`.
fn egress_provider_name(provider: &str) -> &str {
    if provider == "agy" {
        "antigravity"
    } else {
        provider
    }
}

fn grant_gate_id(seed: &str) -> String {
    let material = format!("bullet-farm/live-conformance-grant-gate/{seed}");
    format!("gat_{}", blake3::hash(material.as_bytes()).to_hex())
}

fn wall_ms(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}
