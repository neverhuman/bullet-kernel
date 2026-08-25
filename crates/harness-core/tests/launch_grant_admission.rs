//! A verified launch grant clears exactly `SIGNED_ADMISSION_UNAVAILABLE`,
//! egress evidence clears exactly `EGRESS_ISOLATION_UNAVAILABLE`, and nothing
//! else does. No provider process is ever spawned here.

use bullet_domain::{Observation, ProfileId};
use bullet_harness_core::launch_grant::{
    environment_digest, verify_launch_grant, LaunchGrantClaims, LaunchGrantExpectation,
    LaunchGrantSigningKey, LeaseBinding, MemoryNonceLedger, PolicyBinding, ProviderBinding,
    VerifiedLaunchGrant,
};
use bullet_harness_core::{
    descriptor_digest, executable_digest, AdmissionBlocker, AgentEvent, AgentEventKind,
    AgentSessionId, ArgvBuilder, CanarySecrets, Capability, CapabilityMatrix, CapabilityState,
    ConformanceEvidence, EgressIsolationEvidence, EgressProbe, EgressProbeOutcome,
    EvaluatedAdmission, EventNormalizer, ExpectedProfile, HarnessDescriptor, NativeMeta,
    PatchMutation, PatchOperation, PatchProposal, Preimage, ProbeResult, ProfileIdentity,
    ProfileRef, PromotionStage, ProviderAdmission, ProviderAdmissionPolicy,
    ProviderConformanceReceipt, ProviderProtocol, RuntimeProbeSnapshot,
};
use chrono::{TimeZone, Utc};
use serde_json::json;
use tempfile::TempDir;

type Mutation = fn(&mut LaunchGrantClaims);

struct Fixture {
    _directory: TempDir,
    admission: EvaluatedAdmission,
    key: LaunchGrantSigningKey,
}

fn evaluated() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 25, 5, 0, 0).unwrap();
    let capabilities = CapabilityMatrix::new()
        .with(
            Capability::StructuredOutputSchema,
            CapabilityState::Supported,
        )
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported)
        .with(Capability::StructuredEvents, CapabilityState::Supported);
    let descriptor = HarnessDescriptor {
        provider: "claude".into(),
        binary: executable
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        version: Observation::value("offline-1.0.0".into()),
        stage: PromotionStage::ContractPass,
        capabilities,
    };
    let expected = ExpectedProfile {
        email: Some("claude@offline.invalid".into()),
        account_id_prefix: None,
    };
    let policy = ProviderAdmissionPolicy {
        provider: "claude".into(),
        executable: executable.clone(),
        executable_blake3: executable_digest(&executable).unwrap(),
        version: "offline-1.0.0".into(),
        descriptor_blake3: descriptor_digest(&descriptor).unwrap(),
        profile: ProfileRef {
            profile_id: ProfileId::from_seed("claude"),
            expected: expected.clone(),
        },
        required_protocol: ProviderProtocol::ClaudeStreamJson,
        max_probe_age_seconds: 60,
        runtime_root: root,
        credential_targets: vec![],
        credentials: vec![],
    };
    let probe = RuntimeProbeSnapshot {
        executable_blake3: policy.executable_blake3.clone(),
        descriptor,
        executable,
        protocol: ProviderProtocol::ClaudeStreamJson,
        identity: ProbeResult {
            profile: Observation::value(ProfileIdentity {
                provider: "claude".into(),
                email: expected.email,
                account_id: None,
                subscription: None,
                auth_method: Some("oauth".into()),
            }),
            version: "offline-1.0.0".into(),
        },
        observed_at: now,
    };
    let canaries = CanarySecrets::new(vec!["bullet-host-canary-7f2d9b61".into()]).unwrap();
    let env = vec![("LANG".to_string(), "C.UTF-8".to_string())];
    let mut normalizer = EventNormalizer::new(AgentSessionId::new("offline"), "claude");
    let events: Vec<AgentEvent> = vec![
        normalizer.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none()),
        normalizer.accept(
            AgentEventKind::TurnCompleted,
            json!({}),
            &NativeMeta::none(),
        ),
    ];
    let proposal = PatchProposal {
        schema_version: 1,
        proposal_id: format!("cnt_{}", "1".repeat(64)),
        producing_attempt_id: format!("atm_{}", "2".repeat(64)),
        base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
        base_checkpoint_digest: "4".repeat(64),
        intent_summary: "offline".into(),
        operations: vec![PatchOperation {
            path: "PONG.txt".into(),
            preimage: Preimage::Absent,
            mutation: PatchMutation::Write {
                content_utf8: "PONG\n".into(),
            },
        }],
        gate_ids: vec![bullet_domain::REPOSITORY_GATE_ID.into()],
        claims: vec![],
        uncertainties: vec![],
        done: true,
    };
    let admission = ProviderAdmission::prepare(policy, probe, env, canaries, now)
        .unwrap()
        .finalize(ConformanceEvidence {
            stdout: b"offline",
            stderr: b"",
            events: &events,
            proposal: &proposal,
        })
        .unwrap();
    Fixture {
        _directory: directory,
        admission,
        key: LaunchGrantSigningKey::generate("bullet-kernel", "launch-grant-alpha").unwrap(),
    }
}

fn claims_for(receipt: &ProviderConformanceReceipt, env: &[(String, String)]) -> LaunchGrantClaims {
    LaunchGrantClaims {
        schema_version: "v1alpha1".into(),
        grant_id: "1".repeat(64),
        audience: "provider-runner".into(),
        operation: "launch-provider".into(),
        issuer: "bullet-kernel".into(),
        key_id: "launch-grant-alpha".into(),
        issued_at_unix_ms: 1_800_000_000_000,
        not_before_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_010_000,
        grant_nonce: "2".repeat(64),
        mission_id: format!("mis_{}", "5".repeat(64)),
        repository_id: format!("rep_{}", "4".repeat(64)),
        graph_revision_id: format!("grf_{}", "8".repeat(64)),
        work_package_id: format!("wpk_{}", "a".repeat(64)),
        variant_id: format!("var_{}", "c".repeat(64)),
        attempt_id: format!("atm_{}", "d".repeat(64)),
        attempt_fence: 1,
        runner_id: format!("run_{}", "e".repeat(64)),
        runner_epoch: 1,
        workspace_id: format!("wsp_{}", "f".repeat(64)),
        workspace_nonce_digest: "3".repeat(64),
        authority_epoch: 1,
        freeze_generation: 0,
        provider: receipt.provider.clone(),
        adapter: "claude-stream-json-v1".into(),
        provider_profile_id: receipt.profile_id.clone(),
        model: "claude-test".into(),
        credential_generation: 1,
        protocol: receipt.current_protocol.as_str().into(),
        executable_path: receipt.executable.clone(),
        executable_digest: receipt.executable_blake3.clone(),
        descriptor_digest: receipt.descriptor_blake3.clone(),
        capability_digest: receipt.capability_blake3.clone(),
        policy_snapshot_digest: "6".repeat(64),
        policy_generation: 2,
        sandbox_manifest_digest: "7".repeat(64),
        environment_digest: environment_digest(env).unwrap(),
        gate_ids: vec![format!("gat_{}", "8".repeat(64))],
        budget_reservation_id: "9".repeat(64),
        max_invocations: 1,
        max_wall_clock_ms: 60_000,
        max_cost_micro_usd: 0,
    }
}

fn verified(fixture: &Fixture, claims: &LaunchGrantClaims) -> VerifiedLaunchGrant {
    let grant = fixture.key.sign(claims).unwrap();
    let mut ledger = MemoryNonceLedger::new();
    ledger.register(
        &claims.grant_nonce,
        &claims.attempt_id,
        claims.expires_at_unix_ms,
    );
    let expectation = LaunchGrantExpectation {
        now_unix_ms: claims.not_before_unix_ms,
        lease: LeaseBinding {
            mission_id: claims.mission_id.clone(),
            repository_id: claims.repository_id.clone(),
            graph_revision_id: claims.graph_revision_id.clone(),
            work_package_id: claims.work_package_id.clone(),
            variant_id: claims.variant_id.clone(),
            attempt_id: claims.attempt_id.clone(),
            attempt_fence: claims.attempt_fence,
            runner_id: claims.runner_id.clone(),
            runner_epoch: claims.runner_epoch,
            workspace_id: claims.workspace_id.clone(),
            workspace_nonce_digest: claims.workspace_nonce_digest.clone(),
            authority_epoch: claims.authority_epoch,
            freeze_generation: claims.freeze_generation,
        },
        provider: ProviderBinding {
            provider: claims.provider.clone(),
            adapter: claims.adapter.clone(),
            provider_profile_id: claims.provider_profile_id.clone(),
            model: claims.model.clone(),
            credential_generation: claims.credential_generation,
            protocol: ProviderProtocol::ClaudeStreamJson,
            executable_path: claims.executable_path.clone(),
            executable_digest: claims.executable_digest.clone(),
            descriptor_digest: claims.descriptor_digest.clone(),
            capability_digest: claims.capability_digest.clone(),
            sandbox_manifest_digest: claims.sandbox_manifest_digest.clone(),
            environment_digest: claims.environment_digest.clone(),
        },
        policy: PolicyBinding {
            policy_snapshot_digest: claims.policy_snapshot_digest.clone(),
            policy_generation: claims.policy_generation,
            live_admission_enabled: true,
        },
    };
    verify_launch_grant(
        &grant,
        &fixture.key.verification_key().unwrap(),
        &expectation,
        &mut ledger,
    )
    .unwrap()
}

fn egress_evidence() -> EgressIsolationEvidence {
    let wire = serde_json::json!({
        "receipt_digest": "a".repeat(64),
        "ruleset_digest": "b".repeat(64),
        "allowlist_digest": "c".repeat(64),
        "probes": [
            {"name": "direct-internet", "outcome": "Refused"},
            {"name": "host-jeryu", "outcome": "Refused"},
            {"name": "dns-blocked-udp", "outcome": "Unreachable"}
        ]
    });
    let decoded: EgressIsolationEvidence = serde_json::from_value(wire).unwrap();
    assert_eq!(
        decoded.probes.len(),
        3,
        "bullet-harness-egress evidence wire shape"
    );
    EgressIsolationEvidence {
        receipt_digest: "a".repeat(64),
        ruleset_digest: "b".repeat(64),
        allowlist_digest: "c".repeat(64),
        probes: vec![
            EgressProbe {
                name: "direct-internet".into(),
                outcome: EgressProbeOutcome::Unreachable,
            },
            EgressProbe {
                name: "host-jeryu".into(),
                outcome: EgressProbeOutcome::Refused,
            },
        ],
    }
}

fn blocked_code(admission: &EvaluatedAdmission) -> String {
    admission.require_dispatch().unwrap_err().to_string()
}

#[test]
fn nothing_clears_a_blocker_without_its_evidence() {
    let fixture = evaluated();
    assert_eq!(
        fixture
            .admission
            .require_dispatch()
            .unwrap_err()
            .reason_code(),
        "PROVIDER_ADMISSION_BLOCKED"
    );
    assert!(blocked_code(&fixture.admission).contains("SIGNED_ADMISSION_UNAVAILABLE"));
    let executable = fixture
        .admission
        .executable()
        .to_string_lossy()
        .into_owned();
    let refusal = ArgvBuilder::new(&executable, "/tmp")
        .build_with_admission(&fixture.admission)
        .unwrap_err();
    assert_eq!(refusal.reason_code(), "PROVIDER_ADMISSION_BLOCKED");
    let mut serialized = fixture.admission.receipt().clone();
    serialized.blockers.clear();
    assert!(serialized.require_dispatch().is_err());
}

#[test]
fn verified_grant_and_egress_evidence_clear_exactly_their_blockers() {
    let fixture = evaluated();
    let claims = claims_for(fixture.admission.receipt(), fixture.admission.child_env());
    let grant = verified(&fixture, &claims);
    let envelope_digest = grant.envelope_digest().to_string();
    let admission = fixture.admission.admit_signed(grant).unwrap();
    let receipt = admission.receipt();
    receipt.verify().unwrap();
    assert_eq!(
        receipt.blockers,
        [AdmissionBlocker::EgressIsolationUnavailable]
    );
    let record = receipt.signed_authority.as_ref().unwrap();
    assert_eq!(record.grant_id, claims.grant_id);
    assert_eq!(record.key_id, "launch-grant-alpha");
    assert_eq!(record.issuer, "bullet-kernel");
    assert_eq!(record.envelope_digest, envelope_digest);
    assert_eq!(record.expires_at_unix_ms, claims.expires_at_unix_ms);
    assert!(blocked_code(&admission).contains("EGRESS_ISOLATION_UNAVAILABLE"));

    let admission = admission.admit_egress(egress_evidence()).unwrap();
    assert!(admission.receipt().blockers.is_empty());
    admission.receipt().verify().unwrap();
    admission.require_dispatch().unwrap();
    let executable = admission.executable().to_string_lossy().into_owned();
    let prepared = ArgvBuilder::new(&executable, "/tmp")
        .arg("--version")
        .build_with_admission(&admission)
        .unwrap();
    assert_eq!(prepared.program, executable);
    assert_eq!(prepared.env, admission.child_env());
    let mut tampered = admission.receipt().clone();
    tampered.signed_authority = None;
    assert_eq!(
        tampered.verify().unwrap_err().reason_code(),
        "ADMISSION_REFUSED"
    );
    assert!(
        admission.receipt().clone().require_dispatch().is_err(),
        "serialized receipt"
    );
}

#[test]
fn a_grant_for_another_executable_or_environment_never_clears_the_blocker() {
    let cases: [(&str, Mutation); 6] = [
        ("executable_digest", |c| {
            c.executable_digest = "1".repeat(64)
        }),
        ("descriptor_digest", |c| {
            c.descriptor_digest = "1".repeat(64)
        }),
        ("capability_digest", |c| {
            c.capability_digest = "1".repeat(64)
        }),
        ("environment_digest", |c| {
            c.environment_digest = "1".repeat(64)
        }),
        ("executable_path", |c| {
            c.executable_path = "/usr/bin/claude".into()
        }),
        ("provider_profile_id", |c| {
            c.provider_profile_id = format!("prf_{}", "1".repeat(64))
        }),
    ];
    for (field, mutate) in cases {
        let fixture = evaluated();
        let mut claims = claims_for(fixture.admission.receipt(), fixture.admission.child_env());
        mutate(&mut claims);
        let grant = verified(&fixture, &claims);
        let error = fixture.admission.admit_signed(grant).unwrap_err();
        assert_eq!(
            error.reason_code(),
            "LAUNCH_GRANT_SUBJECT_MISMATCH",
            "{field}"
        );
        assert!(error.to_string().contains(field), "{field}: {error}");
    }
}

#[test]
fn egress_evidence_that_reached_anything_or_lacks_a_probe_is_refused() {
    let mut reached = egress_evidence();
    reached.probes[0].outcome = EgressProbeOutcome::Reached;
    let mut unknown = egress_evidence();
    unknown.probes[1].outcome = EgressProbeOutcome::Unknown;
    let mut missing = egress_evidence();
    missing.probes.pop();
    let mut duplicate = egress_evidence();
    duplicate.probes.push(duplicate.probes[0].clone());
    let mut digest = egress_evidence();
    digest.ruleset_digest = "not-hex".into();
    for (name, evidence) in [
        ("reached", reached),
        ("unknown", unknown),
        ("missing", missing),
        ("duplicate", duplicate),
        ("digest", digest),
    ] {
        let fixture = evaluated();
        let error = fixture.admission.admit_egress(evidence).unwrap_err();
        assert_eq!(error.reason_code(), "ADMISSION_REFUSED", "{name}");
    }
    let fixture = evaluated();
    let admission = fixture.admission.admit_egress(egress_evidence()).unwrap();
    assert_eq!(
        admission.receipt().blockers,
        [AdmissionBlocker::SignedAuthorityUnavailable]
    );
    assert!(admission.receipt().egress_isolation.is_some());
    assert_eq!(
        admission
            .admit_egress(egress_evidence())
            .unwrap_err()
            .reason_code(),
        "ADMISSION_REFUSED"
    );
}
