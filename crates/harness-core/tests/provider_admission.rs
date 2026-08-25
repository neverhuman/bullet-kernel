use bullet_domain::{Observation, ProfileId};
use bullet_harness_core::{
    descriptor_digest, executable_digest, AdmissionBlocker, AgentEvent, AgentEventKind,
    AgentSessionId, ArgvBuilder, CanarySecrets, Capability, CapabilityMatrix, CapabilityState,
    ConformanceEvidence, CredentialGrant, EventNormalizer, ExpectedProfile, HarnessDescriptor,
    NativeMeta, PatchMutation, PatchOperation, PatchProposal, Preimage, ProbeResult,
    ProfileIdentity, ProfileRef, PromotionStage, ProviderAdmission, ProviderAdmissionPolicy,
    ProviderProtocol, RuntimeProbeSnapshot,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

const CANARY: &str = "bullet-host-canary-7f2d9b61";

struct Fixture {
    _directory: TempDir,
    policy: ProviderAdmissionPolicy,
    probe: RuntimeProbeSnapshot,
    now: DateTime<Utc>,
}

fn required_protocol(provider: &str) -> ProviderProtocol {
    match provider {
        "claude" => ProviderProtocol::ClaudeStreamJson,
        "codex" => ProviderProtocol::CodexAppServerJsonl,
        "cursor" => ProviderProtocol::CursorAcp,
        "agy" => ProviderProtocol::AntigravityHeadlessStructured,
        _ => unreachable!(),
    }
}

fn supported_capabilities(provider: &str) -> CapabilityMatrix {
    let mut matrix = CapabilityMatrix::new()
        .with(
            Capability::StructuredOutputSchema,
            CapabilityState::Supported,
        )
        .with(Capability::HeadlessMode, CapabilityState::Supported)
        .with(Capability::MultilinePrompt, CapabilityState::Supported);
    if provider != "agy" {
        matrix.set(Capability::StructuredEvents, CapabilityState::Supported);
    }
    matrix
}

fn fixture(provider: &str, protocol: ProviderProtocol) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let credential = root.join("oauth-source.json");
    fs::write(&credential, b"offline-oauth-fixture").unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let version = if provider == "agy" {
        "1.1.19"
    } else {
        "offline-1.0.0"
    };
    let capabilities = supported_capabilities(provider);
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 22, 0, 0).unwrap();
    let expected = ExpectedProfile {
        email: Some(format!("{provider}@offline.invalid")),
        account_id_prefix: None,
    };
    let profile = ProfileRef {
        profile_id: ProfileId::from_seed(provider),
        expected: expected.clone(),
    };
    let identity = ProbeResult {
        profile: Observation::value(ProfileIdentity {
            provider: provider.into(),
            email: expected.email,
            account_id: None,
            subscription: Some("offline-fixture".into()),
            auth_method: Some("oauth".into()),
        }),
        version: version.into(),
    };
    let policy = ProviderAdmissionPolicy {
        provider: provider.into(),
        executable: executable.clone(),
        executable_blake3: executable_digest(&executable).unwrap(),
        version: version.into(),
        descriptor_blake3: String::new(),
        profile,
        required_protocol: required_protocol(provider),
        max_probe_age_seconds: 60,
        runtime_root: root,
        credential_targets: vec![PathBuf::from(".oauth/session.json")],
        credentials: vec![CredentialGrant {
            source: credential,
            target: PathBuf::from(".oauth/session.json"),
            expected_blake3: blake3::hash(b"offline-oauth-fixture").to_hex().to_string(),
        }],
    };
    let descriptor = HarnessDescriptor {
        provider: provider.into(),
        binary: executable
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        version: Observation::value(version.into()),
        stage: PromotionStage::ContractPass,
        capabilities,
    };
    let mut policy = policy;
    policy.descriptor_blake3 = descriptor_digest(&descriptor).unwrap();
    let probe = RuntimeProbeSnapshot {
        descriptor,
        executable,
        executable_blake3: policy.executable_blake3.clone(),
        protocol,
        identity,
        observed_at: now,
    };
    Fixture {
        _directory: directory,
        policy,
        probe,
        now,
    }
}

fn canaries() -> CanarySecrets {
    CanarySecrets::new(vec![CANARY.into()]).unwrap()
}

fn hostile_environment() -> Vec<(String, String)> {
    [
        ("LANG", "C.UTF-8"),
        ("PATH", CANARY),
        ("HOME", CANARY),
        ("GH_TOKEN", CANARY),
        ("GITHUB_TOKEN", CANARY),
        ("SSH_AUTH_SOCK", CANARY),
        ("AWS_SECRET_ACCESS_KEY", CANARY),
        ("OPENAI_API_KEY", CANARY),
        ("ANTHROPIC_API_KEY", CANARY),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

fn proposal(contents: &str) -> PatchProposal {
    PatchProposal {
        schema_version: 1,
        proposal_id: format!("cnt_{}", "1".repeat(64)),
        producing_attempt_id: format!("atm_{}", "2".repeat(64)),
        base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
        base_checkpoint_digest: "4".repeat(64),
        intent_summary: "write an offline fixture".into(),
        operations: vec![PatchOperation {
            path: "PONG.txt".into(),
            preimage: Preimage::Absent,
            mutation: PatchMutation::Write {
                content_utf8: contents.into(),
            },
        }],
        gate_ids: vec![bullet_domain::REPOSITORY_GATE_ID.into()],
        claims: vec![],
        uncertainties: vec![],
        done: true,
    }
}

fn events(provider: &str) -> Vec<AgentEvent> {
    let mut normalizer = EventNormalizer::new(AgentSessionId::new("offline-session"), provider);
    vec![
        normalizer.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none()),
        normalizer.accept(
            AgentEventKind::TurnCompleted,
            json!({"outcome": "fixture"}),
            &NativeMeta::none(),
        ),
    ]
}

fn prepare(fixture: &Fixture) -> ProviderAdmission {
    ProviderAdmission::prepare(
        fixture.policy.clone(),
        fixture.probe.clone(),
        hostile_environment(),
        canaries(),
        fixture.now,
    )
    .unwrap()
}

fn admission_error(fixture: Fixture) -> &'static str {
    ProviderAdmission::prepare(fixture.policy, fixture.probe, [], canaries(), fixture.now)
        .unwrap_err()
        .reason_code()
}

#[test]
#[cfg(unix)]
fn exact_admission_stages_read_only_oauth_and_never_authorizes_spawn() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    let admission = prepare(&fixture);
    let child_env = admission
        .finalize(ConformanceEvidence {
            stdout: b"offline stdout",
            stderr: b"",
            events: &events("claude"),
            proposal: &proposal("PONG\n"),
        })
        .unwrap();
    let env = child_env.child_env();
    let keys: Vec<_> = env.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "HOME",
            "LANG",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME"
        ]
    );
    assert!(env
        .iter()
        .all(|(key, value)| { !key.contains(CANARY) && !value.contains(CANARY) && key != "PATH" }));
    let home = env
        .iter()
        .find(|(key, _)| key == "HOME")
        .map(|(_, value)| PathBuf::from(value))
        .unwrap();
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(home.join(".oauth/session.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    assert_eq!(
        fs::read(home.join(".oauth/session.json")).unwrap(),
        b"offline-oauth-fixture"
    );
    let receipt = child_env.receipt();
    receipt.verify().unwrap();
    assert_eq!(
        receipt.blockers,
        [
            AdmissionBlocker::SignedAuthorityUnavailable,
            AdmissionBlocker::EgressIsolationUnavailable,
        ]
    );
    assert!(!receipt.environment_blake3.is_empty());
    assert!(!receipt.events_blake3.is_empty());
    assert_eq!(receipt.canary_surfaces.len(), 5);
    let refusal = ArgvBuilder::new(fixture.policy.executable.to_string_lossy(), "/tmp")
        .build_with_admission(&child_env)
        .unwrap_err();
    assert_eq!(refusal.reason_code(), "PROVIDER_ADMISSION_BLOCKED");
    drop(child_env);
    assert!(!home.exists(), "ephemeral HOME is removed on drop");
}

#[test]
fn runtime_protocol_and_capabilities_are_probe_facts_not_provider_assumptions() {
    let cases = [
        ("codex", ProviderProtocol::CodexExecJson),
        ("cursor", ProviderProtocol::CursorStreamJson),
        ("agy", ProviderProtocol::AntigravityHeadlessText),
    ];
    for (provider, current) in cases {
        let fixture = fixture(provider, current);
        let evaluated = prepare(&fixture)
            .finalize(ConformanceEvidence {
                stdout: b"offline",
                stderr: b"",
                events: &events(provider),
                proposal: &proposal("PONG\n"),
            })
            .unwrap();
        assert_eq!(evaluated.receipt().current_protocol, current);
        assert!(evaluated
            .receipt()
            .blockers
            .contains(&AdmissionBlocker::ProtocolNonconformant));
        assert!(evaluated.require_dispatch().is_err());
    }

    let mut fixture = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    fixture
        .probe
        .descriptor
        .capabilities
        .set(Capability::StructuredEvents, CapabilityState::Unknown);
    fixture.policy.descriptor_blake3 = descriptor_digest(&fixture.probe.descriptor).unwrap();
    let evaluated = prepare(&fixture)
        .finalize(ConformanceEvidence {
            stdout: b"offline",
            stderr: b"",
            events: &events("claude"),
            proposal: &proposal("PONG\n"),
        })
        .unwrap();
    assert!(evaluated
        .receipt()
        .blockers
        .contains(&AdmissionBlocker::CapabilityNonconformant));
}

#[test]
fn exact_runtime_subject_mismatches_fail_before_dispatch() {
    let mut version = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    version.probe.descriptor.version = Observation::value("other".into());
    assert_eq!(admission_error(version), "ADMISSION_REFUSED");

    let mut identity = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    if let Observation::Value { value } = &mut identity.probe.identity.profile {
        value.provider = "codex".into();
    }
    assert_eq!(admission_error(identity), "ADMISSION_REFUSED");

    let mut stale = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    stale.probe.observed_at = stale.now - chrono::Duration::seconds(61);
    assert_eq!(admission_error(stale), "ADMISSION_REFUSED");
}

#[test]
#[cfg(unix)]
fn relative_symlink_and_unlisted_credentials_are_refused() {
    use std::os::unix::fs::symlink;

    let mut relative = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    let executable_link = relative.policy.runtime_root.join("provider-link");
    symlink(&relative.probe.executable, &executable_link).unwrap();
    assert_eq!(
        executable_digest(&executable_link)
            .unwrap_err()
            .reason_code(),
        "ADMISSION_REFUSED"
    );
    relative.policy.executable = PathBuf::from("claude");
    relative.probe.executable = PathBuf::from("claude");
    assert_eq!(admission_error(relative), "ADMISSION_REFUSED");

    let mut credential = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    credential.policy.credentials[0].target = PathBuf::from(".ssh/id_ed25519");
    assert_eq!(admission_error(credential), "ADMISSION_REFUSED");

    let mut linked = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    let source = linked.policy.credentials[0].source.clone();
    let link = linked.policy.runtime_root.join("linked-oauth");
    symlink(&source, &link).unwrap();
    linked.policy.credentials[0].source = link;
    assert_eq!(admission_error(linked), "ADMISSION_REFUSED");
}

#[test]
fn canaries_are_refused_on_every_captured_or_accepted_surface() {
    for surface in ["stdout", "stderr", "event_log", "accepted_patch"] {
        let fixture = fixture("claude", ProviderProtocol::ClaudeStreamJson);
        let mut event_log = events("claude");
        let mut patch = proposal("PONG\n");
        let (stdout, stderr) = match surface {
            "stdout" => (CANARY.as_bytes(), b"".as_slice()),
            "stderr" => (b"".as_slice(), CANARY.as_bytes()),
            "event_log" => {
                event_log[0].payload = json!({"leak": CANARY});
                (b"".as_slice(), b"".as_slice())
            }
            "accepted_patch" => {
                patch.operations[0].mutation = PatchMutation::Write {
                    content_utf8: CANARY.into(),
                };
                (b"".as_slice(), b"".as_slice())
            }
            _ => unreachable!(),
        };
        let error = prepare(&fixture)
            .finalize(ConformanceEvidence {
                stdout,
                stderr,
                events: &event_log,
                proposal: &patch,
            })
            .unwrap_err();
        assert_eq!(error.reason_code(), "SECRET_CANARY_EXPOSURE", "{surface}");
        assert!(!error.to_string().contains(CANARY));
    }
}

#[test]
fn malformed_duplicate_delayed_and_crashed_streams_never_conform() {
    let fixture = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    let mut normalizer = EventNormalizer::new(AgentSessionId::new("bad"), "claude");
    let malformed = vec![
        normalizer.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none()),
        normalizer.malformed("not-json"),
        normalizer.accept(
            AgentEventKind::TurnCompleted,
            json!({}),
            &NativeMeta::none(),
        ),
    ];
    assert_protocol_refusal(&fixture, &malformed);

    let mut duplicate = events("claude");
    duplicate[1].event_id = duplicate[0].event_id.clone();
    assert_protocol_refusal(&fixture, &duplicate);

    let mut delayed = EventNormalizer::new(AgentSessionId::new("late"), "claude");
    let delayed = vec![
        delayed.accept(AgentEventKind::TurnStarted, json!({}), &NativeMeta::none()),
        delayed.accept(
            AgentEventKind::TurnCompleted,
            json!({}),
            &NativeMeta::none(),
        ),
        delayed.accept(AgentEventKind::TurnDelta, json!({}), &NativeMeta::none()),
    ];
    assert_protocol_refusal(&fixture, &delayed);

    let mut crashed = events("claude");
    crashed.pop();
    assert_protocol_refusal(&fixture, &crashed);

    let mut failed = events("claude");
    failed[1].kind = AgentEventKind::TurnFailed;
    assert_protocol_refusal(&fixture, &failed);
}

fn assert_protocol_refusal(fixture: &Fixture, event_log: &[AgentEvent]) {
    let error = prepare(fixture)
        .finalize(ConformanceEvidence {
            stdout: b"",
            stderr: b"",
            events: event_log,
            proposal: &proposal("PONG\n"),
        })
        .unwrap_err();
    assert_eq!(error.reason_code(), "PROTOCOL_ERROR");
}

#[test]
fn receipt_tampering_and_command_shaped_model_gates_are_refused() {
    let fixture = fixture("claude", ProviderProtocol::ClaudeStreamJson);
    let evaluated = prepare(&fixture)
        .finalize(ConformanceEvidence {
            stdout: b"offline",
            stderr: b"",
            events: &events("claude"),
            proposal: &proposal("PONG\n"),
        })
        .unwrap();
    let mut tampered = evaluated.receipt().clone();
    tampered.version.push_str("-altered");
    assert_eq!(
        tampered.verify().unwrap_err().reason_code(),
        "ADMISSION_REFUSED"
    );

    let mut command = proposal("PONG\n");
    command.gate_ids = vec!["cargo test".into()];
    let error = prepare(&fixture)
        .finalize(ConformanceEvidence {
            stdout: b"",
            stderr: b"",
            events: &events("claude"),
            proposal: &command,
        })
        .unwrap_err();
    assert_eq!(error.reason_code(), "PROPOSAL_PARSE_FAILED");
}
