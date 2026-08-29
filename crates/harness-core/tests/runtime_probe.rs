//! Probe-only runtime observation: construction from native-looking bytes,
//! canonical digest sensitivity, strict decoding, grant binding, bounds, and
//! the deliberate absence of any path from probe facts to conformance
//! evidence. No provider process is spawned.

use bullet_domain::{Observation, ProfileId};
use bullet_harness_core::launch_grant::canonical_json;
use bullet_harness_core::live::{
    native_text, ContainmentClass, ExecutableIdentity, ObservedCapability, ProbeExit, ProbeFacts,
    ProbeGrantEvidence, ProbeOutcome, ProtocolHandshake, RuntimeProbeError,
    RuntimeProbeObservation, MAX_PROBE_STDOUT_BYTES, MAX_PROBE_VERSION_BYTES,
};
use bullet_harness_core::{
    executable_digest, Capability, CapabilityMatrix, CommandFactory, EvaluatedAdmission,
    HarnessDescriptor, HarnessError, LiveDispatcher, LiveTurnOutcome, LiveTurnRequest,
    PatchMutation, PatchOperation, PatchProposal, Preimage, ProbeResult, ProfileRef,
    PromotionStage, ProviderProtocol, RuntimeConformanceObservation, RuntimeProbeSnapshot,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

const NOW: u64 = 1_788_000_000_000;
const EXPIRES: u64 = NOW + 60_000;
const NATIVE_STDOUT: &str = "1.0.85 (Claude Code)\n\
{\"type\":\"system\",\"subtype\":\"init\",\"output_format\":\"stream-json\"}\n";

type Mutation = Box<dyn Fn(&mut ProbeFacts, &mut ProbeGrantEvidence)>;
type GrantMutation = Box<dyn Fn(&mut ProbeGrantEvidence)>;
type ValueMutation = Box<dyn Fn(&mut Value)>;
type CapabilityMutation = Box<dyn Fn(&mut Vec<ObservedCapability>)>;

fn hex(digit: char) -> String {
    digit.to_string().repeat(64)
}

fn executable() -> ExecutableIdentity {
    static IDENTITY: OnceLock<ExecutableIdentity> = OnceLock::new();
    IDENTITY
        .get_or_init(|| {
            let path = std::env::current_exe().unwrap().canonicalize().unwrap();
            ExecutableIdentity::observe(&path).unwrap()
        })
        .clone()
}

fn grant() -> ProbeGrantEvidence {
    ProbeGrantEvidence {
        grant_blake3: hex('a'),
        provider: "claude".into(),
        executable_blake3: executable().blake3,
        containment: ContainmentClass::EgressDenied,
        expires_at_unix_ms: EXPIRES,
    }
}

fn facts() -> ProbeFacts {
    let executable = executable();
    let observed = [
        (Capability::StructuredEvents, "\"type\":\"system\""),
        (
            Capability::StructuredOutputSchema,
            "\"output_format\":\"stream-json\"",
        ),
    ];
    ProbeFacts {
        provider: "claude".into(),
        argv: vec![executable.path.clone(), "--version".into()],
        executable,
        native_stdout: native_text(NATIVE_STDOUT.as_bytes()).unwrap(),
        handshake: ProtocolHandshake::StreamJsonHelloOk,
        capabilities: observed
            .into_iter()
            .map(|(capability, token)| ObservedCapability {
                capability,
                native_token: token.into(),
            })
            .collect(),
        exit: ProbeExit::Code { code: 0 },
        wall_ms: 1_234,
        observed_at_unix_ms: NOW - 5_000,
        containment_receipt_blake3: hex('b'),
    }
}

fn observe(facts: ProbeFacts, grant: &ProbeGrantEvidence) -> RuntimeProbeObservation {
    RuntimeProbeObservation::from_native(facts, grant, NOW).unwrap()
}

fn refusal(mutate: impl Fn(&mut ProbeFacts)) -> RuntimeProbeError {
    let mut facts = facts();
    mutate(&mut facts);
    RuntimeProbeObservation::from_native(facts, &grant(), NOW).unwrap_err()
}

fn decode_value(value: &Value) -> Result<RuntimeProbeObservation, RuntimeProbeError> {
    RuntimeProbeObservation::decode(&canonical_json(value).unwrap(), &grant(), NOW)
}

#[test]
fn native_facts_round_trip_through_canonical_bytes_and_digest() {
    let observation = observe(facts(), &grant());
    let bytes = observation.encode().unwrap();
    let decoded = RuntimeProbeObservation::decode(&bytes, &grant(), NOW).unwrap();
    assert_eq!(decoded, observation);
    let digest = observation.digest().unwrap();
    assert_eq!(decoded.digest().unwrap(), digest);
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(observation.facts(), &facts());
    assert_eq!(observation.version(), "1.0.85 (Claude Code)");
    assert_eq!(observation.grant_blake3(), hex('a'));
    assert_eq!(observation.containment(), ContainmentClass::EgressDenied);
    let handshake = &observation.facts().handshake;
    let protocol = handshake.demonstrated_protocol();
    assert_eq!(protocol, Some(ProviderProtocol::ClaudeStreamJson));
    let refused = ProtocolHandshake::HandshakeRefused {
        reason: "hello timed out".into(),
    };
    assert_eq!(refused.demonstrated_protocol(), None);
    let text = String::from_utf8(bytes).unwrap();
    for key in ["proposal", "events", "stderr", "gate_ids", "operations"] {
        let key = format!("\"{key}\":");
        assert!(!text.contains(&key), "probe document must not carry {key}");
    }
}

#[test]
fn every_field_is_digest_sensitive() {
    let variants: Vec<Mutation> = vec![
        Box::new(|facts, grant| {
            facts.provider = "codex".into();
            grant.provider = "codex".into();
        }),
        Box::new(|facts, grant| {
            facts.executable.blake3 = hex('c');
            grant.executable_blake3 = hex('c');
        }),
        Box::new(|facts, _| {
            facts.executable.path = "/usr/local/bin/probe".into();
            facts.argv[0] = "/usr/local/bin/probe".into();
        }),
        Box::new(|facts, _| facts.executable.device += 1),
        Box::new(|facts, _| facts.executable.inode += 1),
        Box::new(|facts, _| facts.executable.size += 1),
        Box::new(|facts, _| facts.argv.push("--verbose".into())),
        Box::new(|facts, _| facts.native_stdout.push_str("extra line\n")),
        Box::new(|facts, _| facts.native_stdout.replace_range(0..1, "2")),
        Box::new(|facts, _| {
            facts.handshake = ProtocolHandshake::HandshakeRefused {
                reason: "hello refused".into(),
            };
        }),
        Box::new(|facts, _| facts.handshake = ProtocolHandshake::AppServerInitializeOk),
        Box::new(|facts, _| facts.capabilities.truncate(1)),
        Box::new(|facts, _| facts.capabilities[0].native_token = "\"subtype\":\"init\"".into()),
        Box::new(|facts, _| facts.exit = ProbeExit::Code { code: 1 }),
        Box::new(|facts, _| facts.exit = ProbeExit::Signal { signal: 9 }),
        Box::new(|facts, _| facts.wall_ms += 1),
        Box::new(|facts, _| facts.observed_at_unix_ms += 1),
        Box::new(|_, grant| grant.grant_blake3 = hex('d')),
        Box::new(|_, grant| grant.containment = ContainmentClass::ReadOnlyWorkspaceAbsent),
        Box::new(|facts, _| facts.containment_receipt_blake3 = hex('e')),
    ];
    let mut digests = BTreeSet::from([observe(facts(), &grant()).digest().unwrap()]);
    for (index, mutate) in variants.iter().enumerate() {
        let (mut facts, mut grant) = (facts(), grant());
        mutate(&mut facts, &mut grant);
        let digest = observe(facts, &grant).digest().unwrap();
        assert!(digests.insert(digest), "variant {index} collided");
    }
    assert_eq!(digests.len(), variants.len() + 1);
}

#[test]
fn strict_decoder_refuses_tampered_documents() {
    let bytes = observe(facts(), &grant()).encode().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let loose = text.replacen('{', "{ ", 1);
    let trailing = format!("{text}\n");
    let duplicated = text.replacen("\"wall_ms\":1234", "\"wall_ms\":1234,\"wall_ms\":1234", 1);
    let raw: [&[u8]; 5] = [
        b"",
        loose.as_bytes(),
        trailing.as_bytes(),
        duplicated.as_bytes(),
        &[0xff, b'{', b'}'],
    ];
    for raw in raw {
        let error = RuntimeProbeObservation::decode(raw, &grant(), NOW).unwrap_err();
        assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED");
    }

    let mutations: Vec<ValueMutation> = vec![
        Box::new(|value| value["schema_version"] = json!(2)),
        Box::new(|value| value["extra"] = json!(true)),
        Box::new(|value| value["facts"]["extra"] = json!(true)),
        Box::new(|value| value["version"] = json!("2.0.0")),
        Box::new(|value| value["facts"]["provider"] = json!("Claude")),
        Box::new(|value| value["facts"]["argv"][0] = json!("/bin/other")),
        Box::new(|value| value["facts"]["argv"] = json!([])),
        Box::new(|value| value["facts"]["capabilities"][1]["native_token"] = json!("absent")),
        Box::new(|value| {
            let caps = value["facts"]["capabilities"].as_array().unwrap().clone();
            value["facts"]["capabilities"] = Value::Array(caps.into_iter().rev().collect());
        }),
        Box::new(|value| value["facts"]["executable"]["blake3"] = json!("nothex")),
        Box::new(|value| value["facts"]["executable"]["path"] = json!("relative/bin")),
        Box::new(|value| value["facts"]["executable"]["size"] = json!(0)),
        Box::new(|value| value["facts"]["wall_ms"] = json!(120_001)),
        Box::new(|value| value["facts"]["observed_at_unix_ms"] = json!(0)),
        Box::new(|value| value["grant_blake3"] = json!("A".repeat(64))),
        Box::new(|value| value["facts"]["containment_receipt_blake3"] = json!("")),
        Box::new(|value| value["facts"]["handshake"] = json!({"kind":"unknown_ok"})),
        Box::new(|value| value["facts"]["exit"] = json!({"kind":"code"})),
        Box::new(|value| value["facts"]["native_stdout"] = json!("1.0.85\u{7f}\n")),
    ];
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    for (index, mutate) in mutations.iter().enumerate() {
        let mut value = document.clone();
        mutate(&mut value);
        let error = decode_value(&value).unwrap_err();
        assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED", "{index}");
    }
    assert!(decode_value(&document).is_ok());
}

#[test]
fn probe_only_outcome_never_becomes_conformance_evidence() {
    // Compile-time documented absence: `RuntimeProbeObservation` has no `From`
    // into `RuntimeConformanceObservation`, no `into_parts`, and no proposal or
    // event accessor. The only bridge is this enum; its probe arm refuses.
    let probe = observe(facts(), &grant());
    let outcome = ProbeOutcome::ProbeOnly(Box::new(probe.clone()));
    assert_eq!(outcome.probe_only(), Some(&probe));
    let error = outcome.into_conformance().unwrap_err();
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_NOT_ADMISSIBLE");

    // A conformance observation needs a real, validated proposal: a zero-op
    // proposal is refused, so no probe can fake its way through this arm.
    let stdout = NATIVE_STDOUT.as_bytes().to_vec();
    let zero = proposal(vec![]);
    let zero = RuntimeConformanceObservation::new(snapshot(), stdout.clone(), vec![], vec![], zero);
    assert_eq!(zero.unwrap_err().reason_code(), "PROPOSAL_PARSE_FAILED");
    let write = PatchOperation {
        path: "PONG.txt".into(),
        preimage: Preimage::Absent,
        mutation: PatchMutation::Write {
            content_utf8: "PONG\n".into(),
        },
    };
    let genuine = proposal(vec![write]);
    let genuine =
        RuntimeConformanceObservation::new(snapshot(), stdout, vec![], vec![], genuine).unwrap();
    let conformance = ProbeOutcome::Conformance(Box::new(genuine));
    assert!(conformance.probe_only().is_none());
    let (_, _, _, _, admitted) = conformance.into_conformance().unwrap().into_parts();
    assert_eq!(admitted.operations.len(), 1);
}

#[test]
fn default_dispatcher_hook_refuses_runtime_probe_unavailable() {
    struct Refusing;
    impl LiveDispatcher for Refusing {
        fn provider(&self) -> &str {
            "claude"
        }
        fn descriptor(&self) -> HarnessDescriptor {
            snapshot().descriptor
        }
        fn observed_runtime_version(&self) -> &str {
            "1.0.85"
        }
        fn required_protocol(&self) -> ProviderProtocol {
            ProviderProtocol::ClaudeStreamJson
        }
        fn dispatch_live_turn(
            &self,
            _: &EvaluatedAdmission,
            _: &CommandFactory<'_>,
            _: &LiveTurnRequest,
        ) -> Result<LiveTurnOutcome, HarnessError> {
            Err(HarnessError::KillSwitch)
        }
    }
    let error = Refusing.observe_runtime_probe(&grant()).unwrap_err();
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_UNAVAILABLE");
    assert!(matches!(error, RuntimeProbeError::Unavailable { provider } if provider == "claude"));
    let profile = ProfileRef {
        profile_id: ProfileId::from_seed("claude"),
        expected: Default::default(),
    };
    let executable = PathBuf::from(executable().path);
    let existing = Refusing.observe_runtime_conformance(&executable, &profile, Utc::now());
    let existing = existing.unwrap_err();
    assert_eq!(existing.reason_code(), "RUNTIME_PROBE_UNAVAILABLE");
}

#[test]
fn grant_mismatch_absence_and_expiry_are_refused() {
    let observation = observe(facts(), &grant());
    let missing = observation.verify_grant(None, NOW).unwrap_err();
    assert_eq!(missing.reason_code(), "RUNTIME_PROBE_GRANT_MISSING");
    assert!(observation.verify_grant(Some(&grant()), NOW).is_ok());

    let expired = |at| RuntimeProbeError::GrantExpired {
        expires_at_unix_ms: at,
    };
    assert_eq!(expired(1).reason_code(), "RUNTIME_PROBE_GRANT_EXPIRED");
    for now in [EXPIRES, EXPIRES + 1, u64::MAX] {
        let error = RuntimeProbeObservation::from_native(facts(), &grant(), now).unwrap_err();
        assert_eq!(error, expired(EXPIRES));
    }
    assert!(RuntimeProbeObservation::from_native(facts(), &grant(), EXPIRES - 1).is_ok());

    let mismatch = |field| RuntimeProbeError::GrantMismatch { field };
    assert_eq!(mismatch("x").reason_code(), "RUNTIME_PROBE_GRANT_MISMATCH");
    let error = refusal(|facts| facts.provider = "codex".into());
    assert_eq!(error, mismatch("provider"));
    let error = refusal(|facts| facts.executable.blake3 = hex('f'));
    assert_eq!(error, mismatch("executable_blake3"));
    let error = refusal(|facts| facts.observed_at_unix_ms = EXPIRES);
    assert_eq!(error, mismatch("observed_at_unix_ms"));

    let bytes = observation.encode().unwrap();
    let rebinds: [GrantMutation; 3] = [
        Box::new(|g| g.grant_blake3 = hex('9')),
        Box::new(|g| g.containment = ContainmentClass::ReadOnlyWorkspaceAbsent),
        Box::new(|g| g.expires_at_unix_ms = NOW),
    ];
    let expected = [
        mismatch("grant_blake3"),
        mismatch("containment"),
        expired(NOW),
    ];
    for (mutate, expected) in rebinds.into_iter().zip(expected) {
        let mut grant = grant();
        mutate(&mut grant);
        let error = RuntimeProbeObservation::decode(&bytes, &grant, NOW).unwrap_err();
        assert_eq!(error, expected);
    }

    let malformed: [GrantMutation; 4] = [
        Box::new(|grant| grant.grant_blake3 = "x".repeat(64)),
        Box::new(|grant| grant.executable_blake3 = String::new()),
        Box::new(|grant| grant.expires_at_unix_ms = 0),
        Box::new(|grant| grant.provider = "Claude".into()),
    ];
    for mutate in malformed {
        let mut grant = grant();
        mutate(&mut grant);
        let error = RuntimeProbeObservation::from_native(facts(), &grant, NOW).unwrap_err();
        assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED");
    }
}

#[test]
fn hostile_text_oversized_output_and_capability_tokens_are_refused() {
    let mut exact = b"1.0.85\n".to_vec();
    exact.resize(MAX_PROBE_STDOUT_BYTES, b'x');
    let mut bounded = facts();
    bounded.native_stdout = native_text(&exact).unwrap();
    bounded.capabilities.clear();
    let observation = observe(bounded, &grant());
    let retained = observation.facts().native_stdout.len();
    assert_eq!(retained, MAX_PROBE_STDOUT_BYTES);
    assert_eq!(observation.version(), "1.0.85");
    exact.push(b'x');
    let error = native_text(&exact).unwrap_err();
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_OUTPUT_OVERSIZED");
    assert_eq!(
        error.to_string(),
        "runtime probe output exceeds 16384 bytes"
    );
    let oversized = String::from_utf8(exact).unwrap();
    let through_validate = refusal(|facts| {
        facts.native_stdout.clone_from(&oversized);
        facts.capabilities.clear();
    });
    assert_eq!(through_validate, error);

    let long = format!("{}\n", "9".repeat(MAX_PROBE_VERSION_BYTES + 1));
    let hostile: [&str; 9] = [
        "1.0.85\x1b[0m\n",
        "1.0.85\r\n",
        "\x001.0.85\n",
        "1.0.85\t(Claude Code)\n",
        "1.0.85\n\x07",
        "",
        "\n\n",
        "1.0.85 \u{e9}\n",
        long.as_str(),
    ];
    for stdout in hostile {
        let error = refusal(|facts| {
            facts.native_stdout = stdout.to_string();
            facts.capabilities.clear();
        });
        assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED", "{stdout:?}");
    }
    let error = native_text(b"\xff1.0.85\n").unwrap_err();
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED");
    let error = refusal(|facts| facts.argv.push("--flag\n".into()));
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED");
    let error = refusal(|facts| {
        facts.handshake = ProtocolHandshake::HandshakeRefused {
            reason: "no\x1b[1mhello".into(),
        };
    });
    assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED");
    let mut fine = facts();
    fine.native_stdout = "  1.0.85 (Claude Code)  \n\n".into();
    fine.capabilities.clear();
    assert_eq!(observe(fine, &grant()).version(), "1.0.85 (Claude Code)");

    // absent token, empty token, unsorted, duplicate, control character in token
    let cases: [CapabilityMutation; 5] = [
        Box::new(|caps| caps[0].native_token = "\"input_format\"".into()),
        Box::new(|caps| caps[0].native_token = String::new()),
        Box::new(|caps| caps.reverse()),
        Box::new(|caps| caps[1].capability = Capability::StructuredEvents),
        Box::new(|caps| caps[0].native_token = "\"type\":\n".into()),
    ];
    for (index, mutate) in cases.iter().enumerate() {
        let error = refusal(|facts| mutate(&mut facts.capabilities));
        assert_eq!(error.reason_code(), "RUNTIME_PROBE_MALFORMED", "{index}");
    }
}

#[test]
fn executable_identity_is_observed_from_the_filesystem() {
    let path = std::env::current_exe().unwrap().canonicalize().unwrap();
    let identity = executable();
    assert_eq!(identity.path, path.to_str().unwrap());
    assert_eq!(identity.blake3, executable_digest(&path).unwrap());
    assert_eq!(identity.size, std::fs::metadata(&path).unwrap().len());
    assert!(identity.inode != 0);

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let plain = root.join("plain");
    std::fs::write(&plain, b"not executable").unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let relative = PathBuf::from("relative/probe");
    let missing = root.join("missing");
    for candidate in [relative, missing, plain, link, root] {
        let error = ExecutableIdentity::observe(&candidate).unwrap_err();
        assert_eq!(
            error.reason_code(),
            "RUNTIME_PROBE_EXECUTABLE_INVALID",
            "{candidate:?}"
        );
    }
}

fn snapshot() -> RuntimeProbeSnapshot {
    RuntimeProbeSnapshot {
        descriptor: HarnessDescriptor {
            provider: "claude".into(),
            binary: "claude".into(),
            version: Observation::value("1.0.85".into()),
            stage: PromotionStage::ContractPass,
            capabilities: CapabilityMatrix::new(),
        },
        executable: PathBuf::from(executable().path),
        executable_blake3: executable().blake3,
        protocol: ProviderProtocol::ClaudeStreamJson,
        identity: ProbeResult {
            profile: Observation::Empty,
            version: "1.0.85".into(),
        },
        observed_at: Utc::now(),
    }
}

fn proposal(operations: Vec<PatchOperation>) -> PatchProposal {
    PatchProposal {
        schema_version: 1,
        proposal_id: format!("cnt_{}", hex('1')),
        producing_attempt_id: format!("atm_{}", hex('2')),
        base_checkpoint_id: format!("ckp_{}", hex('3')),
        base_checkpoint_digest: hex('4'),
        operations,
        gate_ids: vec![bullet_domain::REPOSITORY_GATE_ID.into()],
        intent_summary: String::new(),
        claims: vec![],
        uncertainties: vec![],
        done: false,
    }
}
