//! Launch-grant verifier: hub golden equivalence, the full negative suite,
//! replay, and the by-design `POLICY_LIVE_ADMISSION_DISABLED` refusal.

use bullet_harness_core::launch_grant::{
    canonical_json, decode_canonical, environment_digest, verify_launch_grant,
    workspace_nonce_digest, LaunchGrantClaims, LaunchGrantExpectation, LaunchGrantSigningKey,
    LaunchGrantVerificationKey, LeaseBinding, MemoryNonceLedger, PolicyBinding, ProviderBinding,
    SignedLaunchGrant,
};
use bullet_harness_core::{HarnessError, ProviderProtocol};
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::Public;
use serde_json::Value;

/// Fixture-only key material shared with bullet-wire's golden generator.
const SECRET_KEY: [u8; 64] = [
    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125, 159,
    133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116, 30, 185, 219, 187, 188, 4, 124, 3, 253, 112,
    96, 78, 0, 113, 240, 152, 126, 22, 178, 139, 117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177,
    162,
];
const GOLDEN: &str = include_str!("fixtures/launch-grant-golden.json");

fn golden() -> Value {
    serde_json::from_str(GOLDEN).unwrap()
}

fn golden_claims() -> LaunchGrantClaims {
    let golden = golden();
    decode_canonical(golden["claims_canonical_json"].as_str().unwrap().as_bytes()).unwrap()
}

fn signer() -> LaunchGrantSigningKey {
    LaunchGrantSigningKey::from_bytes("bullet-kernel-local", "authority-test-1", &SECRET_KEY)
        .unwrap()
}

fn verifier() -> LaunchGrantVerificationKey {
    signer().verification_key().unwrap()
}

fn expectation(claims: &LaunchGrantClaims, now_unix_ms: u64, live: bool) -> LaunchGrantExpectation {
    LaunchGrantExpectation {
        now_unix_ms,
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
            live_admission_enabled: live,
        },
    }
}

fn ledger_for(claims: &LaunchGrantClaims) -> MemoryNonceLedger {
    let mut ledger = MemoryNonceLedger::new();
    assert!(ledger.register(
        &claims.grant_nonce,
        &claims.attempt_id,
        claims.expires_at_unix_ms
    ));
    ledger
}

fn verify_at(claims: &LaunchGrantClaims, now: u64, live: bool) -> Result<String, HarnessError> {
    let grant = signer().sign(claims).unwrap();
    let mut ledger = ledger_for(claims);
    verify_launch_grant(
        &grant,
        &verifier(),
        &expectation(claims, now, live),
        &mut ledger,
    )
    .map(|verified| verified.envelope_digest().to_string())
}

fn code(result: Result<String, HarnessError>) -> String {
    result.unwrap_err().reason_code().to_string()
}

#[test]
fn hub_golden_vector_is_byte_equivalent() {
    let golden = golden();
    let claims = golden_claims();
    let canonical = golden["claims_canonical_json"].as_str().unwrap();
    assert_eq!(canonical_json(&claims).unwrap(), canonical.as_bytes());
    assert_eq!(claims.digest().unwrap(), golden["claims_digest"]);
    let envelope: SignedLaunchGrant = serde_json::from_value(golden["envelope"].clone()).unwrap();
    assert_eq!(
        envelope.envelope_digest().unwrap(),
        golden["envelope_digest"]
    );
    assert_eq!(signer().public_key_hex(), golden["public_key_hex"]);
    assert_eq!(
        signer().sign(&claims).unwrap(),
        envelope,
        "ed25519 is deterministic"
    );
    let nonce: [u8; 32] = hex::decode(golden["workspace_nonce_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        workspace_nonce_digest(&nonce).unwrap(),
        claims.workspace_nonce_digest
    );
    let environment: Vec<(String, String)> = golden["environment"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
        .collect();
    assert_eq!(
        environment_digest(&environment).unwrap(),
        claims.environment_digest
    );
    let untrusted = UntrustedToken::<Public, V4>::try_from(envelope.paseto.as_str()).unwrap();
    assert_eq!(
        untrusted.untrusted_footer(),
        golden["footer_canonical_json"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        golden["implicit_assertion_utf8"],
        "bullet-farm.launch-grant.v1alpha1"
    );
    let now = golden["verify_at_unix_ms"].as_u64().unwrap();
    let mut ledger = ledger_for(&claims);
    let verified = verify_launch_grant(
        &envelope,
        &verifier(),
        &expectation(&claims, now, true),
        &mut ledger,
    )
    .unwrap();
    assert_eq!(verified.envelope_digest(), golden["envelope_digest"]);
    assert_eq!(verified.claims(), &claims);
    assert!(ledger.is_consumed(&claims.grant_nonce));
}

#[test]
fn v1alpha1_policy_refuses_a_fully_valid_grant_without_consuming_its_nonce() {
    let claims = golden_claims();
    let grant = signer().sign(&claims).unwrap();
    let mut ledger = ledger_for(&claims);
    let error = verify_launch_grant(
        &grant,
        &verifier(),
        &expectation(&claims, claims.not_before_unix_ms, false),
        &mut ledger,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "POLICY_LIVE_ADMISSION_DISABLED");
    let message = error.to_string();
    assert!(message.contains("generation 17"), "{message}");
    assert!(
        message.contains("sandbox_policy.live_admission_enabled"),
        "{message}"
    );
    assert!(!ledger.is_consumed(&claims.grant_nonce));
}

#[test]
fn time_window_is_inclusive_start_exclusive_end() {
    let claims = golden_claims();
    let (not_before, expires_at) = claims.window();
    assert_eq!(
        code(verify_at(&claims, not_before - 1, true)),
        "LAUNCH_GRANT_NOT_YET_VALID"
    );
    assert!(verify_at(&claims, not_before, true).is_ok());
    assert!(verify_at(&claims, expires_at - 1, true).is_ok());
    assert_eq!(
        code(verify_at(&claims, expires_at, true)),
        "LAUNCH_GRANT_EXPIRED"
    );
    assert_eq!(
        code(verify_at(&claims, 0, true)),
        "LAUNCH_GRANT_NOT_YET_VALID"
    );
}

#[test]
fn replay_unknown_and_store_expired_nonces_are_refused() {
    let claims = golden_claims();
    let grant = signer().sign(&claims).unwrap();
    let key = verifier();
    let now = claims.not_before_unix_ms;
    let mut ledger = ledger_for(&claims);
    let first =
        verify_launch_grant(&grant, &key, &expectation(&claims, now, true), &mut ledger).unwrap();
    assert_eq!(first.claims().grant_id, claims.grant_id);
    let replay = verify_launch_grant(&grant, &key, &expectation(&claims, now, true), &mut ledger)
        .unwrap_err();
    assert_eq!(replay.reason_code(), "LAUNCH_GRANT_REPLAYED");
    assert!(replay.to_string().contains(&claims.grant_id));

    let mut empty = MemoryNonceLedger::new();
    let unknown = verify_launch_grant(&grant, &key, &expectation(&claims, now, true), &mut empty)
        .unwrap_err();
    assert_eq!(unknown.reason_code(), "LAUNCH_GRANT_INVALID");

    let mut stale = MemoryNonceLedger::new();
    stale.register(&claims.grant_nonce, &claims.attempt_id, now);
    let expired = verify_launch_grant(&grant, &key, &expectation(&claims, now, true), &mut stale)
        .unwrap_err();
    assert_eq!(expired.reason_code(), "LAUNCH_GRANT_EXPIRED");
}

#[test]
fn wrong_key_forged_signature_tamper_and_wrong_labels_are_refused() {
    let claims = golden_claims();
    let now = claims.not_before_unix_ms;
    let key = verifier();
    let forger =
        LaunchGrantSigningKey::generate("bullet-kernel-local", "authority-test-1").unwrap();
    let forged = forger.sign(&claims).unwrap();
    let mut ledger = ledger_for(&claims);
    let error = verify_launch_grant(&forged, &key, &expectation(&claims, now, true), &mut ledger)
        .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");

    let genuine = signer().sign(&claims).unwrap();
    let mut tampered = genuine.clone();
    let payload_start = "v4.public.".len() + 40;
    let mut bytes = tampered.paseto.clone().into_bytes();
    bytes[payload_start] = if bytes[payload_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    tampered.paseto = String::from_utf8(bytes).unwrap();
    let error = verify_launch_grant(
        &tampered,
        &key,
        &expectation(&claims, now, true),
        &mut ledger,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");

    let mut relabelled = genuine.clone();
    relabelled.key_id = "authority-test-2".into();
    let error = verify_launch_grant(
        &relabelled,
        &key,
        &expectation(&claims, now, true),
        &mut ledger,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_KEY_UNKNOWN");

    let mut footerless = genuine.clone();
    footerless.paseto = footerless.paseto.rsplit_once('.').unwrap().0.to_string();
    let error = verify_launch_grant(
        &footerless,
        &key,
        &expectation(&claims, now, true),
        &mut ledger,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");

    for (schema, paseto) in [
        ("v1", genuine.paseto.clone()),
        (
            "v1alpha1",
            genuine.paseto.replacen("v4.public.", "v4.local.", 1),
        ),
        ("v1alpha1", format!("{} ", genuine.paseto)),
    ] {
        let envelope = SignedLaunchGrant {
            schema_version: schema.into(),
            issuer: genuine.issuer.clone(),
            key_id: genuine.key_id.clone(),
            paseto,
        };
        let error = verify_launch_grant(
            &envelope,
            &key,
            &expectation(&claims, now, true),
            &mut ledger,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");
    }
    assert!(!ledger.is_consumed(&claims.grant_nonce));
}

#[test]
fn environment_and_nonce_digests_refuse_malformed_inputs() {
    assert_eq!(
        workspace_nonce_digest(&[0; 32]).unwrap_err().reason_code(),
        "LAUNCH_GRANT_INVALID"
    );
    for env in [
        vec![("A=B".to_string(), "x".to_string())],
        vec![("A".to_string(), "x\u{0}".to_string())],
        vec![
            ("A".to_string(), "x".to_string()),
            ("A".to_string(), "y".to_string()),
        ],
        vec![(String::new(), "x".to_string())],
    ] {
        assert_eq!(
            environment_digest(&env).unwrap_err().reason_code(),
            "LAUNCH_GRANT_INVALID"
        );
    }
    let unordered = vec![
        ("Z".to_string(), "1".to_string()),
        ("A".to_string(), "2".to_string()),
    ];
    let ordered = vec![
        ("A".to_string(), "2".to_string()),
        ("Z".to_string(), "1".to_string()),
    ];
    assert_eq!(
        environment_digest(&unordered).unwrap(),
        environment_digest(&ordered).unwrap()
    );
}
