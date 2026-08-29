//! Probe-grant issuer/verifier: round trip, cross-purpose isolation against
//! launch grants in both directions, every refusal, and a mutation matrix
//! over every claim field. No provider process is spawned.

use bullet_harness_core::launch_grant::{
    canonical_json, decode_canonical, hash_framed_bytes, mint_probe_grant, probe_grant_footer,
    verify_launch_grant, verify_probe_grant, LaunchGrantClaims, LaunchGrantExpectation,
    LaunchGrantSigningKey, LaunchGrantVerificationKey, LeaseBinding, MemoryNonceLedger,
    PolicyBinding, ProbeExpectation, ProbeGrantClaims, ProbeGrantError, ProbePurpose,
    ProviderBinding, SignedProbeGrant, LAUNCH_GRANT_IMPLICIT_ASSERTION, MAX_PROBE_GRANT_TTL_MS,
    MAX_SAFE_INTEGER, PROBE_GRANT_CLAIMS_DOMAIN, PROBE_GRANT_IMPLICIT_ASSERTION,
    PROBE_GRANT_NONCE_SCOPE, PROBE_GRANT_SCHEMA,
};
use bullet_harness_core::live::{ContainmentClass, ProbeGrantEvidence};
use bullet_harness_core::ProviderProtocol;
use pasetors::keys::AsymmetricSecretKey;
use pasetors::version4::{PublicToken, V4};
use std::collections::BTreeSet;

/// Fixture-only key material shared with the launch-grant golden generator.
const SECRET_KEY: [u8; 64] = [
    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125, 159,
    133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116, 30, 185, 219, 187, 188, 4, 124, 3, 253, 112,
    96, 78, 0, 113, 240, 152, 126, 22, 178, 139, 117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177,
    162,
];
const GOLDEN: &str = include_str!("fixtures/launch-grant-golden.json");
const ISSUER: &str = "bullet-kernel-local";
const KEY_ID: &str = "authority-test-1";
const OTHER_KEY_ID: &str = "authority-test-2";
const NOW: u64 = 1_700_000_000_000;
const GENERATION: u64 = 7;
const EXE: &str = "executable_blake3";
const ISSUED: &str = "issued_at_unix_ms";
const EXPIRES: &str = "expires_at_unix_ms";
const BIG: u64 = MAX_SAFE_INTEGER + 1;

type Refusal = (&'static str, Option<&'static str>);
type Outcome = Result<ProbeGrantEvidence, ProbeGrantError>;
const MALFORMED: &str = "PROBE_GRANT_MALFORMED";
const MISMATCH: &str = "PROBE_GRANT_SUBJECT_MISMATCH";
const SIGNATURE: Refusal = ("PROBE_GRANT_SIGNATURE_INVALID", Some("paseto"));
const EXPIRED: Refusal = ("PROBE_GRANT_EXPIRED", Some(EXPIRES));
const NOT_YET: Refusal = ("PROBE_GRANT_NOT_YET_VALID", Some(ISSUED));
const TTL: Refusal = ("PROBE_GRANT_TTL_EXCEEDED", Some(EXPIRES));
const REPLAYED: Refusal = ("PROBE_GRANT_REPLAYED", Some("nonce"));
const NONCE_UNKNOWN: Refusal = ("PROBE_GRANT_NONCE_UNKNOWN", Some("nonce"));
const KEY_UNKNOWN: Refusal = ("PROBE_GRANT_KEY_UNKNOWN", Some("key_id"));

fn malformed(field: &'static str) -> Refusal {
    (MALFORMED, Some(field))
}

fn claims() -> ProbeGrantClaims {
    ProbeGrantClaims {
        schema: PROBE_GRANT_SCHEMA.to_string(),
        purpose: ProbePurpose::Probe,
        issuer: ISSUER.to_string(),
        key_id: KEY_ID.to_string(),
        provider: "claude".to_string(),
        executable_blake3: "a".repeat(64),
        containment: ContainmentClass::EgressDenied,
        nonce: "1".repeat(64),
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + MAX_PROBE_GRANT_TTL_MS,
    }
}

/// Fixture claims with one string field replaced.
fn with(field: &str, value: &str) -> ProbeGrantClaims {
    let mut mutant = claims();
    let slot = match field {
        "schema" => &mut mutant.schema,
        "issuer" => &mut mutant.issuer,
        "key_id" => &mut mutant.key_id,
        "provider" => &mut mutant.provider,
        EXE => &mut mutant.executable_blake3,
        "nonce" => &mut mutant.nonce,
        other => panic!("no string field {other}"),
    };
    *slot = value.to_string();
    mutant
}

/// Fixture claims with the window replaced.
fn window(issued_at: u64, expires_at: u64) -> ProbeGrantClaims {
    let mut mutant = claims();
    mutant.issued_at_unix_ms = issued_at;
    mutant.expires_at_unix_ms = expires_at;
    mutant
}

fn signer() -> LaunchGrantSigningKey {
    LaunchGrantSigningKey::from_bytes(ISSUER, KEY_ID, &SECRET_KEY).unwrap()
}

fn keys() -> Vec<LaunchGrantVerificationKey> {
    vec![signer().verification_key().unwrap()]
}

fn policy(live: bool) -> PolicyBinding {
    PolicyBinding {
        policy_snapshot_digest: "c".repeat(64),
        policy_generation: GENERATION,
        live_admission_enabled: live,
    }
}

fn expected() -> ProbeExpectation {
    let base = claims();
    ProbeExpectation {
        provider: base.provider,
        executable_blake3: base.executable_blake3,
        containment: base.containment,
    }
}

fn ledger_for(claims: &ProbeGrantClaims) -> MemoryNonceLedger {
    let mut ledger = MemoryNonceLedger::new();
    let expires = claims.expires_at_unix_ms;
    assert!(ledger.register(&claims.nonce, PROBE_GRANT_NONCE_SCOPE, expires));
    ledger
}

fn mint(claims: &ProbeGrantClaims) -> SignedProbeGrant {
    mint_probe_grant(&signer(), claims).unwrap()
}

/// Sign arbitrary payload bytes with the fixture key, bypassing `mint`'s
/// shape checks so verify-side refusals can be exercised on their own.
fn raw_sign(payload: &[u8], footer: &[u8], implicit: &[u8]) -> SignedProbeGrant {
    let secret = AsymmetricSecretKey::<V4>::from(&SECRET_KEY).unwrap();
    let mut token = mint(&claims());
    token.paseto = PublicToken::sign(&secret, payload, Some(footer), Some(implicit)).unwrap();
    token
}

fn raw_claims(claims: &ProbeGrantClaims) -> SignedProbeGrant {
    let footer = probe_grant_footer(ISSUER, KEY_ID).unwrap();
    let payload = canonical_json(claims).unwrap();
    raw_sign(&payload, &footer, PROBE_GRANT_IMPLICIT_ASSERTION)
}

/// Verify against the fixture expectation with the fixture key at `now`.
fn verify(token: &SignedProbeGrant, ledger: &mut MemoryNonceLedger, now: u64) -> Outcome {
    verify_probe_grant(token, &policy(true), &keys(), ledger, now, &expected())
}

fn refusal(result: Outcome) -> Refusal {
    let error = result.unwrap_err();
    (error.reason_code(), error.field())
}

/// Refuse `token` at `now` against the untouched fixture; the fixture nonce
/// must remain unspent afterwards.
fn refused(token: &SignedProbeGrant, now: u64) -> Refusal {
    let base = claims();
    let mut ledger = ledger_for(&base);
    let outcome = refusal(verify(token, &mut ledger, now));
    assert!(!ledger.is_consumed(&base.nonce), "refusal spent the nonce");
    outcome
}

/// Refuse `token` at `NOW` with explicit keys and expectation; the fixture
/// nonce must remain unspent afterwards.
fn refuse_with(
    token: &SignedProbeGrant,
    keys: &[LaunchGrantVerificationKey],
    expectation: &ProbeExpectation,
) -> Refusal {
    let base = claims();
    let mut ledger = ledger_for(&base);
    let result = verify_probe_grant(token, &policy(true), keys, &mut ledger, NOW, expectation);
    assert!(!ledger.is_consumed(&base.nonce), "refusal spent the nonce");
    refusal(result)
}

fn golden_launch_claims() -> LaunchGrantClaims {
    let golden: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    decode_canonical(golden["claims_canonical_json"].as_str().unwrap().as_bytes()).unwrap()
}

fn launch_expectation(claims: &LaunchGrantClaims) -> LaunchGrantExpectation {
    LaunchGrantExpectation {
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
    }
}

fn flip_char(token: &SignedProbeGrant, index: usize) -> SignedProbeGrant {
    let mut bytes = token.paseto.clone().into_bytes();
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    let mut flipped = token.clone();
    flipped.paseto = String::from_utf8(bytes).unwrap();
    flipped
}

#[test]
fn round_trip_binds_evidence_to_the_canonical_claims_and_spends_the_nonce_once() {
    let base = claims();
    let token = mint(&base);
    assert_eq!(token.schema, PROBE_GRANT_SCHEMA);
    assert!(token.paseto.starts_with("v4.public."));
    let bytes = canonical_json(&base).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.starts_with(r#"{"containment":"egress_denied","executable_blake3":"#));
    assert!(text.contains(r#""purpose":"probe""#));
    assert!(text.contains(r#""schema":"bullet.probe-grant.v1""#));
    assert_eq!(decode_canonical::<ProbeGrantClaims>(&bytes).unwrap(), base);

    let mut ledger = ledger_for(&base);
    let evidence = verify(&token, &mut ledger, NOW).unwrap();
    let digest = hash_framed_bytes(PROBE_GRANT_CLAIMS_DOMAIN, &bytes).unwrap();
    assert_eq!(evidence.grant_blake3, digest);
    assert_eq!(evidence.grant_blake3, base.digest().unwrap());
    assert_eq!(evidence.grant_blake3.len(), 64);
    assert_eq!(evidence.provider, "claude");
    assert_eq!(evidence.executable_blake3, base.executable_blake3);
    assert_eq!(evidence.containment, ContainmentClass::EgressDenied);
    assert_eq!(evidence.expires_at_unix_ms, NOW + MAX_PROBE_GRANT_TTL_MS);
    assert!(ledger.is_consumed(&base.nonce));
    assert_eq!(refusal(verify(&token, &mut ledger, NOW)), REPLAYED);

    let last = NOW + MAX_PROBE_GRANT_TTL_MS - 1;
    assert!(verify(&token, &mut ledger_for(&base), last).is_ok());
    assert_eq!(refused(&token, NOW + MAX_PROBE_GRANT_TTL_MS), EXPIRED);
    assert_eq!(refused(&token, u64::MAX), EXPIRED);
    assert_eq!(refused(&token, NOW - 1), NOT_YET);
}

#[test]
fn probe_and_launch_grants_never_satisfy_each_other() {
    let base = claims();
    let launch = golden_launch_claims();
    let launch_token = signer().sign(&launch).unwrap();

    // A launch grant presented as a probe grant: typed purpose refusal, and
    // neither the probe nonce nor the launch nonce is spent.
    let mut as_probe = mint(&base);
    as_probe.paseto = launch_token.paseto.clone();
    let mut ledger = ledger_for(&base);
    let launch_expires = launch.expires_at_unix_ms;
    assert!(ledger.register(&launch.grant_nonce, &launch.attempt_id, launch_expires));
    let error = verify(&as_probe, &mut ledger, NOW).unwrap_err();
    assert_eq!(error.reason_code(), "PROBE_GRANT_PURPOSE_MISMATCH");
    assert_eq!(error.field(), Some("purpose"));
    match error {
        ProbeGrantError::PurposeMismatch { found } => assert_eq!(found, "launch-grant-signing"),
        other => panic!("unexpected {other:?}"),
    }
    assert!(!ledger.is_consumed(&base.nonce));
    assert!(!ledger.is_consumed(&launch.grant_nonce));

    // A probe grant presented as a launch grant is refused before the
    // expectation is even consulted, with no nonce spent under any scope.
    let probe = mint(&base);
    let mut as_launch = launch_token;
    as_launch.paseto = probe.paseto.clone();
    let mut scoped = MemoryNonceLedger::new();
    assert!(scoped.register(&base.nonce, &launch.attempt_id, base.expires_at_unix_ms));
    let key = &keys()[0];
    let exp = launch_expectation(&launch);
    let error = verify_launch_grant(&as_launch, key, &exp, &mut scoped).unwrap_err();
    assert_eq!(error.reason_code(), "LAUNCH_GRANT_INVALID");
    assert!(!scoped.is_consumed(&base.nonce));

    // A probe nonce registered only under an Attempt scope is unknown to the
    // probe verifier: ledger scopes do not bleed.
    assert_eq!(refusal(verify(&probe, &mut scoped, NOW)), NONCE_UNKNOWN);
    assert!(!scoped.is_consumed(&base.nonce));

    // The purpose set is closed: the wire form admits exactly `probe`.
    assert!(decode_canonical::<ProbePurpose>(br#""probe""#).is_ok());
    for foreign in [&br#""launch""#[..], br#""Probe""#, br#""""#, b"1", b"null"] {
        assert!(decode_canonical::<ProbePurpose>(foreign).is_err());
    }
    let text = String::from_utf8(canonical_json(&base).unwrap()).unwrap();
    let payload = text.replace(r#""purpose":"probe""#, r#""purpose":"launch""#);
    assert_ne!(payload, text);
    let footer = probe_grant_footer(ISSUER, KEY_ID).unwrap();
    let forged = raw_sign(payload.as_bytes(), &footer, PROBE_GRANT_IMPLICIT_ASSERTION);
    let error = verify(&forged, &mut ledger_for(&base), NOW).unwrap_err();
    assert_eq!((error.reason_code(), error.field()), malformed("claims"));
    assert!(error.to_string().contains("purpose must be probe"));

    // Probe footer but the launch family's implicit assertion: not ours.
    let crossed = raw_sign(text.as_bytes(), &footer, LAUNCH_GRANT_IMPLICIT_ASSERTION);
    assert_eq!(refused(&crossed, NOW), SIGNATURE);
}

#[test]
fn ttl_cap_and_claim_shape_are_enforced_at_mint_and_at_verify() {
    let over = window(NOW, NOW + MAX_PROBE_GRANT_TTL_MS + 1);
    match mint_probe_grant(&signer(), &over).unwrap_err() {
        ProbeGrantError::TtlExceeded { ttl_ms } => assert_eq!(ttl_ms, 15_001),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(over.digest().unwrap_err().reason_code(), TTL.0);
    assert!(mint_probe_grant(&signer(), &window(NOW, NOW + MAX_PROBE_GRANT_TTL_MS)).is_ok());
    assert_eq!(refused(&raw_claims(&over), NOW), TTL);

    let bad = [
        ("schema", with("schema", "v1alpha1")),
        ("issuer", with("issuer", "bad issuer")),
        ("key_id", with("key_id", "")),
        ("provider", with("provider", "openai")),
        (EXE, with(EXE, &"A".repeat(64))),
        ("nonce", with("nonce", &"1".repeat(63))),
        (ISSUED, window(0, 1)),
        (ISSUED, window(BIG, BIG + 1)),
        (EXPIRES, window(NOW, NOW)),
        (EXPIRES, window(BIG - 2, BIG)),
        ("issuer", with("issuer", "bullet-kernel-other")),
        ("key_id", with("key_id", OTHER_KEY_ID)),
    ];
    for (field, claims) in &bad {
        let error = mint_probe_grant(&signer(), claims).unwrap_err();
        assert_eq!((error.reason_code(), error.field()), malformed(field));
        assert_eq!(refused(&raw_claims(claims), NOW), malformed(field));
    }
}

#[test]
fn subject_mismatch_names_the_field_and_spends_nothing() {
    let token = mint(&claims());
    let mut provider = expected();
    provider.provider = "codex".to_string();
    let mut exe = expected();
    exe.executable_blake3 = "b".repeat(64);
    let mut absent = expected();
    absent.containment = ContainmentClass::ReadOnlyWorkspaceAbsent;
    for (field, expectation) in [
        ("provider", &provider),
        (EXE, &exe),
        ("containment", &absent),
    ] {
        let outcome = refuse_with(&token, &keys(), expectation);
        assert_eq!(outcome, (MISMATCH, Some(field)));
    }
}

#[test]
fn unknown_key_tampered_signature_and_malformed_envelope_are_refused() {
    let base = claims();
    let token = mint(&base);
    let public_hex = keys()[0].public_key_hex().to_string();
    let relabelled = |issuer, key_id| {
        vec![LaunchGrantVerificationKey::from_hex(issuer, key_id, &public_hex).unwrap()]
    };
    let refuse = |keys: &[LaunchGrantVerificationKey]| refuse_with(&token, keys, &expected());
    assert_eq!(refuse(&[]), KEY_UNKNOWN);
    assert_eq!(refuse(&relabelled(ISSUER, OTHER_KEY_ID)), KEY_UNKNOWN);
    let other_issuer = relabelled("bullet-kernel-other", KEY_ID);
    assert_eq!(refuse(&other_issuer), KEY_UNKNOWN);

    // Same labels, different key material, in both directions.
    let stranger = LaunchGrantSigningKey::generate(ISSUER, KEY_ID).unwrap();
    assert_eq!(refuse(&[stranger.verification_key().unwrap()]), SIGNATURE);
    let strangers = mint_probe_grant(&stranger, &base).unwrap();
    assert_eq!(refused(&strangers, NOW), SIGNATURE);

    // Bit flips in the payload/signature segment and in the footer segment.
    let prefix = "v4.public.".len();
    let footer_start = token.paseto.rfind('.').unwrap() + 1;
    for index in [prefix, prefix + 40, footer_start - 2, footer_start + 3] {
        assert_eq!(refused(&flip_char(&token, index), NOW), SIGNATURE);
    }
    let payload = canonical_json(&base).unwrap();
    let other_footer = probe_grant_footer(ISSUER, OTHER_KEY_ID).unwrap();
    let wrong_footer = raw_sign(&payload, &other_footer, PROBE_GRANT_IMPLICIT_ASSERTION);
    assert_eq!(refused(&wrong_footer, NOW), SIGNATURE);
    let no_footer = raw_sign(&payload, b"", PROBE_GRANT_IMPLICIT_ASSERTION);
    assert_eq!(refused(&no_footer, NOW), SIGNATURE);

    // Envelope shape.
    let envelope = |field: &str, value: String| {
        let mut bad = token.clone();
        match field {
            "schema" => bad.schema = value,
            "issuer" => bad.issuer = value,
            "key_id" => bad.key_id = value,
            _ => bad.paseto = value,
        }
        refused(&bad, NOW)
    };
    assert_eq!(envelope("schema", "v1alpha1".into()), malformed("schema"));
    assert_eq!(envelope("issuer", "bad issuer".into()), malformed("issuer"));
    assert_eq!(envelope("key_id", "x".repeat(129)), malformed("key_id"));
    let pasetos = [
        token.paseto.replacen("public", "local", 1),
        format!("{} ", token.paseto),
        format!("{}{}", token.paseto, "A".repeat(4_096)),
        "v4.public.!!!".to_string(),
        "v4.public.".to_string(),
    ];
    for paseto in pasetos {
        assert_eq!(envelope("paseto", paseto), malformed("paseto"));
    }
}

#[test]
fn disabled_live_admission_replay_and_stale_ledger_records_are_refused() {
    let base = claims();
    let token = mint(&base);
    let mut ledger = ledger_for(&base);
    let disabled = policy(false);
    let error = verify_probe_grant(&token, &disabled, &keys(), &mut ledger, NOW, &expected());
    let error = error.unwrap_err();
    assert_eq!(error.reason_code(), "POLICY_LIVE_ADMISSION_DISABLED");
    assert_eq!(error.field(), Some("sandbox_policy.live_admission_enabled"));
    match error {
        ProbeGrantError::LiveAdmissionDisabled { generation, .. } => {
            assert_eq!(generation, GENERATION);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!ledger.is_consumed(&base.nonce));
    // The same ledger still admits once policy allows it: nothing was spent.
    assert!(verify(&token, &mut ledger, NOW).is_ok());
    assert_eq!(refusal(verify(&token, &mut ledger, NOW)), REPLAYED);

    let mut stale = MemoryNonceLedger::new();
    assert!(stale.register(&base.nonce, PROBE_GRANT_NONCE_SCOPE, NOW));
    assert_eq!(refusal(verify(&token, &mut stale, NOW)), EXPIRED);
    let mut empty = MemoryNonceLedger::new();
    assert_eq!(refusal(verify(&token, &mut empty, NOW)), NONCE_UNKNOWN);
    assert!(!empty.is_consumed(&base.nonce));
}

#[test]
fn mutation_matrix_every_claim_flip_is_a_typed_refusal_naming_the_field() {
    let base = claims();
    let now = NOW + 1;
    assert!(verify(&mint(&base), &mut ledger_for(&base), now).is_ok());
    let mut absent = claims();
    absent.containment = ContainmentClass::ReadOnlyWorkspaceAbsent;
    let not_yet = window(now + 1, base.expires_at_unix_ms);
    let flips = [
        ("schema", with("schema", "bullet.probe-grant.v2"), MALFORMED),
        ("issuer", with("issuer", "bullet-kernel-other"), MALFORMED),
        ("key_id", with("key_id", OTHER_KEY_ID), MALFORMED),
        ("provider", with("provider", "codex"), MISMATCH),
        (EXE, with(EXE, &"b".repeat(64)), MISMATCH),
        ("containment", absent, MISMATCH),
        ("nonce", with("nonce", &"2".repeat(64)), NONCE_UNKNOWN.0),
        (ISSUED, not_yet, NOT_YET.0),
        (EXPIRES, window(NOW, now), EXPIRED.0),
    ];
    let mut digests = BTreeSet::new();
    let digest = |claims: &ProbeGrantClaims| {
        hash_framed_bytes(PROBE_GRANT_CLAIMS_DOMAIN, &canonical_json(claims).unwrap()).unwrap()
    };
    digests.insert(digest(&base));
    for (field, mutant, code) in &flips {
        assert_ne!(mutant, &base);
        let mut ledger = ledger_for(&base);
        let outcome = refusal(verify(&raw_claims(mutant), &mut ledger, now));
        assert_eq!(outcome, (*code, Some(*field)));
        assert!(!ledger.is_consumed(&base.nonce), "{field}");
        assert!(digests.insert(digest(mutant)), "{field}");
    }
    // The tenth claim field, `purpose`, is closed at the type level and is
    // covered by the forged-payload case; every other field flipped above.
    assert_eq!(flips.len() + 1, 10);
    assert_eq!(digests.len(), flips.len() + 1);
}
