use bullet_harness_core::{
    authenticate_candidate_preparation_grant, candidate_preparation_scope_paths_digest,
    decode_signed_candidate_preparation_grant, verify_candidate_preparation_grant,
    CandidatePreparationExpectation, CandidatePreparationGrantV1, CandidatePreparationSigningKey,
    HarnessError, MemoryCandidatePreparationNonceLedger, SignedCandidatePreparationGrantV1,
};
use pasetors::keys::AsymmetricSecretKey;
use pasetors::version4::{PublicToken, V4};

const SECRET_KEY: [u8; 64] = [
    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125, 159,
    133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116, 30, 185, 219, 187, 188, 4, 124, 3, 253, 112,
    96, 78, 0, 113, 240, 152, 126, 22, 178, 139, 117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177,
    162,
];

fn id(prefix: &str, byte: char) -> String {
    format!("{prefix}_{}", byte.to_string().repeat(64))
}

fn claims() -> CandidatePreparationGrantV1 {
    CandidatePreparationGrantV1 {
        schema_version: "v1alpha1".to_owned(),
        candidate_preparation_grant_id: id("cpg", '1'),
        issuer: "bullet-kernel".to_owned(),
        key_id: "candidate-test-1".to_owned(),
        signing_purpose: "candidate-preparation-grant-signing".to_owned(),
        claims_domain: "candidate-preparation.grant.v1alpha1".to_owned(),
        envelope_domain: "candidate-preparation.envelope.v1alpha1".to_owned(),
        request_digest: "2".repeat(64),
        authority_token_digest: "3".repeat(64),
        grant_nonce: "4".repeat(64),
        repository_id: id("rep", '5'),
        mission_id: id("mis", '6'),
        plan_revision_id: id("pln", '7'),
        work_package_id: id("wpk", '8'),
        variant_id: id("var", '9'),
        attempt_id: id("atm", 'a'),
        attempt_fence: 3,
        runner_id: id("run", 'b'),
        runner_epoch: 4,
        workspace_id: id("wsp", 'c'),
        scope_grant_digest: "d".repeat(64),
        scope_revision: 2,
        context_revision: 1,
        change_id: id("chg", 'e'),
        graph_revision_id: id("grf", 'f'),
        parent_candidate_ids: vec![id("can", '1'), id("can", '2')],
        context_capsule_id: id("cnt", '3'),
        execution_envelope_id: id("exe", '4'),
        environment_digest: "5".repeat(64),
        toolchain_digest: "6".repeat(64),
        authority_epoch: 2,
        freeze_generation: 1,
        issued_at_unix_ms: 100,
        not_before_unix_ms: 110,
        expires_at_unix_ms: 200,
    }
}

fn signer() -> CandidatePreparationSigningKey {
    CandidatePreparationSigningKey::from_bytes("bullet-kernel", "candidate-test-1", &SECRET_KEY)
        .unwrap()
}

fn ledger(claims: &CandidatePreparationGrantV1) -> MemoryCandidatePreparationNonceLedger {
    let mut ledger = MemoryCandidatePreparationNonceLedger::new();
    assert!(ledger.register(
        &claims.grant_nonce,
        &claims.attempt_id,
        claims.expires_at_unix_ms,
    ));
    ledger
}

fn raw_signed(
    payload: &[u8],
    purpose: &str,
    assertion: &[u8],
) -> SignedCandidatePreparationGrantV1 {
    let footer = serde_jcs::to_vec(&serde_json::json!({
        "schema_version": "v1alpha1",
        "issuer": "bullet-kernel",
        "key_id": "candidate-test-1",
        "purpose": purpose,
    }))
    .unwrap();
    let secret = AsymmetricSecretKey::<V4>::from(&SECRET_KEY).unwrap();
    let paseto = PublicToken::sign(&secret, payload, Some(&footer), Some(assertion)).unwrap();
    SignedCandidatePreparationGrantV1 {
        schema_version: "v1alpha1".to_owned(),
        issuer: "bullet-kernel".to_owned(),
        key_id: "candidate-test-1".to_owned(),
        paseto,
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, HarnessError>) -> &'static str {
    result.unwrap_err().reason_code()
}

#[test]
fn exact_grant_authenticates_and_replay_refuses() {
    let scope = vec!["src".to_owned(), "docs".to_owned()];
    let scope_digest = candidate_preparation_scope_paths_digest(&scope).unwrap();
    assert_eq!(scope_digest.len(), 64);
    assert_ne!(
        scope_digest,
        candidate_preparation_scope_paths_digest(&["docs".into(), "src".into()]).unwrap()
    );
    let claims = claims();
    let signed = signer().sign(&claims).unwrap();
    assert_eq!(
        authenticate_candidate_preparation_grant(&signed, &signer().verification_key().unwrap())
            .unwrap(),
        claims
    );
    let encoded = serde_jcs::to_vec(&signed).unwrap();
    assert_eq!(
        decode_signed_candidate_preparation_grant(&encoded).unwrap(),
        signed
    );
    let expectation = CandidatePreparationExpectation {
        now_unix_ms: 150,
        expected_grant: claims.clone(),
    };
    let mut nonce_ledger = ledger(&claims);
    let verified = verify_candidate_preparation_grant(
        &signed,
        &signer().verification_key().unwrap(),
        &expectation,
        &mut nonce_ledger,
    )
    .unwrap();
    assert_eq!(verified.claims(), &claims);
    assert_eq!(verified.envelope_digest().len(), 64);
    assert_eq!(
        code(verify_candidate_preparation_grant(
            &signed,
            &signer().verification_key().unwrap(),
            &expectation,
            &mut nonce_ledger,
        )),
        "CANDIDATE_PREPARATION_REPLAYED"
    );
}

#[test]
fn time_subject_key_signature_and_nonce_fail_closed() {
    let claims = claims();
    let signed = signer().sign(&claims).unwrap();
    for (now, expected) in [
        (109, "CANDIDATE_PREPARATION_NOT_YET_VALID"),
        (200, "CANDIDATE_PREPARATION_EXPIRED"),
    ] {
        let mut nonce_ledger = ledger(&claims);
        assert_eq!(
            code(verify_candidate_preparation_grant(
                &signed,
                &signer().verification_key().unwrap(),
                &CandidatePreparationExpectation {
                    now_unix_ms: now,
                    expected_grant: claims.clone(),
                },
                &mut nonce_ledger,
            )),
            expected
        );
        assert!(!nonce_ledger.is_consumed(&claims.grant_nonce));
    }

    let mut changed = claims.clone();
    changed.scope_revision += 1;
    let mut nonce_ledger = ledger(&claims);
    assert_eq!(
        code(verify_candidate_preparation_grant(
            &signed,
            &signer().verification_key().unwrap(),
            &CandidatePreparationExpectation {
                now_unix_ms: 150,
                expected_grant: changed,
            },
            &mut nonce_ledger,
        )),
        "CANDIDATE_PREPARATION_SUBJECT_MISMATCH"
    );
    assert!(!nonce_ledger.is_consumed(&claims.grant_nonce));

    let other =
        CandidatePreparationSigningKey::generate("other-kernel", "candidate-test-2").unwrap();
    assert_eq!(
        code(verify_candidate_preparation_grant(
            &signed,
            &other.verification_key().unwrap(),
            &CandidatePreparationExpectation {
                now_unix_ms: 150,
                expected_grant: claims.clone(),
            },
            &mut ledger(&claims),
        )),
        "CANDIDATE_PREPARATION_KEY_UNKNOWN"
    );

    let mut tampered = signed;
    let replacement = if tampered.paseto.ends_with('A') {
        'B'
    } else {
        'A'
    };
    tampered.paseto.pop();
    tampered.paseto.push(replacement);
    assert_eq!(
        code(verify_candidate_preparation_grant(
            &tampered,
            &signer().verification_key().unwrap(),
            &CandidatePreparationExpectation {
                now_unix_ms: 150,
                expected_grant: claims.clone(),
            },
            &mut ledger(&claims),
        )),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );

    assert_eq!(
        code(verify_candidate_preparation_grant(
            &signer().sign(&claims).unwrap(),
            &signer().verification_key().unwrap(),
            &CandidatePreparationExpectation {
                now_unix_ms: 150,
                expected_grant: claims,
            },
            &mut MemoryCandidatePreparationNonceLedger::new(),
        )),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );
}

#[test]
fn recursive_unknowns_and_shape_substitution_refuse() {
    let expected_claims = claims();
    let mut claims_value = serde_json::to_value(&expected_claims).unwrap();
    claims_value["unknown_nested_authority"] = serde_json::json!({"value": true});
    let canonical = serde_jcs::to_vec(&claims_value).unwrap();
    assert!(serde_json::from_slice::<CandidatePreparationGrantV1>(&canonical).is_err());
    for signed in [
        raw_signed(
            &canonical,
            "candidate-preparation-grant-signing",
            b"bullet-farm.candidate-preparation-grant.v1alpha1",
        ),
        raw_signed(
            &serde_jcs::to_vec(&expected_claims).unwrap(),
            "wrong-signing-purpose",
            b"bullet-farm.candidate-preparation-grant.v1alpha1",
        ),
        raw_signed(
            &serde_jcs::to_vec(&expected_claims).unwrap(),
            "candidate-preparation-grant-signing",
            b"bullet-farm.wrong-implicit-assertion.v1alpha1",
        ),
    ] {
        let mut nonces = ledger(&expected_claims);
        assert_eq!(
            code(verify_candidate_preparation_grant(
                &signed,
                &signer().verification_key().unwrap(),
                &CandidatePreparationExpectation {
                    now_unix_ms: 150,
                    expected_grant: expected_claims.clone(),
                },
                &mut nonces,
            )),
            "CANDIDATE_PREPARATION_GRANT_INVALID"
        );
        assert!(!nonces.is_consumed(&expected_claims.grant_nonce));
    }

    let mut carrier = serde_json::to_value(signer().sign(&expected_claims).unwrap()).unwrap();
    carrier["unknown"] = serde_json::json!(true);
    assert_eq!(
        code(decode_signed_candidate_preparation_grant(
            &serde_jcs::to_vec(&carrier).unwrap(),
        )),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );

    let mut wrong_domain = claims();
    wrong_domain.claims_domain = "candidate-preparation.other.v1alpha1".to_owned();
    assert_eq!(
        code(signer().sign(&wrong_domain)),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );
    let mut duplicate = claims();
    duplicate
        .parent_candidate_ids
        .push(duplicate.parent_candidate_ids[0].clone());
    assert_eq!(
        code(signer().sign(&duplicate)),
        "CANDIDATE_PREPARATION_GRANT_INVALID"
    );
}
