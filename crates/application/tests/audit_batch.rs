//! Audit batches refuse every divergence between the record and its leaves,
//! and a chain of batches is continuous end to end or not at all.

use bullet_application::audit_batch::merkle::MerkleError;
use bullet_application::audit_batch::{
    event_leaf, prove_event, verify_batch, verify_chain, verify_chain_from, verify_event_inclusion,
    AuditBatchBuilder, AuditBatchError, AuditSigner, AUDIT_BATCH_ID_PREFIX,
    AUDIT_BATCH_SCHEMA_VERSION, GENESIS_PREVIOUS_ROOT, UNANCHORED_RECEIPT, UNSIGNED_SIGNER,
};
use bullet_application::LedgerEvent;
use bullet_domain::schema_bundle::AuditBatchV1;
use bullet_domain::Digest;

fn event(seq: u64) -> LedgerEvent {
    LedgerEvent {
        seq,
        at: format!("2026-08-26T00:00:{:02}.000Z", seq % 60),
        kind: if seq % 2 == 0 {
            "lease_granted"
        } else {
            "command_reconciled"
        }
        .into(),
        body: format!("{{\"seq\":{seq}}}"),
        event_id: Some(Digest::of(format!("evt:{seq}").as_bytes()).to_hex()),
        stream_id: Some(format!("stream-{}", seq % 3)),
        sequence: Some(seq),
        causation_id: None,
        correlation_id: Some("corr".into()),
        authority_token_hash: (seq % 2 == 0).then(|| Digest::of(b"tok").to_hex()),
    }
}

fn events(range: std::ops::RangeInclusive<u64>) -> Vec<LedgerEvent> {
    range.map(event).collect()
}

fn two_batches() -> (
    Vec<LedgerEvent>,
    Vec<LedgerEvent>,
    AuditBatchV1,
    AuditBatchV1,
) {
    let first = events(1..=5);
    let second = events(6..=8);
    let a = AuditBatchBuilder::genesis().build(&first).unwrap();
    let b = AuditBatchBuilder::after(&a)
        .unwrap()
        .build(&second)
        .unwrap();
    (first, second, a, b)
}

fn code(result: Result<impl std::fmt::Debug, AuditBatchError>) -> &'static str {
    result.expect_err("must refuse").reason_code()
}

#[test]
fn two_batch_continuity_roundtrip() {
    let (first, second, a, b) = two_batches();
    assert_eq!(a.previous_root, GENESIS_PREVIOUS_ROOT);
    assert_eq!(b.previous_root, a.merkle_root);
    assert_ne!(a.merkle_root, b.merkle_root);
    assert_eq!((a.first_sequence, a.last_sequence), (1, 5));
    assert_eq!((b.first_sequence, b.last_sequence), (6, 8));
    for batch in [&a, &b] {
        assert_eq!(batch.schema_version, AUDIT_BATCH_SCHEMA_VERSION);
        assert_eq!(batch.signer, UNSIGNED_SIGNER);
        assert_eq!(batch.external_anchor_receipt, UNANCHORED_RECEIPT);
        let hex = batch
            .audit_batch_id
            .strip_prefix(&format!("{AUDIT_BATCH_ID_PREFIX}_"))
            .expect("contract prefix");
        assert_eq!(Digest::from_hex(hex).unwrap().to_hex(), hex);
        assert_eq!(
            Digest::from_hex(&batch.merkle_root).unwrap().to_hex(),
            batch.merkle_root
        );
    }
    verify_batch(&a, &first).unwrap();
    verify_batch(&b, &second).unwrap();
    let head = verify_chain(&[a.clone(), b.clone()], &[&first, &second]).unwrap();
    assert_eq!(head.batch_count, 2);
    assert_eq!(head.head_root, b.merkle_root);
    assert_eq!(head.last_sequence, 8);
    let fragment = verify_chain_from(&a.merkle_root, std::slice::from_ref(&b), &[&second]).unwrap();
    assert_eq!(fragment.head_root, b.merkle_root);
    let c = AuditBatchBuilder::with_previous_root(&head.head_root)
        .unwrap()
        .build(&events(9..=9))
        .unwrap();
    let three = verify_chain(&[a, b, c], &[&first, &second, &events(9..=9)]).unwrap();
    assert_eq!(three.last_sequence, 9);
}

#[test]
fn builder_is_deterministic_and_identity_binds_previous_root() {
    let first = events(1..=5);
    let again = AuditBatchBuilder::genesis().build(&first).unwrap();
    assert_eq!(again, AuditBatchBuilder::genesis().build(&first).unwrap());
    let other = AuditBatchBuilder::with_previous_root(&Digest::of(b"other").to_hex())
        .unwrap()
        .build(&first)
        .unwrap();
    assert_eq!(other.merkle_root, again.merkle_root);
    assert_ne!(other.audit_batch_id, again.audit_batch_id);
}

#[test]
fn reordered_leaf_is_refused() {
    let (mut first, _, a, _) = two_batches();
    first.swap(1, 2);
    assert_eq!(code(verify_batch(&a, &first)), "AUDIT_LEAF_ORDER");
    assert_eq!(
        AuditBatchBuilder::genesis().build(&first).unwrap_err(),
        AuditBatchError::LeafOrder {
            index: 2,
            previous: 3,
            found: 2
        }
    );
    let mut duplicated = events(1..=3);
    duplicated.push(event(3));
    assert_eq!(
        code(AuditBatchBuilder::genesis().build(&duplicated)),
        "AUDIT_LEAF_ORDER"
    );
}

#[test]
fn truncated_batch_is_refused() {
    let (first, _, a, _) = two_batches();
    assert_eq!(
        verify_batch(&a, &first[..3]).unwrap_err(),
        AuditBatchError::Truncated {
            expected: 5,
            found: 3
        }
    );
    assert_eq!(code(verify_batch(&a, &first[1..])), "AUDIT_RANGE_MISMATCH");
    assert_eq!(
        code(verify_batch(&a, &events(1..=6))),
        "AUDIT_RANGE_MISMATCH"
    );
    let mut shortened = a.clone();
    shortened.last_sequence = 3;
    assert_eq!(
        code(verify_batch(&shortened, &first[..3])),
        "AUDIT_ROOT_MISMATCH"
    );
    assert_eq!(code(verify_batch(&a, &[])), "AUDIT_BATCH_EMPTY");
    assert_eq!(
        code(AuditBatchBuilder::genesis().build(&[])),
        "AUDIT_BATCH_EMPTY"
    );
}

#[test]
fn sequence_gap_is_refused_inside_and_between_batches() {
    let (mut first, second, a, _) = two_batches();
    first.remove(2);
    assert_eq!(
        verify_batch(&a, &first).unwrap_err(),
        AuditBatchError::SequenceGap {
            expected: 3,
            found: 4
        }
    );
    assert_eq!(
        code(AuditBatchBuilder::genesis().build(&first)),
        "AUDIT_SEQUENCE_GAP"
    );
    let (first, _, a, _) = two_batches();
    let skipped = events(7..=8);
    let b = AuditBatchBuilder::after(&a)
        .unwrap()
        .build(&skipped)
        .unwrap();
    assert_eq!(
        verify_chain(&[a.clone(), b], &[&first, &skipped]).unwrap_err(),
        AuditBatchError::SequenceGap {
            expected: 6,
            found: 7
        }
    );
    let overlapping = events(5..=8);
    let b = AuditBatchBuilder::after(&a)
        .unwrap()
        .build(&overlapping)
        .unwrap();
    assert_eq!(
        code(verify_chain(&[a, b], &[&first, &overlapping])),
        "AUDIT_LEAF_ORDER"
    );
    let _ = second;
}

#[test]
fn previous_root_mismatch_is_refused() {
    let (first, second, a, b) = two_batches();
    let foreign = Digest::of(b"foreign-root").to_hex();
    let detached = AuditBatchBuilder::with_previous_root(&foreign)
        .unwrap()
        .build(&second)
        .unwrap();
    verify_batch(&detached, &second).unwrap();
    assert_eq!(
        verify_chain(&[a.clone(), detached.clone()], &[&first, &second]).unwrap_err(),
        AuditBatchError::PreviousRootMismatch {
            index: 1,
            expected: a.merkle_root.clone(),
            found: foreign.clone(),
        }
    );
    assert_eq!(
        code(verify_chain(std::slice::from_ref(&detached), &[&second])),
        "AUDIT_PREVIOUS_ROOT_MISMATCH"
    );
    verify_chain_from(&foreign, &[detached], &[&second]).unwrap();
    let mut relinked = b.clone();
    relinked.previous_root = foreign;
    assert_eq!(
        code(verify_batch(&relinked, &second)),
        "AUDIT_BATCH_ID_MISMATCH"
    );
    assert_eq!(
        code(verify_chain(&[b.clone(), a.clone()], &[&second, &first])),
        "AUDIT_PREVIOUS_ROOT_MISMATCH"
    );
}

#[test]
fn tampered_leaf_is_refused() {
    let (first, _, a, _) = two_batches();
    let tamper: [fn(&mut LedgerEvent); 6] = [
        |e| e.body.push(' '),
        |e| e.at = "2026-08-26T00:00:59.000Z".into(),
        |e| e.kind = "lease_released".into(),
        |e| e.authority_token_hash = None,
        |e| e.correlation_id = None,
        |e| e.stream_id = Some("stream-9".into()),
    ];
    for (index, mutate) in tamper.iter().enumerate() {
        let mut leaves = first.clone();
        let slot = index % first.len();
        mutate(&mut leaves[slot]);
        assert_ne!(event_leaf(&leaves[slot]), event_leaf(&first[slot]));
        assert_eq!(
            code(verify_batch(&a, &leaves)),
            "AUDIT_ROOT_MISMATCH",
            "{index}"
        );
    }
    let mut record = a.clone();
    record.merkle_root = Digest::of(b"forged").to_hex();
    assert_eq!(code(verify_batch(&record, &first)), "AUDIT_ROOT_MISMATCH");
}

#[test]
fn tampered_record_fields_are_refused_with_stable_codes() {
    let (first, _, a, _) = two_batches();
    type Tamper = (fn(&mut AuditBatchV1), &'static str);
    let cases: [Tamper; 8] = [
        (
            |b| b.schema_version = "v1alpha2".into(),
            "AUDIT_SCHEMA_VERSION",
        ),
        (
            |b| b.signer = "audit-key-1".into(),
            "AUDIT_SIGNER_UNSUPPORTED",
        ),
        (|b| b.signer = String::new(), "AUDIT_SIGNER_UNSUPPORTED"),
        (
            |b| b.external_anchor_receipt = "receipt".into(),
            "AUDIT_ANCHOR_UNSUPPORTED",
        ),
        (|b| b.previous_root = "A".repeat(64), "AUDIT_ROOT_MALFORMED"),
        (|b| b.merkle_root.truncate(63), "AUDIT_ROOT_MALFORMED"),
        (|b| b.first_sequence = 6, "AUDIT_RANGE_INVALID"),
        (
            |b| b.audit_batch_id = format!("audit-batch_{}", "0".repeat(64)),
            "AUDIT_BATCH_ID_MISMATCH",
        ),
    ];
    for (mutate, expected) in cases {
        let mut record = a.clone();
        mutate(&mut record);
        assert_eq!(code(verify_batch(&record, &first)), expected);
    }
    assert_eq!(code(verify_chain(&[], &[])), "AUDIT_BATCH_EMPTY");
    assert_eq!(
        code(verify_chain(std::slice::from_ref(&a), &[])),
        "AUDIT_CHAIN_SHAPE"
    );
    assert_eq!(
        code(verify_chain_from("nope", &[a], &[&first])),
        "AUDIT_ROOT_MALFORMED"
    );
}

#[test]
fn event_inclusion_proof_roundtrip_and_forgery() {
    let (first, second, a, b) = two_batches();
    for seq in 6..=8 {
        let proof = prove_event(&b, &second, seq).unwrap();
        assert_eq!((proof.leaf_index, proof.leaf_count), (seq - 6, 3));
        verify_event_inclusion(&b, &event(seq), &proof).unwrap();
        let mut forged = event(seq);
        forged.body.push('!');
        assert_eq!(
            verify_event_inclusion(&b, &forged, &proof).unwrap_err(),
            AuditBatchError::Merkle(MerkleError::RootMismatch)
        );
        assert_eq!(
            code(verify_event_inclusion(&a, &event(seq), &proof)),
            "AUDIT_RANGE_MISMATCH"
        );
    }
    let proof = prove_event(&a, &first, 2).unwrap();
    assert_eq!(
        code(verify_event_inclusion(&a, &event(3), &proof)),
        "AUDIT_RANGE_MISMATCH"
    );
    assert_eq!(code(prove_event(&a, &first, 6)), "AUDIT_RANGE_MISMATCH");
    assert_eq!(
        code(prove_event(&a, &first[..2], 1)),
        "AUDIT_BATCH_TRUNCATED"
    );
    let mut forged = a.clone();
    forged.signer = "someone".into();
    assert_eq!(
        code(verify_event_inclusion(&forged, &event(2), &proof)),
        "AUDIT_SIGNER_UNSUPPORTED"
    );
}

#[test]
fn committed_range_closes_the_duplicate_last_leaf_ambiguity() {
    let three = events(1..=3);
    let a = AuditBatchBuilder::genesis().build(&three).unwrap();
    let mut padded = three.clone();
    padded.push(event(3));
    assert_eq!(code(verify_batch(&a, &padded)), "AUDIT_LEAF_ORDER");
    let mut widened = a.clone();
    widened.last_sequence = 4;
    assert_eq!(code(verify_batch(&widened, &padded)), "AUDIT_LEAF_ORDER");
    assert_eq!(
        code(verify_batch(&widened, &events(1..=4))),
        "AUDIT_ROOT_MISMATCH"
    );
}

#[test]
fn genesis_root_is_thirty_two_zero_bytes() {
    assert_eq!(GENESIS_PREVIOUS_ROOT.len(), 64);
    let digest = Digest::from_hex(GENESIS_PREVIOUS_ROOT).unwrap();
    assert_eq!(digest.as_bytes(), &[0u8; 32]);
    assert_eq!(
        AuditBatchBuilder::with_previous_root(GENESIS_PREVIOUS_ROOT).unwrap(),
        AuditBatchBuilder::genesis()
    );
}

#[test]
fn signer_slot_is_typed_and_uninhabited() {
    assert_eq!(std::mem::size_of::<Option<AuditSigner>>(), 0);
    assert_eq!(AuditBatchBuilder::genesis().signer, None);
}

#[test]
fn event_leaf_covers_every_column_and_absent_never_equals_empty() {
    let base = LedgerEvent {
        seq: 1,
        at: "2026-01-01T00:00:00.000Z".into(),
        kind: "k".into(),
        body: "{}".into(),
        event_id: None,
        stream_id: None,
        sequence: None,
        causation_id: None,
        correlation_id: None,
        authority_token_hash: None,
    };
    let leaf = event_leaf(&base);
    let variants = [
        LedgerEvent {
            event_id: Some(String::new()),
            ..base.clone()
        },
        LedgerEvent {
            stream_id: Some(String::new()),
            ..base.clone()
        },
        LedgerEvent {
            sequence: Some(0),
            ..base.clone()
        },
        LedgerEvent {
            causation_id: Some(String::new()),
            ..base.clone()
        },
        LedgerEvent {
            correlation_id: Some(String::new()),
            ..base.clone()
        },
        LedgerEvent {
            authority_token_hash: Some(String::new()),
            ..base.clone()
        },
        LedgerEvent {
            seq: 2,
            ..base.clone()
        },
        LedgerEvent {
            kind: "k{".into(),
            body: "}".into(),
            ..base.clone()
        },
    ];
    for variant in &variants {
        assert_ne!(event_leaf(variant), leaf, "{variant:?}");
    }
    assert_ne!(event_leaf(&variants[2]), event_leaf(&variants[3]));
}

#[test]
fn malformed_roots_are_refused_before_any_digest_work() {
    for bad in ["", "00", &"0".repeat(63), &"A".repeat(64), &"g".repeat(64)] {
        assert_eq!(
            AuditBatchBuilder::with_previous_root(bad).unwrap_err(),
            AuditBatchError::MalformedRoot("previous_root")
        );
    }
    assert_eq!(
        AuditBatchError::MalformedRoot("previous_root").reason_code(),
        "AUDIT_ROOT_MALFORMED"
    );
}
