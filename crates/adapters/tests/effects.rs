//! Effect persistence: shared conformance plus durability across reopen.

use bullet_adapters::SqliteLedger;
use bullet_application::conformance_effects::check_effects;
use bullet_application::{
    receipt_id, EffectIntentRecord, EffectReceiptRecord, EffectState, Ledger, ReceiptVerdict,
    ZERO_OID,
};
use bullet_domain::{AttemptId, EffectId};

fn private_tempdir() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().expect("private tempdir")
}

#[test]
fn sqlite_ledger_passes_effect_conformance() {
    let dir = private_tempdir();
    let mut n = 0u32;
    check_effects(|| {
        n += 1;
        SqliteLedger::open(dir.path().join(format!("eff-{n}.sqlite"))).expect("open")
    })
    .expect("sqlite ledger effect conformance");
}

#[test]
fn effect_rows_survive_reopen_with_state_and_retries() {
    let dir = private_tempdir();
    let path = dir.path().join("durable.sqlite");
    let intent = EffectIntentRecord {
        id: EffectId::from_seed("du-1"),
        logical_effect_key: "push:du-1:refs/heads/bullet/candidate/du".into(),
        provider: "local-bare".into(),
        target_identity: "refs/heads/bullet/candidate/du".into(),
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: AttemptId::from_seed("du-attempt"),
        fence: 2,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: Some("prov-idem-1".into()),
        state: EffectState::Proposed,
        unknown_retries: 0,
        created_at: "2026-08-24T00:00:00Z".into(),
    };
    let receipt = EffectReceiptRecord {
        id: receipt_id("du-1-r1"),
        effect_intent_id: intent.id.clone(),
        observed_remote_identity: intent.target_identity.clone(),
        observed_state_hash: None,
        verification_method: "git-ls-remote-read-back".into(),
        verification_result: ReceiptVerdict::Absent,
        adopted_after_unknown: false,
        recorded_at: "2026-08-24T00:00:05Z".into(),
    };
    {
        let mut ledger = SqliteLedger::open(&path).expect("open");
        let (row, created) = ledger.record_effect_intent(&intent).expect("record");
        assert!(created);
        for to in [
            EffectState::Authorized,
            EffectState::Dispatching,
            EffectState::OutcomeUnknown,
            EffectState::Dispatching,
        ] {
            ledger.transition_effect(&row.id, to).expect("transition");
        }
        assert!(ledger.record_effect_receipt(&receipt).expect("receipt"));
    }
    let raw = rusqlite::Connection::open(&path).expect("raw reopen");
    let persisted_receipt_id: String = raw
        .query_row("SELECT id FROM effect_receipts", [], |row| row.get(0))
        .expect("persisted receipt id");
    assert_eq!(persisted_receipt_id, receipt.id.as_str());
    assert!(persisted_receipt_id.starts_with("efr_"));
    assert_eq!(persisted_receipt_id.len(), 68);
    drop(raw);
    let mut ledger = SqliteLedger::open(&path).expect("reopen");
    let stored = ledger
        .get_effect_intent_by_id(&intent.id)
        .expect("get")
        .expect("row survives reopen");
    assert_eq!(stored.state, EffectState::Dispatching);
    assert_eq!(stored.unknown_retries, 1);
    assert_eq!(
        stored.provider_idempotency_key.as_deref(),
        Some("prov-idem-1")
    );
    assert_eq!(
        stored.payload_hash,
        intent.payload_digest().expect("digest")
    );
    assert_eq!(
        ledger.effect_receipts(&intent.id).expect("receipts"),
        vec![receipt.clone()]
    );
    // Replaying the identical receipt after reopen is still idempotent.
    assert!(!ledger.record_effect_receipt(&receipt).expect("replay"));
    let unresolved = ledger.unresolved_effects().expect("unresolved");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, intent.id);
}
