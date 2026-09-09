use super::recovery_support::{expire_active_lease, obs, prepare, tx, AT};
use bullet_application::{
    EffectRecoveryContainmentReason, EffectRecoveryDisposition as D, EffectRecoveryStore, Ledger,
    ReceiptVerdict,
};
use rusqlite::{params, Connection};

#[derive(Clone, Copy, Debug)]
enum AuthorityDrift {
    Lease,
    Authority,
    Freeze,
    Restore,
}

#[test]
fn terminal_replay_requires_current_lease_and_every_authority_epoch() {
    for drift in [
        AuthorityDrift::Lease,
        AuthorityDrift::Authority,
        AuthorityDrift::Freeze,
        AuthorityDrift::Restore,
    ] {
        let mut env = prepare(&format!("terminal-replay-{drift:?}"));
        let claim = env
            .ledger
            .claim_effect_recovery(&env.intent.id, &env.authority)
            .expect("claim")
            .expect("row");
        let request = tx(
            &claim,
            &env.authority,
            D::Adopted,
            Some(obs(&claim.intent, ReceiptVerdict::Match)),
            None,
        );
        env.ledger
            .apply_effect_recovery(&request, &env.authority)
            .expect("apply");
        let receipt_before = env
            .ledger
            .effect_receipts(&env.intent.id)
            .expect("receipt before drift");
        assert_eq!(receipt_before.len(), 1);

        move_authority(&env.path, drift);
        let error = env
            .ledger
            .apply_effect_recovery(&request, &env.authority)
            .expect_err("stale terminal replay");
        assert_eq!(error.reason_code(), "EFFECT_RECOVERY_AUTHORITY_STALE");
        assert_eq!(
            env.ledger
                .effect_receipts(&env.intent.id)
                .expect("receipt after drift"),
            receipt_before,
            "first receipt and its database timestamp changed for {drift:?}"
        );
    }
}

#[test]
fn terminal_replay_requires_the_exact_retained_from_disposition() {
    let mut adopted = prepare("terminal-replay-adopted-from");
    let claim = adopted
        .ledger
        .claim_effect_recovery(&adopted.intent.id, &adopted.authority)
        .expect("claim")
        .expect("row");
    let request = tx(
        &claim,
        &adopted.authority,
        D::Adopted,
        Some(obs(&claim.intent, ReceiptVerdict::Match)),
        None,
    );
    adopted
        .ledger
        .apply_effect_recovery(&request, &adopted.authority)
        .expect("apply");
    let mut substituted = request.clone();
    substituted.from = D::ReadbackUnknown;
    let error = adopted
        .ledger
        .apply_effect_recovery(&substituted, &adopted.authority)
        .expect_err("substituted adopted replay");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_SUBJECT_MISMATCH");

    let mut quarantined = prepare("terminal-replay-quarantine-from");
    let claim = quarantined
        .ledger
        .claim_effect_recovery(&quarantined.intent.id, &quarantined.authority)
        .expect("claim")
        .expect("row");
    let unknown = quarantined
        .ledger
        .apply_effect_recovery(
            &tx(
                &claim,
                &quarantined.authority,
                D::ReadbackUnknown,
                None,
                None,
            ),
            &quarantined.authority,
        )
        .expect("unknown");
    let request = tx(
        &unknown,
        &quarantined.authority,
        D::Quarantined,
        None,
        Some(EffectRecoveryContainmentReason::ReadbackUnavailable),
    );
    quarantined
        .ledger
        .apply_effect_recovery(&request, &quarantined.authority)
        .expect("quarantine");
    let mut substituted = request;
    substituted.from = D::Claimed;
    let error = quarantined
        .ledger
        .apply_effect_recovery(&substituted, &quarantined.authority)
        .expect_err("substituted containment replay");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_SUBJECT_MISMATCH");
}

fn move_authority(path: &std::path::Path, drift: AuthorityDrift) {
    if matches!(drift, AuthorityDrift::Lease) {
        expire_active_lease(path);
        return;
    }
    let conn = Connection::open(path).expect("raw");
    match drift {
        AuthorityDrift::Lease => unreachable!("lease handled above"),
        AuthorityDrift::Authority => {
            conn.execute(
                "UPDATE authority_revisions SET authority_epoch=authority_epoch+1 WHERE singleton=1",
                [],
            )
            .expect("move authority");
        }
        AuthorityDrift::Freeze => {
            conn.execute(
                "UPDATE authority_revisions SET freeze_generation=freeze_generation+1 WHERE singleton=1",
                [],
            )
            .expect("move freeze");
        }
        AuthorityDrift::Restore => {
            conn.execute(
                "UPDATE restore_state
                 SET restore_epoch=1,source_snapshot_digest=?1,restored_at=?2
                 WHERE singleton=1",
                params!["d".repeat(64), AT],
            )
            .expect("move restore");
        }
    }
}
