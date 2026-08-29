use super::recovery_support::{authority, expire_active_lease, obs, prepare, tx};
use bullet_application::{
    EffectRecoveryContainmentReason, EffectRecoveryDisposition as D, EffectRecoveryStore,
    LeaseService, ReceiptVerdict,
};
use rusqlite::{types::Value, Connection};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
enum RetryTerminal {
    Adopted,
    Orphaned,
    RetrySpent,
    ReadbackUnavailable,
}

#[test]
fn exact_closed_terminals_return_no_work_without_durable_growth() {
    for terminal in [D::Adopted, D::Orphaned, D::Quarantined] {
        let mut env = prepare(&format!("terminal-no-work-{terminal:?}"));
        settle(&mut env, terminal);
        let before = durable_snapshot(&env.path);
        assert_eq!(
            env.ledger
                .claim_effect_recovery(&env.intent.id, &env.authority)
                .expect("terminal readback"),
            None
        );
        assert_eq!(durable_snapshot(&env.path), before);
    }
}

#[test]
fn exact_retry_lineage_terminals_return_no_work_without_mutation() {
    for terminal in [
        RetryTerminal::Adopted,
        RetryTerminal::Orphaned,
        RetryTerminal::RetrySpent,
        RetryTerminal::ReadbackUnavailable,
    ] {
        let mut env = prepare(&format!("terminal-retry-no-work-{terminal:?}"));
        settle_after_retry(&mut env, terminal);
        let before = durable_snapshot(&env.path);
        assert_eq!(
            env.ledger
                .claim_effect_recovery(&env.intent.id, &env.authority)
                .expect("terminal retry readback"),
            None
        );
        assert_eq!(durable_snapshot(&env.path), before);
    }
}

#[test]
fn inherited_retry_reserved_successor_terminal_is_exact_no_work() {
    let mut env = prepare("terminal-inherited-retry");
    settle_inherited_retry_adopted(&mut env);
    assert_no_work(&mut env);

    let mut substituted = prepare("terminal-inherited-retry-substitution");
    let sequence = settle_inherited_retry_adopted(&mut substituted);
    assert_no_work(&mut substituted);
    Connection::open(&substituted.path)
        .expect("raw")
        .execute(
            "UPDATE outbox SET delivered_at=?1 WHERE seq=?2",
            [
                Value::Text("2031-01-01T00:00:00.000Z".into()),
                Value::Integer(i64::try_from(sequence).expect("sequence")),
            ],
        )
        .expect("substitute inherited delivery");
    assert_subject_refusal_without_mutation(&mut substituted);
}

#[test]
fn successor_born_readback_unknown_terminal_is_exact_no_work() {
    let mut env = prepare("terminal-successor-readback-unknown");
    settle_successor_readback_unknown_adopted(&mut env);
    assert_no_work(&mut env);
}

#[test]
fn terminal_no_work_refuses_stale_lease_and_authority_without_growth() {
    let mut expired = prepare("terminal-no-work-expired");
    settle(&mut expired, D::Adopted);
    expire_active_lease(&expired.path);
    let before = durable_snapshot(&expired.path);
    let error = expired
        .ledger
        .claim_effect_recovery(&expired.intent.id, &expired.authority)
        .expect_err("expired lease");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_AUTHORITY_STALE");
    assert_eq!(durable_snapshot(&expired.path), before);

    let mut frozen = prepare("terminal-no-work-frozen");
    settle(&mut frozen, D::Adopted);
    Connection::open(&frozen.path)
        .expect("raw")
        .execute(
            "UPDATE authority_revisions SET freeze_generation=freeze_generation+1 WHERE singleton=1",
            [],
        )
        .expect("freeze");
    let before = durable_snapshot(&frozen.path);
    let error = frozen
        .ledger
        .claim_effect_recovery(&frozen.intent.id, &frozen.authority)
        .expect_err("stale authority");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_AUTHORITY_STALE");
    assert_eq!(durable_snapshot(&frozen.path), before);
}

#[test]
fn terminal_no_work_refuses_persisted_intent_substitution_without_growth() {
    let mut env = prepare("terminal-no-work-substitution");
    settle(&mut env, D::Adopted);
    Connection::open(&env.path)
        .expect("raw")
        .execute(
            "UPDATE effect_intents SET state='QUARANTINED' WHERE id=?1",
            [env.intent.id.as_str()],
        )
        .expect("substitute intent");
    let before = durable_snapshot(&env.path);
    let error = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect_err("substituted intent");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_SUBJECT_MISMATCH");
    assert_eq!(durable_snapshot(&env.path), before);
}

#[test]
fn terminal_no_work_refuses_db_time_substitution_on_both_retry_paths() {
    for retry in [false, true] {
        let mut receipt = prepare(&format!("terminal-receipt-time-{retry}"));
        settle_adopted(&mut receipt, retry);
        assert_no_work(&mut receipt);
        Connection::open(&receipt.path)
            .expect("raw")
            .execute(
                "UPDATE effect_receipts SET recorded_at=?1
                 WHERE effect_intent_id=?2 AND verification_result='MATCH'",
                ["2031-01-01T00:00:00.000Z", receipt.intent.id.as_str()],
            )
            .expect("substitute receipt time");
        assert_subject_refusal_without_mutation(&mut receipt);

        let mut delivery = prepare(&format!("terminal-delivery-time-{retry}"));
        settle_adopted(&mut delivery, retry);
        assert_no_work(&mut delivery);
        Connection::open(&delivery.path)
            .expect("raw")
            .execute(
                "UPDATE outbox SET delivered_at=?1
                 WHERE kind='effect_recovery' AND payload LIKE 'ecl_%'",
                ["2031-01-01T00:00:00.000Z"],
            )
            .expect("substitute delivery time");
        assert_subject_refusal_without_mutation(&mut delivery);

        if retry {
            let mut absence = prepare("terminal-absence-time-true");
            settle_adopted(&mut absence, true);
            assert_no_work(&mut absence);
            Connection::open(&absence.path)
                .expect("raw")
                .execute(
                    "UPDATE effect_receipts SET recorded_at=?1
                     WHERE effect_intent_id=?2 AND verification_result='ABSENT'",
                    ["2031-01-01T00:00:00.000Z", absence.intent.id.as_str()],
                )
                .expect("substitute absence receipt time");
            assert_subject_refusal_without_mutation(&mut absence);
        }
    }
}

fn settle(env: &mut super::recovery_support::Env, terminal: D) {
    let claim = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    if terminal == D::Quarantined {
        let unknown = env
            .ledger
            .apply_effect_recovery(
                &tx(&claim, &env.authority, D::ReadbackUnknown, None, None),
                &env.authority,
            )
            .expect("unknown");
        env.ledger
            .apply_effect_recovery(
                &tx(
                    &unknown,
                    &env.authority,
                    terminal,
                    None,
                    Some(EffectRecoveryContainmentReason::ReadbackUnavailable),
                ),
                &env.authority,
            )
            .expect("quarantine");
        return;
    }
    let verdict = if terminal == D::Adopted {
        ReceiptVerdict::Match
    } else {
        ReceiptVerdict::Mismatch
    };
    env.ledger
        .apply_effect_recovery(
            &tx(
                &claim,
                &env.authority,
                terminal,
                Some(obs(&claim.intent, verdict)),
                None,
            ),
            &env.authority,
        )
        .expect("terminal");
}

fn settle_adopted(env: &mut super::recovery_support::Env, retry: bool) {
    if retry {
        settle_after_retry(env, RetryTerminal::Adopted);
    } else {
        settle(env, D::Adopted);
    }
}

fn settle_after_retry(env: &mut super::recovery_support::Env, terminal: RetryTerminal) {
    let claim = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    let reserved = env
        .ledger
        .apply_effect_recovery(
            &tx(
                &claim,
                &env.authority,
                D::RetryReserved,
                Some(obs(&claim.intent, ReceiptVerdict::Absent)),
                None,
            ),
            &env.authority,
        )
        .expect("reserve retry");
    match terminal {
        RetryTerminal::Adopted | RetryTerminal::Orphaned => {
            let (to, verdict) = if matches!(terminal, RetryTerminal::Adopted) {
                (D::Adopted, ReceiptVerdict::Match)
            } else {
                (D::Orphaned, ReceiptVerdict::Mismatch)
            };
            env.ledger
                .apply_effect_recovery(
                    &tx(
                        &reserved,
                        &env.authority,
                        to,
                        Some(obs(&reserved.intent, verdict)),
                        None,
                    ),
                    &env.authority,
                )
                .expect("retry terminal");
        }
        RetryTerminal::RetrySpent | RetryTerminal::ReadbackUnavailable => {
            let unknown = env
                .ledger
                .apply_effect_recovery(
                    &tx(&reserved, &env.authority, D::ReadbackUnknown, None, None),
                    &env.authority,
                )
                .expect("retry unknown");
            let spent = matches!(terminal, RetryTerminal::RetrySpent);
            env.ledger
                .apply_effect_recovery(
                    &tx(
                        &unknown,
                        &env.authority,
                        D::Quarantined,
                        spent.then(|| obs(&unknown.intent, ReceiptVerdict::Absent)),
                        Some(if spent {
                            EffectRecoveryContainmentReason::RetrySpentAfterAbsence
                        } else {
                            EffectRecoveryContainmentReason::ReadbackUnavailable
                        }),
                    ),
                    &env.authority,
                )
                .expect("retry quarantine");
        }
    }
}

fn settle_inherited_retry_adopted(env: &mut super::recovery_support::Env) -> u64 {
    let first = reserve_retry(env);
    reacquire(env);
    let inherited = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("successor claim")
        .expect("successor row");
    assert_eq!(inherited.disposition, D::RetryReserved);
    assert_eq!(inherited.claim_generation, first.claim_generation + 1);
    adopt(env, &inherited);
    inherited.outbox_sequence
}

fn settle_successor_readback_unknown_adopted(env: &mut super::recovery_support::Env) {
    let reserved = reserve_retry(env);
    env.ledger
        .apply_effect_recovery(
            &tx(&reserved, &env.authority, D::ReadbackUnknown, None, None),
            &env.authority,
        )
        .expect("readback unknown");
    reacquire(env);
    let inherited = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("successor claim")
        .expect("successor row");
    assert_eq!(inherited.disposition, D::ReadbackUnknown);
    adopt(env, &inherited);
}

fn reserve_retry(
    env: &mut super::recovery_support::Env,
) -> bullet_application::EffectRecoveryClaim {
    let claim = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect("claim")
        .expect("row");
    env.ledger
        .apply_effect_recovery(
            &tx(
                &claim,
                &env.authority,
                D::RetryReserved,
                Some(obs(&claim.intent, ReceiptVerdict::Absent)),
                None,
            ),
            &env.authority,
        )
        .expect("reserve retry")
}

fn reacquire(env: &mut super::recovery_support::Env) {
    expire_active_lease(&env.path);
    let (_, token, grant) =
        LeaseService::acquire(&mut env.ledger, &env.graph, 0, "terminal-successor", 5)
            .expect("reacquire");
    env.authority = authority(&env.ledger, &token);
    env.grant = grant;
}

fn adopt(env: &mut super::recovery_support::Env, claim: &bullet_application::EffectRecoveryClaim) {
    env.ledger
        .apply_effect_recovery(
            &tx(
                claim,
                &env.authority,
                D::Adopted,
                Some(obs(&claim.intent, ReceiptVerdict::Match)),
                None,
            ),
            &env.authority,
        )
        .expect("adopt");
}

fn assert_no_work(env: &mut super::recovery_support::Env) {
    let before = durable_snapshot(&env.path);
    assert_eq!(
        env.ledger
            .claim_effect_recovery(&env.intent.id, &env.authority)
            .expect("terminal readback"),
        None
    );
    assert_eq!(durable_snapshot(&env.path), before);
}

fn assert_subject_refusal_without_mutation(env: &mut super::recovery_support::Env) {
    let before = durable_snapshot(&env.path);
    let error = env
        .ledger
        .claim_effect_recovery(&env.intent.id, &env.authority)
        .expect_err("substituted terminal time");
    assert_eq!(error.reason_code(), "EFFECT_RECOVERY_SUBJECT_MISMATCH");
    assert_eq!(durable_snapshot(&env.path), before);
}

fn durable_snapshot(path: &Path) -> Vec<Vec<Vec<Value>>> {
    let conn = Connection::open(path).expect("raw");
    [
        "SELECT * FROM effect_intents ORDER BY id",
        "SELECT * FROM effect_recovery_claims ORDER BY claim_generation,claim_id",
        "SELECT * FROM outbox ORDER BY seq",
        "SELECT * FROM events ORDER BY seq",
        "SELECT * FROM effect_receipts ORDER BY recorded_at,id",
    ]
    .into_iter()
    .map(|sql| {
        let mut statement = conn.prepare(sql).expect("snapshot statement");
        let width = statement.column_count();
        statement
            .query_map([], |row| {
                (0..width)
                    .map(|column| row.get(column))
                    .collect::<Result<Vec<Value>, _>>()
            })
            .expect("snapshot query")
            .collect::<Result<Vec<_>, _>>()
            .expect("snapshot rows")
    })
    .collect()
}
