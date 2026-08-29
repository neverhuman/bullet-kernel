//! Read-only semantic admission of the retained Kernel ledger.
use super::super::{artifacts, invalid, ComponentReceipt, WorkerError};
use bullet_application::lease_transport::{
    LeaseSettlementOutcome, LeaseSettlementRecord, LeaseSettlementRequest,
};
use bullet_domain::AttemptState;
use bullet_harness_core::launch_grant::workspace_nonce_digest;
use rusqlite::Connection;
use std::fs::File;
#[path = "ledger/custody.rs"]
mod custody;
#[cfg(test)]
pub(crate) use custody::{clear_test_hook, install_test_hook};
const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const AUTHOR_KEY: &str = "txn-demo-product-runner";
const EFFECT_KEY: &str = "txn-demo-effect-authority";
#[derive(Clone)]
struct AttemptRow {
    id: String,
    variant: String,
    package: String,
    fence: u64,
    runner: String,
    runner_epoch: u64,
    workspace: String,
    nonce: [u8; 32],
    scope_revision: u64,
    context_revision: u64,
    state: String,
}
#[derive(Clone)]
struct Fingerprint {
    variant: String,
    fence: u64,
    authority_epoch: u64,
    freeze_generation: u64,
    restore_epoch: u64,
    graph_revision: u64,
    workspace_generation: u64,
    scope_digest: String,
    policy_generation: u64,
    routing_generation: u64,
}
struct EffectRow {
    id: String,
    logical_key: String,
    provider: String,
    target: String,
    desired: String,
    expected_old: String,
    attempt: String,
    fence: u64,
    policy: String,
    payload: String,
    idempotency: Option<String>,
    state: String,
    unknown_retries: u64,
}
struct EffectReceiptRow {
    id: String,
    intent: String,
    remote: String,
    state: Option<String>,
    method: String,
    result: String,
    adopted: u8,
}
pub(super) fn validate(
    path: &std::path::Path,
    file: &File,
    receipt: &ComponentReceipt,
) -> Result<(), WorkerError> {
    custody::with_snapshot(path, file, |connection| {
        validate_snapshot(connection, path, receipt)
    })
}
fn validate_snapshot(
    connection: &Connection,
    path: &std::path::Path,
    receipt: &ComponentReceipt,
) -> Result<(), WorkerError> {
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(invalid)?;
    if quick != "ok" || count(connection, "SELECT count(*) FROM attempts")? != 2 {
        return Err(invalid(
            "retained ledger is not exact read-only SQLite truth",
        ));
    }
    let author = attempt(connection, &receipt.attempt_first)?;
    let effect = attempt(connection, &receipt.attempt_second)?;
    custody::test_point(path, custody::TestStage::BetweenQueries);
    validate_attempt(&author, receipt.fence_first, "succeeded")?;
    validate_attempt(&effect, receipt.fence_second, "superseded")?;
    if author.runner != effect.runner || author.runner_epoch != effect.runner_epoch {
        return Err(invalid(
            "author and effect Attempts do not share the admitted Runner incarnation",
        ));
    }
    if count(connection, "SELECT count(*) FROM active_leases")? != 0
        || count(
            connection,
            "SELECT count(*) FROM lease_authority_fingerprints",
        )? != 2
    {
        return Err(invalid(
            "terminal component ledger retains active or incomplete authority",
        ));
    }
    let author_fingerprint = fingerprint(connection, &receipt.attempt_first)?;
    let effect_fingerprint = fingerprint(connection, &receipt.attempt_second)?;
    validate_fingerprint(&author, &author_fingerprint, receipt)?;
    validate_fingerprint(&effect, &effect_fingerprint, receipt)?;
    let (effect_id, receipt_id) = validate_effect(connection, receipt)?;
    validate_effect_history(connection, &effect_id, &receipt_id)?;
    validate_settlements(
        connection,
        receipt,
        &author,
        &effect,
        &author_fingerprint,
        &effect_fingerprint,
    )
}
fn count(connection: &Connection, sql: &str) -> Result<u64, WorkerError> {
    connection
        .query_row(sql, [], |row| row.get::<_, u64>(0))
        .map_err(invalid)
}
fn attempt(connection: &Connection, id: &str) -> Result<AttemptRow, WorkerError> {
    connection
        .query_row(
            "SELECT variant_id,work_package_id,fence,runner_id,runner_epoch,workspace_id,\
             workspace_nonce,scope_revision,context_revision,state FROM attempts WHERE id=?1",
            [id],
            |row| {
                let nonce: Vec<u8> = row.get(6)?;
                let nonce = nonce.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        6,
                        "workspace_nonce".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok(AttemptRow {
                    id: id.into(),
                    variant: row.get(0)?,
                    package: row.get(1)?,
                    fence: row.get(2)?,
                    runner: row.get(3)?,
                    runner_epoch: row.get(4)?,
                    workspace: row.get(5)?,
                    nonce,
                    scope_revision: row.get(7)?,
                    context_revision: row.get(8)?,
                    state: row.get(9)?,
                })
            },
        )
        .map_err(invalid)
}
fn validate_attempt(row: &AttemptRow, fence: u64, state: &str) -> Result<(), WorkerError> {
    let exact = row.fence == fence
        && row.state == state
        && artifacts::full_id(&row.variant, "var")
        && artifacts::full_id(&row.package, "wpk")
        && artifacts::full_id(&row.runner, "run")
        && artifacts::full_id(&row.workspace, "wsp")
        && row.runner_epoch > 0
        && row.scope_revision > 0
        && row.context_revision > 0;
    exact
        .then_some(())
        .ok_or_else(|| invalid("retained terminal Attempt differs"))
}
fn fingerprint(connection: &Connection, id: &str) -> Result<Fingerprint, WorkerError> {
    connection
        .query_row(
            "SELECT variant_id,fence,authority_epoch,freeze_generation,restore_epoch,graph_revision,\
             workspace_generation,scope_digest,policy_generation,routing_generation \
             FROM lease_authority_fingerprints WHERE attempt_id=?1",
            [id],
            |row| Ok(Fingerprint {
                variant: row.get(0)?, fence: row.get(1)?, authority_epoch: row.get(2)?,
                freeze_generation: row.get(3)?, restore_epoch: row.get(4)?, graph_revision: row.get(5)?,
                workspace_generation: row.get(6)?, scope_digest: row.get(7)?,
                policy_generation: row.get(8)?, routing_generation: row.get(9)?,
            }),
        )
        .map_err(invalid)
}
fn validate_fingerprint(
    attempt: &AttemptRow,
    fingerprint: &Fingerprint,
    receipt: &ComponentReceipt,
) -> Result<(), WorkerError> {
    let exact = fingerprint.variant == attempt.variant
        && fingerprint.fence == attempt.fence
        && fingerprint.authority_epoch == receipt.scope_authority_epoch
        && fingerprint.scope_digest == receipt.scope_paths_digest
        && fingerprint.restore_epoch == 0
        && fingerprint.graph_revision > 0
        && fingerprint.workspace_generation > 0
        && fingerprint.policy_generation > 0
        && fingerprint.routing_generation > 0;
    exact
        .then_some(())
        .ok_or_else(|| invalid("Attempt authority fingerprint differs"))
}

fn validate_effect(
    connection: &Connection,
    receipt: &ComponentReceipt,
) -> Result<(String, String), WorkerError> {
    if count(connection, "SELECT count(*) FROM effect_intents")? != 1
        || count(connection, "SELECT count(*) FROM effect_receipts")? != 1
    {
        return Err(invalid(
            "retained ledger does not contain one exact logical effect",
        ));
    }
    let intent = connection
        .query_row(
            "SELECT id,logical_effect_key,provider,target_identity,desired_state_hash,\
            expected_old_oid,attempt_id,fence,policy_version,payload_hash,provider_idempotency_key,\
            state,unknown_retries FROM effect_intents",
            [],
            |row| {
                Ok(EffectRow {
                    id: row.get(0)?,
                    logical_key: row.get(1)?,
                    provider: row.get(2)?,
                    target: row.get(3)?,
                    desired: row.get(4)?,
                    expected_old: row.get(5)?,
                    attempt: row.get(6)?,
                    fence: row.get(7)?,
                    policy: row.get(8)?,
                    payload: row.get(9)?,
                    idempotency: row.get(10)?,
                    state: row.get(11)?,
                    unknown_retries: row.get(12)?,
                })
            },
        )
        .map_err(invalid)?;
    let target = format!("refs/heads/bullet/candidate/{}", receipt.candidate_id);
    let logical = format!("push:{}:{}", receipt.candidate_id, receipt.fence_second);
    let exact = artifacts::full_id(&intent.id, "efi")
        && intent.logical_key == logical
        && intent.provider == "local-bare"
        && intent.target == target
        && intent.desired == receipt.head_oid
        && intent.expected_old == ZERO_OID
        && intent.attempt == receipt.attempt_second
        && intent.fence == receipt.fence_second
        && intent.policy == "policy-v1"
        && artifacts::lower_hex(&intent.payload, 64)
        && intent.idempotency.is_none()
        && intent.state == "COMMITTED"
        && intent.unknown_retries == 0;
    if !exact {
        return Err(invalid(
            "retained committed effect intent differs from Candidate authority",
        ));
    }
    let observed = connection
        .query_row(
            "SELECT id,effect_intent_id,observed_remote_identity,observed_state_hash,\
            verification_method,verification_result,adopted_after_unknown FROM effect_receipts",
            [],
            |row| {
                Ok(EffectReceiptRow {
                    id: row.get(0)?,
                    intent: row.get(1)?,
                    remote: row.get(2)?,
                    state: row.get(3)?,
                    method: row.get(4)?,
                    result: row.get(5)?,
                    adopted: row.get(6)?,
                })
            },
        )
        .map_err(invalid)?;
    let receipt_exact = artifacts::full_id(&observed.id, "efr")
        && observed.intent == intent.id
        && observed.remote == target
        && observed.state.as_deref() == Some(receipt.head_oid.as_str())
        && observed.method == "git-ls-remote-read-back"
        && observed.result == "MATCH"
        && observed.adopted == 1;
    if !receipt_exact {
        return Err(invalid("retained adopted effect receipt differs"));
    }
    Ok((intent.id, observed.id))
}

fn validate_effect_history(
    connection: &Connection,
    effect: &str,
    receipt: &str,
) -> Result<(), WorkerError> {
    let mut statement = connection
        .prepare(
            "SELECT kind,body FROM events WHERE kind IN\
            ('effect_intent_recorded','effect_transition','effect_receipt_recorded') ORDER BY seq",
        )
        .map_err(invalid)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    let transitions = [
        "PROPOSED->AUTHORIZED",
        "AUTHORIZED->DISPATCHING",
        "DISPATCHING->OUTCOME_UNKNOWN",
        "OUTCOME_UNKNOWN->VERIFIED",
        "VERIFIED->COMMITTED",
    ];
    let mut expected = vec![("effect_intent_recorded".into(), effect.into())];
    expected.extend(
        transitions[..3]
            .iter()
            .map(|edge| ("effect_transition".into(), format!("{effect}:{edge}"))),
    );
    expected.push(("effect_receipt_recorded".into(), receipt.into()));
    expected.extend(
        transitions[3..]
            .iter()
            .map(|edge| ("effect_transition".into(), format!("{effect}:{edge}"))),
    );
    (rows == expected)
        .then_some(())
        .ok_or_else(|| invalid("durable effect UNKNOWN/adoption history differs"))
}

fn validate_settlements(
    connection: &Connection,
    receipt: &ComponentReceipt,
    author: &AttemptRow,
    effect: &AttemptRow,
    author_fingerprint: &Fingerprint,
    effect_fingerprint: &Fingerprint,
) -> Result<(), WorkerError> {
    let mut statement = connection
        .prepare("SELECT settlement_id,request_digest,record_json FROM lease_transport_settlements")
        .map_err(invalid)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(invalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    if rows.len() != 4 {
        return Err(invalid("lease terminal settlement inventory differs"));
    }
    let mut seen = 0_u8;
    for (stored_id, stored_digest, json) in rows {
        let record = LeaseSettlementRecord::decode(&json).map_err(invalid)?;
        if record.settlement_id != stored_id || record.request_digest != stored_digest {
            return Err(invalid(
                "lease settlement row differs from canonical record",
            ));
        }
        let (expected_attempt, fingerprint) = match &record.request {
            LeaseSettlementRequest::Advance(request)
                if request.attempt_id.as_str() == receipt.attempt_first =>
            {
                (author, author_fingerprint)
            }
            LeaseSettlementRequest::Release(request)
                if request.attempt_id.as_str() == receipt.attempt_first =>
            {
                (author, author_fingerprint)
            }
            LeaseSettlementRequest::Release(request)
                if request.attempt_id.as_str() == receipt.attempt_second =>
            {
                (effect, effect_fingerprint)
            }
            _ => return Err(invalid("lease settlement names an unadmitted Attempt")),
        };
        validate_subject(&record, expected_attempt, fingerprint)?;
        let bit = settlement_slot(&record, receipt)?;
        if seen & bit != 0 {
            return Err(invalid("duplicate lease settlement edge"));
        }
        seen |= bit;
    }
    (seen == 0b1111)
        .then_some(())
        .ok_or_else(|| invalid("terminal lease settlement chain is incomplete"))
}

fn validate_subject(
    record: &LeaseSettlementRecord,
    attempt: &AttemptRow,
    fingerprint: &Fingerprint,
) -> Result<(), WorkerError> {
    let subject = &record.subject;
    let settled = match &record.outcome {
        LeaseSettlementOutcome::Advanced(attempt) | LeaseSettlementOutcome::Released(attempt) => {
            attempt
        }
    };
    let incarnation = subject
        .incarnation
        .as_ref()
        .ok_or_else(|| invalid("settlement incarnation absent"))?;
    let nonce = workspace_nonce_digest(&attempt.nonce).map_err(invalid)?;
    let outcome_state_exact = match (&record.request, &record.outcome) {
        (LeaseSettlementRequest::Advance(request), LeaseSettlementOutcome::Advanced(settled)) => {
            settled.state == request.target_state
        }
        (LeaseSettlementRequest::Release(request), LeaseSettlementOutcome::Released(settled)) => {
            settled.state == request.final_state && settled.state.as_str() == attempt.state
        }
        _ => false,
    };
    let exact = subject.workspace_id == attempt.workspace
        && subject.workspace_nonce_digest == nonce
        && subject.workspace_generation == fingerprint.workspace_generation
        && subject.scope_digest == fingerprint.scope_digest
        && subject.policy_generation == fingerprint.policy_generation
        && subject.freeze_generation == fingerprint.freeze_generation
        && subject.graph_revision == fingerprint.graph_revision
        && subject.routing_generation == fingerprint.routing_generation
        && subject.authority_epoch == fingerprint.authority_epoch
        && incarnation.variant_id == attempt.variant
        && incarnation.attempt_id == attempt.id
        && incarnation.fence == attempt.fence
        && incarnation.scope_revision == attempt.scope_revision
        && incarnation.context_revision == attempt.context_revision
        && settled.id.as_str() == attempt.id
        && settled.variant_id.as_str() == attempt.variant
        && settled.work_package_id.as_str() == attempt.package
        && settled.runner_id.as_str() == attempt.runner
        && settled.runner_epoch == attempt.runner_epoch
        && settled.workspace_id.as_str() == attempt.workspace
        && settled.workspace_nonce == attempt.nonce
        && settled.scope_revision == attempt.scope_revision
        && settled.context_revision == attempt.context_revision
        && outcome_state_exact;
    exact
        .then_some(())
        .ok_or_else(|| invalid("lease settlement subject differs from durable Attempt authority"))
}
fn settlement_slot(
    record: &LeaseSettlementRecord,
    receipt: &ComponentReceipt,
) -> Result<u8, WorkerError> {
    match (&record.request, &record.outcome) {
        (LeaseSettlementRequest::Advance(request), LeaseSettlementOutcome::Advanced(_))
            if request.attempt_id.as_str() == receipt.attempt_first
                && request.idempotency_key == AUTHOR_KEY
                && request.expected_state == AttemptState::Starting
                && request.target_state == AttemptState::Running =>
        {
            Ok(1)
        }
        (LeaseSettlementRequest::Advance(request), LeaseSettlementOutcome::Advanced(_))
            if request.attempt_id.as_str() == receipt.attempt_first
                && request.idempotency_key == AUTHOR_KEY
                && request.expected_state == AttemptState::Running
                && request.target_state == AttemptState::Preparing =>
        {
            Ok(2)
        }
        (LeaseSettlementRequest::Release(request), LeaseSettlementOutcome::Released(_))
            if request.attempt_id.as_str() == receipt.attempt_first
                && request.idempotency_key == AUTHOR_KEY
                && request.expected_state == AttemptState::Preparing
                && request.final_state == AttemptState::Succeeded
                && !request.requeue =>
        {
            Ok(4)
        }
        (LeaseSettlementRequest::Release(request), LeaseSettlementOutcome::Released(_))
            if request.attempt_id.as_str() == receipt.attempt_second
                && request.idempotency_key == EFFECT_KEY
                && request.expected_state == AttemptState::Starting
                && request.final_state == AttemptState::Superseded
                && request.requeue =>
        {
            Ok(8)
        }
        _ => Err(invalid(
            "lease settlement transition differs from exact component chain",
        )),
    }
}
