use bullet_adapters::SqliteLedger;
use bullet_application::{
    materialize_plan, EffectIntentRecord, EffectRecoveryAuthority, EffectRecoveryContainmentReason,
    EffectRecoveryDisposition as D, EffectRecoveryObservation, EffectRecoveryTransition,
    EffectState, LeaseGrant, LeaseService, Ledger, PlanInput, ReceiptVerdict, ReleaseRequest,
    StoredGraph, ZERO_OID,
};
use bullet_domain::{AttemptState, AuthorityToken, CandidateId, EffectId, TaskClass};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub(crate) const AT: &str = "2026-08-28T04:00:00.000Z";
const OLD_HEARTBEAT: &str = "2020-01-01T00:00:00.000Z";
const OLD_EXPIRY: &str = "2020-01-01T00:00:05.000Z";

pub(crate) struct Env {
    pub(crate) _dir: TempDir,
    pub(crate) path: PathBuf,
    pub(crate) graph: StoredGraph,
    pub(crate) ledger: SqliteLedger,
    pub(crate) intent: EffectIntentRecord,
    pub(crate) authority: EffectRecoveryAuthority,
    pub(crate) grant: LeaseGrant,
}

pub(crate) fn prepare(seed: &str) -> Env {
    let dir = crate::support::private_tempdir();
    let path = dir.path().join(format!("{seed}.sqlite3"));
    let mut ledger = SqliteLedger::open(&path).expect("open");
    let graph = materialize_plan(
        &mut ledger,
        seed,
        &PlanInput {
            title: "effect recovery".into(),
            objective: "restart-safe local-bare recovery".into(),
            packages: vec![("package".into(), TaskClass::BoundedBugFix)],
        },
        AT,
    )
    .expect("materialize");
    let (_, _, original) =
        LeaseService::acquire(&mut ledger, &graph, 0, &format!("{seed}-o"), 5).expect("original");
    let intent = record_unknown_intent(&mut ledger, seed, &original);
    ledger
        .release_lease(&ReleaseRequest {
            variant_id: original.attempt.variant_id.clone(),
            attempt_id: original.attempt.id.clone(),
            final_state: AttemptState::Crashed,
            requeue: true,
        })
        .expect("release original");
    let (_, token, grant) =
        LeaseService::acquire(&mut ledger, &graph, 0, &format!("{seed}-r"), 5).expect("successor");
    let authority = authority(&ledger, &token);
    Env {
        _dir: dir,
        path,
        graph,
        ledger,
        intent,
        authority,
        grant,
    }
}

fn record_unknown_intent(
    ledger: &mut SqliteLedger,
    seed: &str,
    grant: &LeaseGrant,
) -> EffectIntentRecord {
    let candidate = CandidateId::from_seed(seed);
    let target = format!("refs/heads/bullet/candidate/{candidate}");
    let intent = EffectIntentRecord {
        id: EffectId::from_seed(&format!("{seed}-intent")),
        logical_effect_key: format!("local-bare:{seed}:{target}"),
        provider: "local-bare".into(),
        target_identity: target,
        desired_state_hash: "b".repeat(40),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: grant.attempt.id.clone(),
        fence: grant.attempt.fence,
        policy_version: "policy-v1".into(),
        payload_hash: String::new(),
        provider_idempotency_key: None,
        state: EffectState::Proposed,
        unknown_retries: 0,
        created_at: AT.into(),
    };
    let (intent, created) = ledger.record_effect_intent(&intent).expect("record");
    assert!(created);
    for state in [
        EffectState::Authorized,
        EffectState::Dispatching,
        EffectState::OutcomeUnknown,
    ] {
        ledger.transition_effect(&intent.id, state).expect("effect");
    }
    ledger
        .get_effect_intent_by_id(&intent.id)
        .expect("load")
        .expect("intent")
}

pub(crate) fn authority(ledger: &SqliteLedger, token: &AuthorityToken) -> EffectRecoveryAuthority {
    let current = ledger.current_authority().expect("authority");
    EffectRecoveryAuthority::from_token(
        token,
        current.authority_epoch(),
        current.freeze_generation(),
        0,
    )
    .expect("recovery authority")
}

pub(crate) fn obs(
    intent: &EffectIntentRecord,
    verdict: ReceiptVerdict,
) -> EffectRecoveryObservation {
    let observed = match verdict {
        ReceiptVerdict::Match => Some(intent.desired_state_hash.clone()),
        ReceiptVerdict::Mismatch => Some("c".repeat(40)),
        ReceiptVerdict::Absent => None,
    };
    EffectRecoveryObservation {
        provider: "local-bare".into(),
        remote_identity: intent.target_identity.clone(),
        observed_state_hash: observed,
        verification_method: EffectRecoveryObservation::METHOD.into(),
        verdict,
    }
}

pub(crate) fn tx(
    claim: &bullet_application::EffectRecoveryClaim,
    authority: &EffectRecoveryAuthority,
    to: D,
    observation: Option<EffectRecoveryObservation>,
    reason: Option<EffectRecoveryContainmentReason>,
) -> EffectRecoveryTransition {
    EffectRecoveryTransition::new(claim, authority, to, observation, reason).expect("transition")
}

pub(crate) fn expire_active_lease(path: &Path) {
    Connection::open(path)
        .expect("raw")
        .execute(
            "UPDATE active_leases SET heartbeat_at=?1, expires_at=?2",
            params![OLD_HEARTBEAT, OLD_EXPIRY],
        )
        .expect("expire");
}

pub(crate) fn outbox_phase(
    path: &Path,
    seq: u64,
) -> (String, String, Option<String>, Option<String>) {
    Connection::open(path)
        .expect("raw")
        .query_row(
            "SELECT payload, phase, delivered_at, acked_at FROM outbox WHERE seq=?1",
            [i64::try_from(seq).expect("seq")],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("outbox")
}

pub(crate) fn claim_disposition(path: &Path, id: &str) -> (String, Option<String>) {
    Connection::open(path)
        .expect("raw")
        .query_row(
            "SELECT disposition, invalidated_from FROM effect_recovery_claims WHERE claim_id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("claim row")
}

pub(crate) fn claim_receipt_id(path: &Path, id: &str) -> Option<String> {
    Connection::open(path)
        .expect("raw")
        .query_row(
            "SELECT receipt_id FROM effect_recovery_claims WHERE claim_id=?1",
            [id],
            |row| row.get(0),
        )
        .expect("claim receipt")
}
