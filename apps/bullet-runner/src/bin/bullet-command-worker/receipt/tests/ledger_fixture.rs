//! Minimum exact semantic ledger for public receipt tests.

use bullet_application::lease_transport::{
    AdvanceSettlementRequest, LeaseSettlementOutcome, LeaseSettlementRecord,
    LeaseSettlementRequest, ReleaseSettlementRequest, LEASE_SETTLEMENT_RECORD_VERSION,
};
use bullet_domain::{
    Attempt, AttemptId, AttemptState, CandidateId, Digest, EffectId, EffectReceiptId, RunnerId,
    VariantId, WorkPackageId, WorkspaceId,
};
use bullet_harness_core::launch_grant::workspace_nonce_digest;
use bullet_harness_core::lease_transport::{LeaseIncarnationClaims, LeaseSubjectClaims};
use rusqlite::{params, Connection};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE attempts(id TEXT PRIMARY KEY,variant_id TEXT,work_package_id TEXT,fence INTEGER,
 runner_id TEXT,runner_epoch INTEGER,workspace_id TEXT,workspace_nonce BLOB,scope_revision INTEGER,
 context_revision INTEGER,state TEXT);
CREATE TABLE active_leases(variant_id TEXT,attempt_id TEXT,fence INTEGER,runner_id TEXT,
 runner_epoch INTEGER,workspace_nonce BLOB,heartbeat_at TEXT,expires_at TEXT);
CREATE TABLE lease_authority_fingerprints(attempt_id TEXT PRIMARY KEY,variant_id TEXT,fence INTEGER,
 authority_epoch INTEGER,freeze_generation INTEGER,restore_epoch INTEGER,issued_at TEXT,
 graph_revision INTEGER,workspace_generation INTEGER,scope_digest TEXT,policy_generation INTEGER,
 routing_generation INTEGER);
CREATE TABLE effect_intents(id TEXT PRIMARY KEY,logical_effect_key TEXT,provider TEXT,
 target_identity TEXT,desired_state_hash TEXT,expected_old_oid TEXT,attempt_id TEXT,fence INTEGER,
 policy_version TEXT,payload_hash TEXT,provider_idempotency_key TEXT,state TEXT,unknown_retries INTEGER,
 created_at TEXT);
CREATE TABLE effect_receipts(id TEXT PRIMARY KEY,effect_intent_id TEXT,observed_remote_identity TEXT,
 observed_state_hash TEXT,verification_method TEXT,verification_result TEXT,adopted_after_unknown INTEGER,
 recorded_at TEXT);
CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,body TEXT);
CREATE TABLE lease_transport_settlements(settlement_id TEXT PRIMARY KEY,request_digest TEXT,
 record_json TEXT,recorded_at TEXT);";

pub(super) fn write_header(path: &Path) {
    let mut bytes = vec![0_u8; 100];
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write(
    path: &Path,
    author_id: &str,
    effect_id: &str,
    author_fence: u64,
    effect_fence: u64,
    candidate: &CandidateId,
    head: &str,
    authority_epoch: u64,
    scope_digest: &str,
) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch(SCHEMA).unwrap();
    let runner = RunnerId::from_seed("receipt-ledger-runner");
    let author = attempt(
        author_id,
        "author",
        &runner,
        author_fence,
        AttemptState::Succeeded,
        1,
    );
    let effect = attempt(
        effect_id,
        "effect",
        &runner,
        effect_fence,
        AttemptState::Superseded,
        2,
    );
    insert_attempt(&connection, &author, authority_epoch, scope_digest);
    insert_attempt(&connection, &effect, authority_epoch, scope_digest);
    let intent = EffectId::from_seed("receipt-effect").to_string();
    let effect_receipt = EffectReceiptId::from_seed("receipt-effect-readback").to_string();
    let target = format!("refs/heads/bullet/candidate/{candidate}");
    connection
        .execute(
            "INSERT INTO effect_intents VALUES
        (?1,?2,'local-bare',?3,?4,?5,?6,?7,'policy-v1',?8,NULL,'COMMITTED',0,'now')",
            params![
                intent,
                format!("push:{candidate}:{effect_fence}"),
                target,
                head,
                "0".repeat(40),
                effect_id,
                effect_fence,
                "8".repeat(64)
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO effect_receipts VALUES
        (?1,?2,?3,?4,'git-ls-remote-read-back','MATCH',1,'now')",
            params![effect_receipt, intent, target, head],
        )
        .unwrap();
    for (kind, body) in effect_events(&intent, &effect_receipt) {
        connection
            .execute(
                "INSERT INTO events(kind,body) VALUES (?1,?2)",
                params![kind, body],
            )
            .unwrap();
    }
    let author_running = transition(
        &author,
        AttemptState::Starting,
        AttemptState::Running,
        "txn-demo-product-runner",
    );
    let author_preparing = transition(
        &author,
        AttemptState::Running,
        AttemptState::Preparing,
        "txn-demo-product-runner",
    );
    let author_release = release(
        &author,
        AttemptState::Preparing,
        AttemptState::Succeeded,
        false,
        "txn-demo-product-runner",
    );
    let effect_release = release(
        &effect,
        AttemptState::Starting,
        AttemptState::Superseded,
        true,
        "txn-demo-effect-authority",
    );
    for record in [
        author_running,
        author_preparing,
        author_release,
        effect_release,
    ] {
        insert_settlement(&connection, &record);
    }
    drop(connection);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn attempt(
    id: &str,
    seed: &str,
    runner: &RunnerId,
    fence: u64,
    state: AttemptState,
    nonce: u8,
) -> Attempt {
    Attempt {
        id: AttemptId::parse(id).unwrap(),
        variant_id: VariantId::from_seed(seed),
        work_package_id: WorkPackageId::from_seed(seed),
        fence,
        runner_id: runner.clone(),
        runner_epoch: 1,
        workspace_id: WorkspaceId::from_seed(seed),
        workspace_nonce: [nonce; 32],
        scope_revision: 1,
        context_revision: 1,
        state,
    }
}

fn insert_attempt(connection: &Connection, attempt: &Attempt, authority_epoch: u64, scope: &str) {
    connection
        .execute(
            "INSERT INTO attempts VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                attempt.id.as_str(),
                attempt.variant_id.as_str(),
                attempt.work_package_id.as_str(),
                attempt.fence,
                attempt.runner_id.as_str(),
                attempt.runner_epoch,
                attempt.workspace_id.as_str(),
                attempt.workspace_nonce.as_slice(),
                attempt.scope_revision,
                attempt.context_revision,
                attempt.state.as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO lease_authority_fingerprints VALUES
        (?1,?2,?3,?4,0,0,'now',1,1,?5,1,1)",
            params![
                attempt.id.as_str(),
                attempt.variant_id.as_str(),
                attempt.fence,
                authority_epoch,
                scope
            ],
        )
        .unwrap();
}

fn subject(attempt: &Attempt) -> LeaseSubjectClaims {
    LeaseSubjectClaims {
        workspace_id: attempt.workspace_id.to_string(),
        workspace_generation: 1,
        workspace_nonce_digest: workspace_nonce_digest(&attempt.workspace_nonce).unwrap(),
        scope_digest: "7".repeat(64),
        policy_generation: 1,
        freeze_generation: 0,
        graph_revision: 1,
        routing_generation: 1,
        authority_epoch: 2,
        incarnation: Some(LeaseIncarnationClaims {
            variant_id: attempt.variant_id.to_string(),
            attempt_id: attempt.id.to_string(),
            fence: attempt.fence,
            scope_revision: attempt.scope_revision,
            context_revision: attempt.context_revision,
        }),
    }
}

fn transition(
    attempt: &Attempt,
    expected: AttemptState,
    target: AttemptState,
    key: &str,
) -> LeaseSettlementRecord {
    let request = LeaseSettlementRequest::Advance(AdvanceSettlementRequest {
        acquire_request_digest: Digest::of(format!("acquire:{key}").as_bytes()).to_hex(),
        work_package_id: attempt.work_package_id.clone(),
        runner_id: attempt.runner_id.clone(),
        runner_epoch: attempt.runner_epoch,
        idempotency_key: key.into(),
        variant_id: attempt.variant_id.clone(),
        attempt_id: attempt.id.clone(),
        attempt_fence: attempt.fence,
        expected_state: expected,
        target_state: target,
    });
    record(request, attempt, target, false)
}

fn release(
    attempt: &Attempt,
    expected: AttemptState,
    target: AttemptState,
    requeue: bool,
    key: &str,
) -> LeaseSettlementRecord {
    let request = LeaseSettlementRequest::Release(ReleaseSettlementRequest {
        acquire_request_digest: Digest::of(format!("acquire:{key}").as_bytes()).to_hex(),
        work_package_id: attempt.work_package_id.clone(),
        runner_id: attempt.runner_id.clone(),
        runner_epoch: attempt.runner_epoch,
        idempotency_key: key.into(),
        variant_id: attempt.variant_id.clone(),
        attempt_id: attempt.id.clone(),
        attempt_fence: attempt.fence,
        expected_state: expected,
        final_state: target,
        requeue,
    });
    record(request, attempt, target, true)
}

fn record(
    request: LeaseSettlementRequest,
    attempt: &Attempt,
    state: AttemptState,
    released: bool,
) -> LeaseSettlementRecord {
    let mut outcome = attempt.clone();
    outcome.state = state;
    let digest = request.digest().unwrap();
    LeaseSettlementRecord {
        version: LEASE_SETTLEMENT_RECORD_VERSION.into(),
        settlement_id: format!("lts_{digest}"),
        request_digest: digest,
        request,
        subject: subject(attempt),
        outcome: if released {
            LeaseSettlementOutcome::Released(outcome)
        } else {
            LeaseSettlementOutcome::Advanced(outcome)
        },
    }
}

fn insert_settlement(connection: &Connection, record: &LeaseSettlementRecord) {
    connection
        .execute(
            "INSERT INTO lease_transport_settlements VALUES (?1,?2,?3,'now')",
            params![
                record.settlement_id,
                record.request_digest,
                record.encode().unwrap()
            ],
        )
        .unwrap();
}

fn effect_events(effect: &str, receipt: &str) -> Vec<(&'static str, String)> {
    vec![
        ("effect_intent_recorded", effect.into()),
        (
            "effect_transition",
            format!("{effect}:PROPOSED->AUTHORIZED"),
        ),
        (
            "effect_transition",
            format!("{effect}:AUTHORIZED->DISPATCHING"),
        ),
        (
            "effect_transition",
            format!("{effect}:DISPATCHING->OUTCOME_UNKNOWN"),
        ),
        ("effect_receipt_recorded", receipt.into()),
        (
            "effect_transition",
            format!("{effect}:OUTCOME_UNKNOWN->VERIFIED"),
        ),
        ("effect_transition", format!("{effect}:VERIFIED->COMMITTED")),
    ]
}
