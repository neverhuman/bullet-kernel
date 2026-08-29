use super::*;
use bullet_application::{CommandDispatchDisposition, CommandRequest};
use bullet_domain::{CommandId, RunnerId};
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

fn claim(seed: &str) -> CommandDispatchClaim {
    let request = CommandRequest::new(seed, "run_demo", &serde_json::json!({})).unwrap();
    CommandDispatchClaim {
        schema_version: "bullet.command-dispatch-claim.v1".into(),
        claim_id: format!("dcl_{}", Digest::of(seed.as_bytes()).to_hex()),
        command_id: request.id(),
        outbox_sequence: 1,
        request_digest: request.digest(),
        request,
        runner_id: RunnerId::from_seed("worker-test"),
        runner_epoch: 1,
        authority_epoch: 1,
        freeze_generation: 0,
        restore_epoch: 0,
        disposition: CommandDispatchDisposition::Claimed,
        completion_digest: None,
        claimed_at: "2026-08-27T13:00:00.000Z".into(),
        updated_at: "2026-08-27T13:00:00.000Z".into(),
    }
}

fn record(claim: &CommandDispatchClaim) -> CommandRecord {
    CommandRecord {
        id: claim.command_id.clone(),
        idempotency_key: claim.request.idempotency_key.clone(),
        kind: claim.request.kind.clone(),
        payload: claim.request.payload.clone(),
        payload_digest: claim.request_digest,
        phase: CommandPhase::Unknown,
        response: Some("{}".into()),
    }
}

struct FakePort {
    claims: Mutex<VecDeque<Result<Option<CommandDispatchClaim>, String>>>,
    readbacks: Mutex<VecDeque<Result<Option<CommandDispatchClaim>, String>>>,
    settlements: Mutex<VecDeque<Result<CommandRecord, String>>>,
    completions: Mutex<Vec<(String, ComponentCommandCompletionV1)>>,
}

impl DispatchPort for FakePort {
    async fn claim(&self) -> Result<Option<CommandDispatchClaim>, String> {
        self.claims.lock().unwrap().pop_front().unwrap_or(Ok(None))
    }

    async fn readback(&self) -> Result<Option<CommandDispatchClaim>, String> {
        self.readbacks
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(None))
    }

    async fn settle(
        &self,
        claim_id: &str,
        completion: &ComponentCommandCompletionV1,
    ) -> Result<CommandRecord, String> {
        self.completions
            .lock()
            .unwrap()
            .push((claim_id.into(), completion.clone()));
        self.settlements
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err("missing settlement".into()))
    }
}

fn fake(
    claims: Vec<Result<Option<CommandDispatchClaim>, String>>,
    readbacks: Vec<Result<Option<CommandDispatchClaim>, String>>,
    settlements: Vec<Result<CommandRecord, String>>,
) -> FakePort {
    FakePort {
        claims: Mutex::new(claims.into()),
        readbacks: Mutex::new(readbacks.into()),
        settlements: Mutex::new(settlements.into()),
        completions: Mutex::new(Vec::new()),
    }
}

fn store() -> (tempfile::TempDir, StateStore) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = StateStore::admit(&temp.path().canonicalize().unwrap()).unwrap();
    (temp, store)
}

#[tokio::test]
async fn claim_response_loss_reads_back_the_exact_same_claim() {
    let expected = claim("lost-claim");
    let port = fake(
        vec![Err("lost response".into())],
        vec![Ok(None), Ok(Some(expected.clone()))],
        vec![],
    );
    assert_eq!(acquire_claim(&port).await.unwrap(), Some(expected));
}

#[tokio::test]
async fn settlement_response_loss_keeps_receipt_and_retries_exact_completion() {
    let (_temp, store) = store();
    let claim = claim("lost-settlement");
    let state = store.begin(claim.clone(), &"b".repeat(64)).unwrap();
    let digest = Digest::of(b"exact retained receipt");
    let state = state.retain_receipt("c".repeat(64), digest, 1).unwrap();
    store.persist(&state).unwrap();
    let port = fake(
        vec![],
        vec![],
        vec![Err("lost response".into()), Ok(record(&claim))],
    );

    assert_eq!(
        settle_digest(&port, &store, state.clone(), digest)
            .await
            .unwrap_err()
            .code(),
        "COMMAND_SETTLEMENT_UNKNOWN"
    );
    assert_eq!(store.load().unwrap(), Some(state.clone()));
    settle_digest(&port, &store, state, digest).await.unwrap();
    assert_eq!(store.load().unwrap().unwrap().stage, Stage::SettledUnknown);
    let completions = port.completions.lock().unwrap();
    assert_eq!(completions.len(), 2);
    assert_eq!(completions[0], completions[1]);
    assert_eq!(completions[0].0, claim.claim_id);
    assert_eq!(completions[0].1.command_id, claim.command_id);
    assert_eq!(completions[0].1.request_digest, claim.request_digest);
    assert_eq!(completions[0].1.receipt_digest, digest);
    assert!(!completions[0].1.transaction_gate_eligible);
    assert!(!completions[0].1.independent_evidence_eligible);
}

#[tokio::test]
async fn wrong_or_green_settlement_response_never_closes_state() {
    let (_temp, store) = store();
    let claim = claim("wrong-settlement");
    let state = store
        .begin(claim.clone(), &"b".repeat(64))
        .unwrap()
        .retain_receipt("c".repeat(64), Digest::of(b"receipt"), 1)
        .unwrap();
    store.persist(&state).unwrap();
    let mut wrong = record(&claim);
    wrong.id = CommandId::from_seed("another-command");
    wrong.phase = CommandPhase::Verified;
    let port = fake(vec![], vec![], vec![Ok(wrong)]);
    assert_eq!(
        settle_digest(&port, &store, state.clone(), Digest::of(b"receipt"))
            .await
            .unwrap_err()
            .code(),
        "COMMAND_SETTLEMENT_INVALID"
    );
    assert_eq!(store.load().unwrap(), Some(state));
}

#[test]
fn retained_child_material_routes_to_admission_instead_of_rerun() {
    let (_temp, store) = store();
    let state = store
        .begin(claim("retained-child"), &"b".repeat(64))
        .unwrap();
    let run_root = store.run_root(&state);
    assert!(!child_material_exists(&run_root, &store.receipt_path(&state)).unwrap());
    std::fs::create_dir(run_root.join("data")).unwrap();
    assert!(child_material_exists(&run_root, &store.receipt_path(&state)).unwrap());
}

#[test]
fn retained_claim_cannot_run_as_another_runner_incarnation() {
    let (_temp, store) = store();
    let state = store.begin(claim("wrong-runner"), &"b".repeat(64)).unwrap();
    assert_eq!(
        validate_runner_subject(&state, &RunnerId::from_seed("other"), 1)
            .unwrap_err()
            .code(),
        "COMMAND_RUNNER_SUBJECT_MISMATCH"
    );
    assert_eq!(
        validate_runner_subject(&state, &state.claim.runner_id, 2)
            .unwrap_err()
            .code(),
        "COMMAND_RUNNER_SUBJECT_MISMATCH"
    );
}
