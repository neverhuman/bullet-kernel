use super::*;
use bullet_application::CommandRequest;
use bullet_domain::RunnerId;

fn claim_for(seed: &str) -> CommandDispatchClaim {
    let request = CommandRequest::new(seed, "run_demo", &serde_json::json!({})).unwrap();
    CommandDispatchClaim {
        schema_version: "bullet.command-dispatch-claim.v1".into(),
        claim_id: format!("dcl_{}", Digest::of(seed.as_bytes()).to_hex()),
        command_id: request.id(),
        outbox_sequence: 1,
        request_digest: request.digest(),
        request,
        runner_id: RunnerId::from_seed("state-runner"),
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

fn claim() -> CommandDispatchClaim {
    claim_for("state-command")
}

fn store() -> (tempfile::TempDir, StateStore) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().canonicalize().unwrap();
    let store = StateStore::admit(&root).unwrap();
    (temp, store)
}

#[test]
fn claim_is_durable_before_nonexisting_child_data_and_artifacts() {
    let (_temp, store) = store();
    let state = store.begin(claim(), &"b".repeat(64)).unwrap();
    assert_eq!(store.load().unwrap(), Some(state.clone()));
    assert!(store.run_root(&state).is_dir());
    assert!(!store.run_root(&state).join("data").exists());
    assert!(!store.run_root(&state).join("artifacts").exists());
    assert_eq!(
        std::fs::metadata(store.root.join("current.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn restart_reuses_exact_receipt_and_never_replaces_another_claim() {
    let (_temp, store) = store();
    let state = store.begin(claim(), &"b".repeat(64)).unwrap();
    let retained = state
        .clone()
        .retain_receipt("c".repeat(64), Digest::of(b"receipt"), 1)
        .unwrap();
    store.persist(&retained).unwrap();
    assert_eq!(store.load().unwrap(), Some(retained.clone()));
    assert!(store.begin(state.claim, &"d".repeat(64)).is_err());
    let settled = retained.settled().unwrap();
    store.persist(&settled).unwrap();
    assert_eq!(store.load().unwrap(), Some(settled));
}

#[test]
fn corrupt_or_painted_state_refuses() {
    let (_temp, store) = store();
    let state = store.begin(claim(), &"b".repeat(64)).unwrap();
    let path = store.root.join("current.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["claim"]["transaction_gate_eligible"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(store.load().is_err());
    assert!(store.run_root(&state).is_dir());
}

#[test]
fn settled_archive_is_preserved_while_a_second_command_becomes_current() {
    let (_temp, store) = store();
    let first = store
        .begin(claim_for("first-command"), &"b".repeat(64))
        .unwrap();
    let first = first
        .retain_receipt("c".repeat(64), Digest::of(b"receipt"), 1)
        .unwrap()
        .settled()
        .unwrap();
    store.persist(&first).unwrap();
    let first_archive = store
        .root
        .join(&first.claim.claim_id)
        .join("state-settled-unknown.json");
    let first_bytes = std::fs::read(&first_archive).unwrap();

    let second = store
        .begin(claim_for("second-command"), &"b".repeat(64))
        .unwrap();
    assert_eq!(second.stage, Stage::Claimed);
    assert_ne!(second.claim.claim_id, first.claim.claim_id);
    assert_eq!(store.load().unwrap(), Some(second));
    assert_eq!(std::fs::read(first_archive).unwrap(), first_bytes);
}

#[test]
fn same_claim_partial_initialization_is_recovered_without_deletion() {
    let (_temp, store) = store();
    let claim = claim_for("partial-command");
    let state = WorkerState::new(claim.clone(), &"b".repeat(64)).unwrap();
    let root = store.root.join(&claim.claim_id);
    create_or_admit_private_dir(&root, "claim custody").unwrap();
    create_or_admit_private_dir(&root.join("run"), "private run root").unwrap();
    let claim_bytes = canonical_json(&claim).unwrap();
    write_immutable(&root.join("claim.json"), &claim_bytes).unwrap();
    write_immutable(
        &root.join(Stage::Claimed.file_name()),
        &canonical_json(&state).unwrap(),
    )
    .unwrap();
    assert!(!store.root.join("current.json").exists());

    let recovered = store.begin(claim, &"b".repeat(64)).unwrap();
    assert_eq!(recovered, state);
    assert_eq!(store.load().unwrap(), Some(state));
    assert_eq!(std::fs::read(root.join("claim.json")).unwrap(), claim_bytes);
}

#[test]
fn run_demo_payload_is_exact_and_never_ignored() {
    let (_temp, store) = store();
    let mut claim = claim_for("payload-command");
    claim.request = CommandRequest::new(
        "payload-command",
        "run_demo",
        &serde_json::json!({ "ignored": true }),
    )
    .unwrap();
    claim.command_id = claim.request.id();
    claim.request_digest = claim.request.digest();
    assert_eq!(
        store.begin(claim, &"b".repeat(64)).unwrap_err().code(),
        "COMMAND_STATE_INVALID"
    );
}

#[test]
fn receipt_transition_requires_both_digests_and_admission_time() {
    let (_temp, store) = store();
    let mut state = store.begin(claim(), &"b".repeat(64)).unwrap();
    state.stage = Stage::ReceiptRetained;
    state.receipt_sha256 = Some("c".repeat(64));
    assert_eq!(
        store.persist(&state).unwrap_err().code(),
        "COMMAND_STATE_INVALID"
    );
    assert_eq!(store.load().unwrap().unwrap().stage, Stage::Claimed);
}

#[test]
fn current_state_symlink_is_never_followed() {
    use std::os::unix::fs::symlink;

    let (_temp, store) = store();
    let outside = store.root.join("outside.json");
    std::fs::write(&outside, b"{}").unwrap();
    symlink(&outside, store.root.join("current.json")).unwrap();
    assert_eq!(store.load().unwrap_err().code(), "COMMAND_STATE_INVALID");
}
