//! One product Runner Candidate through preservation, verification, and LocalBare closure.

use super::artifact_custody::ArtifactCustody;
use super::attempt_cleanup::{failed_attempt, settle_attempt};
use super::chaos::{self, Boundary};
use super::command_input::admit_command_input;
use super::forge_chain::close_local_forge;
use super::runner_probe::run_product_runner;
use super::scope_admission::{admit_offline_scope, offline_scope_paths};
use super::signed_verification::verify_candidate;
use super::support::*;
use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, CommandRequest, Ledger, PlanInput};
use bullet_domain::{AttemptState, RunnerId, TaskClass};
use bullet_effects_core::{
    authorize, dispatch, propose, reconcile, IntentInput, LocalBareForge, LossMode,
    LostResponseForge, ReconcileOutcome, ZERO_OID,
};
use bullet_runner_core::lease::{AcquireRequest, HeartbeatCall, LeaseClient};
use bullet_runner_core::RunnerError;
use chrono::{SecondsFormat, Utc};
use serde_json::json;
use std::{fs, path::PathBuf, time::Duration};

pub(crate) async fn run() -> Result<(), String> {
    let command_dispatch = admit_command_input()?;
    chaos::admit_debug_selection()?;
    let scratch_guard = ArtifactCustody::create()?;
    let scratch = private_dir(scratch_guard.path())?;
    let data = match std::env::var_os("BULLET_DATA_DIR") {
        Some(path) => private_dir(&PathBuf::from(path))?,
        None => private_dir(&scratch.join("data"))?,
    };
    scratch_guard.admit_data_dir(&data)?;
    let db = data.join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&db).map_err(|err| fail(err.to_string()))?;
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let granted_scope = offline_scope_paths();
    let scope_admission = admit_offline_scope(&mut ledger, &now)?;
    let graph = materialize_plan(
        &mut ledger,
        "txn-proof-demo",
        &PlanInput {
            title: "Offline COMPONENT_PROOF".into(),
            objective: "Fail-closed local component bridge without live providers.".into(),
            packages: vec![
                ("offline Candidate author".into(), TaskClass::BoundedBugFix),
                (
                    "offline effect authority".into(),
                    TaskClass::MechanicalCodeEdit,
                ),
            ],
        },
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    let [author_package, effect_package] = graph.packages.as_slice() else {
        return Err(fail(
            "demo graph does not have exact author/effect packages",
        ));
    };
    let command = CommandRequest::new(
        "txn-proof-demo",
        "run_demo",
        &json!({ "evidence_class": "COMPONENT_PROOF" }),
    )
    .map_err(|err| fail(err.to_string()))?;
    let command = ledger
        .submit_command(&command)
        .map_err(|err| fail(err.to_string()))?;
    drop(ledger);

    let runner = RunnerId::from_seed("txn-offline-runner");
    let farmd = spawn_durable_farmd(&data, &runner, 1)?;
    let key_document: serde_json::Value = serde_json::from_slice(
        &fs::read(&farmd.candidate_verification_key)
            .map_err(|error| fail(format!("read Candidate verification key: {error}")))?,
    )
    .map_err(|error| fail(format!("decode Candidate verification key: {error}")))?;
    if key_document
        .get("public_key_hex")
        .and_then(serde_json::Value::as_str)
        != Some(farmd.candidate_verification_key_material.public_key_hex())
    {
        return Err(fail(
            "Candidate verification key file differs from the in-process subject",
        ));
    }
    let lease_socket = farmd.lease_socket.clone();
    wait_for(&lease_socket, 120)?;
    wait_for(&farmd.kernel_socket, 120)?;
    std::env::set_var("BULLET_KERNEL_AUTHORITY_SOCKET", &farmd.kernel_socket);
    std::env::set_var(
        "BULLET_KERNEL_AUTHORITY_SERVER_UID",
        farmd.farmd_uid.to_string(),
    );
    std::env::set_var(
        "BULLET_KERNEL_AUTHORITY_SOCKET_GID",
        farmd.socket_gid.to_string(),
    );
    let client = admitted_lease_client(
        lease_socket.clone(),
        data.join("controller-recovery.json"),
        &runner,
        1,
    )?;
    let (source, base) = init_source(&scratch)?;

    let runner_execution = run_product_runner(
        &farmd,
        &client,
        &lease_socket,
        &runner,
        &author_package.id,
        &db,
        &source,
        &base,
        &scratch,
        &granted_scope,
    )
    .await?;
    let first = runner_execution.author_grant.clone();
    if first.attempt.fence != 1 {
        return Err(fail(format!(
            "product author fence was {}, expected 1",
            first.attempt.fence
        )));
    }

    let second = client
        .acquire(&AcquireRequest {
            work_package_id: effect_package.id.clone(),
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: "txn-demo-effect-authority".into(),
            ttl_seconds: 15,
        })
        .await
        .map_err(|error| fail(error.to_string()))?;
    if second.attempt.fence == 0 || second.attempt.id == first.attempt.id {
        let error = fail(format!(
            "effect-authority Attempt/fence was not distinct and positive: {} / {}",
            second.attempt.id, second.attempt.fence
        ));
        return Err(failed_attempt(None, &client, &db, &second, error).await);
    }
    let successor_call = HeartbeatCall::for_grant(&second)
        .map_err(|error| fail(format!("effect-authority heartbeat: {error}")))?;
    let successor_heartbeat = LeaseHeartbeatGuard::start(&client, successor_call);
    let stale = client
        .heartbeat(&HeartbeatCall {
            variant_id: first.lease.variant_id.clone(),
            attempt_id: first.attempt.id.clone(),
            fence: first.attempt.fence,
            runner_id: runner.clone(),
            runner_epoch: 1,
            workspace_nonce: first.authority_token.workspace_nonce,
            ttl_seconds: 15,
        })
        .await;
    let stale_refused = match stale {
        Err(RunnerError::Lease { code, .. }) if code == "LEASE_NOT_ACTIVE" => true,
        Err(error) => {
            let unknown = fail(format!(
                "stale author heartbeat was UNKNOWN: {}: {error}",
                error.reason_code()
            ));
            return Err(
                failed_attempt(Some(successor_heartbeat), &client, &db, &second, unknown).await,
            );
        }
        Ok(()) => {
            let error = fail("stale author heartbeat was accepted");
            return Err(
                failed_attempt(Some(successor_heartbeat), &client, &db, &second, error).await,
            );
        }
    };

    let candidate = &runner_execution.candidate;
    let candidate_id = candidate.id.clone();
    let head = candidate.head_commit.clone();
    let tree = candidate.tree_hash.clone();
    let verifier_repo = runner_execution.candidate_repository.clone();
    let effect_now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let close = close_candidate(
        &db,
        &scratch,
        &effect_now,
        &first,
        &second,
        candidate,
        &verifier_repo,
    )
    .await;
    let (verification, unknown, settled, forge_closure) = match close {
        Ok(closed) => closed,
        Err(error) => {
            return Err(
                failed_attempt(Some(successor_heartbeat), &client, &db, &second, error).await,
            )
        }
    };
    settle_attempt(
        Some(successor_heartbeat),
        &client,
        &db,
        &second,
        AttemptState::Superseded,
    )
    .await?;

    let provider_execution = runner_execution.provider_execution.into_receipt();
    let subject = json!({
        "schema_version": "v1alpha1",
        "evidence_class": "COMPONENT_PROOF",
        "signing_trust": "UNSIGNED_FIXTURE",
        "transaction_gate_eligible": false,
        "independent_evidence_eligible": false,
        "artifact_custody": {
            "retained": scratch_guard.is_retained(),
            "artifact_root_relative": "artifacts",
            "source_repository_relative": "artifacts/source",
            "candidate_repository_relative": "artifacts/preserve/generation/repo",
            "local_forge_relative": "artifacts/effects/target.git",
            "ledger_relative": "data/ledger.sqlite",
            "candidate_id": &candidate_id,
            "base_oid": strip_oid(&candidate.base_commit),
            "head_oid": strip_oid(&head),
            "tree_oid": strip_oid(&tree),
            "target_ref": "refs/heads/main",
            "target_oid": strip_oid(&head),
        },
        "gitd_fixture": false,
        "unknown_then_adopt": true,
        "fence_first": first.attempt.fence,
        "fence_second": second.attempt.fence,
        "attempt_first": first.attempt.id.to_string(),
        "attempt_second": second.attempt.id.to_string(),
        "candidate_id": &candidate_id,
        "base_oid": strip_oid(&candidate.base_commit),
        "head_oid": strip_oid(&head),
        "tree_oid": strip_oid(&tree),
        "verifier_outcome": &verification.verifier_outcome,
        "writer_proof_refused": verification.writer_proof_refused,
        "signed_verification": verification,
        "effect_unknown": unknown.as_str(),
        "effect_settled": settled.as_str(),
        "effect_delivered_oid": &forge_closure.delivered_oid,
        "effect_candidate_bound": forge_closure.effect_candidate_bound,
        "local_forge": forge_closure,
        "stale_refused": stale_refused,
        "scope_grant_id": scope_admission.scope_grant_id,
        "scope_paths_digest": scope_admission.scope_paths_digest,
        "scope_authority_epoch": scope_admission.new_authority_epoch,
        "command_id": command.id.to_string(),
        "command_phase": command.phase.as_str(),
        "command_dispatch": command_dispatch,
        "provider_execution": provider_execution,
        "children": {
            "farmd": "bullet-farmd",
            "runner": "bullet-runner",
            "gitd": "bullet-gitd",
            "verifier": "bullet-verifier-fixture"
        },
        "product_runner_gate_passed": runner_execution.gate_passed,
        "product_runner_outcome": runner_execution.outcome,
        "product_runner_candidate_id": &candidate_id,
        "product_runner_preservation": runner_execution.preservation,
    });
    let proof_json =
        serde_json::to_string_pretty(&subject).map_err(|error| fail(error.to_string()))?;
    let proof_path = match std::env::var_os("TRANSACTION_OFFLINE_RECEIPT") {
        Some(path) => PathBuf::from(path),
        None => data.join("COMPONENT_PROOF.receipt.json"),
    };
    fs::write(&proof_path, &proof_json).map_err(|error| fail(error.to_string()))?;
    println!("{proof_json}");
    println!("COMPONENT_PROOF: {}", proof_path.display());
    farmd.stop()?;
    scratch_guard.finish()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn close_candidate(
    database: &std::path::Path,
    scratch: &std::path::Path,
    now: &str,
    author: &bullet_runner_core::AcquireGrant,
    effect_grant: &bullet_runner_core::AcquireGrant,
    candidate: &bullet_runner_core::CandidateReceipt,
    repository: &std::path::Path,
) -> Result<
    (
        super::signed_verification::SignedVerificationClosure,
        bullet_application::EffectState,
        bullet_application::EffectState,
        super::forge_chain::LocalForgeClosure,
    ),
    String,
> {
    for boundary in [
        Boundary::WorkspaceOpen,
        Boundary::ProviderCompletion,
        Boundary::PatchApply,
        Boundary::CandidatePreparation,
        Boundary::Checkpoint,
    ] {
        chaos::refuse_if_selected(boundary)?;
    }
    chaos::refuse_if_selected(Boundary::VerifierHandoff)?;
    let verification = verify_candidate(
        &candidate.id,
        repository,
        strip_oid(&candidate.base_commit),
        strip_oid(&candidate.head_commit),
        strip_oid(&candidate.tree_hash),
        author.attempt.id.as_str(),
        &author.authority_token.policy_snapshot_hash.to_hex(),
    )
    .await?;
    let effects_root = scratch.join("effects");
    fs::create_dir_all(&effects_root).map_err(|error| fail(error.to_string()))?;
    let mut effects = SqliteLedger::open(database).map_err(|error| fail(error.to_string()))?;
    let forge = LocalBareForge::init(&effects_root.join("target.git"))
        .map_err(|error| fail(error.to_string()))?;
    let token = &effect_grant.authority_token;
    let intent = IntentInput {
        provider: "local-bare".into(),
        logical_effect_key: format!("push:{}:{}", candidate.id, effect_grant.attempt.fence),
        target_ref: format!("refs/heads/bullet/candidate/{}", candidate.id),
        new_oid: strip_oid(&candidate.head_commit).to_owned(),
        expected_old_oid: ZERO_OID.into(),
        attempt_id: token.attempt_id.clone(),
        fence: token.attempt_fence,
        policy_version: "policy-v1".into(),
        provider_idempotency_key: None,
    };
    let (row, _) = propose(&mut effects, &intent, now).map_err(|error| fail(error.to_string()))?;
    let (_, seq) = authorize_with_retry(&mut effects, &row.id, token, now)?;
    let mut lossy = LostResponseForge::new(forge);
    lossy.lose_next(LossMode::AfterPush);
    chaos::refuse_if_selected(Boundary::CandidateDelivery)?;
    let unknown = dispatch(
        &mut effects,
        &mut lossy,
        &row.id,
        repository,
        Some(seq),
        now,
    )
    .map_err(|error| fail(error.to_string()))?;
    if unknown != bullet_application::EffectState::OutcomeUnknown {
        return Err(fail(format!("lost response was {unknown:?}, not UNKNOWN")));
    }
    let adopted = reconcile(
        &mut effects,
        &mut lossy,
        &row.id,
        repository,
        Some(seq),
        now,
    )
    .map_err(|error| fail(error.to_string()))?;
    if adopted != ReconcileOutcome::Adopted {
        return Err(fail(format!("expected Adopted, got {adopted:?}")));
    }
    let settled = effects
        .get_effect_intent_by_id(&row.id)
        .map_err(|error| fail(error.to_string()))?
        .map(|record| record.state)
        .ok_or_else(|| fail("settled intent missing"))?;
    let closure = close_local_forge(
        lossy,
        &intent.target_ref,
        &candidate.id,
        &candidate.base_commit,
        &candidate.head_commit,
        verification.proof_bundle_id(),
        verification.proof_root(),
    )?;
    verification.validate_selected(
        &candidate.id,
        repository,
        strip_oid(&candidate.base_commit),
        strip_oid(&candidate.head_commit),
        strip_oid(&candidate.tree_hash),
        author.attempt.id.as_str(),
        &author.authority_token.policy_snapshot_hash.to_hex(),
    )?;
    closure.validate_selected(
        &candidate.id,
        strip_oid(&candidate.base_commit),
        strip_oid(&candidate.head_commit),
        verification.proof_bundle_id(),
        verification.proof_root(),
    )?;
    Ok((verification, unknown, settled, closure))
}

fn authorize_with_retry(
    effects: &mut SqliteLedger,
    effect_id: &bullet_domain::EffectId,
    token: &bullet_domain::AuthorityToken,
    now: &str,
) -> Result<(bullet_application::EffectIntentRecord, u64), String> {
    let mut last = None;
    for _ in 0..8 {
        match authorize(effects, effect_id, token, now) {
            Ok(authorized) => return Ok(authorized),
            Err(error) => {
                last = Some(error.to_string());
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(fail(last.unwrap_or_else(|| "authorize failed".into())))
}
