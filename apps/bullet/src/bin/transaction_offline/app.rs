//! Offline component bridge through durable farmd UDS, Runner, production gitd, verifier, and LocalBareForge.
use super::artifact_custody::ArtifactCustody;
use super::attempt_cleanup::{failed_attempt, settle_attempt};
use super::chaos::{self, Boundary};
use super::command_input::admit_command_input;
use super::direct_candidate::authorized_candidate_grant;
use super::forge_chain::close_local_forge;
use super::gitd_setup::{prepare_gitd, GitdSetup};
use super::runner_probe::run_product_runner;
use super::scope_admission::{admit_offline_scope, offline_scope_paths};
use super::signed_verification::verify_candidate;
use super::sim_provider::run_sim_provider;
use super::support::*;
use bullet_adapters::SqliteLedger;
use bullet_application::{materialize_plan, CommandRequest, Ledger, PlanInput};
use bullet_domain::{AttemptState, RunnerId, TaskClass, REPOSITORY_GATE_ID};
use bullet_effects_core::{
    authorize, dispatch, propose, reconcile, IntentInput, LocalBareForge, LossMode,
    LostResponseForge, ReconcileOutcome, ZERO_OID,
};
use bullet_runner_core::lease::{AcquireRequest, HeartbeatCall, LeaseClient};
use bullet_runner_core::{Capsule, RunnerError};
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
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
            packages: vec![("offline component bridge".into(), TaskClass::BoundedBugFix)],
        },
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    let package = graph
        .packages
        .first()
        .ok_or_else(|| fail("demo graph has no package"))?
        .clone();
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
    let socket = farmd.lease_socket.clone();
    wait_for(&socket, 120)?;
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
    let lease_socket = socket.clone();
    let client = admitted_lease_client(socket, &runner, 1)?;
    let first = match client
        .acquire(&AcquireRequest {
            work_package_id: package.id.clone(),
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: "txn-demo-a1".into(),
            ttl_seconds: 15,
        })
        .await
    {
        Ok(grant) => grant,
        Err(error) => return Err(fail(error.to_string())),
    };
    let heartbeat_call = match (|| {
        if first.attempt.fence != 1 {
            return Err(fail(format!(
                "first fence was {}, expected 1",
                first.attempt.fence
            )));
        }
        chaos::refuse_if_selected(Boundary::GrantPersistence)?;
        HeartbeatCall::for_grant(&first).map_err(|error| fail(error.to_string()))
    })() {
        Ok(call) => call,
        Err(error) => return Err(failed_attempt(None, &client, &db, &first, error).await),
    };
    let heartbeat = LeaseHeartbeatGuard::start(&client, heartbeat_call);
    let GitdSetup {
        mut session,
        source,
        base,
        work_root,
    } = match prepare_gitd(&scratch, &first).await {
        Ok(setup) => setup,
        Err(error) => {
            return Err(failed_attempt(Some(heartbeat), &client, &db, &first, error).await)
        }
    };
    let gitd = &mut session;
    let gitd_work = async {
    let workspace = match gitd
        .clone_workspace(
            &source,
            &base,
            &work_root,
            &granted_scope,
        )
        .await
    {
        Ok(workspace) => workspace,
        Err(error) => return Err(fail(error.to_string())),
    };
    chaos::refuse_if_selected(Boundary::WorkspaceOpen)?;
    let capsule = Capsule {
        objective: "create PONG.txt containing exactly PONG".into(),
        scope_prefixes: granted_scope.clone(),
        base_sha: workspace.base_sha.clone(),
        producing_attempt_id: first.attempt.id.to_string(),
        base_checkpoint_id: workspace.base_checkpoint_id.clone(),
        base_checkpoint_digest: workspace.base_checkpoint_digest.clone(),
        admitted_gate_ids: vec![REPOSITORY_GATE_ID.into()],
    };
    let provider_execution = run_sim_provider(
        &capsule,
        &workspace.repo_dir,
        &scratch.join("provider-artifacts"),
    )
    .await?;
    let applied = match gitd.apply_proposal(&provider_execution.proposal).await {
        Ok(applied) => applied,
        Err(error) => return Err(fail(error.to_string())),
    };
    chaos::refuse_if_selected(Boundary::PatchApply)?;
    let (candidate_claims, candidate_grant) =
        authorized_candidate_grant(&farmd, &client, &db, &first.attempt).await?;
    let candidate_carrier = serde_json::to_value(candidate_grant)
        .map_err(|error| fail(format!("encode direct Candidate grant: {error}")))?;
    let prepare = match gitd
        .invoke(
            "prepare_candidate",
            json!({
                "change": {
                    "id": candidate_claims.change_id,
                    "mission": candidate_claims.mission_id,
                    "acceptance_root": first.authority_token.acceptance_contract_id.as_str()
                        .strip_prefix("acc_").ok_or_else(|| fail("acceptance contract prefix"))?
                },
                "provenance": {
                    "schema_version": 1,
                    "repository_id": candidate_claims.repository_id,
                    "producing_attempt_id": candidate_claims.attempt_id,
                    "attempt_fence": candidate_claims.attempt_fence,
                    "work_package_id": candidate_claims.work_package_id,
                    "variant_id": candidate_claims.variant_id,
                    "plan_revision_id": candidate_claims.plan_revision_id,
                    "graph_revision_id": candidate_claims.graph_revision_id,
                    "base_checkpoint_id": applied.checkpoint.id,
                    "base_commit": workspace.base_sha,
                    "parent_candidate_ids": [],
                    "granted_scope": &granted_scope,
                    "context_capsule_id": candidate_claims.context_capsule_id,
                    "configuration_snapshot_id": format!("cnt_{}", first.authority_token.config_snapshot_hash.to_hex()),
                    "policy_snapshot_id": format!("cnt_{}", first.authority_token.policy_snapshot_hash.to_hex()),
                    "routing_snapshot_id": format!("cnt_{}", first.authority_token.routing_policy_hash.to_hex()),
                    "environment_digest": candidate_claims.environment_digest,
                    "toolchain_digest": candidate_claims.toolchain_digest
                },
                "candidate_preparation_grant": candidate_carrier
            }),
        )
        .await
    {
        Ok(prepare) => prepare,
        Err(error) => return Err(fail(format!("prepare_candidate: {error}"))),
    };
    let candidate_id = prepare
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| fail(format!("candidate id missing: {prepare}")))?
        .to_string();
    let head = prepare
        .get("head_commit")
        .or_else(|| prepare.pointer("/manifest/head_commit"))
        .and_then(Value::as_str)
        .ok_or_else(|| fail(format!("head missing: {prepare}")))?
        .to_string();
    let tree = prepare
        .get("tree_hash")
        .or_else(|| prepare.get("tree_oid"))
        .or_else(|| prepare.pointer("/manifest/tree_oid"))
        .and_then(Value::as_str)
        .ok_or_else(|| fail(format!("tree missing: {prepare}")))?
        .to_string();
    chaos::refuse_if_selected(Boundary::CandidatePreparation)?;
    let preserve_to = scratch.join("preserve");
    gitd.preserve(&preserve_to)
        .await
        .map_err(|error| fail(format!("preserve Candidate: {error}")))?;
    chaos::refuse_if_selected(Boundary::Checkpoint)?;
    let verifier_repo = preserve_to.join("generation/repo");
    if !verifier_repo.is_dir() {
        return Err(fail("preserved Candidate repository is missing"));
    }

    chaos::refuse_if_selected(Boundary::VerifierHandoff)?;
    let verification = verify_candidate(
        &candidate_id,
        &verifier_repo,
        strip_oid(&workspace.base_sha),
        strip_oid(&head),
        strip_oid(&tree),
        first.attempt.id.as_str(),
        &first.authority_token.policy_snapshot_hash.to_hex(),
    )
    .await?;
    let effects_root = scratch.join("effects");
    fs::create_dir_all(&effects_root).map_err(|err| fail(err.to_string()))?;
    let effect_head = strip_oid(&head).to_owned();
    let mut effects = SqliteLedger::open(&db).map_err(|err| fail(err.to_string()))?;
    let token_ref = &first.authority_token;
    let forge = LocalBareForge::init(&effects_root.join("target.git"))
        .map_err(|err| fail(err.to_string()))?;
    let intent = IntentInput {
        provider: "local-bare".into(),
        logical_effect_key: format!("push:{candidate_id}:{}", first.attempt.fence),
        target_ref: format!("refs/heads/bullet/candidate/{candidate_id}"),
        new_oid: effect_head,
        expected_old_oid: ZERO_OID.into(),
        attempt_id: token_ref.attempt_id.clone(),
        fence: token_ref.attempt_fence,
        policy_version: "policy-v1".into(),
        provider_idempotency_key: None,
    };
    let (row, _) = propose(&mut effects, &intent, &now).map_err(|err| fail(err.to_string()))?;
    let (_authorized, seq) = {
        let mut last = None;
        let mut authorized = None;
        for _ in 0..8 {
            match authorize(&mut effects, &row.id, token_ref, &now) {
                Ok(ok) => {
                    authorized = Some(ok);
                    break;
                }
                Err(error) => {
                    last = Some(error.to_string());
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        authorized.ok_or_else(|| fail(last.unwrap_or_else(|| "authorize failed".into())))?
    };
    let mut lossy = LostResponseForge::new(forge);
    lossy.lose_next(LossMode::AfterPush);
    chaos::refuse_if_selected(Boundary::CandidateDelivery)?;
    let unknown = dispatch(
        &mut effects,
        &mut lossy,
        &row.id,
        &verifier_repo,
        Some(seq),
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    if unknown != bullet_application::EffectState::OutcomeUnknown {
        return Err(fail(format!("lost response was {unknown:?}, not UNKNOWN")));
    }
    let adopted = reconcile(
        &mut effects,
        &mut lossy,
        &row.id,
        &verifier_repo,
        Some(seq),
        &now,
    )
    .map_err(|err| fail(err.to_string()))?;
    if adopted != ReconcileOutcome::Adopted {
        return Err(fail(format!("expected Adopted, got {adopted:?}")));
    }
    let settled = effects
        .get_effect_intent_by_id(&row.id)
        .map_err(|err| fail(err.to_string()))?
        .map(|record| record.state)
        .ok_or_else(|| fail("settled intent missing"))?;
    let forge_closure = close_local_forge(
        lossy,
        &intent.target_ref,
        &candidate_id,
        &base,
        &head,
        verification.proof_bundle_id(),
        verification.proof_root(),
    )?;
    Ok((
        candidate_id,
        head,
        tree,
        verification,
        unknown,
        settled,
        forge_closure,
        provider_execution,
    ))
    }
    .await;
    let gitd_shutdown = gitd.kill().await.map_err(|error| fail(error.to_string()));
    let completed = match (gitd_work, gitd_shutdown) {
        (Ok(work), Ok(())) => Ok(work),
        (Err(work), Ok(())) => Err(work),
        (Ok(_), Err(shutdown)) => Err(shutdown),
        (Err(work), Err(shutdown)) => {
            Err(fail(format!("{work}; gitd shutdown failed: {shutdown}")))
        }
    };
    let (
        candidate_id,
        head,
        tree,
        verification,
        unknown,
        settled,
        forge_closure,
        provider_execution,
    ) = match completed {
        Ok(work) => work,
        Err(work) => {
            return Err(failed_attempt(Some(heartbeat), &client, &db, &first, work).await);
        }
    };
    settle_attempt(
        Some(heartbeat),
        &client,
        &db,
        &first,
        AttemptState::Superseded,
    )
    .await?;
    let second = match client
        .acquire(&AcquireRequest {
            work_package_id: package.id.clone(),
            runner_id: runner.clone(),
            runner_epoch: 1,
            idempotency_key: "txn-demo-a2".into(),
            ttl_seconds: 15,
        })
        .await
    {
        Ok(grant) => grant,
        Err(error) => return Err(fail(error.to_string())),
    };
    if second.attempt.fence != 2 {
        let error = fail(format!(
            "successor fence was {}, expected 2",
            second.attempt.fence
        ));
        return Err(failed_attempt(None, &client, &db, &second, error).await);
    }
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
        Err(RunnerError::Lease { code, .. }) if code == "LEASE_FENCE_STALE" => true,
        Err(error) => {
            let unknown = fail(format!(
                "stale fence heartbeat was UNKNOWN: {}: {error}",
                error.reason_code()
            ));
            return Err(failed_attempt(None, &client, &db, &second, unknown).await);
        }
        Ok(()) => {
            let error = fail("stale fence heartbeat was accepted");
            return Err(failed_attempt(None, &client, &db, &second, error).await);
        }
    };
    settle_attempt(None, &client, &db, &second, AttemptState::Superseded).await?;

    let runner_execution = run_product_runner(
        &farmd,
        &client,
        &lease_socket,
        &runner,
        &package.id,
        &db,
        &source,
        &base,
        &scratch,
        &granted_scope,
    )
    .await?;

    let provider_execution = provider_execution.into_receipt();
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
            "base_oid": strip_oid(&base),
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
        "candidate_id": candidate_id,
        "base_oid": strip_oid(&base),
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
        "product_runner_candidate_id": runner_execution.candidate_id,
    });
    if second.attempt.fence != first.attempt.fence + 1 {
        return Err(fail("fence pair is not successor"));
    }
    let proof_json = serde_json::to_string_pretty(&subject).map_err(|err| fail(err.to_string()))?;
    let proof_path = match std::env::var_os("TRANSACTION_OFFLINE_RECEIPT") {
        Some(path) => PathBuf::from(path),
        None => data.join("COMPONENT_PROOF.receipt.json"),
    };
    fs::write(&proof_path, &proof_json).map_err(|err| fail(err.to_string()))?;
    println!("{proof_json}");
    println!("COMPONENT_PROOF: {}", proof_path.display());
    farmd.stop()?;
    scratch_guard.finish()?;
    Ok(())
}
