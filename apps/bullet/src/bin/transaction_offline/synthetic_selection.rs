//! Two isolated sequential simulator lanes without selection or receipt authority.

mod assertions;
mod effect_authority;
mod effect_chain;
mod effect_receipt;
mod effect_records;
mod effect_settlement;
mod fault;
mod journal;
mod participant;
mod private_artifact;
mod receipt;
mod receipt_storage;
mod selected_subject;
mod selector;

use self::assertions::{close_lane, require_failed_abort, LaneBarrier};
use self::journal::LaneJournal;
use self::participant::SelectionParticipantClient;
use super::artifact_custody::ArtifactCustody;
use super::farmd_fixture::{spawn_synthetic_farmd, RunnerRegistration, SyntheticFarmd};
use super::runner_probe::register_candidate_source;
use super::scope_admission::{admit_offline_scope, offline_scope_paths};
use super::support::{fail, init_source, private_dir, wait_for};
use bullet_adapters::SqliteLedger;
use bullet_application::lease_transport::SyntheticSelectedAcquireBody;
use bullet_application::{materialize_synthetic_selection, PlanInput};
use bullet_domain::{
    AttemptState, RunnerId, TaskClass, VariantId, WorkPackageId, REPOSITORY_GATE_ID,
};
use bullet_harness_sim::SimAdapter;
use bullet_runner_core::{
    run_attempt, start_heartbeat, AcquireRequest, AttemptConfig, CandidatePreparationAdmission,
    HeartbeatCall, HeartbeatConfig, HeartbeatHandle, LeaseClient, MonotonicClock, ReleaseCall,
};
use chrono::{SecondsFormat, Utc};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const RETAINED_ENV: [&str; 3] = [
    "TRANSACTION_OFFLINE_ARTIFACT_ROOT",
    "TRANSACTION_OFFLINE_RECEIPT",
    "TRANSACTION_OFFLINE_EFFECT_RECEIPT",
];
const CREDENTIAL_ENVS: [&str; 16] = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "SSH_AUTH_SOCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "JERYU_TOKEN",
    "BULLET_CANARY_SECRET",
    "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL",
    "GIT_DIR",
    "GIT_WORK_TREE",
];

struct LaneRun {
    registration: RunnerRegistration,
    variant_id: VariantId,
    grant: bullet_runner_core::AcquireGrant,
    barrier: LaneBarrier,
    workspace_root: PathBuf,
    recovery_file: PathBuf,
}

pub(super) async fn run() -> Result<(), String> {
    preflight()?;
    let custody = ArtifactCustody::synthetic_selection_retained()?;
    let scratch = custody.artifacts().to_path_buf();
    let data = custody.data().to_path_buf();
    let database = data.join("ledger.sqlite");
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut ledger = SqliteLedger::open(&database).map_err(|error| fail(error.to_string()))?;
    admit_offline_scope(&mut ledger, &now)?;
    let graph = materialize_synthetic_selection(
        &mut ledger,
        "df-dog1-two-lane",
        &PlanInput {
            title: "DF-DOG1 synthetic selection".into(),
            objective: "Run two isolated simulator Candidates and select one blinded handle."
                .into(),
            packages: vec![("two isolated lanes".into(), TaskClass::BoundedBugFix)],
        },
        &now,
    )
    .map_err(|error| fail(format!("materialize synthetic graph: {error}")))?;
    if graph.packages.len() != 1 || graph.variants.len() != 2 {
        return Err(fail(
            "synthetic graph is not exactly one package/two Variants",
        ));
    }
    let package = graph.packages[0].id.clone();
    let variants = [graph.variants[0].id.clone(), graph.variants[1].id.clone()];
    if graph
        .variants
        .iter()
        .any(|variant| variant.fence_counter != 0)
    {
        return Err(fail("synthetic Variants are not fresh"));
    }
    let selection_digest = graph.plan.canonical_hash;
    drop(ledger);
    let (source, base) = init_source(&scratch)?;
    let registrations = [
        RunnerRegistration {
            runner_id: RunnerId::from_seed("df-dog1-runner-a"),
            runner_epoch: 1,
        },
        RunnerRegistration {
            runner_id: RunnerId::from_seed("df-dog1-runner-b"),
            runner_epoch: 1,
        },
    ];
    let farmd = spawn_synthetic_farmd(&data, &registrations)?;
    wait_for(&farmd.lease_socket, 120)?;
    wait_for(&farmd.kernel_socket, 120)?;
    configure_kernel_authority(&farmd);

    let lane_a = run_lane(
        0,
        &farmd,
        &registrations[0],
        variants[0].clone(),
        &package,
        selection_digest,
        &database,
        &source,
        &base,
        &scratch,
    )
    .await?;
    let lane_b = run_lane(
        1,
        &farmd,
        &registrations[1],
        variants[1].clone(),
        &package,
        selection_digest,
        &database,
        &source,
        &base,
        &scratch,
    )
    .await?;
    receipt::require_distinct(&lane_a, &lane_b)?;
    farmd.stop()?;
    if fault::before_selection() {
        return Err(fail("SYNTHETIC_DOGFOOD_FAULT_BEFORE_SELECTION"));
    }
    let selection_bytes = receipt::create(
        custody.receipt(),
        &database,
        &scratch,
        selection_digest,
        &package,
        &base,
        [&lane_a, &lane_b],
    )?;
    if fault::after_receipt() {
        return Err(fail("SYNTHETIC_DOGFOOD_FAULT_AFTER_RECEIPT"));
    }
    let selected = selected_subject::seal(&selection_bytes, [&lane_a, &lane_b])?;
    if selected.plan_digest() != selection_digest.to_hex() {
        return Err(fail("sealed selected subject changed the plan digest"));
    }
    let closed =
        effect_chain::run_selected(&database, &data, &scratch, &selected, [&lane_a, &lane_b])
            .await?;
    let bytes = effect_receipt::create(
        custody.effect_receipt(),
        &database,
        &selection_bytes,
        &selected,
        &closed.grant,
        &closed.settlement,
        closed.chain,
    )?;
    if fault::after_effect_receipt() {
        return Err(fail("SYNTHETIC_DOGFOOD_FAULT_AFTER_EFFECT_RECEIPT"));
    }
    println!(
        "{}",
        std::str::from_utf8(&bytes).map_err(|_| fail("effect receipt is not UTF-8"))?
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_lane(
    index: usize,
    farmd: &SyntheticFarmd,
    registration: &RunnerRegistration,
    variant_id: VariantId,
    package: &WorkPackageId,
    selection_digest: bullet_domain::Digest,
    database: &Path,
    source: &Path,
    base: &str,
    scratch: &Path,
) -> Result<LaneRun, String> {
    let selected = SyntheticSelectedAcquireBody::new(
        selection_digest,
        package.clone(),
        registration.runner_id.clone(),
        registration.runner_epoch,
        variant_id.clone(),
        15,
    )
    .map_err(|error| fail(format!("build selected lane {index}: {error}")))?;
    let request = AcquireRequest {
        work_package_id: selected.inner().work_package_id.clone(),
        runner_id: selected.inner().runner_id.clone(),
        runner_epoch: selected.inner().runner_epoch,
        idempotency_key: selected.inner().idempotency_key.clone(),
        ttl_seconds: selected.inner().ttl_seconds,
    };
    let workspace_root = private_dir(&scratch.join(format!("lane-{index}")))?;
    let preservation_destination = scratch.join(format!("lane-{index}-preserved"));
    let journal = Arc::new(
        LaneJournal::create(&workspace_root.join("lane-journal.jsonl"))
            .map_err(|error| fail(format!("create lane journal: {error}")))?,
    );
    let signed = farmd.client(index, registration)?;
    let participant = Arc::new(
        SelectionParticipantClient::new(signed.clone(), selected)
            .map_err(|error| fail(format!("construct lane participant: {error}")))?,
    );
    let grant = participant
        .pre_acquire()
        .await
        .map_err(|error| fail(format!("pre-acquire selected lane {index}: {error}")))?;
    let call = match HeartbeatCall::for_grant(&grant) {
        Ok(call) => call,
        Err(error) => {
            return Err(abort_primed(
                participant.as_ref(),
                None,
                index,
                farmd,
                registration,
                database,
                &grant,
                fail(format!("construct primed heartbeat: {error}")),
            )
            .await)
        }
    };
    let primed_client: Arc<dyn LeaseClient> = participant.clone();
    let primed_heartbeat = match start_heartbeat(
        primed_client,
        call,
        HeartbeatConfig::default(),
        Arc::new(MonotonicClock::new()),
    ) {
        Ok(handle) => handle,
        Err(error) => {
            return Err(abort_primed(
                participant.as_ref(),
                None,
                index,
                farmd,
                registration,
                database,
                &grant,
                fail(format!("start primed heartbeat: {error}")),
            )
            .await)
        }
    };
    let request_digest = match register_candidate_source(&signed, &grant.attempt).await {
        Ok(digest) => digest,
        Err(error) => {
            return Err(abort_primed(
                participant.as_ref(),
                Some(&primed_heartbeat),
                index,
                farmd,
                registration,
                database,
                &grant,
                error,
            )
            .await)
        }
    };
    let setup = (|| {
        if fault::after_acquire() || fault::lane_b_after_acquire(index) {
            let reason = if index == 1 && fault::lane_b_after_acquire(index) {
                "SYNTHETIC_DOGFOOD_FAULT_LANE_B_AFTER_ACQUIRE"
            } else {
                "SYNTHETIC_DOGFOOD_FAULT_AFTER_ACQUIRE"
            };
            return Err(fail(reason));
        }
        let admission = CandidatePreparationAdmission::from_key_file(
            request_digest,
            &farmd.candidate_verification_key,
        )
        .map_err(|error| fail(format!("admit Candidate authority: {error}")))?;
        Ok::<_, String>(
            AttemptConfig::new(
                source.to_path_buf(),
                base.to_owned(),
                workspace_root.clone(),
                "create PONG.txt containing exactly PONG".into(),
                offline_scope_paths(),
                vec![REPOSITORY_GATE_ID.into()],
            )
            .with_candidate_preparation(admission)
            .with_preservation_destination(preservation_destination.clone()),
        )
    })();
    let config = match setup {
        Ok(config) if primed_heartbeat.frozen().is_none() => config,
        Ok(_) => {
            return Err(abort_primed(
                participant.as_ref(),
                Some(&primed_heartbeat),
                index,
                farmd,
                registration,
                database,
                &grant,
                fail("primed heartbeat froze during Candidate setup"),
            )
            .await)
        }
        Err(error) => {
            return Err(abort_primed(
                participant.as_ref(),
                Some(&primed_heartbeat),
                index,
                farmd,
                registration,
                database,
                &grant,
                error,
            )
            .await)
        }
    };
    primed_heartbeat.abort();
    let lease_client: Arc<dyn bullet_runner_core::LeaseClient> = participant.clone();
    let outcome = run_attempt(
        lease_client,
        Arc::new(SimAdapter::new()),
        journal.clone(),
        Arc::new(MonotonicClock::new()),
        &request,
        &config,
    )
    .await
    .map_err(|error| fail(format!("run selected lane {index}: {error}")))?;
    let returned_grant = participant
        .grant()
        .map_err(|error| fail(format!("read selected grant: {error}")))?;
    if returned_grant.attempt != grant.attempt {
        return Err(fail("cached selected grant changed during run_attempt"));
    }
    let settlement = participant
        .settlement_request()
        .map_err(|error| fail(format!("read lane settlement request: {error}")))?;
    let recovery_file = farmd
        .recovery_file(index)
        .ok_or_else(|| fail("lane recovery file is absent"))?
        .to_path_buf();
    let recovered = farmd.client(index, registration)?;
    recovered
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Superseded,
            requeue: true,
        })
        .await
        .map_err(|error| fail(format!("strict recovery terminal replay: {error}")))?;
    let journal_entries = journal
        .reopen()
        .map_err(|error| fail(format!("strict lane journal reopen: {error}")))?;
    let barrier = close_lane(
        database,
        &workspace_root,
        &preservation_destination,
        base,
        &grant,
        &outcome,
        &settlement,
        &journal_entries,
        true,
    )?;
    let mut terminal_grant = grant;
    terminal_grant.attempt.state = AttemptState::Superseded;
    Ok(LaneRun {
        registration: registration.clone(),
        variant_id,
        grant: terminal_grant,
        barrier,
        workspace_root,
        recovery_file,
    })
}

#[allow(clippy::too_many_arguments)]
async fn abort_primed(
    participant: &SelectionParticipantClient,
    heartbeat: Option<&HeartbeatHandle>,
    index: usize,
    farmd: &SyntheticFarmd,
    registration: &RunnerRegistration,
    database: &Path,
    grant: &bullet_runner_core::AcquireGrant,
    original: String,
) -> String {
    if let Some(heartbeat) = heartbeat {
        heartbeat.abort();
    }
    if let Err(error) = participant.abort_primed_failed().await {
        return fail(format!("{original}; primed abort outcome UNKNOWN: {error}"));
    }
    let settlement = match participant.settlement_request() {
        Ok(request) => request,
        Err(error) => return fail(format!("{original}; primed abort request absent: {error}")),
    };
    let recovered = match farmd.client(index, registration) {
        Ok(client) => client,
        Err(error) => return fail(format!("{original}; primed recovery reopen: {error}")),
    };
    if let Err(error) = recovered
        .release(&ReleaseCall {
            attempt_id: grant.attempt.id.clone(),
            outcome: AttemptState::Failed,
            requeue: true,
        })
        .await
    {
        return fail(format!(
            "{original}; primed recovery replay UNKNOWN: {error}"
        ));
    }
    match require_failed_abort(database, grant, &settlement) {
        Ok(()) => original,
        Err(error) => fail(format!("{original}; primed abort readback failed: {error}")),
    }
}

fn configure_kernel_authority(farmd: &SyntheticFarmd) {
    std::env::set_var("BULLET_KERNEL_AUTHORITY_SOCKET", &farmd.kernel_socket);
    std::env::set_var(
        "BULLET_KERNEL_AUTHORITY_SERVER_UID",
        farmd.farmd_uid.to_string(),
    );
    std::env::set_var(
        "BULLET_KERNEL_AUTHORITY_SOCKET_GID",
        farmd.socket_gid.to_string(),
    );
}

fn preflight() -> Result<(), String> {
    fault::preflight()?;
    super::chaos::admit_debug_selection()?;
    if let Some(name) = RETAINED_ENV
        .iter()
        .find(|name| std::env::var_os(name).is_none())
    {
        return Err(fail(format!(
            "SYNTHETIC_DOGFOOD_RETAINED_OUTPUT_REQUIRED: {name}"
        )));
    }
    if let Some(name) = CREDENTIAL_ENVS
        .iter()
        .find(|name| std::env::var_os(name).is_some())
    {
        return Err(fail(format!(
            "SYNTHETIC_DOGFOOD_CREDENTIAL_REFUSED: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_identity_check_requires_every_subject_to_differ() {
        assert_eq!(RETAINED_ENV.len(), 3);
        assert_eq!(CREDENTIAL_ENVS.len(), 16);
    }
}
