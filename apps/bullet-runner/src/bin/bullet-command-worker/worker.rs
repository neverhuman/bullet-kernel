//! Restart-safe command claim, component execution, and UNKNOWN settlement.

use super::claim_fd::SealedClaim;
use super::error::WorkerError;
use super::manifest::AdmittedManifest;
use super::receipt::{admit_receipt, readback_retained_receipt, AdmittedReceipt};
use super::state::{Stage, StateStore, WorkerState};
use bullet_application::{CommandDispatchClaim, CommandRecord, ComponentCommandCompletionV1};
use bullet_domain::{CommandPhase, Digest, RunnerId};
use bullet_runner_core::SignedLeaseRpcClient;
use std::future::Future;
use std::time::Duration;

trait DispatchPort {
    fn claim(&self) -> impl Future<Output = Result<Option<CommandDispatchClaim>, String>> + Send;
    fn readback(&self)
        -> impl Future<Output = Result<Option<CommandDispatchClaim>, String>> + Send;
    fn settle(
        &self,
        claim_id: &str,
        completion: &ComponentCommandCompletionV1,
    ) -> impl Future<Output = Result<CommandRecord, String>> + Send;
}

impl DispatchPort for SignedLeaseRpcClient {
    async fn claim(&self) -> Result<Option<CommandDispatchClaim>, String> {
        self.claim_command_dispatch()
            .await
            .map_err(|error| error.to_string())
    }

    async fn readback(&self) -> Result<Option<CommandDispatchClaim>, String> {
        self.readback_command_dispatch()
            .await
            .map_err(|error| error.to_string())
    }

    async fn settle(
        &self,
        claim_id: &str,
        completion: &ComponentCommandCompletionV1,
    ) -> Result<CommandRecord, String> {
        self.settle_component_command_dispatch(claim_id, completion)
            .await
            .map_err(|error| error.to_string())
    }
}

pub(super) async fn run_once(
    client: &SignedLeaseRpcClient,
    store: &StateStore,
    manifest: &AdmittedManifest,
    deadline: Duration,
    expected_runner: &RunnerId,
    expected_runner_epoch: u64,
) -> Result<bool, WorkerError> {
    run_once_with(
        client,
        store,
        manifest,
        deadline,
        expected_runner,
        expected_runner_epoch,
    )
    .await
}

async fn run_once_with<C: DispatchPort>(
    client: &C,
    store: &StateStore,
    manifest: &AdmittedManifest,
    deadline: Duration,
    expected_runner: &RunnerId,
    expected_runner_epoch: u64,
) -> Result<bool, WorkerError> {
    let retained = store.load()?;
    let state = if let Some(state) = retained.filter(|state| state.stage != Stage::SettledUnknown) {
        state
    } else {
        let Some(claim) = acquire_claim(client).await? else {
            return Ok(false);
        };
        store.begin(claim, manifest.sha256())?
    };
    if state.binary_manifest_sha256 != manifest.sha256() {
        return Err(WorkerError::input(
            "BINARY_MANIFEST_DRIFT",
            "retained claim uses another binary manifest",
        ));
    }
    validate_runner_subject(&state, expected_runner, expected_runner_epoch)?;
    let (state, receipt) = admit_or_execute(store, manifest, state, deadline)?;
    settle_retained(client, store, state, &receipt).await?;
    Ok(true)
}

fn validate_runner_subject(
    state: &WorkerState,
    expected_runner: &RunnerId,
    expected_runner_epoch: u64,
) -> Result<(), WorkerError> {
    if state.claim.runner_id != *expected_runner
        || state.claim.runner_epoch != expected_runner_epoch
    {
        return Err(WorkerError::input(
            "COMMAND_RUNNER_SUBJECT_MISMATCH",
            "retained claim belongs to another Runner incarnation",
        ));
    }
    Ok(())
}

async fn acquire_claim<C: DispatchPort>(
    client: &C,
) -> Result<Option<CommandDispatchClaim>, WorkerError> {
    match client.readback().await {
        Ok(Some(claim)) => Ok(Some(claim)),
        Ok(None) => match client.claim().await {
            Ok(claim) => Ok(claim),
            Err(_) => client.readback().await.map_err(|error| {
                WorkerError::input(
                    "COMMAND_CLAIM_UNKNOWN",
                    format!("read back claim after response loss: {error}"),
                )
            }),
        },
        Err(error) => Err(WorkerError::input("COMMAND_CLAIM_READBACK_FAILED", error)),
    }
}

fn admit_or_execute(
    store: &StateStore,
    manifest: &AdmittedManifest,
    state: WorkerState,
    deadline: Duration,
) -> Result<(WorkerState, AdmittedReceipt), WorkerError> {
    let run_root = store.run_root(&state);
    let receipt_path = store.receipt_path(&state);
    let has_child_material = child_material_exists(&run_root, &receipt_path)?;
    let admitted = match state.stage {
        Stage::Claimed => {
            if !has_child_material {
                let sealed = SealedClaim::create(&state.claim)?;
                let output = super::child::run_transaction(
                    manifest,
                    &sealed,
                    &run_root,
                    &receipt_path,
                    deadline,
                )?;
                if !output.status.success() {
                    return Err(WorkerError::input(
                        "COMMAND_CHILD_FAILED",
                        format!(
                            "transaction child exited {:?}: {}",
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    ));
                }
                let _bounded_stdout = output.stdout;
            }
            admit_receipt(&receipt_path, &run_root, &state.claim, manifest.sha256())?
        }
        Stage::ReceiptRetained => readback_retained_receipt(
            &receipt_path,
            &run_root,
            &state.claim,
            manifest.sha256(),
            state.receipt_sha256.as_deref().ok_or_else(|| {
                WorkerError::input("COMMAND_STATE_INVALID", "retained receipt SHA-256 absent")
            })?,
            state.receipt_digest.ok_or_else(|| {
                WorkerError::input("COMMAND_STATE_INVALID", "retained receipt digest absent")
            })?,
        )?,
        Stage::SettledUnknown => {
            return Err(WorkerError::input(
                "COMMAND_STATE_INVALID",
                "settled state cannot execute",
            ))
        }
    };
    match state.stage {
        Stage::Claimed => {
            let retained = state.retain_receipt(
                admitted.raw_sha256().into(),
                admitted.receipt_digest(),
                current_unix_ms()?,
            )?;
            store.persist(&retained)?;
            Ok((retained, admitted))
        }
        Stage::ReceiptRetained => {
            if state.receipt_sha256.as_deref() != Some(admitted.raw_sha256())
                || state.receipt_digest != Some(admitted.receipt_digest())
            {
                return Err(WorkerError::input(
                    "COMMAND_RECEIPT_DRIFT",
                    "retained receipt SHA-256 changed after restart",
                ));
            }
            Ok((state, admitted))
        }
        Stage::SettledUnknown => Err(WorkerError::input(
            "COMMAND_STATE_INVALID",
            "settled state cannot execute",
        )),
    }
}

fn current_unix_ms() -> Result<u64, WorkerError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| WorkerError::input("COMMAND_RECEIPT_TIME_INVALID", error.to_string()))?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        WorkerError::input(
            "COMMAND_RECEIPT_TIME_INVALID",
            "receipt admission time overflow",
        )
    })
}

fn child_material_exists(
    run_root: &std::path::Path,
    receipt: &std::path::Path,
) -> Result<bool, WorkerError> {
    for path in [run_root.join("data"), run_root.join("artifacts")] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(WorkerError::input(
                    "COMMAND_CHILD_MATERIAL_INVALID",
                    error.to_string(),
                ))
            }
        }
    }
    match std::fs::symlink_metadata(receipt) {
        Ok(metadata) => Ok(metadata.len() > 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(WorkerError::input(
            "COMMAND_CHILD_MATERIAL_INVALID",
            error.to_string(),
        )),
    }
}

async fn settle_retained<C: DispatchPort>(
    client: &C,
    store: &StateStore,
    state: WorkerState,
    receipt: &AdmittedReceipt,
) -> Result<(), WorkerError> {
    settle_digest(client, store, state, receipt.receipt_digest()).await
}

async fn settle_digest<C: DispatchPort>(
    client: &C,
    store: &StateStore,
    state: WorkerState,
    receipt_digest: Digest,
) -> Result<(), WorkerError> {
    if state.stage != Stage::ReceiptRetained {
        return Err(WorkerError::input(
            "COMMAND_STATE_INVALID",
            "settlement requires a retained receipt",
        ));
    }
    let completion = ComponentCommandCompletionV1::new(&state.claim, receipt_digest)
        .map_err(|error| WorkerError::input("COMMAND_COMPLETION_INVALID", error.to_string()))?;
    let record = client
        .settle(&state.claim.claim_id, &completion)
        .await
        .map_err(|error| WorkerError::input("COMMAND_SETTLEMENT_UNKNOWN", error))?;
    record
        .validate()
        .map_err(|error| WorkerError::input("COMMAND_SETTLEMENT_INVALID", error.to_string()))?;
    if record.id != state.claim.command_id || record.phase != CommandPhase::Unknown {
        return Err(WorkerError::input(
            "COMMAND_SETTLEMENT_INVALID",
            "Kernel settlement did not return the exact UNKNOWN public command",
        ));
    }
    store.persist(&state.settled()?)
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
