//! Public-command dispatch methods on the peer-authenticated workload socket.

use super::{CallResult, RpcRequest};
use bullet_adapters::SqliteLedger;
use bullet_application::{CommandDispatchStore, ComponentCommandCompletionV1, LeaseService};
use bullet_domain::RunnerId;
use serde::Deserialize;

const INVALID: &str = "COMMAND_DISPATCH_REQUEST_INVALID";

pub(super) fn is_method(method: &str) -> bool {
    matches!(
        method,
        "command_claim" | "command_readback" | "command_settle_component"
    )
}

pub(super) fn call(
    ledger: &mut SqliteLedger,
    runner_id: &RunnerId,
    runner_epoch: u64,
    request: &RpcRequest,
) -> CallResult {
    let now = LeaseService::rfc3339(chrono::Utc::now());
    match request.method.as_str() {
        "command_claim" => {
            let _: Empty = parse_params(request)?;
            let claim = ledger
                .claim_next_command_dispatch(runner_id, runner_epoch, &now)
                .map_err(map_error)?;
            encode(claim)
        }
        "command_readback" => {
            let _: Empty = parse_params(request)?;
            let claim = ledger
                .readback_command_dispatch(runner_id, runner_epoch)
                .map_err(map_error)?;
            encode(claim)
        }
        "command_settle_component" => {
            let params: SettleParams = parse_params(request)?;
            let record = ledger
                .settle_component_command_dispatch(
                    &params.claim_id,
                    runner_id,
                    runner_epoch,
                    &params.completion,
                    &now,
                )
                .map_err(map_error)?;
            encode(record)
        }
        _ => unreachable!("command dispatch route checked before call"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettleParams {
    claim_id: String,
    completion: ComponentCommandCompletionV1,
}

fn parse_params<T: for<'de> Deserialize<'de>>(
    request: &RpcRequest,
) -> Result<T, (&'static str, String)> {
    serde_json::from_value(request.params.clone()).map_err(|error| {
        (
            INVALID,
            format!("closed command dispatch params required: {error}"),
        )
    })
}

fn encode(value: impl serde::Serialize) -> CallResult {
    serde_json::to_value(value).map_err(|error| ("ENCODING_FAILURE", error.to_string()))
}

fn map_error(error: bullet_application::CommandDispatchError) -> (&'static str, String) {
    (error.reason_code(), error.to_string())
}
