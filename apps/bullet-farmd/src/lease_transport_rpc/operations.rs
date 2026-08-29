use super::{CallResult, RpcRequest};
#[cfg(all(feature = "test-seams", debug_assertions))]
use bullet_application::lease_transport::SyntheticSelectedAcquireBody;
use bullet_application::lease_transport::{
    KernelLeaseTransport, LeaseSettlementRequest, SignedAcquireBody, SignedAdvanceBody,
    SignedHeartbeatBody, SignedLeaseError, SignedReleaseBody,
};
use bullet_application::{LeaseGrant, LeaseService, Ledger, StoredGraph};
use bullet_domain::{RunnerId, VariantId, WorkPackageId};
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};

pub(super) fn call<L: Ledger>(
    ledger: &mut L,
    transport: &KernelLeaseTransport,
    hello_runner: &RunnerId,
    hello_epoch: u64,
    request: &RpcRequest,
) -> Result<CallResult, Error> {
    const MISMATCH: (&str, &str) = ("LEASE_TRANSPORT_SUBJECT_MISMATCH", "hello");
    let now = unix_ms();
    let subject = |runner: &RunnerId, epoch: u64| runner == hello_runner && epoch == hello_epoch;
    let result = match request.method.as_str() {
        "acquire" => {
            let body: SignedAcquireBody = parse_params(request)?;
            if !subject(&body.runner_id, body.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_grant(
                transport.acquire(ledger, &body, now),
                &*ledger,
                &body.work_package_id,
            )
        }
        #[cfg(all(feature = "test-seams", debug_assertions))]
        "synthetic_acquire_selected_variant" => {
            let selected: SyntheticSelectedAcquireBody = parse_params(request)?;
            if let Err(error) = selected.validate_binding() {
                return Ok(Err((error.reason_code(), error.to_string())));
            }
            let body = selected.inner();
            if !subject(&body.runner_id, body.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_grant(
                transport.acquire_selected_variant(
                    ledger,
                    body,
                    selected.selected_variant_id(),
                    now,
                ),
                &*ledger,
                &body.work_package_id,
            )
        }
        "readback" => {
            let body: SignedAcquireBody = parse_params(request)?;
            if !subject(&body.runner_id, body.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_grant(
                transport.readback(ledger, &body, now),
                &*ledger,
                &body.work_package_id,
            )
        }
        "readback_active" => {
            let body: SignedAcquireBody = parse_params(request)?;
            if !subject(&body.runner_id, body.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_grant(
                transport.readback_active(ledger, &body, now),
                &*ledger,
                &body.work_package_id,
            )
        }
        "heartbeat" => {
            let body: SignedHeartbeatBody = parse_params(request)?;
            if !subject(&body.call.runner_id, body.call.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_unit(transport.heartbeat(ledger, &body, now))
        }
        "release" => {
            let body: SignedReleaseBody = parse_params(request)?;
            if !subject(&body.runner_id, body.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_unit(transport.release(ledger, &body, now))
        }
        "advance" => {
            let body: SignedAdvanceBody = parse_params(request)?;
            if !subject(&body.runner_id, body.runner_epoch) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_json(transport.advance(ledger, &body, now))
        }
        "settle" => {
            let body: LeaseSettlementRequest = parse_params(request)?;
            if !subject(body.runner_id(), body.runner_epoch()) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_json(transport.settle(ledger, &body, now))
        }
        "settlement_readback" => {
            let body: LeaseSettlementRequest = parse_params(request)?;
            if !subject(body.runner_id(), body.runner_epoch()) {
                return Ok(Err((MISMATCH.0, MISMATCH.1.to_string())));
            }
            map_json(transport.settlement_readback(ledger, &body, now))
        }
        "next_ready" => next_ready(&*ledger),
        other => Err(("LEASE_TRANSPORT_INVALID", format!("unknown method {other}"))),
    };
    Ok(result)
}

fn next_ready(ledger: &dyn Ledger) -> CallResult {
    let Some(row) = ledger
        .ready_rows()
        .map_err(|err| (err.reason_code(), err.to_string()))?
        .into_iter()
        .next()
    else {
        return Ok(serde_json::Value::Null);
    };
    let mut found = None;
    for mission in ledger
        .list_missions()
        .map_err(|err| (err.reason_code(), err.to_string()))?
    {
        let Some(graph) = ledger
            .get_graph(&mission.id)
            .map_err(|err| (err.reason_code(), err.to_string()))?
        else {
            continue;
        };
        if let Some(variant) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == row.work_package_id)
        {
            let title = graph
                .packages
                .iter()
                .find(|package| package.id == row.work_package_id)
                .map(|package| package.title.clone())
                .unwrap_or_default();
            found = Some(serde_json::json!({
                "work_package_id": row.work_package_id.to_string(),
                "mission_id": graph.mission.id.to_string(),
                "variant_id": variant.id.to_string(),
                "title": title,
                "enqueued_at": row.enqueued_at,
            }));
            break;
        }
    }
    Ok(found.unwrap_or(serde_json::Value::Null))
}

fn parse_params<T: for<'de> Deserialize<'de>>(request: &RpcRequest) -> Result<T, Error> {
    serde_json::from_value(request.params.clone())
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))
}

fn map_grant(
    result: Result<LeaseGrant, SignedLeaseError>,
    ledger: &dyn Ledger,
    package: &WorkPackageId,
) -> CallResult {
    let grant = result.map_err(|error| (error.reason_code(), error.to_string()))?;
    let (graph, _) = graph_for_package(ledger, package)?.ok_or((
        "NOT_FOUND",
        format!("work package {package} not in any graph"),
    ))?;
    let token = LeaseService::token_for(&graph, &grant.attempt)
        .map_err(|err| (err.reason_code(), err.to_string()))?;
    serde_json::to_value(serde_json::json!({
        "attempt": grant.attempt,
        "authority_token": token,
        "lease": grant.lease,
    }))
    .map_err(|err| ("ENCODING", err.to_string()))
}

fn graph_for_package(
    ledger: &dyn Ledger,
    package: &WorkPackageId,
) -> Result<Option<(StoredGraph, VariantId)>, (&'static str, String)> {
    for mission in ledger
        .list_missions()
        .map_err(|err| (err.reason_code(), err.to_string()))?
    {
        let Some(graph) = ledger
            .get_graph(&mission.id)
            .map_err(|err| (err.reason_code(), err.to_string()))?
        else {
            continue;
        };
        if let Some(variant_id) = graph
            .variants
            .iter()
            .find(|variant| variant.work_package_id == *package)
            .map(|variant| variant.id.clone())
        {
            return Ok(Some((graph, variant_id)));
        }
    }
    Ok(None)
}

fn map_json<T: Serialize>(result: Result<T, SignedLeaseError>) -> CallResult {
    match result {
        Ok(value) => serde_json::to_value(value).map_err(|err| ("ENCODING", err.to_string())),
        Err(error) => Err((error.reason_code(), error.to_string())),
    }
}

fn map_unit(result: Result<(), SignedLeaseError>) -> CallResult {
    match result {
        Ok(()) => Ok(serde_json::json!({"ok": true})),
        Err(error) => Err((error.reason_code(), error.to_string())),
    }
}

fn unix_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

#[cfg(test)]
#[path = "operations/tests.rs"]
mod tests;
