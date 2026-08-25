//! `HttpLeaseClient`: the leftover unsigned client for farmd `/api/v1/leases/*`.
//! Those routes are not mounted (farmd returns `NOT_FOUND`). Do not remount
//! this client as admission. The signed replacement is
//! `bullet_application::lease_transport::SignedLeaseService`.

use crate::error::RunnerError;
use crate::http::HttpJson;
use crate::lease::{
    AcquireGrant, AcquireRequest, HeartbeatCall, LeaseClient, ReadyView, ReleaseCall,
};
use async_trait::async_trait;
use bullet_domain::{AttemptId, AttemptState};
use serde::Deserialize;
use serde_json::{json, Value};

/// HTTP client against the farmd lease API.
pub struct HttpLeaseClient {
    http: HttpJson,
}

impl HttpLeaseClient {
    /// Client for one farmd base URL such as `http://127.0.0.1:7420`.
    ///
    /// # Errors
    ///
    /// Returns `PROTOCOL_ERROR` for an unsupported base URL.
    pub fn new(base: &str) -> Result<Self, RunnerError> {
        Ok(Self {
            http: HttpJson::new(base)?,
        })
    }
}

fn problem_error(status: u16, body: &Value) -> RunnerError {
    let code = body
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("HTTP_ERROR")
        .to_string();
    let message = body
        .get("title")
        .and_then(Value::as_str)
        .map_or_else(|| format!("http status {status}"), str::to_string);
    if code == "STALE_AUTHORITY" {
        return RunnerError::StaleAuthority(message);
    }
    RunnerError::Lease { code, message }
}

fn decode<T: serde::de::DeserializeOwned>(value: Value, what: &str) -> Result<T, RunnerError> {
    serde_json::from_value(value)
        .map_err(|err| RunnerError::Protocol(format!("decode {what}: {err}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot<T> {
    data: T,
    as_of_sequence: u64,
    observed_at: String,
    source: String,
}

fn decode_snapshot<T: serde::de::DeserializeOwned>(
    value: Value,
    what: &str,
) -> Result<T, RunnerError> {
    let snapshot: Snapshot<T> = decode(value, what)?;
    if snapshot.source != "bullet-kernel/sqlite-ledger" {
        return Err(RunnerError::Protocol(format!(
            "decode {what}: untrusted snapshot source"
        )));
    }
    chrono::DateTime::parse_from_rfc3339(&snapshot.observed_at)
        .map_err(|err| RunnerError::Protocol(format!("decode {what}: observed_at: {err}")))?;
    let _ = snapshot.as_of_sequence;
    Ok(snapshot.data)
}

#[async_trait]
impl LeaseClient for HttpLeaseClient {
    async fn acquire(&self, request: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
        let body = json!({
            "work_package_id": request.work_package_id.as_str(),
            "runner_id": request.runner_id.as_str(),
            "runner_epoch": request.runner_epoch,
            "idempotency_key": request.idempotency_key,
            "ttl_seconds": request.ttl_seconds,
        });
        let (status, value) = self.http.post("/api/v1/leases/acquire", &body).await?;
        if status != 200 {
            return Err(problem_error(status, &value));
        }
        decode(value, "acquire grant")
    }

    async fn heartbeat(&self, call: &HeartbeatCall) -> Result<(), RunnerError> {
        let body = serde_json::to_value(call)
            .map_err(|err| RunnerError::Protocol(format!("encode heartbeat: {err}")))?;
        let (status, value) = self.http.post("/api/v1/leases/heartbeat", &body).await?;
        if status == 204 {
            return Ok(());
        }
        Err(problem_error(status, &value))
    }

    async fn advance(
        &self,
        attempt_id: &AttemptId,
        state: AttemptState,
    ) -> Result<(), RunnerError> {
        let body = json!({ "attempt_id": attempt_id.as_str(), "state": state.as_str() });
        let (status, value) = self.http.post("/api/v1/attempts/advance", &body).await?;
        if status == 204 {
            return Ok(());
        }
        Err(problem_error(status, &value))
    }

    async fn release(&self, call: &ReleaseCall) -> Result<(), RunnerError> {
        let body = json!({
            "attempt_id": call.attempt_id.as_str(),
            "outcome": call.outcome.as_str(),
            "requeue": call.requeue,
        });
        let (status, value) = self.http.post("/api/v1/leases/release", &body).await?;
        if status == 204 {
            return Ok(());
        }
        Err(problem_error(status, &value))
    }

    async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
        let (status, value) = self.http.get("/api/v1/ready").await?;
        match status {
            200 => decode_snapshot(value, "ready snapshot"),
            _ => Err(problem_error(status, &value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_snapshot() -> Value {
        json!({
            "data": {
                "work_package_id": "wp_one",
                "mission_id": "mis_one",
                "variant_id": "var_one",
                "title": "one",
                "enqueued_at": "2026-01-01T00:00:00.000Z"
            },
            "as_of_sequence": 3,
            "observed_at": "2026-01-01T00:00:01.000Z",
            "source": "bullet-kernel/sqlite-ledger"
        })
    }

    #[test]
    fn ready_snapshot_requires_exact_runtime_provenance() {
        decode_snapshot::<ReadyView>(ready_snapshot(), "ready").expect("valid snapshot");
        for (field, value) in [
            ("source", json!("attacker/projection")),
            ("observed_at", json!("not-a-timestamp")),
        ] {
            let mut hostile = ready_snapshot();
            hostile[field] = value;
            assert!(decode_snapshot::<ReadyView>(hostile, "ready").is_err());
        }
        let mut extra = ready_snapshot();
        extra["optimistic"] = json!(true);
        assert!(decode_snapshot::<ReadyView>(extra, "ready").is_err());
    }

    #[test]
    fn ready_snapshot_preserves_verified_empty() {
        let mut empty = ready_snapshot();
        empty["data"] = Value::Null;
        let decoded = decode_snapshot::<Option<ReadyView>>(empty, "ready").expect("empty snapshot");
        assert!(decoded.is_none());
    }
}
