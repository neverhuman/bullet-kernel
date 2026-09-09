//! Result-field validation extracted without changing the admitted transcript shape.

use super::exact_fields;
use serde_json::{Map, Value};

/// Validate the fields every `result` frame shares.
///
/// `admits_vendor_fields` relaxes only the closed-set rule: a real build adds
/// timing and accounting keys (`first_content_frame_ms`, `queued_turn_count`,
/// `subagent_stats`, `time_to_request_ms`, `ttft_stream_ms` on 2.1.266) that
/// carry no admission meaning. Every value check below stays exact.
pub(crate) fn valid_result_common(object: &Map<String, Value>, admits_vendor_fields: bool) -> bool {
    let required = [
        "type",
        "subtype",
        "uuid",
        "session_id",
        "duration_ms",
        "duration_api_ms",
        "is_error",
        "num_turns",
        "stop_reason",
        "total_cost_usd",
        "usage",
        "modelUsage",
        "permission_denials",
    ];
    let optional = [
        "result",
        "structured_output",
        "errors",
        "api_error_status",
        "ttft_ms",
        "deferred_tool_use",
        "fast_mode_state",
        "fast_mode_disabled_reason",
        "terminal_reason",
    ];
    let fields_ok = if admits_vendor_fields {
        required.iter().all(|key| object.contains_key(*key))
    } else {
        exact_fields(object, &required, &optional)
    };
    fields_ok
        && object.get("duration_ms").and_then(Value::as_u64).is_some()
        && object
            .get("duration_api_ms")
            .and_then(Value::as_u64)
            .is_some()
        && object
            .get("num_turns")
            .and_then(Value::as_u64)
            .is_some_and(|turns| turns > 0)
        && object
            .get("total_cost_usd")
            .and_then(Value::as_f64)
            .is_some_and(|cost| cost.is_finite() && cost >= 0.0)
        && object.get("usage").is_some_and(Value::is_object)
        && object.get("modelUsage").is_some_and(Value::is_object)
        && object
            .get("permission_denials")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && object
            .get("terminal_reason")
            .is_none_or(|reason| reason.is_null() || reason.is_string())
}
