//! Bind a public `CommandRequest` to its exact durable outbox payload.
//!
//! Submit stays HTTP 202 `PENDING`; peer-authenticated workload dispatch is a
//! separate Unix-socket authority boundary.

use bullet_application::CommandRequest;

/// Exact outbox payload for one admitted command request.
pub(crate) fn encode_command_dispatch(request: &CommandRequest) -> Result<String, String> {
    serde_json::to_string(request).map_err(|error| format!("command dispatch encoding: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::commands::OfflineCommandResolution;
    use bullet_domain::CommandPhase;

    fn refuses_success_phases(resolution: &OfflineCommandResolution) -> bool {
        !matches!(
            resolution.phase(),
            CommandPhase::Applied | CommandPhase::Verified
        )
    }

    #[test]
    fn dispatch_run_demo_settles_unknown_without_applied_or_verified() {
        let request =
            CommandRequest::new("dispatch-run-demo", "run_demo", &serde_json::json!({})).unwrap();
        let encoded = encode_command_dispatch(&request).unwrap();
        assert!(encoded.contains("run_demo"));
        let resolution = request.offline_worker_resolution().unwrap();
        assert_eq!(resolution.phase(), CommandPhase::Unknown);
        assert!(refuses_success_phases(&resolution));
        assert!(resolution
            .response()
            .contains("EXECUTION_ADAPTER_UNAVAILABLE"));
        assert!(!resolution.response().contains("APPLIED"));
        assert!(!resolution.response().contains("VERIFIED"));
    }

    #[test]
    fn dispatch_unknown_kind_fails_without_applied_or_verified() {
        let request =
            CommandRequest::new("dispatch-other", "not_a_kind", &serde_json::json!({})).unwrap();
        let resolution = request.offline_worker_resolution().unwrap();
        assert_eq!(resolution.phase(), CommandPhase::Failed);
        assert!(refuses_success_phases(&resolution));
        assert!(resolution.response().contains("UNSUPPORTED_COMMAND_KIND"));
    }
}
