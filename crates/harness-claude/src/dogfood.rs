//! Read-only dogfood dispatch (ADR 0015). New file only: the frozen
//! ConformanceV1 path in `dispatch.rs` is unchanged.
//!
//! Argv is closed. The transcript is parsed under
//! [`TranscriptProfile::DogfoodReadOnlyV0`] with the enrolled runtime version.

use crate::protocol::{
    ClaudeStreamOutcome, ClaudeStreamTranscript, TranscriptProfile, READ_ONLY_TOOL_ALLOWLIST,
};
use bullet_harness_core::live::dispatch::artifact_digest;
use bullet_harness_core::{
    capture_turn, proposal, scan_events, AgentEvent, AgentEventKind, ArgvBuilder, CommandFactory,
    HarnessError, LiveTurnOutcome, LiveTurnRequest, PatchProposal,
};
use std::path::Path;

/// Exact tools flag for one dogfood read-only turn.
pub const DOGFOOD_TOOLS: &str = "Read,Glob,Grep";

/// Closed argv for one dogfood read-only turn. Extra flags are refused by
/// comparing the built vector to this constructor.
#[must_use]
pub fn dogfood_argv(prompt: &str, schema: &str, max_budget_usd: &str) -> Vec<String> {
    vec![
        "-p".into(),
        prompt.to_owned(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--permission-mode".into(),
        "plan".into(),
        "--tools".into(),
        DOGFOOD_TOOLS.into(),
        "--json-schema".into(),
        schema.to_owned(),
        "--max-budget-usd".into(),
        max_budget_usd.to_owned(),
        "--strict-mcp-config".into(),
        "--disable-slash-commands".into(),
        "--setting-sources".into(),
        String::new(),
    ]
}

/// Dispatch one read-only dogfood turn against a fully-cleared admission.
///
/// # Errors
///
/// `PROVIDER_ADMISSION_BLOCKED`, spawn/IO failures, canary exposure, extra
/// argv, a tool outside the allowlist, or a non-dogfood transcript.
pub fn dispatch_dogfood_turn(
    executable: &Path,
    factory: &CommandFactory<'_>,
    request: &LiveTurnRequest,
    enrolled_runtime_version: &str,
) -> Result<DogfoodTurnOutcome, HarnessError> {
    if request.expected_runtime_version != enrolled_runtime_version {
        return Err(HarnessError::Protocol {
            provider: "claude".to_string(),
            reason: "dogfood turn must use the enrolled runtime version".into(),
        });
    }
    if !executable.is_absolute() {
        return Err(HarnessError::AdmissionRefused {
            reason: "dogfood executable must be absolute".into(),
        });
    }
    let schema = proposal::schema_source();
    let budget = request.max_budget_usd();
    let expected = dogfood_argv(&request.prompt, schema, &budget);
    let cwd = request.workdir.to_string_lossy().into_owned();
    let mut builder = ArgvBuilder::new(executable.to_string_lossy().into_owned(), &cwd);
    for arg in &expected {
        builder = builder.arg(arg);
    }
    let prepared = builder.timeout(request.wall_timeout).build()?;
    if prepared.args != expected {
        return Err(HarnessError::AdmissionRefused {
            reason: "dogfood argv is not the admitted closed set".into(),
        });
    }

    let capture = capture_turn(factory, &prepared, &request.canaries)?;

    let mut transcript = ClaudeStreamTranscript::new_with_profile(
        request.session_id.clone(),
        request.invocation_id.clone(),
        &cwd,
        enrolled_runtime_version,
        request.gate_ids.clone(),
        TranscriptProfile::DogfoodReadOnlyV0,
    )?;
    let _ = transcript.user_message(&request.prompt)?;

    let mut events: Vec<AgentEvent> = Vec::new();
    for line in &capture.stdout_lines {
        if line.is_empty() {
            continue;
        }
        events.extend(transcript.ingest_line(line)?);
    }
    let outcome = transcript.outcome()?;
    let proposal = match outcome {
        ClaudeStreamOutcome::Proposal(proposal) => proposal.clone(),
        ClaudeStreamOutcome::Failed(reason) => {
            return Err(HarnessError::Protocol {
                provider: "claude".to_string(),
                reason: reason.clone(),
            });
        }
    };

    let events_blake3 = scan_events(&events, &request.canaries)?;
    let response_text = extract_response(&events);
    let native_session_id = events
        .iter()
        .find_map(|event| event.native_session_id.clone());
    let total_cost_micro_usd = extract_cost_micro_usd(&events);
    let _ = READ_ONLY_TOOL_ALLOWLIST;
    Ok(DogfoodTurnOutcome {
        proposal,
        live: LiveTurnOutcome {
            response_text,
            native_session_id,
            total_cost_micro_usd,
            exit_code: capture.exit_code,
            wall_ms: capture.wall_ms,
            timed_out: capture.timed_out,
            stdout_blake3: artifact_digest(b"stdout", capture.stdout().as_bytes()),
            stderr_blake3: artifact_digest(b"stderr", capture.stderr.as_bytes()),
            events_blake3,
            events,
        },
    })
}

/// One validated dogfood proposal plus the captured turn facts.
#[derive(Clone, Debug)]
pub struct DogfoodTurnOutcome {
    /// The only admitted terminal: one PatchProposal.
    pub proposal: PatchProposal,
    /// Cost, wall, native session, and artifact digests.
    pub live: LiveTurnOutcome,
}

fn extract_response(events: &[AgentEvent]) -> String {
    let mut text = String::new();
    for event in events {
        if event.kind != AgentEventKind::TurnDelta {
            continue;
        }
        if let Some(chunk) = event.payload.get("text").and_then(|value| value.as_str()) {
            text.push_str(chunk);
        }
    }
    text
}

fn extract_cost_micro_usd(events: &[AgentEvent]) -> Option<u64> {
    for event in events {
        if event.kind != AgentEventKind::UsageReported {
            continue;
        }
        if let Some(usd) = event
            .payload
            .get("total_cost_usd")
            .and_then(serde_json::Value::as_f64)
        {
            if usd.is_finite() && usd >= 0.0 {
                return Some((usd * 1_000_000.0).round() as u64);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::dogfood_argv;
    use bullet_harness_core::proposal;

    #[test]
    fn argv_is_exactly_the_admitted_flags() {
        let schema = proposal::schema_source();
        let args = dogfood_argv("fix the date", schema, "0.250000");
        assert_eq!(
            args,
            [
                "-p",
                "fix the date",
                "--output-format",
                "stream-json",
                "--verbose",
                "--permission-mode",
                "plan",
                "--tools",
                "Read,Glob,Grep",
                "--json-schema",
                schema,
                "--max-budget-usd",
                "0.250000",
                "--strict-mcp-config",
                "--disable-slash-commands",
                "--setting-sources",
                "",
            ]
        );
        assert!(!args
            .iter()
            .any(|arg| arg.contains("Bash") || arg == "--dangerously-skip-permissions"));
    }
}
