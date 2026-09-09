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
    enrolled_blake3: &str,
    factory: &CommandFactory<'_>,
    request: &LiveTurnRequest,
    enrolled_runtime_version: &str,
    expected_child_cwd: &str,
) -> Result<DogfoodTurnOutcome, DogfoodDispatchError> {
    if request.expected_runtime_version != enrolled_runtime_version {
        return Err(DogfoodDispatchError::before_spawn(HarnessError::Protocol {
            provider: "claude".to_string(),
            reason: "dogfood turn must use the enrolled runtime version".into(),
        }));
    }
    if !executable.is_absolute() {
        return Err(DogfoodDispatchError::before_spawn(
            HarnessError::AdmissionRefused {
                reason: "dogfood executable must be absolute".into(),
            },
        ));
    }
    // The provider dialect, not the canonical contract: Claude Code refuses a
    // 2020-12 `$schema` declaration outright and exits before the turn runs.
    let schema =
        proposal::schema_source_for_provider().map_err(DogfoodDispatchError::before_spawn)?;
    let budget = request.max_budget_usd();
    let expected = dogfood_argv(&request.prompt, &schema, &budget);
    let cwd = request.workdir.to_string_lossy().into_owned();
    let mut builder = ArgvBuilder::new(executable.to_string_lossy().into_owned(), &cwd);
    for arg in &expected {
        builder = builder.arg(arg);
    }
    // The plain `build()` quarantines every known provider basename; the
    // dogfood path re-verifies the enrolled path and content digest instead,
    // which is strictly stronger evidence than the basename it bypasses.
    let prepared = builder
        .timeout(request.wall_timeout)
        .build_enrolled_dogfood(executable, enrolled_blake3)
        .map_err(DogfoodDispatchError::before_spawn)?;
    if prepared.args != expected {
        return Err(DogfoodDispatchError::before_spawn(
            HarnessError::AdmissionRefused {
                reason: "dogfood argv is not the admitted closed set".into(),
            },
        ));
    }

    // Validate and seed the transcript before attempting capture, so invalid
    // gates or prompts do not launch a child. Containment can change its cwd;
    // bind system/init to the expected in-sandbox path supplied by the caller.
    let mut transcript = ClaudeStreamTranscript::new_with_profile(
        request.session_id.clone(),
        request.invocation_id.clone(),
        expected_child_cwd,
        enrolled_runtime_version,
        request.gate_ids.clone(),
        TranscriptProfile::DogfoodReadOnlyV0,
    )
    .map_err(DogfoodDispatchError::before_spawn)?;
    let _ = transcript
        .user_message(&request.prompt)
        .map_err(DogfoodDispatchError::before_spawn)?;

    let capture = capture_turn(factory, &prepared, &request.canaries)
        .map_err(DogfoodDispatchError::CaptureUnavailable)?;
    // Capture supplies child-process facts; provider execution and billing
    // are not established merely by launching the factory's command.
    let mut observed = ObservedTurn {
        exit_code: capture.exit_code,
        wall_ms: capture.wall_ms,
        timed_out: capture.timed_out,
        stdout_blake3: artifact_digest(b"stdout", capture.stdout().as_bytes()),
        stderr_blake3: artifact_digest(b"stderr", capture.stderr.as_bytes()),
        total_cost_micro_usd: None,
        stdout_lines: capture.stdout_lines.clone(),
        stderr: capture.stderr.clone(),
    };
    let mut events: Vec<AgentEvent> = Vec::new();
    for line in &capture.stdout_lines {
        if line.is_empty() {
            continue;
        }
        let batch = transcript
            .ingest_line(line)
            .map_err(|error| after_turn(&observed, error))?;
        if let Some(cost) =
            extract_cost_micro_usd(&batch).map_err(|error| after_turn(&observed, error))?
        {
            observed.total_cost_micro_usd = Some(cost);
        }
        events.extend(batch);
    }
    let after = |error| after_turn(&observed, error);
    if observed.timed_out {
        return Err(after(HarnessError::Timeout {
            seconds: request.wall_timeout.as_secs(),
        }));
    }
    if observed.exit_code != Some(0) {
        return Err(after(HarnessError::ProviderFailure {
            provider: "claude".into(),
            exit: observed.exit_code,
            reason: "captured child did not exit successfully".into(),
        }));
    }
    let outcome = transcript.outcome().map_err(&after)?;
    let proposal = match outcome {
        ClaudeStreamOutcome::Proposal(proposal) => proposal.clone(),
        ClaudeStreamOutcome::Failed(reason) => {
            return Err(after(HarnessError::Protocol {
                provider: "claude".to_string(),
                reason: reason.clone(),
            }));
        }
    };

    let events_blake3 = scan_events(&events, &request.canaries).map_err(&after)?;
    let response_text = extract_response(&events);
    let native_session_id = events
        .iter()
        .find_map(|event| event.native_session_id.clone());
    let _ = READ_ONLY_TOOL_ALLOWLIST;
    Ok(DogfoodTurnOutcome {
        proposal,
        live: LiveTurnOutcome {
            response_text,
            native_session_id,
            total_cost_micro_usd: observed.total_cost_micro_usd,
            exit_code: observed.exit_code,
            wall_ms: observed.wall_ms,
            timed_out: observed.timed_out,
            stdout_blake3: observed.stdout_blake3.clone(),
            stderr_blake3: observed.stderr_blake3.clone(),
            events_blake3,
            events,
        },
    })
}

/// Child-process facts returned by a successful capture operation.
/// Capture failures can lack these facts; cost is validated reported telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTurn {
    /// Child exit status, when the child was reaped.
    pub exit_code: Option<i32>,
    /// Wall-clock duration reported by capture.
    pub wall_ms: u64,
    /// Whether the wall timeout fired.
    pub timed_out: bool,
    /// Domain-separated digest of captured stdout.
    pub stdout_blake3: String,
    /// Domain-separated digest of captured stderr.
    pub stderr_blake3: String,
    /// Provider-reported cost, when the turn reported one.
    pub total_cost_micro_usd: Option<u64>,
    /// Captured stdout lines. Held so a caller can persist them for
    /// diagnosis; the digests above are what a receipt commits to.
    pub stdout_lines: Vec<String>,
    /// Captured stderr.
    pub stderr: String,
}

/// Why a dogfood dispatch did not produce a proposal and which capture
/// facts are available. This classification does not establish billing.
#[derive(Clone, Debug)]
pub enum DogfoodDispatchError {
    /// Refused before calling the command factory or capture operation.
    BeforeSpawn(HarnessError),
    /// Capture was attempted but returned no usable facts. Child execution,
    /// partial output, cessation and usage are unavailable at this boundary.
    CaptureUnavailable(HarnessError),
    /// Capture returned facts and the dispatch was then refused. The caller
    /// can retain those facts without inferring provider execution or spend.
    AfterTurn {
        /// The refusal.
        error: HarnessError,
        /// Available capture facts. Boxed to keep the `Err` variant small.
        observed: Box<ObservedTurn>,
    },
}

impl DogfoodDispatchError {
    /// Wrap a refusal decided before this dispatch calls capture.
    #[must_use]
    pub fn before_spawn(error: HarnessError) -> Self {
        Self::BeforeSpawn(error)
    }

    /// The underlying refusal, regardless of when it was decided.
    #[must_use]
    pub fn error(&self) -> &HarnessError {
        match self {
            Self::BeforeSpawn(error)
            | Self::CaptureUnavailable(error)
            | Self::AfterTurn { error, .. } => error,
        }
    }

    /// Child-process facts, present only when capture returned them.
    #[must_use]
    pub fn observed(&self) -> Option<&ObservedTurn> {
        match self {
            Self::BeforeSpawn(_) | Self::CaptureUnavailable(_) => None,
            Self::AfterTurn { observed, .. } => Some(observed),
        }
    }
}

impl std::fmt::Display for DogfoodDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeSpawn(error) => write!(formatter, "{error}"),
            Self::CaptureUnavailable(error) => {
                write!(formatter, "capture facts unavailable: {error}")
            }
            Self::AfterTurn { error, observed } => write!(
                formatter,
                "{error} (captured child: exit {:?}, {} ms)",
                observed.exit_code, observed.wall_ms
            ),
        }
    }
}

impl std::error::Error for DogfoodDispatchError {}

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

fn after_turn(observed: &ObservedTurn, error: HarnessError) -> DogfoodDispatchError {
    DogfoodDispatchError::AfterTurn {
        error,
        observed: Box::new(observed.clone()),
    }
}

fn extract_cost_micro_usd(events: &[AgentEvent]) -> Result<Option<u64>, HarnessError> {
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
                let rounded = (usd * 1_000_000.0).round();
                // u64::MAX rounds up to 2^64 as f64; use an exclusive bound.
                if !rounded.is_finite() || rounded >= u64::MAX as f64 {
                    return Err(HarnessError::Protocol {
                        provider: "claude".into(),
                        reason: "reported cost cannot be represented in micro-USD".into(),
                    });
                }
                return Ok(Some(rounded as u64));
            }
        }
    }
    Ok(None)
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
