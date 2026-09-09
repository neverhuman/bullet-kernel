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

    // The transcript is constructed and seeded BEFORE the provider is spawned.
    // Its constructor refuses an empty or malformed gate selection, and the
    // provider turn costs real money: a refusal that can only be discovered
    // after the spawn is a refusal that bills the operator for nothing. The
    // containment chdirs the child into its own clone destination, so the cwd
    // the provider reports in system/init is the in-sandbox path, never the
    // host workdir this process sees.
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
        .map_err(DogfoodDispatchError::before_spawn)?;
    // Everything below this line runs after the provider has been billed, so
    // every refusal carries the observed turn facts for a durable record.
    let observed = ObservedTurn {
        exit_code: capture.exit_code,
        wall_ms: capture.wall_ms,
        timed_out: capture.timed_out,
        stdout_blake3: artifact_digest(b"stdout", capture.stdout().as_bytes()),
        stderr_blake3: artifact_digest(b"stderr", capture.stderr.as_bytes()),
        total_cost_micro_usd: None,
        stdout_lines: capture.stdout_lines.clone(),
        stderr: capture.stderr.clone(),
    };
    let after = |error: HarnessError| DogfoodDispatchError::AfterTurn {
        error,
        observed: Box::new(observed.clone()),
    };

    let mut events: Vec<AgentEvent> = Vec::new();
    for line in &capture.stdout_lines {
        if line.is_empty() {
            continue;
        }
        events.extend(transcript.ingest_line(line).map_err(&after)?);
    }
    // Cost is observable from the ingested events even when the turn is about
    // to be refused, so a failed run still reports what it spent.
    let observed = ObservedTurn {
        total_cost_micro_usd: extract_cost_micro_usd(&events),
        ..observed
    };
    let after = |error: HarnessError| DogfoodDispatchError::AfterTurn {
        error,
        observed: Box::new(observed.clone()),
    };
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

/// Facts observed about a provider turn that actually ran. Present on every
/// refusal that follows the spawn, so billed work is never silently lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTurn {
    /// Child exit status, when the child was reaped.
    pub exit_code: Option<i32>,
    /// Wall-clock duration of the turn.
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

/// Why a dogfood dispatch did not produce a proposal, and whether the
/// provider had already been spawned when it was decided.
#[derive(Clone, Debug)]
pub enum DogfoodDispatchError {
    /// Refused before the provider process started. No spend occurred.
    BeforeSpawn(HarnessError),
    /// The provider ran to completion and the turn was then refused. The
    /// caller must persist `observed` so the spend is recorded.
    AfterTurn {
        /// The refusal.
        error: HarnessError,
        /// What the billed turn did. Boxed to keep the `Err` variant small.
        observed: Box<ObservedTurn>,
    },
}

impl DogfoodDispatchError {
    /// Wrap a refusal decided before any provider process existed.
    #[must_use]
    pub fn before_spawn(error: HarnessError) -> Self {
        Self::BeforeSpawn(error)
    }

    /// The underlying refusal, regardless of when it was decided.
    #[must_use]
    pub fn error(&self) -> &HarnessError {
        match self {
            Self::BeforeSpawn(error) | Self::AfterTurn { error, .. } => error,
        }
    }

    /// Turn facts, present only when the provider had already run.
    #[must_use]
    pub fn observed(&self) -> Option<&ObservedTurn> {
        match self {
            Self::BeforeSpawn(_) => None,
            Self::AfterTurn { observed, .. } => Some(observed),
        }
    }
}

impl std::fmt::Display for DogfoodDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeSpawn(error) => write!(formatter, "{error}"),
            Self::AfterTurn { error, observed } => write!(
                formatter,
                "{error} (provider ran: exit {:?}, {} ms)",
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
