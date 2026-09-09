//! The in-code scenario table: the 18 deterministic conditions of spec
//! s33.2. Each condition compiles to raw provider lines that the simulator
//! parses exactly the way a real adapter parses a CLI stream.

use bullet_domain::Digest;
use serde_json::json;

/// The 18 simulated conditions (spec s33.2 bullet list, one variant each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimCondition {
    /// Token/text streaming deltas.
    Streaming,
    /// Structured tool call.
    ToolCall,
    /// Local plan and permission prompt.
    PermissionPrompt,
    /// Usage events (per turn and cumulative).
    UsageEvents,
    /// Context usage report.
    ContextReport,
    /// Auth expiry mid-run.
    AuthExpiry,
    /// 401/429/5xx responses.
    HttpErrors,
    /// Quota reset observation.
    QuotaReset,
    /// Malformed, out-of-order, and duplicate events.
    EventAnomalies,
    /// Delayed stale event after turn close.
    DelayedStaleEvent,
    /// Long turn (interruptible).
    LongTurn,
    /// Refusal without a proposal.
    Refusal,
    /// Provider process crash.
    ProcessCrash,
    /// Native resume failure.
    ResumeFailure,
    /// False completion claim.
    FalseCompletion,
    /// Context limit reached.
    ContextLimit,
    /// Terminal-only dialog.
    TerminalOnlyDialog,
    /// Provider version drift.
    VersionDrift,
}

impl SimCondition {
    /// All 18 conditions.
    pub const ALL: [SimCondition; 18] = [
        SimCondition::Streaming,
        SimCondition::ToolCall,
        SimCondition::PermissionPrompt,
        SimCondition::UsageEvents,
        SimCondition::ContextReport,
        SimCondition::AuthExpiry,
        SimCondition::HttpErrors,
        SimCondition::QuotaReset,
        SimCondition::EventAnomalies,
        SimCondition::DelayedStaleEvent,
        SimCondition::LongTurn,
        SimCondition::Refusal,
        SimCondition::ProcessCrash,
        SimCondition::ResumeFailure,
        SimCondition::FalseCompletion,
        SimCondition::ContextLimit,
        SimCondition::TerminalOnlyDialog,
        SimCondition::VersionDrift,
    ];

    /// Stable scenario name used in prompts (`condition:<name>`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::ToolCall => "tool_call",
            Self::PermissionPrompt => "permission_prompt",
            Self::UsageEvents => "usage_events",
            Self::ContextReport => "context_report",
            Self::AuthExpiry => "auth_expiry",
            Self::HttpErrors => "http_errors",
            Self::QuotaReset => "quota_reset",
            Self::EventAnomalies => "event_anomalies",
            Self::DelayedStaleEvent => "delayed_stale_event",
            Self::LongTurn => "long_turn",
            Self::Refusal => "refusal",
            Self::ProcessCrash => "process_crash",
            Self::ResumeFailure => "resume_failure",
            Self::FalseCompletion => "false_completion",
            Self::ContextLimit => "context_limit",
            Self::TerminalOnlyDialog => "terminal_only_dialog",
            Self::VersionDrift => "version_drift",
        }
    }

    /// Select the condition named in the prompt; default is Streaming.
    #[must_use]
    pub fn from_prompt(prompt: &str) -> Self {
        Self::ALL
            .iter()
            .find(|c| prompt.contains(&format!("condition:{}", c.as_str())))
            .copied()
            .unwrap_or(Self::Streaming)
    }
}

/// The canonical happy-path proposal the simulator emits.
#[must_use]
pub fn sample_proposal() -> serde_json::Value {
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "intent_summary": "create PONG.txt containing PONG",
        "operations": [
            {
                "path": "PONG.txt",
                "preimage": { "kind": "absent" },
                "mutation": { "kind": "write", "content_utf8": "PONG\n" }
            }
        ],
        "gate_ids": [bullet_domain::REPOSITORY_GATE_ID],
        "claims": ["PONG.txt exists after apply"],
        "uncertainties": [],
        "done": true
    })
}

fn prompt_value(prompt: &str, label: &str) -> Option<String> {
    prompt
        .lines()
        .find_map(|line| line.trim().strip_prefix(label).map(str::to_owned))
}

fn sample_proposal_for(prompt: &str) -> serde_json::Value {
    let mut proposal = sample_proposal();
    proposal["proposal_id"] = format!("cnt_{}", Digest::of(prompt.as_bytes()).to_hex()).into();
    for (field, label) in [
        ("producing_attempt_id", "Producing attempt ID: "),
        ("base_checkpoint_id", "Base checkpoint ID: "),
        ("base_checkpoint_digest", "Base checkpoint digest: "),
    ] {
        if let Some(value) = prompt_value(prompt, label) {
            proposal[field] = value.into();
        }
    }
    if let Some(start) = prompt.find("gat_") {
        let end = start.saturating_add(68);
        if let Some(gate) = prompt.get(start..end) {
            proposal["gate_ids"] = json!([gate]);
        }
    }
    proposal
}

fn line(kind: &str, payload: serde_json::Value) -> String {
    json!({ "kind": kind, "payload": payload }).to_string()
}

fn line_native(kind: &str, payload: serde_json::Value, id: &str, seq: u64) -> String {
    json!({ "kind": kind, "payload": payload, "native_id": id, "native_seq": seq }).to_string()
}

fn closing(proposal: bool, prompt: &str) -> Vec<String> {
    let body = if proposal {
        json!({ "proposal": sample_proposal_for(prompt), "text": "done" })
    } else {
        json!({ "proposal": null, "text": "done" })
    };
    vec![
        line(
            "usage.reported",
            json!({ "input_tokens": 812, "output_tokens": 204, "cost_usd": 0.004 }),
        ),
        line("turn.completed", body),
    ]
}

/// Raw provider lines for one condition. `LongTurn` is generated in the
/// adapter loop instead so it can observe interrupts.
#[must_use]
pub fn script(condition: SimCondition, prompt: &str) -> Vec<String> {
    let start = line("turn.started", json!({}));
    match condition {
        SimCondition::Streaming | SimCondition::ResumeFailure | SimCondition::LongTurn => {
            let mut lines = vec![
                start,
                line("thinking.delta", json!({ "text": "planning" })),
                line("turn.delta", json!({ "text": "PO" })),
                line("turn.delta", json!({ "text": "NG" })),
            ];
            lines.extend(closing(true, prompt));
            lines
        }
        SimCondition::ToolCall => {
            let mut lines = vec![
                start,
                line(
                    "tool.requested",
                    json!({ "tool": "read_file", "args": { "path": "README.md" } }),
                ),
                line("tool.started", json!({ "tool": "read_file" })),
                line(
                    "tool.completed",
                    json!({ "tool": "read_file", "bytes": 120 }),
                ),
                line("turn.delta", json!({ "text": "read it" })),
            ];
            lines.extend(closing(true, prompt));
            lines
        }
        SimCondition::PermissionPrompt => vec![
            start,
            line("plan.proposed", json!({ "plan": "create PONG.txt" })),
            line("plan.waiting", json!({})),
            line(
                "permission.requested",
                json!({ "tool": "write_file", "path": "PONG.txt" }),
            ),
        ],
        SimCondition::UsageEvents => {
            let mut lines = vec![
                start,
                line("turn.delta", json!({ "text": "…" })),
                line(
                    "usage.reported",
                    json!({ "input_tokens": 500, "output_tokens": 100, "cost_usd": 0.002 }),
                ),
            ];
            lines.extend(closing(true, prompt));
            lines
        }
        SimCondition::ContextReport => {
            let mut lines = vec![
                start,
                line(
                    "context.reported",
                    json!({ "tokens_used": 12_000, "context_window": 200_000 }),
                ),
            ];
            lines.extend(closing(true, prompt));
            lines
        }
        SimCondition::AuthExpiry => vec![
            start,
            line(
                "auth.required",
                json!({ "http_status": 401, "reason": "token expired" }),
            ),
        ],
        SimCondition::HttpErrors => vec![
            start,
            line("auth.required", json!({ "http_status": 401 })),
            line(
                "rate_limited",
                json!({ "http_status": 429, "retry_after_s": 30 }),
            ),
            line(
                "turn.failed",
                json!({ "http_status": 503, "reason": "upstream unavailable" }),
            ),
        ],
        SimCondition::QuotaReset => {
            let mut lines = vec![
                start,
                line(
                    "quota.reported",
                    json!({ "dimension": "requests", "remaining": 2, "resets_at": "2026-08-24T12:00:00Z" }),
                ),
                line(
                    "quota.reported",
                    json!({ "dimension": "requests", "remaining": 500, "reset": true }),
                ),
            ];
            lines.extend(closing(true, prompt));
            lines
        }
        SimCondition::EventAnomalies => {
            let mut lines = vec![
                line_native("turn.started", json!({}), "n1", 1),
                line_native("turn.delta", json!({ "text": "a" }), "n2", 2),
                line_native("turn.delta", json!({ "text": "a" }), "n2", 3),
                line_native("turn.delta", json!({ "text": "late" }), "n3", 2),
                "this line is not json {".to_string(),
                line_native("turn.delta", json!({ "text": "b" }), "n4", 4),
            ];
            lines.extend(closing(true, prompt));
            lines
        }
        SimCondition::DelayedStaleEvent => {
            let mut lines = vec![start];
            lines.extend(closing(true, prompt));
            lines.push(line("turn.delta", json!({ "text": "stale straggler" })));
            lines
        }
        SimCondition::Refusal => vec![
            start,
            line(
                "turn.completed",
                json!({ "proposal": null, "text": "refused", "refusal": "policy refusal" }),
            ),
        ],
        SimCondition::ProcessCrash => vec![
            start,
            line("turn.delta", json!({ "text": "partial" })),
            line(
                "turn.failed",
                json!({ "reason": "process crashed", "signal": 9 }),
            ),
        ],
        SimCondition::FalseCompletion => vec![
            start,
            line(
                "turn.completed",
                json!({ "proposal": null, "text": "all done!", "done_claim": true }),
            ),
        ],
        SimCondition::ContextLimit => vec![
            start,
            line(
                "context.reported",
                json!({ "tokens_used": 199_500, "context_window": 200_000 }),
            ),
            line("turn.failed", json!({ "reason": "context limit reached" })),
        ],
        SimCondition::TerminalOnlyDialog => vec![
            start,
            line(
                "permission.requested",
                json!({ "channel": "terminal_only", "dialog": "Trust this folder?" }),
            ),
        ],
        SimCondition::VersionDrift => {
            let mut lines = vec![
                line("session.started", json!({ "binary_version": "sim-9.9.9" })),
                start,
            ];
            lines.extend(closing(true, prompt));
            lines
        }
    }
}
