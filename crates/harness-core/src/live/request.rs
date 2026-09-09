//! The provider-side inputs to one live-conformance dispatch. The
//! policy/ledger/issuer orchestration lives in `bullet_application`; this
//! request carries only what a provider adapter needs to run and parse a
//! single read-only turn.

use crate::admission::CanarySecrets;
use crate::ids::{AgentSessionId, InvocationId};
use std::path::PathBuf;
use std::time::Duration;

/// The exact prompt every live-conformance turn dispatches.
pub const CONFORMANCE_PROMPT: &str = "Reply with the single word PONG and nothing else.";

/// The single word a conforming provider must reply with.
pub const CONFORMANCE_EXPECTED_RESPONSE: &str = "PONG";

/// Inputs for one guarded provider dispatch. The adapter builds argv through
/// `ArgvBuilder::build_with_admission`, runs it through the caller-supplied
/// command factory, and parses via its own frozen protocol contract.
#[derive(Clone, Debug)]
pub struct LiveTurnRequest {
    /// Kernel session id bound into normalized envelopes.
    pub session_id: AgentSessionId,
    /// Kernel invocation id bound into normalized envelopes.
    pub invocation_id: InvocationId,
    /// The prompt to dispatch (always [`CONFORMANCE_PROMPT`]).
    pub prompt: String,
    /// Absolute read-only working directory.
    pub workdir: PathBuf,
    /// Exact runtime version the frozen protocol contract expects.
    pub expected_runtime_version: String,
    /// Ordered admitted gate identifiers for the structured proposal contract.
    pub gate_ids: Vec<String>,
    /// Tightest cost cap in micro-USD.
    pub max_cost_micro_usd: u64,
    /// Wall-clock bound for the whole invocation.
    pub wall_timeout: Duration,
    /// Host canaries that must never reach a provider-facing surface.
    pub canaries: CanarySecrets,
}

impl LiveTurnRequest {
    /// Cost cap formatted as a fixed-precision USD budget flag value.
    #[must_use]
    pub fn max_budget_usd(&self) -> String {
        format!("{:.6}", self.max_cost_micro_usd as f64 / 1_000_000.0)
    }
}
