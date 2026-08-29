//! Turn vocabulary for [`super::ClaudeSession`]: the typed refusal set, the
//! unforgeable turn ticket, native-derived turn evidence, and the completion
//! path itself.
//!
//! [`TurnTicket`] authorizes exactly one completion: its fields are private,
//! it is neither `Clone` nor `Default`, and its only constructor is
//! `pub(super)` — reachable solely through `ClaudeSession::begin_turn`, and
//! therefore only through `ClaudeSession::send`. [`TurnRecord`]'s fields are
//! private for the same reason: outside this crate a record exists only
//! because a turn was really dispatched. Every envelope inside one came from
//! native transcript bytes (ADR 0001); nothing here synthesizes an event.

use super::{ClaudeSession, SessionPhase};
use bullet_harness_core::{AgentEvent, AgentEventKind, HarnessError, InvocationId, PatchProposal};
use std::fmt;

/// Typed session failure. Every variant carries a stable reason code;
/// `UNKNOWN` is never one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// `start` has not been called.
    NotStarted,
    /// The session is terminated; nothing further is admitted.
    Terminated,
    /// Turn `turn` is already in flight.
    TurnInProgress { turn: u32 },
    /// Turn `turn` was interrupted; its completion is discarded.
    Interrupted { turn: u32 },
    /// The ticket names a turn that is not in flight.
    TurnNotInFlight { turn: u32 },
    /// The turn reached a terminal outcome without a proposal.
    NoProposal { turn: u32 },
    /// `count` proposal-bearing envelopes reached one turn.
    ProposalAmbiguous { turn: u32, count: usize },
    /// The transcript, or the proposal it carried, violated the contract.
    TranscriptMalformed { turn: u32, reason: String },
    /// The caller's `now` reached the grant's exclusive expiry.
    AuthorityExpired { now_ms: u64, expires_at_ms: u64 },
    /// The grant's invocation allowance is spent.
    InvocationsExhausted { max_invocations: u64 },
    /// The session's gate set is not the grant's gate set.
    GateMismatch,
    /// The session's wall bound exceeds the grant's.
    WallBoundExceeded { wall_ms: u128, max_wall_ms: u64 },
    /// Requested or accumulated spend exceeds the authorized budget.
    BudgetExceeded { spent: u64, budget: u64 },
    /// The turn hit its wall bound; a timeout is never a success.
    TurnTimedOut { turn: u32 },
    /// The provider process crashed or reported no exit status.
    TurnAborted { turn: u32, exit_code: Option<i32> },
    /// The turn produced a proposal but reported no spend.
    CostUnreported { turn: u32 },
    /// A child group kill could not be confirmed; the session is terminal.
    KillUnconfirmed { detail: String },
    /// A guarded-dispatch or configuration failure keeps its own code.
    Harness(HarnessError),
}

impl SessionError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::NotStarted => "SESSION_NOT_STARTED",
            Self::Terminated => "SESSION_TERMINATED",
            Self::TurnInProgress { .. } => "SESSION_TURN_IN_PROGRESS",
            Self::Interrupted { .. } => "SESSION_INTERRUPTED",
            Self::TurnNotInFlight { .. } => "SESSION_TURN_NOT_IN_FLIGHT",
            Self::NoProposal { .. } => "SESSION_NO_PROPOSAL",
            Self::ProposalAmbiguous { .. } => "SESSION_PROPOSAL_AMBIGUOUS",
            Self::TranscriptMalformed { .. } => "SESSION_TRANSCRIPT_MALFORMED",
            Self::AuthorityExpired { .. } => "SESSION_AUTHORITY_EXPIRED",
            Self::InvocationsExhausted { .. } => "SESSION_INVOCATIONS_EXHAUSTED",
            Self::GateMismatch => "SESSION_GATE_MISMATCH",
            Self::WallBoundExceeded { .. } => "SESSION_WALL_BOUND_EXCEEDED",
            Self::BudgetExceeded { .. } => "SESSION_BUDGET_EXCEEDED",
            Self::TurnTimedOut { .. } => "SESSION_TURN_TIMED_OUT",
            Self::TurnAborted { .. } => "SESSION_TURN_ABORTED",
            Self::CostUnreported { .. } => "SESSION_COST_UNREPORTED",
            Self::KillUnconfirmed { .. } => "SESSION_KILL_UNCONFIRMED",
            Self::Harness(error) => error.reason_code(),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Harness(error) => write!(f, "{}: {error}", error.reason_code()),
            Self::TranscriptMalformed { turn, reason } => {
                write!(f, "{}: turn {turn}: {reason}", self.reason_code())
            }
            Self::KillUnconfirmed { detail } => write!(f, "{}: {detail}", self.reason_code()),
            other => write!(f, "{}: {other:?}", other.reason_code()),
        }
    }
}

impl std::error::Error for SessionError {}

/// One in-flight turn: its number, its invocation id, and the prompt that
/// travels by argv. Outside the crate it cannot be read, cloned, defaulted,
/// or constructed, so a ticket always names a really open turn.
///
/// ```compile_fail,E0616
/// use bullet_harness_claude::TurnTicket;
/// fn peek(ticket: TurnTicket) -> u32 {
///     ticket.turn
/// }
/// ```
pub struct TurnTicket {
    turn: u32,
    invocation_id: InvocationId,
    prompt: String,
}

impl TurnTicket {
    pub(super) fn issue(turn: u32, invocation_id: InvocationId, prompt: &str) -> Self {
        Self {
            turn,
            invocation_id,
            prompt: prompt.to_string(),
        }
    }

    /// Turn number this ticket opens.
    #[must_use]
    pub fn turn(&self) -> u32 {
        self.turn
    }

    /// Invocation id `<session>.t<n>` bound to this turn.
    #[must_use]
    pub fn invocation_id(&self) -> &InvocationId {
        &self.invocation_id
    }

    pub(super) fn prompt(&self) -> &str {
        &self.prompt
    }
}

/// Never renders the prompt: tickets are logged, and provider prompts are
/// neither authority nor diagnostics.
impl fmt::Debug for TurnTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnTicket")
            .field("turn", &self.turn)
            .field("invocation_id", &self.invocation_id)
            .finish_non_exhaustive()
    }
}

/// One completed turn: native-derived envelopes, the single validated
/// proposal, observed exit facts, and the spend charged to the session.
///
/// ```compile_fail,E0616
/// use bullet_harness_claude::TurnRecord;
/// fn peek(record: TurnRecord) -> bool {
///     record.timed_out
/// }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct TurnRecord {
    turn: u32,
    invocation_id: InvocationId,
    events: Vec<AgentEvent>,
    proposal: PatchProposal,
    exit_code: Option<i32>,
    timed_out: bool,
    cost_micro_usd: u64,
}

impl TurnRecord {
    /// Turn number.
    #[must_use]
    pub fn turn(&self) -> u32 {
        self.turn
    }

    /// Invocation id of the dispatched turn.
    #[must_use]
    pub fn invocation_id(&self) -> &InvocationId {
        &self.invocation_id
    }

    /// Envelopes derived from the native transcript, in arrival order.
    #[must_use]
    pub fn events(&self) -> &[AgentEvent] {
        &self.events
    }

    /// The single validated proposal the terminal frame carried.
    #[must_use]
    pub fn proposal(&self) -> &PatchProposal {
        &self.proposal
    }

    /// Observed exit code; a record only ever holds `Some(0)`.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Always false: a timed-out turn is a refusal, never a record.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// Spend the provider reported for this turn, in micro-USD.
    #[must_use]
    pub fn cost_micro_usd(&self) -> u64 {
        self.cost_micro_usd
    }
}

impl ClaudeSession {
    /// Close turn `ticket` with native-derived envelopes. Private: outside
    /// this crate a record can only come back from `ClaudeSession::send`.
    ///
    /// ```compile_fail,E0599
    /// use bullet_harness_claude::{ClaudeSession, SessionError, TurnRecord, TurnTicket};
    /// fn forge(s: &mut ClaudeSession, t: &TurnTicket) -> Result<TurnRecord, SessionError> {
    ///     s.complete_turn(t, Vec::new(), Some(0), false, Some(0))
    /// }
    /// ```
    pub(super) fn complete_turn(
        &mut self,
        ticket: &TurnTicket,
        events: Vec<AgentEvent>,
        exit_code: Option<i32>,
        timed_out: bool,
        cost_micro_usd: Option<u64>,
    ) -> Result<TurnRecord, SessionError> {
        self.require_in_flight(ticket)?;
        let turn = ticket.turn();
        // Spend is charged before any verdict: a refused turn still cost money.
        if let Some(over) = self.charge(cost_micro_usd.unwrap_or(0)) {
            return Err(self.refuse_turn(over));
        }
        if timed_out {
            return Err(self.refuse_turn(SessionError::TurnTimedOut { turn }));
        }
        if exit_code != Some(0) {
            return Err(self.refuse_turn(SessionError::TurnAborted { turn, exit_code }));
        }
        let proposal = match extract_proposal(turn, &events) {
            Ok(proposal) => proposal,
            Err(error) => return Err(self.refuse_turn(error)),
        };
        let Some(cost_micro_usd) = cost_micro_usd else {
            return Err(self.refuse_turn(SessionError::CostUnreported { turn }));
        };
        let record = TurnRecord {
            turn,
            invocation_id: ticket.invocation_id().clone(),
            events,
            proposal,
            exit_code,
            timed_out,
            cost_micro_usd,
        };
        self.commit(&record);
        Ok(record)
    }

    /// Charge `cost` to the budget; `Some(error)` once the total is over it.
    fn charge(&mut self, cost: u64) -> Option<SessionError> {
        self.spent_micro_usd = self.spent_micro_usd.saturating_add(cost);
        let budget = self.config.max_cost_micro_usd;
        (self.spent_micro_usd > budget).then_some(SessionError::BudgetExceeded {
            spent: self.spent_micro_usd,
            budget,
        })
    }

    /// Abandon the in-flight turn; the typed error is the only record. An
    /// unconfirmed kill outranks it and makes the session terminal.
    pub(super) fn refuse_turn(&mut self, error: SessionError) -> SessionError {
        match self.kill_live() {
            Ok(()) => {
                self.phase = SessionPhase::Started;
                error
            }
            Err(detail) => {
                let code = error.reason_code();
                self.fail_terminal(&format!("{detail}; the turn also refused with {code}"))
            }
        }
    }

    fn require_in_flight(&self, ticket: &TurnTicket) -> Result<(), SessionError> {
        let expected = ticket.turn();
        match self.phase() {
            SessionPhase::Created => Err(SessionError::NotStarted),
            SessionPhase::Terminated => Err(SessionError::Terminated),
            SessionPhase::Interrupted => Err(SessionError::Interrupted { turn: expected }),
            SessionPhase::Started => Err(SessionError::TurnNotInFlight { turn: expected }),
            SessionPhase::Turn(turn) if turn == expected => Ok(()),
            SessionPhase::Turn(turn) => Err(SessionError::TurnInProgress { turn }),
        }
    }
}

/// Exactly one proposal, carried only by `turn.completed`, within the
/// proposal bounds. Anything else is a typed refusal and no record.
pub(super) fn extract_proposal(
    turn: u32,
    events: &[AgentEvent],
) -> Result<PatchProposal, SessionError> {
    if events
        .iter()
        .any(|event| event.kind == AgentEventKind::ProtocolError)
    {
        return Err(malformed(turn, "turn envelopes contain protocol.error"));
    }
    let carriers: Vec<&AgentEvent> = events
        .iter()
        .filter(|event| event.payload.get("proposal").is_some())
        .collect();
    let Some(carrier) = carriers.first() else {
        return Err(SessionError::NoProposal { turn });
    };
    if carriers.len() > 1 {
        return Err(SessionError::ProposalAmbiguous {
            turn,
            count: carriers.len(),
        });
    }
    if carrier.kind != AgentEventKind::TurnCompleted {
        return Err(malformed(turn, "proposal carried outside turn.completed"));
    }
    let value = carrier
        .payload
        .get("proposal")
        .ok_or_else(|| malformed(turn, "proposal carrier lost its payload"))?;
    PatchProposal::from_value(value)
        .map_err(|error| malformed(turn, &format!("terminal PatchProposal invalid: {error}")))
}

/// A guarded-dispatch failure keeps its own harness code; a transcript
/// contract violation becomes the session's malformed code.
pub(super) fn classify(turn: u32, error: HarnessError) -> SessionError {
    match error {
        HarnessError::Protocol { reason, .. } => SessionError::TranscriptMalformed { turn, reason },
        other => SessionError::Harness(other),
    }
}

fn malformed(turn: u32, reason: &str) -> SessionError {
    SessionError::TranscriptMalformed {
        turn,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_proposal, SessionError, TurnTicket};
    use bullet_harness_core::{
        AgentEvent, AgentEventKind, AgentSessionId, EventNormalizer, InvocationId, NativeMeta,
    };
    use serde_json::{json, Value};

    const GATE: &str = "gat_8888888888888888888888888888888888888888888888888888888888888888";

    fn proposal_value() -> Value {
        let hex = |ch: char| ch.to_string().repeat(64);
        json!({
            "schema_version": 1, "proposal_id": format!("cnt_{}", hex('1')),
            "producing_attempt_id": format!("atm_{}", hex('2')),
            "base_checkpoint_id": format!("ckp_{}", hex('3')), "base_checkpoint_digest": hex('4'),
            "intent_summary": "unit fixture", "gate_ids": [GATE], "claims": [],
            "uncertainties": [], "done": true, "operations": [{"path": "PONG.txt",
                "preimage": {"kind": "absent"},
                "mutation": {"kind": "write", "content_utf8": "PONG\n"}}],
        })
    }

    fn emit(n: &mut EventNormalizer, kind: AgentEventKind, payload: Value) -> AgentEvent {
        n.accept(kind, payload, &NativeMeta::none())
    }

    fn normalizer() -> EventNormalizer {
        EventNormalizer::new(AgentSessionId::new("unit-session"), "claude")
    }

    #[test]
    fn a_ticket_reports_its_identity_and_never_renders_its_prompt() {
        let ticket = TurnTicket::issue(7, InvocationId::new("unit-session.t7"), "secret prompt");
        let rendered = format!("{ticket:?}");
        assert!(!rendered.contains("secret prompt"), "{rendered}");
        assert!(rendered.contains("turn: 7") && rendered.contains("unit-session.t7"));
        assert_eq!((ticket.turn(), ticket.prompt()), (7, "secret prompt"));
        assert_eq!(ticket.invocation_id().as_str(), "unit-session.t7");
    }

    #[test]
    fn ambiguous_misplaced_or_anomalous_proposal_carriers_never_extract() {
        let mut n = normalizer();
        let carried = json!({"proposal": proposal_value()});
        let (started, completed) = (AgentEventKind::TurnStarted, AgentEventKind::TurnCompleted);
        let twice = vec![
            emit(&mut n, started, json!({})),
            emit(&mut n, completed, carried.clone()),
            emit(&mut n, completed, carried.clone()),
        ];
        let error = extract_proposal(4, &twice).unwrap_err();
        assert_eq!(error, SessionError::ProposalAmbiguous { turn: 4, count: 2 });
        assert_eq!(error.reason_code(), "SESSION_PROPOSAL_AMBIGUOUS");
        let mut fresh = normalizer();
        let delta = AgentEventKind::TurnDelta;
        let misplaced = vec![
            emit(&mut fresh, started, json!({})),
            emit(&mut fresh, delta, carried),
        ];
        let error = extract_proposal(1, &misplaced).unwrap_err();
        assert_eq!(error.reason_code(), "SESSION_TRANSCRIPT_MALFORMED");
        assert!(
            error.to_string().contains("outside turn.completed"),
            "{error}"
        );
        let anomaly = vec![n.malformed("garbage")];
        let error = extract_proposal(2, &anomaly).unwrap_err();
        assert!(error.to_string().contains("protocol.error"), "{error}");
    }

    #[test]
    fn an_absent_or_out_of_bounds_proposal_is_a_typed_refusal() {
        let mut n = normalizer();
        let failed = json!({"subtype": "error_max_turns"});
        let terminal = vec![emit(&mut n, AgentEventKind::TurnFailed, failed)];
        let error = extract_proposal(3, &terminal).unwrap_err();
        assert_eq!(error, SessionError::NoProposal { turn: 3 });
        assert_eq!(error.reason_code(), "SESSION_NO_PROPOSAL");
        let mut oversized = proposal_value();
        oversized["operations"][0]["mutation"]["content_utf8"] = json!("x".repeat(1_048_577));
        let events = vec![emit(
            &mut n,
            AgentEventKind::TurnCompleted,
            json!({"proposal": oversized}),
        )];
        let error = extract_proposal(5, &events).unwrap_err();
        assert_eq!(error.reason_code(), "SESSION_TRANSCRIPT_MALFORMED");
        assert!(
            error.to_string().contains("PatchProposal invalid"),
            "{error}"
        );
    }
}
