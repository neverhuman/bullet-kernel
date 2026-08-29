//! Admitted Claude session state machine (execution plan M3 / ADAPT-1a):
//! `Created → Started → Turn(n) → Started …`, `Interrupted` as a side state,
//! `Terminated` terminal. A session exists only around a [`DispatchCleared`]
//! handle, minted only by spending a [`VerifiedLaunchGrant`] here, so the
//! type system prevents an unadmitted session and the grant's own bounds
//! (expiry, invocations, gates, wall bound, budget) reach every later
//! decision. `start` freezes argv, env keys, and workspace but spawns
//! nothing; [`ClaudeSession::send`] is the ONLY way to obtain a
//! [`TurnRecord`]. Every event came from native transcript bytes (ADR 0001),
//! and the session never reads a clock: the caller supplies `now`.

mod turn;

use crate::dispatch::dispatch_live_turn;
use crate::{ClaudeStreamTranscript, OBSERVED_CLAUDE_SCHEMA_VERSION};
use bullet_harness_core::{
    kill_process_group, Ack, AgentEvent, AgentSessionId, CanarySecrets, CommandFactory,
    EgressIsolationEvidence, EvaluatedAdmission, HarnessError, InvocationId, LaunchGrantClaims,
    LiveTurnRequest, PidSlot, VerifiedLaunchGrant,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use turn::classify;

pub use turn::{SessionError, TurnRecord, TurnTicket};

/// Read-only tokens `dispatch_live_turn` freezes after `-p <prompt>`; the
/// budget value follows as the final token.
const FROZEN_ARGV: [&str; 6] = [
    "--output-format",
    "stream-json",
    "--verbose",
    "--permission-mode",
    "plan",
    "--max-budget-usd",
];
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_SESSION_ID_BYTES: usize = 96;
/// Bounded liveness re-checks after a group kill; polling is never authority.
const KILL_CONFIRM_POLLS: u32 = 25;
const KILL_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A dispatch-cleared admission plus the bounds of the grant that cleared
/// it. [`DispatchCleared::require`] is the only constructor: it spends the
/// verified grant on `admit_signed`, admits audited egress evidence, and
/// re-verifies the receipt, so neither an already-cleared nor a weaker
/// admission mints one. NOT `Clone`: one grant, one handle, one session. It
/// exposes no accessor for the admission it holds, so holding the handle
/// cannot be turned into an unaccounted `dispatch_live_turn` of one's own.
///
/// ```compile_fail,E0308
/// use bullet_harness_claude::DispatchCleared;
/// fn twice(cleared: DispatchCleared) -> DispatchCleared {
///     let copy: DispatchCleared = cleared.clone();
///     copy
/// }
/// ```
#[derive(Debug)]
pub struct DispatchCleared {
    admission: EvaluatedAdmission,
    /// The authenticated claims: only `verify_launch_grant` mints these.
    grant: LaunchGrantClaims,
}

impl DispatchCleared {
    /// Mint the handle at the exact chokepoint `build_with_admission` uses.
    /// The verified grant is consumed here, so the bounds it carries are
    /// authenticated ones no caller can substitute.
    ///
    /// # Errors
    ///
    /// `LAUNCH_GRANT_SUBJECT_MISMATCH` when the grant does not name this
    /// admission's own facts, `ADMISSION_REFUSED` for an already-cleared
    /// admission or unproven containment, and `PROVIDER_ADMISSION_BLOCKED`
    /// when any other blocker survives.
    pub fn require(
        admission: EvaluatedAdmission,
        grant: VerifiedLaunchGrant,
        egress: EgressIsolationEvidence,
    ) -> Result<Self, HarnessError> {
        let claims = grant.claims().clone();
        let admission = admission.admit_signed(grant)?;
        let admission = admission.admit_egress(egress)?;
        admission.require_dispatch()?;
        Ok(Self {
            admission,
            grant: claims,
        })
    }
}

/// Nothing is spawned in `Created` or `Started`; `Turn(n)` is in flight;
/// `Interrupted` may start a new turn; `Terminated` is final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Created,
    Started,
    Turn(u32),
    Interrupted,
    Terminated,
}

/// What `start` freezes: executable, fixed tokens after `-p <prompt>`, child
/// env keys (never values), workspace, per-turn wall bound. Never the prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchRecord {
    pub program: PathBuf,
    pub fixed_args: Vec<String>,
    pub env_keys: Vec<String>,
    pub workspace: PathBuf,
    pub wall_timeout: Duration,
}

/// Per-session inputs: Kernel session id, absolute read-only workdir, ordered
/// admitted gate ids, positive micro-USD cap, positive wall bound, canaries.
/// Every bound must be inside the grant's and none may widen it.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub session_id: AgentSessionId,
    pub workdir: PathBuf,
    pub gate_ids: Vec<String>,
    pub max_cost_micro_usd: u64,
    pub wall_timeout: Duration,
    pub canaries: CanarySecrets,
}

/// State machine for one admitted read-only Claude session.
#[derive(Debug)]
pub struct ClaudeSession {
    cleared: DispatchCleared,
    config: SessionConfig,
    phase: SessionPhase,
    launch: Option<LaunchRecord>,
    turns_started: u32,
    turns: Vec<TurnRecord>,
    log: Vec<AgentEvent>,
    pid_slot: PidSlot,
    observed_now_unix_ms: u64,
    spent_micro_usd: u64,
    unconfirmed: Option<String>,
}

impl ClaudeSession {
    /// The only constructor. A session cannot exist without a
    /// [`DispatchCleared`] handle: any other first argument is a type error,
    /// not a runtime refusal. The handle is consumed, so one cleared grant
    /// yields at most one session.
    ///
    /// ```compile_fail,E0308
    /// use bullet_harness_claude::session::{ClaudeSession, SessionConfig, SessionError};
    /// fn unadmitted(config: SessionConfig) -> Result<ClaudeSession, SessionError> {
    ///     ClaudeSession::new((), config, 0)
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// `ADMISSION_REFUSED` for a zero budget/timeout or oversized id;
    /// `PROTOCOL_ERROR`/`PROPOSAL_PARSE_FAILED` for a bad id, workdir, or
    /// gate list; `SESSION_GATE_MISMATCH`, `SESSION_BUDGET_EXCEEDED`,
    /// `SESSION_WALL_BOUND_EXCEEDED`, or `SESSION_AUTHORITY_EXPIRED` when
    /// the config asks for more than the grant gave at `now_unix_ms`.
    pub fn new(
        cleared: DispatchCleared,
        config: SessionConfig,
        now_unix_ms: u64,
    ) -> Result<Self, SessionError> {
        if config.max_cost_micro_usd == 0
            || config.wall_timeout.is_zero()
            || config.session_id.as_str().len() > MAX_SESSION_ID_BYTES
        {
            return Err(refused("budget, wall timeout, and session id are bounded"));
        }
        let cwd = config.workdir.to_string_lossy().into_owned();
        ClaudeStreamTranscript::new(
            config.session_id.clone(),
            InvocationId::new("session-config-probe"),
            &cwd,
            OBSERVED_CLAUDE_SCHEMA_VERSION,
            config.gate_ids.clone(),
        )
        .map_err(SessionError::Harness)?;
        let grant = &cleared.grant;
        if config.gate_ids != grant.gate_ids {
            return Err(SessionError::GateMismatch);
        }
        if config.max_cost_micro_usd > grant.max_cost_micro_usd {
            return Err(SessionError::BudgetExceeded {
                spent: config.max_cost_micro_usd,
                budget: grant.max_cost_micro_usd,
            });
        }
        let wall_ms = config.wall_timeout.as_millis();
        if wall_ms > u128::from(grant.max_wall_clock_ms) {
            return Err(SessionError::WallBoundExceeded {
                wall_ms,
                max_wall_ms: grant.max_wall_clock_ms,
            });
        }
        let mut session = Self {
            cleared,
            config,
            phase: SessionPhase::Created,
            launch: None,
            turns_started: 0,
            turns: Vec::new(),
            log: Vec::new(),
            pid_slot: Arc::new(Mutex::new(None)),
            observed_now_unix_ms: 0,
            spent_micro_usd: 0,
            unconfirmed: None,
        };
        session.require_authority(now_unix_ms)?;
        Ok(session)
    }

    /// Freeze the launch record. Idempotent once started; spawns nothing.
    ///
    /// # Errors
    ///
    /// `SESSION_TERMINATED` after `terminate`; `SESSION_KILL_UNCONFIRMED`
    /// once a kill could not be confirmed.
    pub fn start(&mut self) -> Result<LaunchRecord, SessionError> {
        self.require_confirmed()?;
        if self.phase == SessionPhase::Terminated {
            return Err(SessionError::Terminated);
        }
        if let Some(record) = &self.launch {
            return Ok(record.clone());
        }
        let admission = &self.cleared.admission;
        let mut fixed_args: Vec<String> = FROZEN_ARGV.iter().map(ToString::to_string).collect();
        fixed_args.push(budget_flag(self.config.max_cost_micro_usd));
        let record = LaunchRecord {
            program: admission.executable().to_path_buf(),
            fixed_args,
            env_keys: admission
                .child_env()
                .iter()
                .map(|(k, _)| k.clone())
                .collect(),
            workspace: self.config.workdir.clone(),
            wall_timeout: self.config.wall_timeout,
        };
        self.launch = Some(record.clone());
        self.phase = SessionPhase::Started;
        Ok(record)
    }

    /// Run exactly one guarded one-shot turn through `factory` at the
    /// caller's `now_unix_ms`; the only path to a [`TurnRecord`]. Kill
    /// switch, denied tokens, the admission chokepoint, canary scans, and
    /// the wall-clock group kill live inside [`dispatch_live_turn`]; expiry,
    /// invocations, spend, timeout, and exit status are enforced here.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`]. A refusal never yields a record and never lets
    /// a later `send` spend authority the grant no longer has.
    pub fn send(
        &mut self,
        factory: &CommandFactory<'_>,
        prompt: &str,
        now_unix_ms: u64,
    ) -> Result<TurnRecord, SessionError> {
        self.require_confirmed()?;
        self.require_authority(now_unix_ms)?;
        let ticket = self.begin_turn(prompt)?;
        let request = self.request(&ticket);
        match dispatch_live_turn(&self.cleared.admission, factory, &request) {
            Ok(outcome) => self.complete_turn(
                &ticket,
                outcome.events,
                outcome.exit_code,
                outcome.timed_out,
                outcome.total_cost_micro_usd,
            ),
            Err(error) => Err(self.refuse_turn(classify(ticket.turn(), error))),
        }
    }

    /// Kill any supervised child group and mark the session interrupted.
    /// Idempotent; the in-flight turn, if any, is abandoned.
    ///
    /// # Errors
    ///
    /// `SESSION_NOT_STARTED`, `SESSION_TERMINATED`, or the terminal
    /// `SESSION_KILL_UNCONFIRMED`.
    pub fn interrupt(&mut self) -> Result<Ack, SessionError> {
        self.require_confirmed()?;
        match self.phase {
            SessionPhase::Created => return Err(SessionError::NotStarted),
            SessionPhase::Terminated => return Err(SessionError::Terminated),
            SessionPhase::Interrupted => return Ok(Ack { acknowledged: true }),
            SessionPhase::Started | SessionPhase::Turn(_) => {}
        }
        if let Err(detail) = self.kill_live() {
            return Err(self.fail_terminal(&detail));
        }
        self.phase = SessionPhase::Interrupted;
        Ok(Ack { acknowledged: true })
    }

    /// Kill any supervised child group and terminate. Idempotent and legal
    /// from every phase.
    ///
    /// # Errors
    ///
    /// `SESSION_KILL_UNCONFIRMED` when the group is not confirmed dead;
    /// repeat calls keep returning that same refusal.
    pub fn terminate(&mut self) -> Result<Ack, SessionError> {
        self.require_confirmed()?;
        if self.phase != SessionPhase::Terminated {
            if let Err(detail) = self.kill_live() {
                return Err(self.fail_terminal(&detail));
            }
            self.phase = SessionPhase::Terminated;
        }
        Ok(Ack { acknowledged: true })
    }

    /// Current phase.
    #[must_use]
    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// Completed turns in order.
    #[must_use]
    pub fn turns(&self) -> &[TurnRecord] {
        &self.turns
    }

    /// Every native-derived envelope of every completed turn, in order. The
    /// session adds nothing of its own.
    #[must_use]
    pub fn events(&self) -> Vec<AgentEvent> {
        self.log.clone()
    }

    /// Slot a supervised runner fills with the live child pid for the group
    /// kill; `dispatch_live_turn` reaps its one-shot child and never fills it.
    /// A pid left here must be confirmed gone before any later operation.
    #[must_use]
    pub fn pid_slot(&self) -> PidSlot {
        Arc::clone(&self.pid_slot)
    }

    /// Open turn `n`: `Started | Interrupted → Turn(n)`. Spawns nothing and
    /// yields no record; only [`ClaudeSession::send`] completes a turn.
    ///
    /// # Errors
    ///
    /// `SESSION_NOT_STARTED`, `SESSION_TERMINATED`,
    /// `SESSION_TURN_IN_PROGRESS`, `SESSION_INVOCATIONS_EXHAUSTED`,
    /// `SESSION_KILL_UNCONFIRMED`, or `ADMISSION_REFUSED` for a bad prompt.
    pub fn begin_turn(&mut self, prompt: &str) -> Result<TurnTicket, SessionError> {
        self.require_confirmed()?;
        match self.phase {
            SessionPhase::Created => return Err(SessionError::NotStarted),
            SessionPhase::Terminated => return Err(SessionError::Terminated),
            SessionPhase::Turn(turn) => return Err(SessionError::TurnInProgress { turn }),
            SessionPhase::Started | SessionPhase::Interrupted => {}
        }
        let allowance = self.cleared.grant.max_invocations.min(u64::from(u32::MAX));
        if u64::from(self.turns_started) >= allowance {
            return Err(SessionError::InvocationsExhausted {
                max_invocations: allowance,
            });
        }
        if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.contains('\0') {
            return Err(refused("prompt is empty, oversized, or contains NUL"));
        }
        let turn = self.turns_started.saturating_add(1);
        self.turns_started = turn;
        self.phase = SessionPhase::Turn(turn);
        let invocation = InvocationId::new(format!("{}.t{turn}", self.config.session_id));
        Ok(TurnTicket::issue(turn, invocation, prompt))
    }

    /// The exact request `dispatch_live_turn` receives for one ticket.
    #[must_use]
    pub fn request(&self, ticket: &TurnTicket) -> LiveTurnRequest {
        LiveTurnRequest {
            session_id: self.config.session_id.clone(),
            invocation_id: ticket.invocation_id().clone(),
            prompt: ticket.prompt().to_string(),
            workdir: self.config.workdir.clone(),
            expected_runtime_version: OBSERVED_CLAUDE_SCHEMA_VERSION.to_string(),
            gate_ids: self.config.gate_ids.clone(),
            max_cost_micro_usd: self.config.max_cost_micro_usd,
            wall_timeout: self.config.wall_timeout,
            canaries: self.config.canaries.clone(),
        }
    }

    /// Adopt one completed turn: its envelopes, its record, `Turn(n) → Started`.
    pub(super) fn commit(&mut self, record: &TurnRecord) {
        self.log.extend(record.events().iter().cloned());
        self.phase = SessionPhase::Started;
        self.turns.push(record.clone());
    }

    /// Grant bounds before every dispatch: the observed `now` never moves
    /// backwards, and the allowance is clamped so the turn counter cannot wrap.
    fn require_authority(&mut self, now_unix_ms: u64) -> Result<(), SessionError> {
        let grant = &self.cleared.grant;
        self.observed_now_unix_ms = self.observed_now_unix_ms.max(now_unix_ms);
        let now_ms = self.observed_now_unix_ms;
        if now_ms >= grant.expires_at_unix_ms {
            return Err(SessionError::AuthorityExpired {
                now_ms,
                expires_at_ms: grant.expires_at_unix_ms,
            });
        }
        let allowance = grant.max_invocations.min(u64::from(u32::MAX));
        if u64::from(self.turns_started) >= allowance {
            return Err(SessionError::InvocationsExhausted {
                max_invocations: allowance,
            });
        }
        let budget = self.config.max_cost_micro_usd;
        if self.spent_micro_usd >= budget {
            return Err(SessionError::BudgetExceeded {
                spent: self.spent_micro_usd,
                budget,
            });
        }
        Ok(())
    }

    fn require_confirmed(&self) -> Result<(), SessionError> {
        match &self.unconfirmed {
            Some(detail) => Err(SessionError::KillUnconfirmed {
                detail: detail.clone(),
            }),
            None => Ok(()),
        }
    }

    fn fail_terminal(&mut self, detail: &str) -> SessionError {
        self.unconfirmed = Some(detail.to_string());
        self.phase = SessionPhase::Terminated;
        SessionError::KillUnconfirmed {
            detail: detail.to_string(),
        }
    }

    /// Take the supervised pid and confirm its group is gone. A poisoned lock
    /// or a still-present pid is `Err(detail)`, never a silent success.
    fn kill_live(&mut self) -> Result<(), String> {
        let taken = match self.pid_slot.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => {
                return Err(
                    "the supervised pid lock is poisoned; a live child group may remain".into(),
                )
            }
        };
        let Some(pid) = taken else { return Ok(()) };
        kill_process_group(pid);
        if process_present(pid) {
            return Err(format!(
                "pid {pid} is still present after the group kill was issued"
            ));
        }
        Ok(())
    }
}

/// Bounded liveness observation for one pid. A host with no observable
/// process table reports "still present": nothing unseen is ever claimed.
fn process_present(pid: u32) -> bool {
    if !Path::new("/proc/self").is_dir() {
        return true;
    }
    let entry = PathBuf::from(format!("/proc/{pid}"));
    for _ in 0..KILL_CONFIRM_POLLS {
        if !entry.exists() {
            return false;
        }
        std::thread::sleep(KILL_POLL_INTERVAL);
    }
    entry.exists()
}

fn refused(reason: &str) -> SessionError {
    SessionError::Harness(HarnessError::AdmissionRefused {
        reason: reason.to_string(),
    })
}

fn budget_flag(max_cost_micro_usd: u64) -> String {
    format!("{:.6}", max_cost_micro_usd as f64 / 1_000_000.0)
}
