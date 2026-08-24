//! Session state machine (spec s18.2): 16 main states plus 10 exception
//! states, with an explicit legal-edge table. The spec's prose summary counts
//! differ; the state list here matches the s18.2 blocks verbatim.

use crate::error::HarnessError;
use serde::{Deserialize, Serialize};

/// One agent session's lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session object exists; nothing spawned.
    Created,
    /// Provider process is being started.
    Starting,
    /// Effective account identity is being probed (s8.6).
    IdentityProbing,
    /// Context is loading into the session.
    ContextLoading,
    /// Idle and able to accept a turn.
    Ready,
    /// A turn is executing.
    Running,
    /// Blocked on a tool invocation.
    WaitingTool,
    /// Blocked on local plan approval.
    WaitingLocalPlan,
    /// Blocked on a permission decision.
    WaitingPermission,
    /// Deliberately paused.
    Paused,
    /// Writing a checkpoint.
    Checkpointing,
    /// Compaction or context migration in progress.
    ContextTransition,
    /// Resuming a prior native session.
    Resuming,
    /// Final output being assembled.
    Completing,
    /// Shutdown initiated.
    Terminating,
    /// Fully stopped; terminal.
    Terminated,
    /// Exception: provider demands re-authentication.
    AuthRequired,
    /// Exception: provider throttled (429 class).
    Throttled,
    /// Exception: context near its limit.
    ContextAtRisk,
    /// Exception: no observable progress.
    Unresponsive,
    /// Exception: stream violated its protocol.
    ProtocolError,
    /// Exception: terminal-only dialog; screen state unknown.
    ScreenUnknown,
    /// Exception: process liveness unknown.
    ProcessUnknown,
    /// Exception: blocked by policy.
    PolicyBlocked,
    /// Exception: isolated pending operator review.
    Quarantined,
    /// Exception: provider process died.
    Crashed,
}

macro_rules! allow {
    ($from:expr, $to:expr, $($ok:pat => $dst:expr),+ $(,)?) => {
        match ($from, $to) {
            $($ok => Ok($dst),)+
            _ => Err(HarnessError::IllegalTransition {
                from: format!("{:?}", $from),
                to: format!("{:?}", $to),
            }),
        }
    };
}

impl SessionState {
    /// The 16 main states in spec order.
    pub const MAIN: [SessionState; 16] = [
        SessionState::Created,
        SessionState::Starting,
        SessionState::IdentityProbing,
        SessionState::ContextLoading,
        SessionState::Ready,
        SessionState::Running,
        SessionState::WaitingTool,
        SessionState::WaitingLocalPlan,
        SessionState::WaitingPermission,
        SessionState::Paused,
        SessionState::Checkpointing,
        SessionState::ContextTransition,
        SessionState::Resuming,
        SessionState::Completing,
        SessionState::Terminating,
        SessionState::Terminated,
    ];

    /// The 10 exception states in spec order.
    pub const EXCEPTIONS: [SessionState; 10] = [
        SessionState::AuthRequired,
        SessionState::Throttled,
        SessionState::ContextAtRisk,
        SessionState::Unresponsive,
        SessionState::ProtocolError,
        SessionState::ScreenUnknown,
        SessionState::ProcessUnknown,
        SessionState::PolicyBlocked,
        SessionState::Quarantined,
        SessionState::Crashed,
    ];

    /// True for the 10 exception states.
    #[must_use]
    pub fn is_exception(self) -> bool {
        Self::EXCEPTIONS.contains(&self)
    }

    /// Terminated is the only terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        self == Self::Terminated
    }

    /// Apply one legal edge.
    ///
    /// Any non-terminal, non-exception state may enter any exception state
    /// (faults strike anywhere). All other edges come from the explicit table.
    ///
    /// # Errors
    ///
    /// `ILLEGAL_STATE_EDGE` when the edge is not in the table.
    pub fn transition(self, to: Self) -> Result<Self, HarnessError> {
        use SessionState::*;
        if to.is_exception() && !self.is_exception() && !self.is_terminal() {
            return Ok(to);
        }
        allow!(
            self,
            to,
            (Created, Starting) => Starting,
            (Created, Resuming) => Resuming,
            (Starting, IdentityProbing) => IdentityProbing,
            (IdentityProbing, ContextLoading) => ContextLoading,
            (ContextLoading, Ready) => Ready,
            (Resuming, IdentityProbing) => IdentityProbing,
            (Resuming, Ready) => Ready,
            (Ready, Running) => Running,
            (Running, WaitingTool) => WaitingTool,
            (WaitingTool, Running) => Running,
            (Running, WaitingLocalPlan) => WaitingLocalPlan,
            (WaitingLocalPlan, Running) => Running,
            (Running, WaitingPermission) => WaitingPermission,
            (WaitingPermission, Running) => Running,
            (Running, Paused) => Paused,
            (Paused, Running) => Running,
            (Running, Checkpointing) => Checkpointing,
            (Checkpointing, Running) => Running,
            (Running, ContextTransition) => ContextTransition,
            (ContextTransition, Running) => Running,
            (ContextTransition, Ready) => Ready,
            (Running, Ready) => Ready,
            (Running, Completing) => Completing,
            (Completing, Terminating) => Terminating,
            (
                Created | Starting | IdentityProbing | ContextLoading | Ready | Running
                | WaitingTool | WaitingLocalPlan | WaitingPermission | Paused
                | Checkpointing | ContextTransition | Resuming,
                Terminating
            ) => Terminating,
            (Terminating, Terminated) => Terminated,
            (AuthRequired, Starting) => Starting,
            (Throttled, Ready) => Ready,
            (Throttled, Running) => Running,
            (ContextAtRisk, ContextTransition) => ContextTransition,
            (Unresponsive, Running) => Running,
            (Unresponsive, ProcessUnknown) => ProcessUnknown,
            (Unresponsive, Crashed) => Crashed,
            (ScreenUnknown, Running) => Running,
            (ScreenUnknown, Crashed) => Crashed,
            (ProcessUnknown, Crashed) => Crashed,
            (ProtocolError, Quarantined) => Quarantined,
            (PolicyBlocked, Quarantined) => Quarantined,
            (Crashed, Resuming) => Resuming,
            (
                AuthRequired | Throttled | ContextAtRisk | Unresponsive | ProtocolError
                | ScreenUnknown | ProcessUnknown | PolicyBlocked | Quarantined | Crashed,
                Terminating
            ) => Terminating,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SessionState::*;

    #[test]
    fn state_counts_match_spec() {
        assert_eq!(SessionState::MAIN.len(), 16);
        assert_eq!(SessionState::EXCEPTIONS.len(), 10);
    }

    #[test]
    fn happy_path_is_legal() {
        let chain = [
            Created,
            Starting,
            IdentityProbing,
            ContextLoading,
            Ready,
            Running,
            Completing,
            Terminating,
            Terminated,
        ];
        let mut state = chain[0];
        for next in &chain[1..] {
            state = state.transition(*next).expect("legal edge");
        }
        assert_eq!(state, Terminated);
    }

    #[test]
    fn waiting_states_bounce_back_to_running() {
        for waiting in [WaitingTool, WaitingLocalPlan, WaitingPermission, Paused] {
            assert_eq!(Running.transition(waiting).unwrap(), waiting);
            assert_eq!(waiting.transition(Running).unwrap(), Running);
        }
    }

    #[test]
    fn terminated_is_terminal() {
        for to in SessionState::MAIN
            .iter()
            .chain(SessionState::EXCEPTIONS.iter())
        {
            assert!(Terminated.transition(*to).is_err(), "{to:?}");
        }
    }

    #[test]
    fn exceptions_enter_from_any_active_state_and_recover() {
        assert_eq!(Running.transition(Throttled).unwrap(), Throttled);
        assert_eq!(Throttled.transition(Running).unwrap(), Running);
        assert_eq!(Starting.transition(AuthRequired).unwrap(), AuthRequired);
        assert_eq!(AuthRequired.transition(Starting).unwrap(), Starting);
        assert_eq!(Crashed.transition(Resuming).unwrap(), Resuming);
        for exc in SessionState::EXCEPTIONS {
            assert_eq!(exc.transition(Terminating).unwrap(), Terminating);
        }
    }

    #[test]
    fn illegal_edges_carry_the_reason_code() {
        let err = Created.transition(Running).unwrap_err();
        assert_eq!(err.reason_code(), "ILLEGAL_STATE_EDGE");
        assert!(ProtocolError.transition(Running).is_err());
    }
}
