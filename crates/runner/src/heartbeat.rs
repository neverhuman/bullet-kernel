//! The heartbeat supervisor: renew the lease on an interval, keep a local
//! monotonic self-kill deadline strictly shorter than the server expiry, and
//! broadcast a freeze the moment authority is stale or the deadline passes.

use crate::clock::{Clock, SelfKillDeadline};
use crate::error::RunnerError;
use crate::lease::{HeartbeatCall, LeaseClient};
use bullet_application::LeaseService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Heartbeat cadence. The TTL comes only from the admitted grant.
#[derive(Clone, Debug)]
pub struct HeartbeatConfig {
    /// Interval between heartbeats.
    pub interval: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
        }
    }
}

/// Why the runner froze.
#[derive(Clone, Debug)]
pub enum FreezeReason {
    /// The ledger matched zero lease rows.
    StaleAuthority(String),
    /// The local monotonic deadline passed without an acknowledged beat.
    SelfKill {
        /// Monotonic milliseconds at the deadline.
        elapsed_ms: u64,
    },
}

impl FreezeReason {
    /// The typed error this freeze surfaces as.
    #[must_use]
    pub fn to_error(&self) -> RunnerError {
        match self {
            Self::StaleAuthority(detail) => RunnerError::StaleAuthority(detail.clone()),
            Self::SelfKill { elapsed_ms } => RunnerError::SelfKill {
                elapsed_ms: *elapsed_ms,
            },
        }
    }
}

/// Handle to the running heartbeat task. Dropping it stops the task.
pub struct HeartbeatHandle {
    task: JoinHandle<()>,
    rx: watch::Receiver<Option<FreezeReason>>,
}

impl HeartbeatHandle {
    /// The freeze reason, if the runner must stop mutating.
    #[must_use]
    pub fn frozen(&self) -> Option<FreezeReason> {
        self.rx.borrow().clone()
    }

    /// Stop heartbeating (normal completion path).
    pub fn abort(&self) {
        self.task.abort();
    }
}

impl Drop for HeartbeatHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start the heartbeat supervisor for one grant.
pub fn start_heartbeat(
    client: Arc<dyn LeaseClient>,
    call: HeartbeatCall,
    config: HeartbeatConfig,
    clock: Arc<dyn Clock>,
) -> Result<HeartbeatHandle, RunnerError> {
    LeaseService::validate_ttl(call.ttl_seconds).map_err(|error| RunnerError::Lease {
        code: error.reason_code().into(),
        message: error.to_string(),
    })?;
    if config.interval.is_zero() {
        return Err(RunnerError::Protocol(
            "heartbeat interval must be greater than zero".into(),
        ));
    }
    let (tx, rx) = watch::channel(None);
    let task = tokio::spawn(heartbeat_loop(client, call, config, clock, tx));
    Ok(HeartbeatHandle { task, rx })
}

async fn heartbeat_loop(
    client: Arc<dyn LeaseClient>,
    call: HeartbeatCall,
    config: HeartbeatConfig,
    clock: Arc<dyn Clock>,
    tx: watch::Sender<Option<FreezeReason>>,
) {
    let admitted_ttl = Duration::from_secs(
        u64::try_from(call.ttl_seconds).expect("HeartbeatCall TTL was validated from its grant"),
    );
    let mut deadline = SelfKillDeadline::new(clock.now(), admitted_ttl);
    let cadence = config.interval.min(deadline.budget() / 2);
    let mut ticker = tokio::time::interval(cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let now = clock.now();
        if deadline.expired(now) {
            let _ = tx.send(Some(FreezeReason::SelfKill {
                elapsed_ms: now.as_millis() as u64,
            }));
            return;
        }
        match tokio::time::timeout(cadence, client.heartbeat(&call)).await {
            Ok(Ok(())) => deadline.renew(clock.now()),
            Ok(Err(err)) if err.is_stale() => {
                let _ = tx.send(Some(FreezeReason::StaleAuthority(err.to_string())));
                return;
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "heartbeat transport failure; deadline keeps closing");
            }
            Err(_) => tracing::warn!("heartbeat timed out; deadline keeps closing"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::lease::{AcquireGrant, AcquireRequest, ReadyView, ReleaseCall};
    use async_trait::async_trait;
    use bullet_domain::{AttemptId, AttemptState, RunnerId, VariantId};

    struct StubClient {
        stale: bool,
        hangs: bool,
        entered: Option<Arc<tokio::sync::Notify>>,
    }

    #[async_trait]
    impl LeaseClient for StubClient {
        async fn acquire(&self, _r: &AcquireRequest) -> Result<AcquireGrant, RunnerError> {
            Err(RunnerError::Protocol("stub".into()))
        }
        async fn heartbeat(&self, _c: &HeartbeatCall) -> Result<(), RunnerError> {
            if self.hangs {
                if let Some(entered) = &self.entered {
                    entered.notify_one();
                }
                return std::future::pending().await;
            }
            if self.stale {
                return Err(RunnerError::StaleAuthority("zero rows".into()));
            }
            Ok(())
        }
        async fn advance(&self, _a: &AttemptId, _s: AttemptState) -> Result<(), RunnerError> {
            Err(RunnerError::Protocol("stub".into()))
        }
        async fn release(&self, _c: &ReleaseCall) -> Result<(), RunnerError> {
            Err(RunnerError::Protocol("stub".into()))
        }
        async fn next_ready(&self) -> Result<Option<ReadyView>, RunnerError> {
            Ok(None)
        }
    }

    fn call() -> HeartbeatCall {
        HeartbeatCall {
            variant_id: VariantId::from_seed("hb"),
            attempt_id: AttemptId::from_seed("hb"),
            fence: 1,
            runner_id: RunnerId::from_seed("hb"),
            runner_epoch: 1,
            workspace_nonce: [7u8; 32],
            ttl_seconds: 1,
        }
    }

    async fn wait_frozen(handle: &HeartbeatHandle) -> FreezeReason {
        for _ in 0..200 {
            if let Some(reason) = handle.frozen() {
                return reason;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("heartbeat never froze");
    }

    #[tokio::test]
    async fn self_kill_fires_on_the_mocked_clock_even_when_beats_succeed() {
        let clock = Arc::new(ManualClock::new());
        let config = HeartbeatConfig {
            interval: Duration::from_millis(10),
        };
        let handle = start_heartbeat(
            Arc::new(StubClient {
                stale: false,
                hangs: false,
                entered: None,
            }),
            call(),
            config,
            clock.clone(),
        )
        .expect("valid heartbeat");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            handle.frozen().is_none(),
            "healthy beats renew the deadline"
        );
        clock.set_ms(10_000);
        let reason = wait_frozen(&handle).await;
        assert!(matches!(reason, FreezeReason::SelfKill { .. }));
        assert_eq!(reason.to_error().reason_code(), "SELF_KILL_DEADLINE");
    }

    #[tokio::test]
    async fn stale_heartbeat_freezes_with_the_typed_reason() {
        let clock = Arc::new(ManualClock::new());
        let config = HeartbeatConfig {
            interval: Duration::from_millis(10),
        };
        let handle = start_heartbeat(
            Arc::new(StubClient {
                stale: true,
                hangs: false,
                entered: None,
            }),
            call(),
            config,
            clock,
        )
        .expect("valid heartbeat");
        let reason = wait_frozen(&handle).await;
        assert!(matches!(reason, FreezeReason::StaleAuthority(_)));
        assert_eq!(reason.to_error().reason_code(), "STALE_AUTHORITY");
    }

    #[tokio::test]
    async fn one_second_grant_overrides_slower_default_observation_interval() {
        let clock = Arc::new(ManualClock::new());
        let handle = start_heartbeat(
            Arc::new(StubClient {
                stale: false,
                hangs: false,
                entered: None,
            }),
            call(),
            HeartbeatConfig::default(),
            clock.clone(),
        )
        .expect("one-second grant");
        tokio::task::yield_now().await;
        clock.set_ms(800);
        let reason = wait_frozen(&handle).await;
        assert!(matches!(reason, FreezeReason::SelfKill { .. }));
    }

    #[tokio::test]
    async fn hanging_heartbeat_cannot_outlive_one_second_local_budget() {
        let clock = Arc::new(ManualClock::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let handle = start_heartbeat(
            Arc::new(StubClient {
                stale: false,
                hangs: true,
                entered: Some(entered.clone()),
            }),
            call(),
            HeartbeatConfig::default(),
            clock.clone(),
        )
        .expect("one-second grant");
        entered.notified().await;
        clock.set_ms(800);
        let reason = tokio::time::timeout(Duration::from_millis(700), wait_frozen(&handle))
            .await
            .expect("bounded heartbeat wait");
        assert!(matches!(reason, FreezeReason::SelfKill { .. }));
    }
}
