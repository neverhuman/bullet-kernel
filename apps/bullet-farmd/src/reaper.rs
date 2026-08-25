//! Farmd's writer-lease maintenance tick.
//!
//! A runner that dies without releasing leaves an `active_leases` holder row
//! behind. Kernel `4effc37d` made the acquisition boundary reclaim exactly that
//! Variant's dead lease inside its own transaction, which frees any Variant a
//! successor actually asks for — but nothing reclaimed a Variant nobody asked
//! for. This tick is that missing caller: while farmd runs, expiry reclamation
//! is the daemon's own responsibility and waits on no operator.
//!
//! The tick owns no reclamation logic. It calls [`LeaseService::expire_due`],
//! which reaches the ledger's single-transaction sweep, and every lease that
//! sweep reclaims goes through the same `reclaim_expired_variant` the
//! acquisition path goes through. So there is one durable truth per dead
//! incarnation whichever path wins the race: the Attempt reaches its terminal
//! `Crashed` state, the package returns to the ready queue, one `lease_expired`
//! event and one `lease_reclaimed` outbox row commit with them, and the
//! successor is granted fence N+1 because no fence counter was rewound.

use crate::api::SharedState;
use bullet_application::{ExpiredLease, LeaseService, Ledger, LedgerError};
use serde::Serialize;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;

/// Shortest lease lifetime the frozen Phase-1 policy admits, in milliseconds.
/// `validate_lease_ttl` is the only authority on that range; the unit tests
/// below fail if it ever moves rather than letting this constant drift.
const MIN_ADMITTED_LEASE_TTL_MS: u64 = 1_000;

/// Ceiling on the maintenance interval: half the shortest admissible lease, so
/// a lease that expires can never wait longer than one tick to be reclaimed.
pub const MAX_INTERVAL_MS: u64 = MIN_ADMITTED_LEASE_TTL_MS / 2;

/// A maintenance interval the daemon will actually run at.
///
/// Construction is the only way to obtain one and it admits
/// `1..=MAX_INTERVAL_MS` milliseconds. An operator may make farmd reap *more*
/// often than policy requires; no configuration makes it reap less often, and
/// none turns it off. A daemon that cannot reap is the defect this tick closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReapInterval(u64);

impl ReapInterval {
    /// The policy interval: half the shortest lease the ledger admits.
    #[must_use]
    pub const fn policy_default() -> Self {
        Self(MAX_INTERVAL_MS)
    }

    /// Admit one operator-supplied interval.
    ///
    /// # Errors
    ///
    /// Returns a message when `millis` is zero — reaping is never optional — or
    /// slower than the policy ceiling.
    pub fn from_millis(millis: u64) -> Result<Self, String> {
        if millis == 0 {
            return Err("reap interval must be at least 1ms: farmd always reaps".into());
        }
        if millis > MAX_INTERVAL_MS {
            return Err(format!(
                "reap interval {millis}ms is slower than the {MAX_INTERVAL_MS}ms policy ceiling, \
                 which is half the shortest lease the ledger admits"
            ));
        }
        Ok(Self(millis))
    }

    /// This interval in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.0
    }

    /// This interval as a [`Duration`].
    #[must_use]
    pub const fn duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

impl Default for ReapInterval {
    fn default() -> Self {
        Self::policy_default()
    }
}

impl fmt::Display for ReapInterval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for ReapInterval {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let millis = value
            .parse::<u64>()
            .map_err(|_| format!("reap interval must be whole milliseconds, not {value:?}"))?;
        Self::from_millis(millis)
    }
}

/// One completed maintenance tick, as `/health` reports it.
#[derive(Clone, Debug, Serialize)]
pub struct ReapRun {
    /// When the most recent tick finished, RFC 3339 UTC.
    pub last_run_at: String,
    /// Writer leases this daemon has reclaimed through the tick since start.
    pub reclaimed: u64,
}

/// What the tick has done so far.
///
/// `None` until the first tick completes, so a daemon whose tick has never
/// fired answers `/health` with exactly the body it always answered.
#[derive(Default)]
pub struct ReapObservation(Mutex<Option<ReapRun>>);

impl ReapObservation {
    async fn record(&self, at: String, reclaimed: usize) {
        let reclaimed = u64::try_from(reclaimed).unwrap_or(u64::MAX);
        let mut observed = self.0.lock().await;
        let total = observed.as_ref().map_or(0, |run| run.reclaimed);
        *observed = Some(ReapRun {
            last_run_at: at,
            reclaimed: total.saturating_add(reclaimed),
        });
    }

    pub(crate) async fn snapshot(&self) -> Option<ReapRun> {
        self.0.lock().await.clone()
    }
}

/// One maintenance sweep against the store's own clock.
///
/// Reclamation belongs to the ledger, not to this function:
/// [`LeaseService::expire_due`] reclaims every due lease in one transaction.
/// Each reclamation is logged with its Variant, the dead Attempt, the dead
/// fence, and whether the freed work package is observably back on the ready
/// queue — read back from the ledger, never assumed.
///
/// # Errors
///
/// Returns the store failure. A sweep that fails reclaims nothing and the next
/// tick retries it.
pub fn sweep<L: Ledger>(ledger: &mut L) -> Result<Vec<ExpiredLease>, LedgerError> {
    let reclaimed = LeaseService::expire_due(ledger)?;
    if reclaimed.is_empty() {
        return Ok(reclaimed);
    }
    let ready = ledger.ready_rows()?;
    for lease in &reclaimed {
        tracing::info!(
            variant_id = %lease.variant_id,
            dead_attempt_id = %lease.attempt_id,
            dead_fence = lease.fence,
            work_package_id = %lease.work_package_id,
            successor_ready = ready
                .iter()
                .any(|row| row.work_package_id == lease.work_package_id),
            "farmd maintenance tick reclaimed an expired writer lease"
        );
    }
    Ok(reclaimed)
}

/// One tick against the daemon's own ledger, recording what it did for
/// `/health`. A tick with nothing due writes no event and no outbox row.
///
/// # Errors
///
/// Returns the store failure; the reported observation stays at the last tick
/// that completed.
pub async fn run_once(state: &SharedState) -> Result<Vec<ExpiredLease>, LedgerError> {
    let reclaimed = {
        let mut ledger = state.ledger.lock().await;
        sweep(&mut *ledger)?
    };
    state
        .reaper
        .record(LeaseService::rfc3339(chrono::Utc::now()), reclaimed.len())
        .await;
    Ok(reclaimed)
}

/// Run the tick for the life of the process.
///
/// The first tick fires immediately, then once per `interval`. A sweep that
/// overruns its interval delays the next one instead of queueing sweeps behind
/// a lock they would all contend for.
pub fn spawn(state: SharedState, interval: ReapInterval) -> tokio::task::JoinHandle<()> {
    tracing::info!(
        interval_ms = interval.millis(),
        "farmd writer-lease maintenance tick started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval.duration());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = run_once(&state).await {
                tracing::error!(
                    error = %error,
                    "farmd maintenance tick failed; the next tick retries"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_application::records::{validate_lease_ttl, MAX_LEASE_TTL_SECONDS};

    #[test]
    fn the_interval_ceiling_is_half_the_shortest_lease_the_ledger_admits() {
        assert!(validate_lease_ttl(0).is_err(), "zero is not a lease");
        assert!(validate_lease_ttl(1).is_ok(), "one second is admitted");
        assert!(validate_lease_ttl(MAX_LEASE_TTL_SECONDS).is_ok());
        assert!(validate_lease_ttl(MAX_LEASE_TTL_SECONDS + 1).is_err());
        assert_eq!(MIN_ADMITTED_LEASE_TTL_MS, 1_000);
        assert_eq!(MAX_INTERVAL_MS, 500);
        assert_eq!(
            ReapInterval::policy_default().duration(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn the_interval_is_configurable_downward_only_and_never_off() {
        assert_eq!(ReapInterval::default(), ReapInterval::policy_default());
        assert_eq!(ReapInterval::policy_default().to_string(), "500");
        for admitted in [1_u64, 2, 250, MAX_INTERVAL_MS] {
            let parsed: ReapInterval = admitted.to_string().parse().expect("admitted");
            assert_eq!(parsed.millis(), admitted);
        }
        for refused in ["0", "501", "1000", "", "-1", "off", "3.5", "500ms"] {
            assert!(
                refused.parse::<ReapInterval>().is_err(),
                "{refused} must not become a tick interval"
            );
        }
    }
}
