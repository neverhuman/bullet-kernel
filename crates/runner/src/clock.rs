//! Monotonic clocks and the runner self-kill deadline (spec section 28.2):
//! a local monotonic deadline strictly SHORTER than the server lease expiry,
//! renewed only by an acknowledged heartbeat.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monotonic time source. Never wall-clock; never goes backwards.
pub trait Clock: Send + Sync {
    /// Monotonic elapsed time since the clock's origin.
    fn now(&self) -> Duration;
}

/// Real monotonic clock backed by `Instant`.
#[derive(Debug)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    /// Clock starting now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Hand-driven clock for deterministic tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    millis: AtomicU64,
}

impl ManualClock {
    /// Clock at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Jump to an absolute millisecond value.
    pub fn set_ms(&self, ms: u64) {
        self.millis.store(ms, Ordering::SeqCst);
    }

    /// Advance by milliseconds.
    pub fn advance_ms(&self, ms: u64) {
        self.millis.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}

/// The self-kill deadline: 4/5 of the lease TTL from the last acknowledged
/// heartbeat. When it passes, the runner freezes and terminates itself even
/// if the server never answered.
#[derive(Clone, Copy, Debug)]
pub struct SelfKillDeadline {
    budget: Duration,
    deadline: Duration,
}

impl SelfKillDeadline {
    /// Deadline `now + 4/5 * ttl`. The budget is strictly shorter than the
    /// server expiry for every ttl of at least five nanoseconds.
    #[must_use]
    pub fn new(now: Duration, ttl: Duration) -> Self {
        let budget = (ttl / 5) * 4;
        Self {
            budget,
            deadline: now + budget,
        }
    }

    /// Renew after an acknowledged heartbeat.
    pub fn renew(&mut self, now: Duration) {
        self.deadline = now + self.budget;
    }

    /// True at and after the deadline.
    #[must_use]
    pub fn expired(&self, now: Duration) -> bool {
        now >= self.deadline
    }

    /// The renewal budget (4/5 of the ttl).
    #[must_use]
    pub fn budget(&self) -> Duration {
        self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_strictly_shorter_than_the_ttl() {
        for ttl_ms in [10u64, 1000, 30_000, 3_600_000] {
            let ttl = Duration::from_millis(ttl_ms);
            let deadline = SelfKillDeadline::new(Duration::ZERO, ttl);
            assert!(deadline.budget() < ttl, "{ttl_ms}ms");
            assert_eq!(deadline.budget(), (ttl / 5) * 4);
        }
    }

    #[test]
    fn expiry_flips_exactly_at_the_deadline_under_a_mocked_clock() {
        let clock = ManualClock::new();
        let ttl = Duration::from_secs(30);
        let deadline = SelfKillDeadline::new(clock.now(), ttl);
        clock.set_ms(23_999);
        assert!(!deadline.expired(clock.now()));
        clock.set_ms(24_000);
        assert!(deadline.expired(clock.now()));
        clock.set_ms(29_999);
        assert!(deadline.expired(clock.now()), "stays expired");
    }

    #[test]
    fn renewal_extends_from_the_acknowledged_beat() {
        let clock = ManualClock::new();
        let mut deadline = SelfKillDeadline::new(clock.now(), Duration::from_secs(10));
        clock.set_ms(7_000);
        assert!(!deadline.expired(clock.now()));
        deadline.renew(clock.now());
        clock.set_ms(14_999);
        assert!(!deadline.expired(clock.now()));
        clock.set_ms(15_000);
        assert!(deadline.expired(clock.now()));
    }
}
