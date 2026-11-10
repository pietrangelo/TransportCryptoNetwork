//! Dead-peer detection on a link (docs/analysis/resilience.md §5.2, D-3 with review 0007's
//! verdict): a `Ping` every `interval`, and the link is dead when **no inbound frame at all**
//! arrived for `interval × misses`. Any frame proves the path, so a busy link is never
//! declared dead for a late `Pong`. Sans-IO: time is passed in.

use core::time::Duration;
use std::time::Instant;

/// The keepalive parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessConfig {
    /// One `Ping` per interval.
    pub interval: Duration,
    /// Silent intervals before the link is dead.
    pub misses: u32,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            misses: 3,
        }
    }
}

impl LivenessConfig {
    /// The silence after which the link is dead.
    #[must_use]
    pub fn dead_after(&self) -> Duration {
        self.interval.saturating_mul(self.misses)
    }

    /// `Ok` for a usable configuration.
    ///
    /// # Errors
    /// A zero interval or count, or an interval over one hour.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.interval.is_zero() || self.misses == 0 {
            return Err("the keepalive interval and misses must not be zero");
        }
        if self.interval > Duration::from_secs(3_600) {
            return Err("the keepalive interval is at most one hour");
        }
        Ok(())
    }
}

/// What the link owner must do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessAction {
    /// Send a `Ping`.
    SendPing,
    /// Nothing arrived for too long: close the link.
    Dead,
}

/// The keepalive state of one link.
#[derive(Debug, Clone)]
pub struct Liveness {
    config: LivenessConfig,
    last_inbound: Instant,
    next_ping: Instant,
}

impl Liveness {
    /// A link that just came up at `now`.
    #[must_use]
    pub fn new(config: LivenessConfig, now: Instant) -> Self {
        Self {
            config,
            last_inbound: now,
            next_ping: later(now, config.interval),
        }
    }

    /// A frame arrived.
    pub fn on_inbound(&mut self, now: Instant) {
        if now > self.last_inbound {
            self.last_inbound = now;
        }
    }

    /// The action due at `now`, if any.
    pub fn poll(&mut self, now: Instant) -> Option<LivenessAction> {
        if now >= self.dead_at() {
            return Some(LivenessAction::Dead);
        }
        if now >= self.next_ping {
            self.next_ping = later(now, self.config.interval);
            return Some(LivenessAction::SendPing);
        }
        None
    }

    /// When [`Liveness::poll`] next has something to do.
    #[must_use]
    pub fn next_deadline(&self) -> Instant {
        self.next_ping.min(self.dead_at())
    }

    fn dead_at(&self) -> Instant {
        later(self.last_inbound, self.config.dead_after())
    }
}

/// `at + after`, or `at` itself if the sum is past the clock's range (the deadline is then
/// due at once: fail closed, never a panic).
fn later(at: Instant, after: Duration) -> Instant {
    at.checked_add(after).unwrap_or(at)
}
