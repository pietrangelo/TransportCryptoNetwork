//! When the agent reconnects to a relay (docs/analysis/resilience.md §5.2, D-2): sans-IO, with
//! the random sample passed in.
//!
//! - After a **failure** (connect, handshake, or a session that ended before `stable_after`,
//!   as a relay in a crash loop): full jitter, `U(0, min(cap, base·2ⁿ⁻¹))` for the n-th failure
//!   in a row. Drawing the whole delay at random spreads a fleet that failed together.
//! - After a session that **lived** (the relay restarted or drained): `U(0, spread)`, and the
//!   failure count starts again. Without it a whole fleet would come back in one wave.

use core::time::Duration;

/// The reconnect parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectConfig {
    /// The ceiling of the first failure's delay; it doubles with every further failure.
    pub base: Duration,
    /// The largest ceiling.
    pub cap: Duration,
    /// The window of the first retry after a session that lived. Zero retries at once.
    pub spread: Duration,
    /// A session shorter than this counts as a failure (a relay that accepts and drops).
    pub stable_after: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(30),
            spread: Duration::from_secs(10),
            stable_after: Duration::from_secs(10),
        }
    }
}

/// The longest cap and spread accepted: one hour.
const MAX_DELAY: Duration = Duration::from_secs(3_600);

impl ReconnectConfig {
    /// `Ok` for a usable configuration.
    ///
    /// # Errors
    /// A zero base or cap, a cap below the base, a cap or spread over one hour.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.base.is_zero() || self.cap.is_zero() {
            return Err("the reconnect base and cap must not be zero");
        }
        if self.cap < self.base {
            return Err("the reconnect cap must not be below the base");
        }
        if self.cap > MAX_DELAY || self.spread > MAX_DELAY || self.stable_after > MAX_DELAY {
            return Err("reconnect delays are at most one hour");
        }
        Ok(())
    }
}

/// How the last attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// No session: connect, handshake or registration failed (a refusal before
    /// authentication looks like this too).
    Failed,
    /// A session that was established and then ended after `lived`.
    Ended {
        /// How long it lasted.
        lived: Duration,
    },
}

/// The reconnect state of one relay.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    config: ReconnectConfig,
    failures: u32,
}

impl ReconnectPolicy {
    /// No failure yet.
    #[must_use]
    pub const fn new(config: ReconnectConfig) -> Self {
        Self {
            config,
            failures: 0,
        }
    }

    /// Failures in a row so far.
    #[must_use]
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    /// The delay before the next attempt, given how the last one ended and a uniformly random
    /// `sample`.
    pub fn next(&mut self, end: SessionEnd, sample: u64) -> Duration {
        let lived = match end {
            SessionEnd::Ended { lived } => lived >= self.config.stable_after,
            SessionEnd::Failed => false,
        };
        if lived {
            self.failures = 0;
            return uniform(self.config.spread, sample);
        }
        self.failures = self.failures.saturating_add(1);
        // base · 2^(n-1), saturating long before any overflow (2^31 × base ≫ cap).
        let doublings = self.failures.saturating_sub(1).min(31);
        let ceiling = self
            .config
            .base
            .saturating_mul(1_u32 << doublings)
            .min(self.config.cap);
        uniform(ceiling, sample)
    }
}

/// `U(0, ceiling)` in milliseconds, both ends included: the sample scaled by multiply and
/// shift (Lemire), so 0 maps to 0 and `u64::MAX` to the ceiling, with no modulo bias worth
/// the name for ceilings of at most an hour.
fn uniform(ceiling: Duration, sample: u64) -> Duration {
    let span = ceiling.as_millis().saturating_add(1);
    let drawn = u128::from(sample)
        .checked_mul(span)
        .map_or(0, |product| product >> 64);
    Duration::from_millis(u64::try_from(drawn).unwrap_or(u64::MAX))
}
