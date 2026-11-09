//! The sans-IO parts of the process lifecycle (resilience.md §5.4, review 0007 AP-4, AP-21):
//!
//! - [`ProgressWatchdog`]: the systemd watchdog is kicked only while the hub makes progress, as
//!   seen through a counter the hub increments for every event it processes. A busy hub is
//!   healthy; a hub that stopped processing anything (deadlock, livelock) stops the kicks and
//!   systemd restarts the service.
//! - [`DrainController`]: a graceful stop waits for the last client stream, at most until a
//!   deadline.
//! - [`ClockJumpDetector`]: a step of the wall clock against the monotonic clock (certificate
//!   validity depends on the wall clock, PROTOCOL §15.6).

use std::time::{Duration, Instant, SystemTime};

/// What to do at one watchdog check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    /// Progress since the previous check (or the first check, a baseline): kick.
    Kick,
    /// No progress since the previous check: do not kick, nothing to report yet (or the stall
    /// was already reported).
    Hold,
    /// The second check in a row without progress: do not kick, and report the stall (once
    /// per stall).
    Stalled,
}

/// The checks in a row without progress that make a stall (finding A10-3): one alone can be a
/// check that came just before the hub's tick.
pub const STALL_CHECKS: u32 = 2;

/// Decides whether to kick the watchdog from a monotonically increasing progress counter.
#[derive(Debug, Clone, Default)]
pub struct ProgressWatchdog {
    last: Option<u64>,
    misses: u32,
}

impl ProgressWatchdog {
    /// A watchdog that has seen nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: None,
            misses: 0,
        }
    }

    /// The action for the counter's current value. The first observation is a baseline and
    /// kicks (the hub may not have ticked yet at startup, finding A10-3); afterwards, a counter
    /// that moved kicks, and [`STALL_CHECKS`] checks in a row without a move are a stall.
    pub fn observe(&mut self, counter: u64) -> WatchdogAction {
        let moved = self.last.is_none_or(|prev| counter != prev);
        self.last = Some(counter);
        if moved {
            self.misses = 0;
            return WatchdogAction::Kick;
        }
        self.misses = self.misses.saturating_add(1);
        if self.misses == STALL_CHECKS {
            WatchdogAction::Stalled
        } else {
            WatchdogAction::Hold
        }
    }
}

/// What to do at a step of a drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStep {
    /// Client streams are still open: keep waiting.
    Wait,
    /// The drain is over: `expired` if streams were still open at the deadline (they are then
    /// closed with `Close Drained`).
    Finished {
        /// The deadline was reached with streams still open.
        expired: bool,
    },
}

/// A graceful stop: no new connections, the open sessions finish on their own until a deadline.
#[derive(Debug, Clone, Copy)]
pub struct DrainController {
    deadline: Instant,
}

impl DrainController {
    /// A drain started at `started` that lasts at most `timeout`.
    #[must_use]
    pub fn new(started: Instant, timeout: Duration) -> Self {
        Self {
            deadline: started.checked_add(timeout).unwrap_or(started),
        }
    }

    /// The step at `now` with `active` client streams open.
    #[must_use]
    pub fn step(&self, now: Instant, active: usize) -> DrainStep {
        if now >= self.deadline {
            DrainStep::Finished {
                expired: active > 0,
            }
        } else if active == 0 {
            DrainStep::Finished { expired: false }
        } else {
            DrainStep::Wait
        }
    }

    /// When the remaining streams are closed.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// A wall-clock step, in seconds: negative backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockJump {
    /// How far the wall clock moved beyond the monotonic clock.
    pub delta_secs: i64,
}

/// Compares the progress of the wall clock with the monotonic clock between observations.
#[derive(Debug, Clone, Copy)]
pub struct ClockJumpDetector {
    threshold: Duration,
    wall: SystemTime,
    mono: Instant,
}

impl ClockJumpDetector {
    /// A detector that reports differences of at least `threshold`.
    #[must_use]
    pub const fn new(threshold: Duration, wall: SystemTime, mono: Instant) -> Self {
        Self {
            threshold,
            wall,
            mono,
        }
    }

    /// The jump since the previous observation, if any; the observation becomes the new
    /// reference either way.
    pub fn observe(&mut self, wall: SystemTime, mono: Instant) -> Option<ClockJump> {
        let wall_delta = signed_millis_between(self.wall, wall);
        let mono_delta = i128::from(
            i64::try_from(mono.saturating_duration_since(self.mono).as_millis())
                .unwrap_or(i64::MAX),
        );
        self.wall = wall;
        self.mono = mono;
        let delta_ms = wall_delta.saturating_sub(mono_delta);
        let threshold = i128::try_from(self.threshold.as_millis()).unwrap_or(i128::MAX);
        if delta_ms.saturating_abs() < threshold {
            return None;
        }
        // Rounded to whole seconds, toward zero.
        let delta_secs = i64::try_from(delta_ms / 1_000).unwrap_or(if delta_ms < 0 {
            i64::MIN
        } else {
            i64::MAX
        });
        Some(ClockJump { delta_secs })
    }
}

/// `to - from` in milliseconds, signed.
fn signed_millis_between(from: SystemTime, to: SystemTime) -> i128 {
    match to.duration_since(from) {
        Ok(d) => i128::try_from(d.as_millis()).unwrap_or(i128::MAX),
        Err(e) => i128::try_from(e.duration().as_millis())
            .unwrap_or(i128::MAX)
            .saturating_neg(),
    }
}
