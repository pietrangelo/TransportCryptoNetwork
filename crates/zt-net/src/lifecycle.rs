//! The process lifecycle of the services (resilience.md §5.4, review 0007 AP-4, AP-21):
//! termination signals, supervised critical tasks, the systemd watchdog driven by real
//! progress, the clock watch and the process hardening done at startup.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use zt_application::lifecycle::{ClockJumpDetector, ProgressWatchdog, WatchdogAction};

use crate::systemd;

/// The drain of a graceful stop when the command line says nothing (OPERATIONS §14). It
/// stays below the units' `TimeoutStopSec=90s`.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// A counter of processed work. The hub increments it for every event it handles (its own
/// one-second tick included), so it stops only when the hub stops.
#[derive(Debug, Clone, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    /// A counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One more unit of work.
    pub fn advance(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// The current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// `SIGTERM` and `SIGINT`: the start of a graceful stop. Created as early as possible, as the
/// first thing inside the runtime: from then on the signal no longer kills the process at
/// once. (The agent reads and validates its files before the runtime exists, so a `SIGTERM`
/// during that read still has its default action; nothing is open yet to drain.)
#[derive(Debug)]
pub struct Terminate {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
}

impl Terminate {
    /// Installs the handlers. Must be called inside a tokio runtime.
    ///
    /// # Errors
    /// A handler cannot be installed.
    pub fn listen() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                term: signal(SignalKind::terminate())?,
                int: signal(SignalKind::interrupt())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// Waits for the first signal.
    pub async fn wait(mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.term.recv() => {}
                _ = self.int.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// The critical background tasks of a service: reloads, watches, the watchdog. None of them
/// is supposed to end; when one does (a panic or a return) the service must stop, visibly,
/// instead of going on without hot revocation or without its watchdog.
#[derive(Debug, Default)]
pub struct Supervisor {
    tasks: tokio::task::JoinSet<()>,
    names: std::collections::HashMap<tokio::task::Id, &'static str>,
}

impl Supervisor {
    /// No tasks yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns a critical task.
    pub fn spawn<F>(&mut self, name: &'static str, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = self.tasks.spawn(task);
        self.names.insert(handle.id(), name);
    }

    /// Resolves when a critical task ends, with a description of how; never with no tasks.
    pub async fn failed(&mut self) -> String {
        let Some(joined) = self.tasks.join_next_with_id().await else {
            return std::future::pending().await;
        };
        let (id, how) = match joined {
            Ok((id, ())) => (id, "stopped"),
            Err(err) if err.is_panic() => (err.id(), "panicked"),
            Err(err) => (err.id(), "was cancelled"),
        };
        let name = self.names.remove(&id).unwrap_or("unknown");
        tracing::error!(
            target: "zt_audit",
            event_kind = "critical_task_failed",
            task = name,
            how,
            "a critical task {how}: stopping the service"
        );
        format!("critical task {name} {how}")
    }
}

/// The shortest `WatchdogSec` accepted: three hub ticks. The hub and the agent's heartbeat move
/// the progress counter once a second at idle, so a check more frequent than that misses
/// progress and a healthy service gets killed (finding A10-3).
pub const MIN_WATCHDOG: Duration = Duration::from_secs(3);

/// How often the watchdog is checked for a `WatchdogSec` of `interval`: a third of it.
///
/// # Errors
/// `interval` below [`MIN_WATCHDOG`], as a message for the operator.
pub fn watchdog_period(interval: Duration) -> Result<Duration, String> {
    if interval < MIN_WATCHDOG {
        return Err(format!(
            "WatchdogSec={} ms is below the minimum of {} s (three hub ticks)",
            interval.as_millis(),
            MIN_WATCHDOG.as_secs()
        ));
    }
    Ok(interval.checked_div(3).unwrap_or(interval))
}

/// The watchdog systemd asked for, checked at startup: `Ok(None)` without one.
///
/// # Errors
/// See [`watchdog_period`].
pub fn check_watchdog() -> Result<Option<Duration>, String> {
    systemd::watchdog_interval()
        .map(watchdog_period)
        .transpose()
}

/// Kicks the systemd watchdog (`WATCHDOG=1`) every third of `WatchdogSec`, but only while
/// `progress` moves (AP-4): a hub that stopped processing anything gets the service restarted.
/// The first check is a baseline and kicks; a stall is reported after two checks in a row
/// without progress (finding A10-3). Without a watchdog it waits forever, so it can be
/// supervised like any critical task. The binaries refuse a `WatchdogSec` below
/// [`MIN_WATCHDOG`] at startup ([`check_watchdog`]); a library user gets a third of it anyway.
pub async fn watchdog(role: &'static str, progress: Progress) {
    let Some(interval) = systemd::watchdog_interval() else {
        return std::future::pending().await;
    };
    let period = watchdog_period(interval).unwrap_or_else(|_| {
        interval
            .checked_div(3)
            .unwrap_or(interval)
            .max(Duration::from_millis(100))
    });
    let mut ticks = tokio::time::interval(period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut w = ProgressWatchdog::new();
    let mut stalled = false;
    loop {
        ticks.tick().await;
        match w.observe(progress.get()) {
            WatchdogAction::Kick => {
                systemd::notify("WATCHDOG=1");
                if stalled {
                    tracing::info!(role, "progress resumed: watchdog kicked again");
                }
                stalled = false;
            }
            WatchdogAction::Hold => {}
            WatchdogAction::Stalled => {
                stalled = true;
                tracing::error!(
                    target: "zt_audit",
                    event_kind = "watchdog_stalled",
                    role,
                    "no progress for two watchdog checks: the watchdog is no longer kicked"
                );
            }
        }
    }
}

/// A wall-clock step of at least this much against the monotonic clock is reported.
pub const CLOCK_JUMP_THRESHOLD: Duration = Duration::from_secs(5);

/// How often the clock is compared.
const CLOCK_CHECK: Duration = Duration::from_secs(10);

/// Reports steps of the wall clock (`clock_jumped`, PROTOCOL §15.6): certificate validity
/// and revocation timing follow the wall clock, and a backward step makes expired
/// certificates valid again until the clock is corrected. A VM suspend and resume looks like a
/// forward step. Crossing the [`clock_floor`] either way is reported too: below it no
/// certificate is accepted ([`certificate_time`]).
pub async fn watch_clock(role: &'static str) {
    let mut c = ClockJumpDetector::new(
        CLOCK_JUMP_THRESHOLD,
        SystemTime::now(),
        std::time::Instant::now(),
    );
    let mut below = before_floor(crate::unix_now());
    let mut ticks = tokio::time::interval(CLOCK_CHECK);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        if let Some(jump) = c.observe(SystemTime::now(), std::time::Instant::now()) {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "clock_jumped",
                role,
                delta_secs = jump.delta_secs,
                direction = if jump.delta_secs < 0 { "backward" } else { "forward" },
                "the wall clock stepped"
            );
        }
        let now = crate::unix_now();
        match (below, before_floor(now)) {
            (false, true) => unsynchronised(role, now),
            (true, false) => tracing::warn!(
                target: "zt_audit",
                event_kind = "clock_synchronised",
                role,
                now = now.as_secs(),
                "the wall clock is past this build again: certificates are checked again"
            ),
            _ => {}
        }
        below = before_floor(now);
    }
}

/// The oldest plausible time: the build's `SOURCE_DATE_EPOCH` when set, otherwise the start of
/// this release line (2026-01-01). A clock before it has not been synchronised.
#[must_use]
pub fn clock_floor() -> u64 {
    option_env!("SOURCE_DATE_EPOCH")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1_767_225_600)
}

fn before_floor(now: zt_domain::UnixTime) -> bool {
    now.as_secs() < clock_floor()
}

/// The time certificates are evaluated at (R3-C11, finding A10-7): the wall clock, or zero
/// while it is before `floor`. A clock before the build cannot be trusted, and evaluating at
/// zero makes every certificate not yet valid (fail closed, as a clock before 1970 already
/// does): a certificate that expired before the build, and was left off the denylist because
/// expiry was relied on, does not become valid again. Key-pinned peers do not depend on time.
#[must_use]
pub fn certificate_time(now: zt_domain::UnixTime, floor: u64) -> zt_domain::UnixTime {
    if now.as_secs() < floor {
        zt_domain::UnixTime::from_secs(0)
    } else {
        now
    }
}

/// [`certificate_time`] for the wall clock and [`clock_floor`].
#[must_use]
pub fn certificate_now() -> zt_domain::UnixTime {
    certificate_time(crate::unix_now(), clock_floor())
}

fn unsynchronised(role: &'static str, now: zt_domain::UnixTime) {
    tracing::error!(
        target: "zt_audit",
        event_kind = "clock_unsynchronised",
        role,
        now = now.as_secs(),
        floor = clock_floor(),
        "the wall clock is before this build: certificates are refused until it is synchronised"
    );
}

/// Logs `clock_unsynchronised` if the wall clock is before [`clock_floor`]. Not fatal: the
/// service still starts, so a host with a broken RTC can be reached (with a pinned key) and
/// fixed; certificates are refused meanwhile ([`certificate_time`]).
pub fn check_clock(role: &'static str) {
    let now = crate::unix_now();
    if before_floor(now) {
        unsynchronised(role, now);
    }
}

/// Process hardening at startup: no core dumps and no `ptrace` by unprivileged processes of
/// the same user (`PR_SET_DUMPABLE` 0), so the keys in memory do not end up on disk. The units
/// add `LimitCORE=0`.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    if let Err(err) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        tracing::warn!(error = %err, "cannot disable core dumps");
    }
}

/// The configuration generation: 1 at startup, one more for every reload that applied
/// something (one per `SIGHUP` at most).
#[derive(Debug, Clone, Default)]
pub struct Generation(Arc<AtomicU64>);

impl Generation {
    /// Generation 0, before the first load.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next generation.
    #[must_use]
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }
}

/// Logs `configuration_loaded` with the next generation and the digests of the files parsed
/// at startup.
pub fn configuration_loaded(generation: &Generation, files: &crate::config::Digests) -> u64 {
    let generation = generation.next();
    tracing::info!(
        target: "zt_audit",
        event_kind = "configuration_loaded",
        generation,
        files = %files,
        "configuration loaded"
    );
    generation
}
