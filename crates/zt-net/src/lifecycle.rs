//! The process lifecycle of the services (resilience.md §5.4, review 0007 AP-4, AP-21):
//! termination signals, supervised critical tasks, the systemd watchdog driven by real
//! progress, the clock watch and the process hardening done at startup.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use zt_application::lifecycle::{ClockJumpDetector, ProgressWatchdog};

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

/// `SIGTERM` and `SIGINT`: the start of a graceful stop. Created as early as possible, before
/// the files are read: from then on the signal no longer kills the process at once.
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

/// Kicks the systemd watchdog (`WATCHDOG=1`) every third of `WatchdogSec`, but only while
/// `progress` moves (AP-4): a hub that stopped processing anything gets the service restarted.
/// Without a watchdog it waits forever, so it can be supervised like any critical task.
pub async fn watchdog(role: &'static str, progress: Progress) {
    let Some(interval) = systemd::watchdog_interval() else {
        return std::future::pending().await;
    };
    let period = interval
        .checked_div(3)
        .unwrap_or(interval)
        .max(Duration::from_millis(100));
    let mut ticks = tokio::time::interval(period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut w = ProgressWatchdog::new();
    let mut stalled = false;
    loop {
        ticks.tick().await;
        if w.should_kick(progress.get()) {
            systemd::notify("WATCHDOG=1");
            if stalled {
                tracing::info!(role, "progress resumed: watchdog kicked again");
            }
            stalled = false;
        } else if !stalled {
            stalled = true;
            tracing::error!(
                target: "zt_audit",
                event_kind = "watchdog_stalled",
                role,
                "no progress since the last check: the watchdog is no longer kicked"
            );
        }
    }
}

/// A wall-clock step of at least this much against the monotonic clock is reported.
pub const CLOCK_JUMP_THRESHOLD: Duration = Duration::from_secs(5);

/// How often the clock is compared.
const CLOCK_CHECK: Duration = Duration::from_secs(10);

/// Reports steps of the wall clock (`clock_jumped`, PROTOCOL §15.6): certificate validity
/// and revocation timing follow the wall clock, and a backward step makes expired
/// certificates valid again until the clock is corrected.
pub async fn watch_clock(role: &'static str) {
    let mut c = ClockJumpDetector::new(
        CLOCK_JUMP_THRESHOLD,
        SystemTime::now(),
        std::time::Instant::now(),
    );
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

/// Logs `clock_unsynchronised` if the wall clock is before [`clock_floor`]. Not fatal: the
/// service still starts, so a host with a broken RTC can be reached and fixed.
pub fn check_clock(role: &'static str) {
    let now = crate::unix_now().as_secs();
    let floor = clock_floor();
    if now < floor {
        tracing::error!(
            target: "zt_audit",
            event_kind = "clock_unsynchronised",
            role,
            now,
            floor,
            "the wall clock is before this build: certificate checks are unreliable"
        );
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

/// The SHA-256 of each file, as `path=sha256:hex` joined by `, `: what a log line or
/// `check` prints to identify the configuration in force.
#[must_use]
pub fn digests(files: &[&std::path::Path]) -> String {
    use sha2::Digest;
    files
        .iter()
        .map(|path| {
            let digest = std::fs::read(path).map_or_else(
                |_| "unreadable".to_owned(),
                |bytes| format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes))),
            );
            format!("{}={digest}", path.display())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The configuration generation: 1 at startup, one more for every successful reload.
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

/// Logs `configuration_loaded` with the next generation and the digests of `files`.
pub fn configuration_loaded(generation: &Generation, files: &[&std::path::Path]) {
    tracing::info!(
        target: "zt_audit",
        event_kind = "configuration_loaded",
        generation = generation.next(),
        files = digests(files),
        "configuration loaded"
    );
}
