//! Reloading of trust files on `SIGHUP`, without restart (hot revocation), and how its outcome
//! reaches `systemctl reload` (finding A10-1).
//!
//! The running process is the only judge of a reload: it reads its own files, with its own
//! arguments and the keys in force, and either applies them or keeps the previous ones. Each
//! attempt is announced to systemd (`RELOADING=1` with `MONOTONIC_USEC`, then `READY=1`) and
//! recorded in a small state file in the service's runtime directory (`RuntimeDirectory=`,
//! `$RUNTIME_DIRECTORY`). `ExecReload=zt-<bin> reload --pid $MAINPID` ([`request`]) sends the
//! `SIGHUP` and waits for the first attempt that started after it, so `systemctl reload` fails
//! exactly when the running process rejected the files, with its reason. `ExecReload=` repeats
//! none of `ExecStart=`'s arguments, so a drop-in that changes them cannot make the two
//! disagree.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::lifecycle::Generation;

/// The name of the state file inside the runtime directory.
pub const STATE_FILE: &str = "reload.state";

/// The largest state file read back.
const MAX_STATE_LEN: u64 = 16 * 1024;

/// What one reload attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// `Ok` with the generation and the digests of what was applied (`path=sha256:hex`), or the
    /// reason the files were rejected (the previous configuration stays in force).
    pub result: Result<(u64, String), String>,
    /// Problems that did not block the reload: for the relay, a key file that could not be
    /// reloaded while the policy was.
    pub warnings: Vec<String>,
}

impl Default for Outcome {
    fn default() -> Self {
        Self {
            result: Err(String::new()),
            warnings: Vec::new(),
        }
    }
}

impl Outcome {
    /// Applied as `generation`, with the digests of the files applied.
    #[must_use]
    pub const fn applied(generation: u64, files: String) -> Self {
        Self {
            result: Ok((generation, files)),
            warnings: Vec::new(),
        }
    }

    /// Rejected for `reason`: the previous configuration stays in force.
    #[must_use]
    pub const fn rejected(reason: String) -> Self {
        Self {
            result: Err(reason),
            warnings: Vec::new(),
        }
    }
}

/// The reload state published for [`request`]: the attempts started and completed and the
/// outcome of the last completed one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// The process that wrote it.
    pub pid: u32,
    /// Reload attempts started since the process started.
    pub started: u64,
    /// Reload attempts completed: `started` once the current one is over.
    pub completed: u64,
    /// The outcome of the last completed attempt (at startup: the initial load).
    pub last: Outcome,
}

impl State {
    /// The text of the state file: one `key=value` per line, values on one line.
    #[must_use]
    pub fn render(&self) -> String {
        let one_line = |s: &str| s.replace(['\n', '\r'], " ");
        let mut lines = vec![
            format!("pid={}", self.pid),
            format!("started={}", self.started),
            format!("completed={}", self.completed),
        ];
        match &self.last.result {
            Ok((generation, files)) => {
                lines.push("outcome=applied".into());
                lines.push(format!("generation={generation}"));
                lines.push(format!("files={}", one_line(files)));
            }
            Err(reason) => {
                lines.push("outcome=rejected".into());
                lines.push(format!("reason={}", one_line(reason)));
            }
        }
        lines.extend(
            self.last
                .warnings
                .iter()
                .map(|w| format!("warning={}", one_line(w))),
        );
        lines.push(String::new());
        lines.join("\n")
    }

    /// Parses [`State::render`]'s text; `None` if it is not one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut state = Self::default();
        let (mut outcome, mut generation, mut files, mut reason) = (None, None, None, None);
        for line in text.lines() {
            let (key, value) = line.split_once('=')?;
            match key {
                "pid" => state.pid = value.parse().ok()?,
                "started" => state.started = value.parse().ok()?,
                "completed" => state.completed = value.parse().ok()?,
                "outcome" => outcome = Some(value.to_owned()),
                "generation" => generation = Some(value.parse::<u64>().ok()?),
                "files" => files = Some(value.to_owned()),
                "reason" => reason = Some(value.to_owned()),
                "warning" => state.last.warnings.push(value.to_owned()),
                _ => {}
            }
        }
        state.last.result = match outcome.as_deref()? {
            "applied" => Ok((generation?, files.unwrap_or_default())),
            "rejected" => Err(reason.unwrap_or_default()),
            _ => return None,
        };
        Some(state)
    }
}

/// Writes the reload state into the runtime directory, if there is one.
#[derive(Debug, Clone)]
pub struct Publisher {
    dir: Option<PathBuf>,
    state: State,
}

impl Publisher {
    /// A publisher into `dir` (`None`: nothing is written, `reload` cannot be used) for the
    /// startup load that produced `initial`.
    #[must_use]
    pub fn new(dir: Option<PathBuf>, initial: Outcome) -> Self {
        Self {
            dir,
            state: State {
                pid: std::process::id(),
                started: 0,
                completed: 0,
                last: initial,
            },
        }
    }

    /// Writes the current state (atomically: a temporary file, then a rename). An error is
    /// logged: the service runs on, only `reload` cannot learn the outcome.
    pub fn publish(&self) {
        let Some(dir) = &self.dir else { return };
        let path = dir.join(STATE_FILE);
        let temporary = dir.join(format!("{STATE_FILE}.tmp"));
        let written = std::fs::write(&temporary, self.state.render())
            .and_then(|()| std::fs::rename(&temporary, &path));
        if let Err(err) = written {
            tracing::warn!(path = %path.display(), error = %err, "cannot publish the reload state");
        }
    }

    fn begin(&mut self) {
        self.state.started = self.state.started.saturating_add(1);
        self.publish();
    }

    fn end(&mut self, outcome: Outcome) {
        self.state.completed = self.state.started;
        self.state.last = outcome;
        self.publish();
    }
}

/// The `SIGHUP`s received since it was created. It must be created **before** reading the
/// files to reload, so a signal arriving during the read is not lost; from that moment on a
/// `SIGHUP` no longer terminates the process. Before that (during process startup) the
/// default action still applies: this is why the service announces readiness to systemd only
/// afterwards ([`crate::systemd::notify_ready`], finding 0004-2).
#[derive(Debug)]
pub struct Hangups {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
}

impl Hangups {
    /// Starts collecting `SIGHUP`s. Must be called inside a tokio runtime.
    ///
    /// # Errors
    /// The signal handler cannot be installed.
    pub fn listen() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                signal: signal(SignalKind::hangup())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    async fn next(&mut self) -> Option<()> {
        #[cfg(unix)]
        {
            self.signal.recv().await
        }
        #[cfg(not(unix))]
        std::future::pending().await
    }
}

/// On every `SIGHUP`: announces the reload to systemd, calls `reload` (which validates the
/// files, applies them or keeps the previous ones, logs its audit events and takes the next
/// `generation` only if it applied something), publishes the outcome and tells systemd it is
/// done. One `SIGHUP` is one attempt and at most one generation (finding A10-10).
pub async fn on_sighup<F>(
    mut hangups: Hangups,
    mut publisher: Publisher,
    generation: Generation,
    mut reload: F,
) where
    F: FnMut(&Generation) -> Outcome,
{
    while hangups.next().await.is_some() {
        crate::systemd::notify(&format!(
            "RELOADING=1\nMONOTONIC_USEC={}",
            crate::systemd::monotonic_usec()
        ));
        publisher.begin();
        let outcome = reload(&generation);
        publisher.end(outcome);
        crate::systemd::notify_ready();
    }
}

/// Why [`request`] could not report a reload.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// No runtime directory: neither `--runtime-dir` nor `$RUNTIME_DIRECTORY`.
    #[error("no runtime directory: run under systemd with RuntimeDirectory= or pass --runtime-dir")]
    NoRuntimeDirectory,
    /// The process does not publish its state there (another process, an older release, or
    /// not running).
    #[error("process {pid} has not published its reload state in {dir}")]
    NotPublished {
        /// The process.
        pid: u32,
        /// The runtime directory.
        dir: String,
    },
    /// The signal could not be sent.
    #[error("cannot signal process {pid}: {source}")]
    Signal {
        /// The process.
        pid: u32,
        /// The error.
        source: std::io::Error,
    },
    /// The process ended before reporting.
    #[error("process {0} ended before it reported the reload")]
    Gone(u32),
    /// No report within the time allowed.
    #[error("process {0} did not report the reload in time")]
    Timeout(u32),
}

/// The runtime directory: `explicit`, else the first entry of `$RUNTIME_DIRECTORY`.
#[must_use]
pub fn runtime_dir(explicit: Option<PathBuf>) -> Option<PathBuf> {
    explicit.or_else(|| {
        let value = std::env::var_os("RUNTIME_DIRECTORY")?;
        let text = value.to_string_lossy();
        let first = text.split(':').next().filter(|s| !s.is_empty())?;
        Some(PathBuf::from(first))
    })
}

fn read_state(dir: &Path) -> Option<State> {
    use std::io::Read;
    let file = std::fs::File::open(dir.join(STATE_FILE)).ok()?;
    let mut text = String::new();
    file.take(MAX_STATE_LEN).read_to_string(&mut text).ok()?;
    State::parse(&text)
}

/// `reload --pid`: sends `SIGHUP` to `pid` and waits, up to `wait`, for the outcome of the first
/// reload attempt that started after the request, as the process published it in `dir`.
///
/// # Errors
/// See [`RequestError`].
pub fn request(pid: u32, dir: &Path, wait: Duration) -> Result<Outcome, RequestError> {
    let not_published = || RequestError::NotPublished {
        pid,
        dir: dir.display().to_string(),
    };
    let before = read_state(dir)
        .filter(|s| s.pid == pid)
        .ok_or_else(not_published)?;
    // The attempt in flight, if any, may have read the files before they were edited: the
    // answer is the first attempt that starts after this read.
    let target = before.started.saturating_add(1);
    signal_hangup(pid)?;
    let deadline = std::time::Instant::now().checked_add(wait);
    loop {
        if let Some(state) = read_state(dir).filter(|s| s.pid == pid)
            && state.completed >= target
        {
            return Ok(state.last);
        }
        if !alive(pid) {
            return Err(RequestError::Gone(pid));
        }
        if deadline.is_none_or(|d| std::time::Instant::now() >= d) {
            return Err(RequestError::Timeout(pid));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn signal_hangup(pid: u32) -> Result<(), RequestError> {
    use rustix::process::{Pid, Signal, kill_process};
    let raw = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or(RequestError::Signal {
            pid,
            source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
        })?;
    kill_process(raw, Signal::HUP).map_err(|err| RequestError::Signal {
        pid,
        source: err.into(),
    })
}

#[cfg(not(unix))]
fn signal_hangup(pid: u32) -> Result<(), RequestError> {
    Err(RequestError::Signal {
        pid,
        source: std::io::Error::from(std::io::ErrorKind::Unsupported),
    })
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    use rustix::process::{Pid, test_kill_process};
    i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .is_some_and(|p| test_kill_process(p).is_ok())
}

#[cfg(not(unix))]
fn alive(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_state_round_trips() {
        let applied = State {
            pid: 42,
            started: 3,
            completed: 3,
            last: Outcome {
                result: Ok((5, "a=sha256:00, b=sha256:11".into())),
                warnings: vec!["key file\nunreadable".into()],
            },
        };
        let parsed = State::parse(&applied.render()).unwrap();
        assert_eq!(parsed.pid, 42);
        assert_eq!(
            parsed.last.result,
            Ok((5, "a=sha256:00, b=sha256:11".into()))
        );
        assert_eq!(parsed.last.warnings, ["key file unreadable"]);
        let rejected = State {
            last: Outcome {
                result: Err("policy.toml: bad".into()),
                warnings: Vec::new(),
            },
            ..applied
        };
        assert_eq!(State::parse(&rejected.render()).unwrap(), rejected);
        assert!(State::parse("pid=1\nnonsense\n").is_none());
        assert!(State::parse("pid=1\nstarted=0\ncompleted=0\n").is_none());
    }
}
