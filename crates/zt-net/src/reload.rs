//! Reloading of trust files on `SIGHUP`, without restart (hot revocation).

use std::path::PathBuf;

use crate::Updater;
use crate::config::ConfigError;
use crate::lifecycle::{Generation, digests};

/// The audit events of a reload and what they identify.
#[derive(Debug, Clone)]
pub struct ReloadEvents {
    /// Successful reload, e.g. `policy_reloaded`.
    pub reloaded: &'static str,
    /// Failed reload: the previous value is kept. E.g. `policy_reload_failed`.
    pub failed: &'static str,
    /// The service's configuration generation: a successful reload takes the next one.
    pub generation: Generation,
    /// The files reloaded: their SHA-256 goes in the success line (R3-C8).
    pub files: Vec<PathBuf>,
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

/// On every `SIGHUP` calls `load` and, if it succeeds, replaces the value. An invalid file (or
/// one that has become insecure) changes nothing: better the previous policy than no policy.
pub async fn on_sighup<T, F>(
    mut hangups: Hangups,
    updater: Updater<T>,
    events: ReloadEvents,
    load: F,
) where
    F: Fn() -> Result<T, ConfigError>,
{
    while hangups.next().await.is_some() {
        match load() {
            Ok(value) => {
                updater.replace(value);
                let files: Vec<&std::path::Path> =
                    events.files.iter().map(PathBuf::as_path).collect();
                tracing::info!(
                    target: "zt_audit",
                    event_kind = events.reloaded,
                    generation = events.generation.next(),
                    files = digests(&files),
                    "configuration reloaded"
                );
            }
            Err(err) => {
                tracing::error!(
                    target: "zt_audit",
                    event_kind = events.failed,
                    error = %err,
                    "reload failed: keeping the previous configuration"
                );
            }
        }
    }
}
