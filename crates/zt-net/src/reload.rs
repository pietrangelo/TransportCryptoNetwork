//! Ricarica dei file di trust con `SIGHUP`, senza riavvio (revoca a caldo).

use crate::Updater;
use crate::config::ConfigError;

/// Nomi degli eventi di audit di una ricarica.
#[derive(Debug, Clone, Copy)]
pub struct ReloadEvents {
    /// Ricarica riuscita, es. `policy_reloaded`.
    pub reloaded: &'static str,
    /// Ricarica fallita: si tiene il valore precedente. Es. `policy_reload_failed`.
    pub failed: &'static str,
}

/// A ogni `SIGHUP` richiama `load` e, se riesce, sostituisce il valore. Un file non valido (o
/// diventato insicuro) non cambia nulla: meglio la policy di prima che nessuna policy.
#[cfg(unix)]
pub async fn on_sighup<T, F>(updater: Updater<T>, events: ReloadEvents, load: F)
where
    F: Fn() -> Result<T, ConfigError>,
{
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = match signal(SignalKind::hangup()) {
        Ok(hup) => hup,
        Err(err) => {
            tracing::error!(error = %err, "cannot install the SIGHUP handler: reload disabled");
            return;
        }
    };
    while hup.recv().await.is_some() {
        match load() {
            Ok(value) => {
                updater.replace(value);
                tracing::info!(target: "zt_audit", event_kind = events.reloaded, "configuration reloaded");
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

/// Su piattaforme senza segnali la ricarica non è disponibile.
#[cfg(not(unix))]
pub async fn on_sighup<T, F>(updater: Updater<T>, events: ReloadEvents, load: F)
where
    F: Fn() -> Result<T, ConfigError>,
{
    let _ = (updater, events, load);
    std::future::pending::<()>().await;
}
