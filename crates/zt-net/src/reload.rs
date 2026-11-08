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

/// I `SIGHUP` ricevuti da quando è stato creato. Va creato **prima** di leggere i file da
/// ricaricare, così un segnale arrivato durante la lettura non va perso; da quel momento un
/// `SIGHUP` non termina più il processo. Prima (durante l'avvio del processo) l'azione
/// predefinita resta: per questo il servizio annuncia di essere pronto a systemd solo dopo
/// ([`crate::systemd::notify_ready`], finding 0004-2).
#[derive(Debug)]
pub struct Hangups {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
}

impl Hangups {
    /// Inizia a raccogliere i `SIGHUP`. Va chiamata dentro un runtime tokio.
    ///
    /// # Errors
    /// Il gestore del segnale non può essere installato.
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

/// A ogni `SIGHUP` richiama `load` e, se riesce, sostituisce il valore. Un file non valido (o
/// diventato insicuro) non cambia nulla: meglio la policy di prima che nessuna policy.
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
