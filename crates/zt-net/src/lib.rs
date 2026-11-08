//! # zt-net
//!
//! Adapter di rete di TCN, basati su tokio. Collegano i casi d'uso sans-IO
//! (`zt-application`) e l'handshake (`zt-crypto`) a socket reali.
//!
//! - [`channel`]: messaggi Noise su TCP, con typestate `Pending` → `Established`;
//! - [`relay`]: server del relay (hub single-thread attorno a `RelayCore`);
//! - [`agent`]: agent outbound-only con riconnessione;
//! - [`client`]: libreria client (usata dai test e da `zt-client`);
//! - [`config`]: file di chiavi e policy.
//!
//! Ogni operazione di I/O ha un timeout; ogni coda è limitata.
#![forbid(unsafe_code)]

pub mod agent;
pub mod channel;
pub mod client;
pub mod config;
mod error;
pub mod relay;
mod revocable;
mod stream;

pub use error::NetError;
pub use revocable::{Revocable, Updater};

use std::time::Duration;

/// Timeout di tutte le operazioni di rete.
#[derive(Debug, Clone)]
pub struct Timeouts {
    /// Handshake Noise completo.
    pub handshake: Duration,
    /// Silenzio massimo su una connessione (nessun frame completo ricevuto).
    pub idle: Duration,
    /// Scrittura di un singolo messaggio.
    pub write: Duration,
    /// Risposta a un `Open` e handshake end-to-end.
    pub open: Duration,
    /// Connessione al demone SSH locale.
    pub ssh_connect: Duration,
    /// Intervallo dei `Ping` di keepalive.
    pub keepalive: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            idle: Duration::from_secs(90),
            write: Duration::from_secs(30),
            open: Duration::from_secs(15),
            ssh_connect: Duration::from_secs(5),
            keepalive: Duration::from_secs(30),
        }
    }
}

/// Scadenza a `after` da adesso. Una durata assurda che manderebbe in overflow l'orologio
/// scade subito (fail closed) invece di non scadere mai.
pub(crate) fn deadline(after: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(after).unwrap_or(now)
}
