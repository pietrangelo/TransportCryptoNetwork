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
pub mod keys;
pub mod logging;
pub mod relay;
pub mod reload;
mod revocable;
mod stream;
pub mod systemd;

pub use error::NetError;
pub use revocable::{Revocable, Updater};

use std::time::Duration;

use zt_crypto::PublicKey;

/// Relay al massimo in un elenco di un agent o di un client (PROTOCOL §13).
pub const MAX_RELAYS: usize = 8;

/// Un relay: indirizzo e chiave pinnata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Indirizzo (`host:porta`).
    pub address: String,
    /// Chiave pubblica del relay, pinnata.
    pub public_key: PublicKey,
}

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

/// L'orologio di sistema in secondi Unix; prima del 1970 vale 0 (fail closed: nessun
/// certificato è ancora valido, PROTOCOL §15.6).
#[must_use]
pub fn unix_now() -> zt_domain::UnixTime {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    zt_domain::UnixTime::from_secs(secs)
}

/// `YYYY-MM-DDTHH:MM:SSZ` (calendario gregoriano prolettico, UTC), per le date dei certificati
/// mostrate a un operatore.
#[must_use]
pub fn utc_text(time: zt_domain::UnixTime) -> String {
    civil(time.as_secs()).unwrap_or_else(|| format!("@{}", time.as_secs()))
}

/// Da secondi Unix a data civile (H. Hinnant, `civil_from_days`), solo con aritmetica
/// controllata.
fn civil(secs: u64) -> Option<String> {
    let days = secs.checked_div(86_400)?;
    let rem = secs.checked_rem(86_400)?;
    let (hh, mm, ss) = (
        rem.checked_div(3_600)?,
        rem.checked_rem(3_600)?.checked_div(60)?,
        rem.checked_rem(60)?,
    );
    let z = days.checked_add(719_468)?;
    let era = z.checked_div(146_097)?;
    let doe = z.checked_rem(146_097)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1_460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let day = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let month = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let mut year = yoe.checked_add(era.checked_mul(400)?)?;
    if month <= 2 {
        year = year.checked_add(1)?;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z"
    ))
}

/// Scadenza a `after` da adesso. Una durata assurda che manderebbe in overflow l'orologio
/// scade subito (fail closed) invece di non scadere mai.
pub(crate) fn deadline(after: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(after).unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::utc_text;
    use zt_domain::UnixTime;

    #[test]
    fn utc_dates() {
        assert_eq!(utc_text(UnixTime::from_secs(0)), "1970-01-01T00:00:00Z");
        assert_eq!(
            utc_text(UnixTime::from_secs(1_794_128_400)),
            "2026-11-08T09:00:00Z"
        );
        assert_eq!(
            utc_text(UnixTime::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(
            utc_text(UnixTime::from_secs(4_102_444_799)),
            "2099-12-31T23:59:59Z"
        );
        // Nessun overflow nemmeno all'estremo.
        assert!(utc_text(UnixTime::from_secs(u64::MAX)).ends_with('Z'));
    }
}
