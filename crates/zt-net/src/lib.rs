//! # zt-net
//!
//! TCN network adapters, based on tokio. They connect the sans-IO use cases
//! (`zt-application`) and the handshake (`zt-crypto`) to real sockets.
//!
//! - [`channel`]: Noise messages over TCP, with `Pending` → `Established` typestate;
//! - [`relay`]: relay server (single-threaded hub around `RelayCore`);
//! - [`agent`]: outbound-only agent with reconnection;
//! - [`client`]: client library (used by the tests and by `zt-client`);
//! - [`config`]: key and policy files.
//!
//! Every I/O operation has a timeout; every queue is bounded.
#![forbid(unsafe_code)]

pub mod agent;
pub mod channel;
pub mod client;
pub mod config;
mod error;
pub mod keys;
pub mod lifecycle;
pub mod logging;
pub mod net;
pub mod relay;
pub mod reload;
mod revocable;
mod stream;
pub mod systemd;

pub use error::NetError;
pub use revocable::{Revocable, Updater};

use std::time::Duration;

/// Maximum number of relays in an agent's or a client's list (PROTOCOL §13).
pub const MAX_RELAYS: usize = 8;

/// A relay: address and pinned key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Address (`host:port`).
    pub address: String,
    /// Public key of the relay, pinned: v1, or v2 (needed by the hybrid IK suite, PQ-AUTH).
    pub public_key: zt_crypto::PeerKey,
    /// Handshake suite pinned for this relay (PROTOCOL §7.5): no fallback to another one.
    pub suite: zt_domain::HandshakeSuite,
}

/// Timeouts of all network operations.
#[derive(Debug, Clone)]
pub struct Timeouts {
    /// Complete Noise handshake.
    pub handshake: Duration,
    /// Maximum silence on a connection (no complete frame received).
    pub idle: Duration,
    /// Writing a single message.
    pub write: Duration,
    /// Response to an `Open` and end-to-end handshake.
    pub open: Duration,
    /// Connection to the local SSH daemon.
    pub ssh_connect: Duration,
    /// Interval of keepalive `Ping`s.
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
            keepalive: Duration::from_secs(10),
        }
    }
}

/// The system clock in Unix seconds; before 1970 it is 0 (fail closed: no certificate is yet
/// valid, PROTOCOL §15.6).
#[must_use]
pub fn unix_now() -> zt_domain::UnixTime {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    zt_domain::UnixTime::from_secs(secs)
}

/// `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian calendar, UTC), for certificate dates shown to
/// an operator.
#[must_use]
pub fn utc_text(time: zt_domain::UnixTime) -> String {
    civil(time.as_secs()).unwrap_or_else(|| format!("@{}", time.as_secs()))
}

/// From Unix seconds to a civil date (H. Hinnant, `civil_from_days`), using only checked
/// arithmetic.
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

/// Locks `mutex`, also when it is poisoned: the guarded tables (admission, per-identity
/// lines) stay consistent across a panic (each operation is a few map updates), and refusing
/// every connection would be worse.
pub(crate) fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Deadline `after` from now. An absurd duration that would overflow the clock expires
/// immediately (fail closed) instead of never expiring.
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
        // No overflow even at the extreme.
        assert!(utc_text(UnixTime::from_secs(u64::MAX)).ends_with('Z'));
    }
}
