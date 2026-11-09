//! Admission of relay connections (R-1, PROTOCOL §10.1): pre-authentication pool, per-source
//! budget refunded only after key confirmation, established pool, per-identity concurrency
//! and aggregated pre-authentication logging.
//!
//! RED stub: every operation fails closed until the implementation lands.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use zt_domain::{AccessPolicy, AuthFailureReason, Fingerprint};

/// The shortest accepted `msg1_deadline` (finding AP-20).
pub const MIN_MSG1_DEADLINE: Duration = Duration::from_secs(5);

/// Admission limits of a relay. The defaults are documented in PROTOCOL §10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionConfig {
    /// Connections that have not yet confirmed their key (handshake in progress).
    pub max_preauth: usize,
    /// Connections whose key is confirmed (agents and clients).
    pub max_established: usize,
    /// Confirmed connections per identity.
    pub max_per_identity: usize,
    /// Unconfirmed handshakes per IPv4 address or IPv6 /64 in a burst.
    pub source_burst: u32,
    /// One more unconfirmed handshake per source every `source_refill`.
    pub source_refill: Duration,
    /// Sources tracked by the per-source budget.
    pub max_tracked_sources: usize,
    /// New /64 prefixes per IPv6 /48 in a burst.
    pub wide_burst: u32,
    /// One more new /64 per /48 every `wide_refill`.
    pub wide_refill: Duration,
    /// Tracked /48 prefixes.
    pub max_tracked_wide: usize,
    /// Time from accept to a complete message 1.
    pub msg1_deadline: Duration,
    /// Time from accept to message 2 sent.
    pub handshake_timeout: Duration,
    /// Time from message 2 to the first authentic transport frame (key confirmation).
    pub first_frame_deadline: Duration,
    /// Interval of the aggregated `preauth_summary` audit event.
    pub summary_interval: Duration,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_preauth: 1_024,
            max_established: 8_192,
            max_per_identity: 512,
            source_burst: 64,
            source_refill: Duration::from_secs(3),
            max_tracked_sources: 65_536,
            wide_burst: 64,
            wide_refill: Duration::from_secs(1),
            max_tracked_wide: 16_384,
            msg1_deadline: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            first_frame_deadline: Duration::from_secs(5),
            summary_interval: Duration::from_secs(10),
        }
    }
}

/// Why an [`AdmissionConfig`] was refused. The variant names the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmissionConfigError {
    /// A limit or duration that must not be zero is zero.
    Zero(&'static str),
    /// A limit or duration over its maximum.
    TooLarge(&'static str),
    /// `msg1_deadline` below [`MIN_MSG1_DEADLINE`].
    Msg1DeadlineTooShort,
    /// `msg1_deadline` after `handshake_timeout`.
    Msg1DeadlineAfterHandshake,
}

impl core::fmt::Display for AdmissionConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AdmissionConfigError {}

impl AdmissionConfig {
    /// Checks every limit (stub).
    ///
    /// # Errors
    /// Always (stub).
    pub fn validate(&self) -> Result<(), AdmissionConfigError> {
        Err(AdmissionConfigError::Zero("stub"))
    }
}

/// One accepted connection, until it is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ticket(u64);

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The pre-authentication pool is full.
    PreauthPoolFull,
    /// The source used up its budget of unconfirmed handshakes.
    SourceRateLimited,
    /// The established pool is full.
    EstablishedPoolFull,
    /// The identity already has `max_per_identity` confirmed connections.
    IdentityLimit,
    /// The ticket is not (or no longer) pending.
    UnknownTicket,
}

/// A pre-authentication failure, counted in the aggregated summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PreauthFailure {
    /// Per-source budget used up.
    RateLimited,
    /// Pre-authentication pool full.
    PreauthPoolFull,
    /// Established pool full at key confirmation.
    EstablishedPoolFull,
    /// Identity concurrency limit at key confirmation.
    IdentityLimit,
    /// Message 1 invalid for every accepted suite and key.
    HandshakeFailed,
    /// Message 1 not complete within `msg1_deadline`, or the handshake not within
    /// `handshake_timeout`.
    Timeout,
    /// A length prefix over the largest legitimate message 1.
    Oversized,
    /// A valid message 1 from a key the configuration does not know.
    UnknownPeer,
    /// A certificate rejected before its signature was verified, from an unknown key.
    UnverifiedCertificate,
    /// Message 2 sent, but no authentic transport frame followed (for example a replayed
    /// message 1).
    Unconfirmed,
    /// Closed before message 1 was complete.
    Aborted,
}

impl PreauthFailure {
    /// Stable name, the key in the summary (stub).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        ""
    }
}

/// The aggregated pre-authentication failures of one interval. It never names an identity or
/// an address (finding AP-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreauthSummary {
    /// How many failures of each kind, in a stable order.
    pub counts: Vec<(PreauthFailure, u64)>,
    /// Distinct sources (IPv4 address or IPv6 /64), at most [`MAX_DISTINCT`].
    pub distinct_sources: usize,
    /// Distinct unknown keys, at most [`MAX_DISTINCT`].
    pub distinct_keys: usize,
    /// `true` if a distinct count reached [`MAX_DISTINCT`] (the real value is larger).
    pub saturated: bool,
}

/// The most distinct sources or keys a summary counts.
pub const MAX_DISTINCT: usize = 4_096;

/// The admission state of a relay. See the module documentation.
#[derive(Debug)]
pub struct Admission {
    config: AdmissionConfig,
}

impl Admission {
    /// An admission with no connections. `config` must be valid (stub).
    #[must_use]
    pub fn new(config: AdmissionConfig, _now: Instant) -> Self {
        Self { config }
    }

    /// The limits in force.
    #[must_use]
    pub fn config(&self) -> &AdmissionConfig {
        &self.config
    }

    /// A new TCP connection from `source` (stub).
    ///
    /// # Errors
    /// Always (stub).
    pub fn on_accept(&mut self, _source: IpAddr, _now: Instant) -> Result<Ticket, Refusal> {
        Err(Refusal::PreauthPoolFull)
    }

    /// Key confirmation of `ticket` by `peer` (stub).
    ///
    /// # Errors
    /// Always (stub).
    pub fn on_confirmed(
        &mut self,
        _ticket: Ticket,
        _peer: Fingerprint,
        _now: Instant,
    ) -> Result<(), Refusal> {
        Err(Refusal::UnknownTicket)
    }

    /// The connection of `ticket` closed (stub).
    pub fn release(&mut self, _ticket: Ticket) {}

    /// Connections in the pre-authentication pool (stub).
    #[must_use]
    pub fn preauth_count(&self) -> usize {
        usize::MAX
    }

    /// Connections in the established pool (stub).
    #[must_use]
    pub fn established_count(&self) -> usize {
        usize::MAX
    }

    /// Confirmed connections of `peer` (stub).
    #[must_use]
    pub fn identity_count(&self, _peer: &Fingerprint) -> usize {
        usize::MAX
    }

    /// Records a pre-authentication failure for the summary (stub).
    pub fn record(&mut self, _failure: PreauthFailure, _source: IpAddr, _key: Option<Fingerprint>) {
    }

    /// The summary of the interval that ended, if it had failures (stub).
    pub fn poll_summary(&mut self, _now: Instant) -> Option<PreauthSummary> {
        None
    }
}

/// `true` if an `authentication_failed` for `peer` deserves its own audit line (stub).
#[must_use]
pub fn is_known_identity(
    _policy: &AccessPolicy,
    _peer: &Fingerprint,
    _reason: AuthFailureReason,
) -> bool {
    true
}
