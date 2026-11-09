//! Admission of relay connections (R-1, PROTOCOL §10.1): pre-authentication pool, per-source
//! budget refunded only after key confirmation, established pool, per-identity concurrency
//! and aggregated pre-authentication logging.
//!
//! ```text
//! accept ──(per-source token, pre-auth slot)──▶ pending ──first authentic frame──▶ established
//!   │ refused: rate_limited / preauth_pool_full     │ token given back, identity charged
//!   ▼                                               ▼ released: slot freed, token stays spent
//! dropped without a reply                         unconfirmed (replay, scanner, failure)
//! ```
//!
//! Sans-IO: the caller passes the clock and the source address; nothing here sleeps or logs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use zt_domain::{AccessPolicy, AuthFailureReason, CertRejection, Fingerprint};

use crate::ratelimit::{HandshakeGate, source_key};

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

/// The largest pool or table a configuration may ask for.
const MAX_POOL: usize = 1_048_576;
/// The largest per-identity concurrency (a fleet controller with many forks fits easily).
const MAX_PER_IDENTITY: usize = 8_192;
/// The largest burst of a rate-limit bucket.
const MAX_BURST: u32 = 65_536;
/// The longest configurable deadline: a handshake that needs more is not a handshake.
const MAX_DURATION: Duration = Duration::from_secs(300);
/// The slowest refill (a slower refill is stricter, never looser; one day is plenty).
const MAX_REFILL: Duration = Duration::from_secs(86_400);
/// The longest summary interval.
const MAX_SUMMARY_INTERVAL: Duration = Duration::from_secs(3_600);

impl AdmissionConfig {
    /// Checks every limit: none may be zero or absurd, and `msg1_deadline` lies between
    /// [`MIN_MSG1_DEADLINE`] and `handshake_timeout` (finding AP-20).
    ///
    /// # Errors
    /// The first offending field, as an [`AdmissionConfigError`].
    pub fn validate(&self) -> Result<(), AdmissionConfigError> {
        use AdmissionConfigError::{TooLarge, Zero};
        let sizes = [
            ("max_preauth", self.max_preauth, MAX_POOL),
            ("max_established", self.max_established, MAX_POOL),
            ("max_per_identity", self.max_per_identity, MAX_PER_IDENTITY),
            ("max_tracked_sources", self.max_tracked_sources, MAX_POOL),
            ("max_tracked_wide", self.max_tracked_wide, MAX_POOL),
        ];
        let bursts = [
            ("source_burst", self.source_burst),
            ("wide_burst", self.wide_burst),
        ];
        let durations = [
            ("source_refill", self.source_refill, MAX_REFILL),
            ("wide_refill", self.wide_refill, MAX_REFILL),
            ("msg1_deadline", self.msg1_deadline, MAX_DURATION),
            ("handshake_timeout", self.handshake_timeout, MAX_DURATION),
            (
                "first_frame_deadline",
                self.first_frame_deadline,
                MAX_DURATION,
            ),
            (
                "summary_interval",
                self.summary_interval,
                MAX_SUMMARY_INTERVAL,
            ),
        ];
        for (name, value, _) in sizes {
            if value == 0 {
                return Err(Zero(name));
            }
        }
        for (name, value) in bursts {
            if value == 0 {
                return Err(Zero(name));
            }
        }
        for (name, value, _) in durations {
            if value.is_zero() {
                return Err(Zero(name));
            }
        }
        for (name, value, max) in sizes {
            if value > max {
                return Err(TooLarge(name));
            }
        }
        for (name, value) in bursts {
            if value > MAX_BURST {
                return Err(TooLarge(name));
            }
        }
        for (name, value, max) in durations {
            if value > max {
                return Err(TooLarge(name));
            }
        }
        if self.msg1_deadline < MIN_MSG1_DEADLINE {
            return Err(AdmissionConfigError::Msg1DeadlineTooShort);
        }
        if self.msg1_deadline > self.handshake_timeout {
            return Err(AdmissionConfigError::Msg1DeadlineAfterHandshake);
        }
        Ok(())
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
    /// Stable name, the key in the summary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::PreauthPoolFull => "preauth_pool_full",
            Self::EstablishedPoolFull => "established_pool_full",
            Self::IdentityLimit => "identity_limit",
            Self::HandshakeFailed => "handshake_failed",
            Self::Timeout => "timeout",
            Self::Oversized => "oversized",
            Self::UnknownPeer => "unknown_peer",
            Self::UnverifiedCertificate => "unverified_certificate",
            Self::Unconfirmed => "unconfirmed",
            Self::Aborted => "aborted",
        }
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
    gate: HandshakeGate,
    next_ticket: u64,
    /// Unconfirmed connections and their source (needed for the refund).
    pending: HashMap<Ticket, IpAddr>,
    /// Confirmed connections and their identity.
    established: HashMap<Ticket, Fingerprint>,
    per_identity: HashMap<Fingerprint, usize>,
    interval: Interval,
}

/// The failures of the current summary interval.
#[derive(Debug)]
struct Interval {
    started: Instant,
    counts: BTreeMap<PreauthFailure, u64>,
    sources: HashSet<[u8; 9]>,
    keys: HashSet<Fingerprint>,
    saturated: bool,
}

impl Interval {
    fn new(started: Instant) -> Self {
        Self {
            started,
            counts: BTreeMap::new(),
            sources: HashSet::new(),
            keys: HashSet::new(),
            saturated: false,
        }
    }
}

/// Inserts into a bounded distinct set; `false` if the set was full and `value` new.
fn insert_bounded<T: std::hash::Hash + Eq>(set: &mut HashSet<T>, value: T) -> bool {
    if set.len() < MAX_DISTINCT || set.contains(&value) {
        set.insert(value);
        true
    } else {
        false
    }
}

impl Admission {
    /// An admission with no connections. `config` should have passed
    /// [`AdmissionConfig::validate`]; an invalid one is not a panic, only absurd limits.
    #[must_use]
    pub fn new(config: AdmissionConfig, now: Instant) -> Self {
        let gate = HandshakeGate::new(
            config.max_tracked_sources,
            config.source_burst,
            config.source_refill,
            config.wide_burst,
            config.wide_refill,
            config.max_tracked_wide,
        );
        Self {
            config,
            gate,
            next_ticket: 0,
            pending: HashMap::new(),
            established: HashMap::new(),
            per_identity: HashMap::new(),
            interval: Interval::new(now),
        }
    }

    /// The limits in force.
    #[must_use]
    pub fn config(&self) -> &AdmissionConfig {
        &self.config
    }

    /// A new TCP connection from `source`: it takes a pre-authentication slot and one token of
    /// the source's budget. A refusal is counted in the summary.
    ///
    /// # Errors
    /// [`Refusal::PreauthPoolFull`] or [`Refusal::SourceRateLimited`]. The pool is checked
    /// first, so a full pool does not spend the source's tokens.
    pub fn on_accept(&mut self, source: IpAddr, now: Instant) -> Result<Ticket, Refusal> {
        if self.pending.len() >= self.config.max_preauth {
            self.record(PreauthFailure::PreauthPoolFull, source, None);
            return Err(Refusal::PreauthPoolFull);
        }
        if !self.gate.admit(source, now) {
            self.record(PreauthFailure::RateLimited, source, None);
            return Err(Refusal::SourceRateLimited);
        }
        let ticket = Ticket(self.next_ticket);
        self.next_ticket = self.next_ticket.wrapping_add(1);
        self.pending.insert(ticket, source);
        Ok(ticket)
    }

    /// Key confirmation of `ticket` by `peer`: the first authentic transport frame arrived.
    /// The connection moves to the established pool, the identity is charged and the source's
    /// token is given back (finding AP-1). A refusal ends the pre-authentication of the
    /// ticket without a refund: the caller closes the connection.
    ///
    /// # Errors
    /// [`Refusal::UnknownTicket`] if `ticket` is not pending (already confirmed or released),
    /// [`Refusal::EstablishedPoolFull`], [`Refusal::IdentityLimit`].
    pub fn on_confirmed(
        &mut self,
        ticket: Ticket,
        peer: Fingerprint,
        now: Instant,
    ) -> Result<(), Refusal> {
        let source = self.pending.remove(&ticket).ok_or(Refusal::UnknownTicket)?;
        if self.established.len() >= self.config.max_established {
            self.record(PreauthFailure::EstablishedPoolFull, source, None);
            return Err(Refusal::EstablishedPoolFull);
        }
        let held = self.per_identity.get(&peer).copied().unwrap_or(0);
        if held >= self.config.max_per_identity {
            self.record(PreauthFailure::IdentityLimit, source, None);
            return Err(Refusal::IdentityLimit);
        }
        self.per_identity.insert(peer, held.saturating_add(1));
        self.established.insert(ticket, peer);
        self.gate.refund(source, now);
        Ok(())
    }

    /// The connection of `ticket` closed. Releasing an unknown ticket, or twice, does nothing.
    pub fn release(&mut self, ticket: Ticket) {
        if self.pending.remove(&ticket).is_some() {
            return;
        }
        let Some(peer) = self.established.remove(&ticket) else {
            return;
        };
        match self.per_identity.get(&peer).copied() {
            Some(n) if n > 1 => {
                self.per_identity.insert(peer, n.saturating_sub(1));
            }
            _ => {
                self.per_identity.remove(&peer);
            }
        }
    }

    /// Connections in the pre-authentication pool.
    #[must_use]
    pub fn preauth_count(&self) -> usize {
        self.pending.len()
    }

    /// Connections in the established pool.
    #[must_use]
    pub fn established_count(&self) -> usize {
        self.established.len()
    }

    /// Confirmed connections of `peer`.
    #[must_use]
    pub fn identity_count(&self, peer: &Fingerprint) -> usize {
        self.per_identity.get(peer).copied().unwrap_or(0)
    }

    /// Records a pre-authentication failure for the summary. `key` is the initiator's key
    /// when the failure happened after message 1 was decrypted; it is only counted, never
    /// reported.
    pub fn record(&mut self, failure: PreauthFailure, source: IpAddr, key: Option<Fingerprint>) {
        let interval = &mut self.interval;
        let count = interval.counts.entry(failure).or_insert(0);
        *count = count.saturating_add(1);
        let mut kept = insert_bounded(&mut interval.sources, source_key(source));
        if let Some(key) = key {
            kept &= insert_bounded(&mut interval.keys, key);
        }
        if !kept {
            interval.saturated = true;
        }
    }

    /// The summary of the interval that ended, if it had failures. An interval ends
    /// `summary_interval` after it started; the next one starts at `now`.
    pub fn poll_summary(&mut self, now: Instant) -> Option<PreauthSummary> {
        let end = self
            .interval
            .started
            .checked_add(self.config.summary_interval)?;
        if now < end {
            return None;
        }
        let ended = core::mem::replace(&mut self.interval, Interval::new(now));
        if ended.counts.is_empty() {
            return None;
        }
        let saturated = ended.saturated
            || ended.sources.len() >= MAX_DISTINCT
            || ended.keys.len() >= MAX_DISTINCT;
        Some(PreauthSummary {
            counts: ended.counts.into_iter().collect(),
            distinct_sources: ended.sources.len(),
            distinct_keys: ended.keys.len(),
            saturated,
        })
    }
}

/// `true` if an `authentication_failed` for `peer` deserves its own audit line (finding AP-3):
/// the configuration knows the key (whitelisted or revoked), or a pinned CA's signature binds
/// it (a certificate rejected after its signature was verified). Anything else is a key that
/// anyone could have made up, and only counts in the summary.
#[must_use]
pub fn is_known_identity(
    policy: &AccessPolicy,
    peer: &Fingerprint,
    reason: AuthFailureReason,
) -> bool {
    if policy.role(peer).is_some() || policy.cert_trust().is_key_revoked(peer) {
        return true;
    }
    match reason {
        AuthFailureReason::Certificate(check) => !matches!(
            check,
            CertRejection::Malformed
                | CertRejection::KeyMismatch
                | CertRejection::UnknownAuthority
                | CertRejection::BadSignature
        ),
        _ => false,
    }
}
