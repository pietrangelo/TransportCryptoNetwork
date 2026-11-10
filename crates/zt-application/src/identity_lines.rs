//! Per-identity rate limiting of audit lines (findings A8-2 and A9-2).
//!
//! A recorded message 1 of a known identity can be replayed at will, by anyone on the path to
//! the relay or by a compromised relay towards an agent. Each replay must not produce its own
//! line naming the victim: the first event of an identity in an interval is logged in full,
//! the others are counted and reported once at the end of the interval. The table is bounded:
//! beyond [`MAX_LOGGED_IDENTITIES`] identities per interval, events are only counted, so made-up
//! keys cannot grow it.
//!
//! Sans-IO: the caller decides when an interval ends (it calls [`IdentityLines::take`]).

use std::collections::HashMap;

use zt_domain::{AuthFailureReason, Fingerprint, HandshakeSuite};

use crate::admission::Refusal;

/// The most identities whose audit events are logged per interval (finding A8-2): at most
/// two lines (the first event in full, then a `_repeated` count) for each, per interval.
pub const MAX_LOGGED_IDENTITIES: usize = 256;

/// An audit event about an identity, logged in full once per identity and interval, then
/// counted (finding A8-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentityEvent {
    /// `authentication_failed` (for example a revoked key or an expired certificate, which a
    /// replayed message 1 can produce at will).
    AuthenticationFailed(AuthFailureReason),
    /// `handshake_suite_rejected`: the suite is not accepted (for the identity's role on the
    /// relay, for clients on the agent).
    SuiteRejected(HandshakeSuite),
    /// `admission_refused`: a confirmed identity refused at its concurrency limit or because
    /// the established pool is full (finding A8-10).
    AdmissionRefused(Refusal),
}

/// The events about one identity that were counted instead of logged in an interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepeatedEvent {
    /// The identity.
    pub peer: Fingerprint,
    /// The event.
    pub event: IdentityEvent,
    /// How many times it happened after the logged one.
    pub count: u64,
}

/// What an interval counted instead of logging.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityLinesSummary {
    /// One entry per identity and event with at least one repeat, at most
    /// [`MAX_LOGGED_IDENTITIES`].
    pub repeated: Vec<RepeatedEvent>,
    /// Events about identities beyond [`MAX_LOGGED_IDENTITIES`]: only counted.
    pub suppressed_identities: u64,
}

impl IdentityLinesSummary {
    /// `true` if there is nothing to report.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.repeated.is_empty() && self.suppressed_identities == 0
    }
}

/// The identity events of the current interval.
#[derive(Debug, Default)]
pub struct IdentityLines {
    /// How many after the first, which was logged.
    seen: HashMap<(Fingerprint, IdentityEvent), u64>,
    suppressed_identities: u64,
}

impl IdentityLines {
    /// `true` if the caller should log the event in full now: the first such event of the
    /// identity in the interval, while fewer than [`MAX_LOGGED_IDENTITIES`] identity events are
    /// tracked. Otherwise it is counted.
    pub fn note(&mut self, peer: Fingerprint, event: IdentityEvent) -> bool {
        if let Some(count) = self.seen.get_mut(&(peer, event)) {
            *count = count.saturating_add(1);
            return false;
        }
        if self.seen.len() >= MAX_LOGGED_IDENTITIES {
            self.suppressed_identities = self.suppressed_identities.saturating_add(1);
            return false;
        }
        self.seen.insert((peer, event), 0);
        true
    }

    /// Ends the interval: what was counted, and a fresh table.
    pub fn take(&mut self) -> IdentityLinesSummary {
        let ended = core::mem::take(self);
        IdentityLinesSummary {
            repeated: ended
                .seen
                .into_iter()
                .filter(|(_, count)| *count > 0)
                .map(|((peer, event), count)| RepeatedEvent { peer, event, count })
                .collect(),
            suppressed_identities: ended.suppressed_identities,
        }
    }
}
