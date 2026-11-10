//! R-6 efficiency, the sans-IO decisions (resilience.md §5.6, review 0007 AP-22, D-13): how far
//! a receiver grows a stream's window, and which connection the relay's global byte budget
//! sheds (per authenticated identity, review 0013 A13-1). The byte accounting itself lives in
//! the network adapter; these are the rules.

use std::collections::HashMap;
use std::hash::Hash;

use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW};

use crate::relay::ConnId;

/// Receive-window auto-tuning for one stream (R6-E3, R6-E4).
///
/// The window starts at [`INITIAL_WINDOW`]. When this side delivered a whole window since the
/// last change and its backlog stayed below a quarter of the target (it waited on an empty
/// queue: its reader keeps up), the window, not the reader, is the bottleneck: the tuner asks
/// for the window to double, up to [`MAX_WINDOW`]. A receiver whose reader lags keeps a backlog
/// and never grows. The receiver cannot see the sender's credit itself (the grants in flight
/// are invisible to it), so the backlog is the signal; on a fast link where the window is not
/// the limit the window may still grow, bounded by the budget. The caller grows it only if the byte budget has room ([`Self::grew`]),
/// otherwise the window stays ([`Self::refused`]). Never beyond `MAX_WINDOW`, the limit every
/// peer and the relay enforce.
#[derive(Debug, Clone)]
pub struct WindowTuner {
    target: u32,
    delivered: u64,
}

impl Default for WindowTuner {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowTuner {
    /// A tuner at the initial window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            target: INITIAL_WINDOW,
            delivered: 0,
        }
    }

    /// The window this side grants the sender.
    #[must_use]
    pub const fn target(&self) -> u32 {
        self.target
    }

    /// Consumed credit is returned once it reaches this (a quarter of the target).
    #[must_use]
    pub const fn update_threshold(&self) -> u32 {
        self.target / 4
    }

    /// `n` bytes were delivered to the local reader.
    pub fn on_delivered(&mut self, n: u32) {
        self.delivered = self.delivered.saturating_add(u64::from(n));
    }

    /// The growth to ask the budget for, or 0. `backlog` is the least data received and not yet
    /// delivered since the last update (0 if the receiver waited for data).
    #[must_use]
    pub fn wants_growth(&self, backlog: u32) -> u32 {
        let room = MAX_WINDOW.saturating_sub(self.target);
        if room == 0
            || backlog >= self.update_threshold()
            || self.delivered < u64::from(self.target)
        {
            return 0;
        }
        self.target.min(room)
    }

    /// The budget granted the growth `by` (as returned by [`Self::wants_growth`]).
    pub fn grew(&mut self, by: u32) {
        self.target = self.target.saturating_add(by).min(MAX_WINDOW);
        self.delivered = 0;
    }

    /// The budget refused the growth: the window stays; ask again after another window.
    pub const fn refused(&mut self) {
        self.delivered = 0;
    }
}

/// At most this fraction of the relay's budget (one over `IDENTITY_SHARE`) may be queued
/// towards one authenticated identity, never less than one connection's full credit (review
/// 0013, A13-1).
pub const IDENTITY_SHARE: usize = 4;

/// One connection's backlog, as the relay sees it when the budget is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backlog<K> {
    /// The connection.
    pub conn: ConnId,
    /// The authenticated identity of its peer (its fingerprint).
    pub identity: K,
    /// The peer is an agent.
    pub agent: bool,
    /// Bytes queued towards it and not yet written.
    pub bytes: usize,
}

/// The limits [`shed_victim`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShedLimits {
    /// The global byte budget.
    pub budget: usize,
    /// The most one identity may hold: a quarter of the budget, at least one connection's
    /// credit.
    pub identity_cap: usize,
    /// An agent's normal credit (its streams × the largest window): shed only as a last
    /// resort.
    pub agent_credit: usize,
}

impl ShedLimits {
    /// The limits for `budget`, where one connection may legitimately have `conn_credit`
    /// bytes queued (its streams × the largest window) and an agent `agent_credit`.
    #[must_use]
    pub const fn new(budget: usize, conn_credit: usize, agent_credit: usize) -> Self {
        let share = budget / IDENTITY_SHARE;
        Self {
            budget,
            identity_cap: if share > conn_credit {
                share
            } else {
                conn_credit
            },
            agent_credit,
        }
    }
}

/// Why a connection is shed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedCause {
    /// Its identity holds more than [`ShedLimits::identity_cap`].
    IdentityCap,
    /// The budget as a whole is exceeded and its identity holds the most of it.
    Budget,
}

impl ShedCause {
    /// The stable name of the cause, for the audit line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityCap => "identity_cap",
            Self::Budget => "budget",
        }
    }
}

/// The connection to shed, with the identity it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shed<K> {
    /// The connection.
    pub conn: ConnId,
    /// Its identity.
    pub identity: K,
    /// The peer is an agent.
    pub agent: bool,
    /// Bytes queued towards the whole identity (every connection of it).
    pub identity_bytes: usize,
    /// Why.
    pub cause: ShedCause,
}

/// What one identity holds.
struct Holding {
    bytes: usize,
    agent: bool,
    /// Its largest connection: (backlog, id), the newest on a tie.
    largest: (usize, ConnId),
}

/// The connection the relay sheds (D-13, fair per identity since review 0013, A13-1), or
/// `None`. The backlogs are summed per authenticated identity, so spreading a backlog over many
/// connections does not hide it:
///
/// 1. an identity holding more than [`ShedLimits::identity_cap`] is shed, even within the
///    budget (the largest such identity first);
/// 2. past the budget (`total > budget`), the identity with the largest *excess* is shed: its
///    bytes minus, for an agent, its normal credit, so an agent within its credit is never shed
///    for a client; when nobody has an excess (only agents within their credit hold the
///    budget), the largest identity, as a last resort.
///
/// Within the identity, its largest connection goes, the newest on a tie (a long-lived
/// connection is not dropped for a newcomer). A connection with nothing queued is never shed.
pub fn shed_victim<K: Eq + Hash + Copy>(
    total: usize,
    limits: &ShedLimits,
    backlogs: impl IntoIterator<Item = Backlog<K>>,
) -> Option<Shed<K>> {
    let mut identities: HashMap<K, Holding> = HashMap::new();
    for b in backlogs.into_iter().filter(|b| b.bytes > 0) {
        let h = identities.entry(b.identity).or_insert(Holding {
            bytes: 0,
            agent: false,
            largest: (0, b.conn),
        });
        h.bytes = h.bytes.saturating_add(b.bytes);
        h.agent |= b.agent;
        h.largest = h.largest.max((b.bytes, b.conn));
    }
    let shed = |(identity, h): (&K, &Holding), cause| Shed {
        conn: h.largest.1,
        identity: *identity,
        agent: h.agent,
        identity_bytes: h.bytes,
        cause,
    };
    if let Some(over) = identities
        .iter()
        .filter(|(_, h)| h.bytes > limits.identity_cap)
        .max_by_key(|(_, h)| (h.bytes, h.largest.1))
    {
        return Some(shed(over, ShedCause::IdentityCap));
    }
    if total <= limits.budget {
        return None;
    }
    let excess = |h: &Holding| {
        if h.agent {
            h.bytes.saturating_sub(limits.agent_credit)
        } else {
            h.bytes
        }
    };
    identities
        .iter()
        .filter(|(_, h)| excess(h) > 0)
        .max_by_key(|(_, h)| (excess(h), h.largest.1))
        .or_else(|| {
            identities
                .iter()
                .max_by_key(|(_, h)| (h.bytes, h.largest.1))
        })
        .map(|victim| shed(victim, ShedCause::Budget))
}
