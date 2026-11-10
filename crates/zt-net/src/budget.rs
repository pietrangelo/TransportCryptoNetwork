//! Global byte budgets for buffered stream data (resilience R-6, review 0007 AP-22 and D-13):
//! backpressure instead of an out-of-memory.
//!
//! - On the agent (and the client), every stream's receive window is a [`Reservation`]: a new
//!   session gets its initial window once the client is authenticated (review 0013, A13-2), or
//!   is closed (`Drained`); a window grows only
//!   while the budget has room outside its last quarter, kept for the initial windows of new
//!   streams, so one bulk stream cannot starve the others.
//! - On the relay, every frame queued towards a peer carries a [`Charge`]; past the budget, or
//!   past an identity's share of it, the relay sheds the largest connection of the identity
//!   that holds the most ([`zt_application::efficiency::shed_victim`], review 0013 A13-1).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MIB: usize = 1024 * 1024;

/// An agent's full credit with `max_streams` streams: every stream's window at its largest
/// (`MAX_WINDOW`), what the relay may legitimately have queued towards it.
#[must_use]
pub fn agent_credit(max_streams: usize) -> usize {
    max_streams.saturating_mul(usize::try_from(zt_domain::flow::MAX_WINDOW).unwrap_or(usize::MAX))
}

/// The smallest default queue budget of the relay: two agents' full credit with the default
/// 64 streams (review 0013, A13-1), so one agent holding its normal credit is never the
/// identity over its share.
pub const MIN_QUEUE_BUDGET: usize = 128 * MIB;
/// The largest default queue budget of the relay.
pub const MAX_QUEUE_BUDGET: usize = 1024 * MIB;

/// A byte budget shared by every stream or connection of a process.
#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
}

impl ByteBudget {
    /// A budget of `limit` bytes, none used.
    #[must_use]
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    /// The limit, in bytes.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes reserved or charged now.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// More charged than the limit.
    #[must_use]
    pub fn exceeded(&self) -> bool {
        self.used() > self.limit
    }

    /// Applies `f` to the bytes used, atomically; `false` if `f` refuses. A plain
    /// compare-exchange loop: `fetch_update` is deprecated on nightly (renamed `try_update`),
    /// which stable does not have yet.
    fn update(&self, f: impl Fn(usize) -> Option<usize>) -> bool {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = f(current) else {
                return false;
            };
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Takes `n` bytes if the total stays within `ceiling`.
    fn take(&self, n: usize, ceiling: usize) -> bool {
        self.update(|used| used.checked_add(n).filter(|&total| total <= ceiling))
    }

    fn give_back(&self, n: usize) {
        // Never below zero: every give-back matches an earlier take.
        self.update(|used| Some(used.saturating_sub(n)));
    }

    /// Reserves `n` bytes, or `None` if they do not fit in the limit.
    #[must_use]
    pub fn try_reserve(self: &Arc<Self>, n: usize) -> Option<Reservation> {
        self.take(n, self.limit).then(|| Reservation {
            budget: Arc::clone(self),
            bytes: n,
        })
    }

    /// Charges `n` bytes whatever the limit (the relay's queued frames: the caller sheds when
    /// [`Self::exceeded`]); released when the charge is dropped.
    #[must_use]
    pub fn charge(self: &Arc<Self>, n: usize) -> Charge {
        self.used.fetch_add(n, Ordering::AcqRel);
        Charge {
            budget: Arc::clone(self),
            bytes: n,
        }
    }
}

/// Bytes reserved from a [`ByteBudget`] (a receive window), released on drop.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl Reservation {
    /// Grows the reservation by `n` bytes if the budget stays within three quarters of its
    /// limit (the last quarter is for the initial windows of new streams).
    #[must_use]
    pub fn try_grow(&mut self, n: usize) -> bool {
        let limit = self.budget.limit;
        let ceiling = limit.saturating_sub(limit / 4);
        let grown = self.budget.take(n, ceiling);
        if grown {
            self.bytes = self.bytes.saturating_add(n);
        }
        grown
    }

    /// The bytes held.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.give_back(self.bytes);
    }
}

/// Bytes charged to a [`ByteBudget`] (a queued frame), released on drop.
#[derive(Debug)]
pub struct Charge {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl Charge {
    /// The bytes charged.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.give_back(self.bytes);
    }
}

/// The relay's queue budget for a machine with `memory` bytes (the smaller of the physical
/// memory and the cgroup limit): a quarter of it, from 128 MiB to 1 GiB; 1 GiB if unknown.
#[must_use]
pub fn queue_budget_for(memory: Option<u64>) -> usize {
    memory.map_or(MAX_QUEUE_BUDGET, |m| {
        usize::try_from(m / 4)
            .unwrap_or(usize::MAX)
            .clamp(MIN_QUEUE_BUDGET, MAX_QUEUE_BUDGET)
    })
}

/// The relay's default queue budget on this machine ([`queue_budget_for`]).
#[must_use]
pub fn default_queue_budget() -> usize {
    queue_budget_for(memory())
}

/// The agent's default buffer budget: like the relay's queue budget, a quarter of the memory
/// from 128 MiB to 1 GiB ([`queue_budget_for`]).
#[must_use]
pub fn default_buffer_budget() -> usize {
    default_queue_budget()
}

/// A receive window outside any shared budget (the client's single stream): its own budget,
/// large enough to grow to `MAX_WINDOW` within the three-quarter rule.
#[must_use]
pub fn standalone_window() -> Option<Reservation> {
    let max = usize::try_from(zt_domain::flow::MAX_WINDOW).ok()?;
    let initial = usize::try_from(zt_domain::flow::INITIAL_WINDOW).ok()?;
    // limit - limit/4 >= MAX_WINDOW
    ByteBudget::new(max.saturating_add(max / 3).saturating_add(4)).try_reserve(initial)
}

/// Physical memory, capped by the cgroup v2 limit if there is one.
fn memory() -> Option<u64> {
    let physical = std::fs::read_to_string("/proc/meminfo").ok().and_then(|m| {
        m.lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .map(|kb| kb.saturating_mul(1024))
    });
    let cgroup = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    match (physical, cgroup) {
        (Some(p), Some(c)) => Some(p.min(c)),
        (p, c) => p.or(c),
    }
}
