//! R-6 efficiency, the sans-IO decisions (resilience.md §5.6, review 0007 AP-22, D-13): how far
//! a receiver grows a stream's window, and which connection the relay's global byte budget
//! sheds. The byte accounting itself lives in the network adapter; these are the rules.

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

/// The connection the relay sheds when its queued bytes `total` exceed `budget` (D-13): the one
/// with the largest backlog, the slowest reader; on a tie the newest (highest id), so a
/// long-lived connection is not dropped for a newcomer. A connection with nothing queued is
/// never shed. `None` within the budget.
pub fn shed_victim(
    total: usize,
    budget: usize,
    backlogs: impl IntoIterator<Item = (ConnId, usize)>,
) -> Option<ConnId> {
    if total <= budget {
        return None;
    }
    backlogs
        .into_iter()
        .filter(|&(_, b)| b > 0)
        .max_by_key(|&(id, b)| (b, id))
        .map(|(id, _)| id)
}
