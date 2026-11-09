//! Duplicate agents (docs/analysis/resilience.md §5.2, G15): two processes with the same agent
//! key (a cloned VM) take the node from each other on every registration. The relay never
//! blocks them, since whoever holds the key could use a block to deny service; it counts the
//! takeovers per node in a sliding window and reports a node that crosses the threshold, at
//! most once per window.

use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use zt_domain::NodeId;

/// The flapping thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlapConfig {
    /// The sliding window.
    pub window: Duration,
    /// Takeovers within the window that make a node flapping.
    pub threshold: u32,
}

impl Default for FlapConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            threshold: 3,
        }
    }
}

#[derive(Debug, Default)]
struct NodeTakeovers {
    at: VecDeque<Instant>,
    reported: Option<Instant>,
}

/// Takeovers per node. A node's entry holds at most `threshold` instants per window plus one
/// report time; nodes are those of the policy, so the table is bounded by it.
#[derive(Debug)]
pub struct FlapDetector {
    config: FlapConfig,
    nodes: HashMap<NodeId, NodeTakeovers>,
}

impl FlapDetector {
    /// No takeover yet.
    #[must_use]
    pub fn new(config: FlapConfig) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
        }
    }

    /// A registration for `node` replaced another connection at `now`. `Some(count)` if the
    /// node is to be reported now (`count` takeovers within the window).
    pub fn on_takeover(&mut self, node: &NodeId, now: Instant) -> Option<u32> {
        let window = self.config.window;
        let entry = self.nodes.entry(node.clone()).or_default();
        while entry
            .at
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= window)
        {
            entry.at.pop_front();
        }
        entry.at.push_back(now);
        // Bounded: only the count up to a generous multiple of the threshold matters.
        let keep = usize::try_from(self.config.threshold)
            .unwrap_or(usize::MAX)
            .saturating_mul(64)
            .max(1);
        while entry.at.len() > keep {
            entry.at.pop_front();
        }
        let count = u32::try_from(entry.at.len()).unwrap_or(u32::MAX);
        if count < self.config.threshold {
            return None;
        }
        if entry
            .reported
            .is_some_and(|r| now.saturating_duration_since(r) < window)
        {
            return None;
        }
        entry.reported = Some(now);
        Some(count)
    }
}
