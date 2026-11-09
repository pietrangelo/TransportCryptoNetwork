//! R-2 specification and attacks: the agent's reconnect policy (docs/analysis/resilience.md
//! §5.2, D-2; catalogue R2-L1, R2-L4, R2-L5). Full jitter on failures, a spread window after a
//! session that lived, a 30 s cap; sans-IO, with the random sample passed in.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::time::Duration;

use proptest::prelude::*;
use zt_application::reconnect::{ReconnectConfig, ReconnectPolicy, SessionEnd};

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

#[test]
fn the_defaults_are_those_of_the_plan() {
    let c = ReconnectConfig::default();
    assert_eq!(c.base, secs(1));
    assert_eq!(c.cap, secs(30));
    assert_eq!(c.spread, secs(10));
    assert_eq!(c.stable_after, secs(10));
    assert!(c.validate().is_ok());
}

/// Full jitter: `U(0, min(cap, base·2ⁿ))`, the ceiling doubling per failure up to the cap.
#[test]
fn failures_draw_the_whole_delay_at_random_under_a_doubling_ceiling() {
    let mut p = ReconnectPolicy::new(ReconnectConfig::default());
    let ceilings = [1, 2, 4, 8, 16, 30, 30, 30];
    for ceiling in ceilings {
        // The largest sample reaches the ceiling, a zero sample gives no delay at all.
        let mut probe = p.clone();
        assert_eq!(
            probe.next(SessionEnd::Failed, u64::MAX),
            secs(ceiling).min(secs(30))
        );
        let mut zero = p.clone();
        assert_eq!(zero.next(SessionEnd::Failed, 0), Duration::ZERO);
        let d = p.next(SessionEnd::Failed, 123_456_789);
        assert!(d <= secs(ceiling), "{d:?} > {ceiling}s");
    }
    assert_eq!(p.failures(), 8);
}

/// After a session that lived (the relay restarted or drained), the first retry is drawn from
/// the spread window and the failure count resets.
#[test]
fn a_session_that_lived_is_followed_by_a_spread_retry() {
    let mut p = ReconnectPolicy::new(ReconnectConfig::default());
    for _ in 0..5 {
        p.next(SessionEnd::Failed, 7);
    }
    let d = p.next(SessionEnd::Ended { lived: secs(3_600) }, u64::MAX);
    assert_eq!(d, secs(10));
    assert_eq!(p.failures(), 0);
    let d = p.next(SessionEnd::Ended { lived: secs(60) }, 0);
    assert_eq!(d, Duration::ZERO);
    // Then a failure (the relay still down) keeps the spread window as the floor of its
    // ceiling (finding A10-4), and the doubling takes over above it.
    assert_eq!(p.next(SessionEnd::Failed, u64::MAX), secs(10));
}

/// A spread window of zero is allowed (single relay): retry at once after a lived session.
#[test]
fn a_zero_spread_retries_at_once() {
    let mut p = ReconnectPolicy::new(ReconnectConfig {
        spread: Duration::ZERO,
        ..ReconnectConfig::default()
    });
    assert_eq!(
        p.next(SessionEnd::Ended { lived: secs(600) }, u64::MAX),
        Duration::ZERO
    );
}

/// R2-L5: a relay that accepts and drops at once (a crash loop) is a failure, not a lived
/// session: the backoff keeps growing instead of resetting to the spread window.
#[test]
fn a_relay_that_drops_immediately_is_backed_off() {
    let mut p = ReconnectPolicy::new(ReconnectConfig::default());
    for _ in 0..6 {
        p.next(SessionEnd::Ended { lived: secs(1) }, 1);
    }
    assert_eq!(p.failures(), 6);
    assert_eq!(
        p.clone()
            .next(SessionEnd::Ended { lived: secs(2) }, u64::MAX),
        secs(30)
    );
}

#[test]
fn absurd_configurations_are_refused() {
    let d = ReconnectConfig::default();
    for bad in [
        ReconnectConfig {
            base: Duration::ZERO,
            ..d
        },
        ReconnectConfig { cap: secs(0), ..d },
        ReconnectConfig {
            base: secs(60),
            cap: secs(30),
            ..d
        },
        ReconnectConfig {
            cap: secs(7_200),
            ..d
        },
        ReconnectConfig {
            spread: secs(7_200),
            ..d
        },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

/// The spread is uniform: over many draws each tenth of the window gets its share (R2-L1).
#[test]
fn the_spread_is_uniform_over_the_window() {
    let p = ReconnectPolicy::new(ReconnectConfig::default());
    let mut buckets = [0_u32; 10];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..10_000 {
        // xorshift: a deterministic sample sequence.
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let d = p.clone().next(SessionEnd::Ended { lived: secs(600) }, x);
        let i = (d.as_millis() * 10 / 10_001) as usize;
        buckets[i] += 1;
    }
    for (i, n) in buckets.iter().enumerate() {
        assert!((800..=1_200).contains(n), "bucket {i}: {n} of 10 000");
    }
}

proptest! {
    /// R2-L4: after any history and for any sample, the delay never exceeds the cap (nor the
    /// spread after a lived session) and nothing overflows.
    #[test]
    fn backoff_is_bounded_for_any_sample(
        history in proptest::collection::vec((any::<bool>(), any::<u64>(), 0_u64..100_000), 0..300),
        sample in any::<u64>(),
        base_ms in 1_u64..5_000,
        cap_s in 1_u64..3_600,
        spread_s in 0_u64..3_600,
    ) {
        let config = ReconnectConfig {
            base: Duration::from_millis(base_ms),
            cap: secs(cap_s).max(Duration::from_millis(base_ms)),
            spread: secs(spread_s),
            ..ReconnectConfig::default()
        };
        let mut p = ReconnectPolicy::new(config);
        for (failed, s, lived) in history {
            let end = if failed { SessionEnd::Failed } else { SessionEnd::Ended { lived: secs(lived) } };
            let d = p.next(end, s);
            prop_assert!(d <= config.cap.max(config.spread));
        }
        prop_assert!(p.next(SessionEnd::Failed, sample) <= config.cap);
    }
}
