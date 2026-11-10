//! R-2 specification: dead-peer detection on the agent's relay link (resilience.md §5.2, D-3
//! with review 0007's verdict: "dead" means no inbound frame at all for 3 × 10 s, not only
//! missing `Pong`s; catalogue R2-L2, R2-L7). Sans-IO, time passed in.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use std::time::{Duration, Instant};

use zt_application::liveness::{Liveness, LivenessAction, LivenessConfig};

fn s(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn the_defaults_are_a_10_second_keepalive_and_three_misses() {
    let c = LivenessConfig::default();
    assert_eq!(c.interval, s(10));
    assert_eq!(c.misses, 3);
    assert_eq!(c.dead_after(), s(30));
}

#[test]
fn it_pings_every_interval() {
    let t0 = Instant::now();
    let mut l = Liveness::new(LivenessConfig::default(), t0);
    assert_eq!(l.poll(t0), None);
    assert_eq!(l.poll(t0 + s(9)), None);
    assert_eq!(l.poll(t0 + s(10)), Some(LivenessAction::SendPing));
    assert_eq!(l.poll(t0 + s(10)), None, "one ping per interval");
    l.on_inbound(t0 + s(11));
    assert_eq!(l.poll(t0 + s(20)), Some(LivenessAction::SendPing));
    assert_eq!(l.next_deadline(), t0 + s(30));
}

/// R2-L7: three unanswered pings, i.e. no inbound frame for 30 s, end the session.
#[test]
fn silence_for_three_intervals_is_death() {
    let t0 = Instant::now();
    let mut l = Liveness::new(LivenessConfig::default(), t0);
    for k in 1..3 {
        assert_eq!(l.poll(t0 + s(10 * k)), Some(LivenessAction::SendPing));
    }
    assert_eq!(l.poll(t0 + s(29)), None);
    assert_eq!(l.poll(t0 + s(30)), Some(LivenessAction::Dead));
    // Dead stays dead.
    assert_eq!(l.poll(t0 + s(31)), Some(LivenessAction::Dead));
}

/// Any inbound frame proves the path, not only a `Pong`: a busy link is never declared dead.
#[test]
fn any_inbound_frame_keeps_the_link_alive() {
    let t0 = Instant::now();
    let mut l = Liveness::new(LivenessConfig::default(), t0);
    for k in 1..20 {
        l.on_inbound(t0 + s(5 * k));
        assert_ne!(l.poll(t0 + s(5 * k)), Some(LivenessAction::Dead));
    }
    assert_eq!(l.next_deadline(), t0 + s(100));
}

#[test]
fn a_clock_that_does_not_move_never_panics() {
    let t0 = Instant::now();
    let mut l = Liveness::new(LivenessConfig::default(), t0 + s(5));
    // An `now` earlier than the start (a reordered sample) is just "not yet".
    assert_eq!(l.poll(t0), None);
    l.on_inbound(t0);
}

#[test]
fn absurd_configurations_are_refused() {
    for bad in [
        LivenessConfig {
            interval: Duration::ZERO,
            misses: 3,
        },
        LivenessConfig {
            interval: s(10),
            misses: 0,
        },
        LivenessConfig {
            interval: s(4_000),
            misses: 3,
        },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
    assert!(LivenessConfig::default().validate().is_ok());
}
