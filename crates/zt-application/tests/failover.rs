//! R-4 specification and attacks: the client's failover plan (docs/analysis/resilience.md §5.3,
//! catalogue R4-F1..R4-F7; review 0007 AP-10 and D-4; backlog A5-4). Sans-IO: time enters as the
//! time elapsed since the plan started, the jitter as a sample passed in.
//!
//! - an overall deadline (8 s) for establishment only, inside the 10 s `ConnectTimeout` that
//!   Ansible passes to `ssh` (finding A11-2);
//! - per-step timeouts: connect 3 s, outer handshake 5 s, `OpenAck` 4 s at most, shared out
//!   over the relays left within the deadline and never under the stagger (finding A11-3);
//! - a staggered hedge (2 s plus jitter) with at most two attempts in flight, **only while the
//!   attempt in flight has not completed connect and outer handshake** (AP-10): a relay that
//!   handshakes and then is slow to answer `Open` is overloaded, not dead;
//! - the first `OpenAck` wins, every other attempt is cancelled, nothing is retried after it;
//! - a policy answer before any `OpenAck` ends every attempt (fail closed).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::time::Duration;

use zt_application::failover::{
    Action, Event, FailoverConfig, FailoverPlan, Failure, GiveUp, MAX_IN_FLIGHT, Step,
};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// A plan with the defaults and no jitter (sample 0).
fn plan(relays: usize) -> FailoverPlan {
    FailoverPlan::new(FailoverConfig::default(), relays, 0)
}

/// Runs the plan's timer up to `until`, waking at every `next_wake`, and collects the actions.
fn run_until(plan: &mut FailoverPlan, until: Duration) -> Vec<(Duration, Action)> {
    let mut out = Vec::new();
    while let Some(wake) = plan.next_wake() {
        if wake > until {
            break;
        }
        for a in plan.tick(wake) {
            out.push((wake, a));
        }
    }
    out
}

/// Connect and outer handshake of `relay` at `now`.
fn ready(plan: &mut FailoverPlan, now: Duration, relay: usize) -> Vec<Action> {
    let mut out = plan.handle(now, Event::Connected(relay));
    out.extend(plan.handle(now, Event::OuterReady(relay)));
    out
}

// ---------- specification ----------

#[test]
fn the_defaults_are_those_of_the_plan() {
    let c = FailoverConfig::default();
    assert_eq!(c.deadline, secs(8));
    assert_eq!(c.connect, secs(3));
    assert_eq!(c.handshake, secs(5));
    assert_eq!(c.open, secs(4));
    assert_eq!(c.stagger, secs(2));
    assert_eq!(MAX_IN_FLIGHT, 2);
    assert!(c.validate().is_ok());
}

#[test]
fn invalid_configurations_are_refused() {
    let base = FailoverConfig::default();
    for bad in [
        FailoverConfig {
            deadline: Duration::ZERO,
            ..base
        },
        FailoverConfig {
            connect: Duration::ZERO,
            ..base
        },
        FailoverConfig {
            handshake: Duration::ZERO,
            ..base
        },
        FailoverConfig {
            open: Duration::ZERO,
            ..base
        },
        FailoverConfig {
            stagger: Duration::ZERO,
            ..base
        },
        // Over five minutes: an `ssh` that hangs that long is a bug, not a policy.
        FailoverConfig {
            deadline: secs(301),
            ..base
        },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
    // A short deadline is fine: it simply ends the attempts earlier.
    assert!(
        FailoverConfig {
            deadline: secs(1),
            ..base
        }
        .validate()
        .is_ok()
    );
}

/// The relays are tried in the configured order: the first one alone at the start.
#[test]
fn the_first_relay_starts_alone() {
    let mut p = plan(3);
    assert_eq!(p.start(), vec![Action::Start(0)]);
    assert_eq!(p.in_flight(), 1);
}

/// A healthy first relay: no hedge, `Proceed` on its `OpenAck`.
#[test]
fn a_healthy_relay_is_used_without_a_hedge() {
    let mut p = plan(2);
    p.start();
    assert!(ready(&mut p, ms(50), 0).is_empty());
    assert_eq!(p.handle(ms(80), Event::Acked(0)), vec![Action::Proceed(0)]);
    assert!(p.is_finished());
    assert_eq!(p.next_wake(), None);
}

/// R4-F1: a black-holed first relay (no connect) costs the stagger: relay 2 starts at 2 s,
/// with relay 1 still in flight, then relay 1 is cancelled when relay 2 wins.
#[test]
fn a_black_holed_first_relay_costs_only_the_stagger() {
    let mut p = plan(2);
    p.start();
    assert_eq!(p.next_wake(), Some(secs(2)));
    assert!(p.tick(ms(1_999)).is_empty());
    assert_eq!(p.tick(secs(2)), vec![Action::Start(1)]);
    assert_eq!(p.in_flight(), 2);
    ready(&mut p, ms(2_050), 1);
    assert_eq!(
        p.handle(ms(2_080), Event::Acked(1)),
        vec![Action::Proceed(1), Action::Cancel(0)]
    );
}

/// A relay that accepts TCP but does not complete the outer handshake (overloaded handshake
/// workers, a proxy that accepts and drops) is hedged too.
#[test]
fn a_slow_handshake_is_hedged() {
    let mut p = plan(2);
    p.start();
    assert!(p.handle(ms(10), Event::Connected(0)).is_empty());
    assert_eq!(p.tick(secs(2)), vec![Action::Start(1)]);
}

/// AP-10: once relay 1 has completed connect and outer handshake, a missing `OpenAck` is
/// overload, not a dead relay: no hedge, the plan waits up to the open timeout (here half of
/// the 7.9 s left, for the two relays left) and only then moves on.
#[test]
fn a_slow_open_ack_is_never_hedged() {
    let mut p = plan(2);
    p.start();
    ready(&mut p, ms(100), 0);
    // The next wake is the open timeout, not a stagger.
    assert_eq!(p.next_wake(), Some(ms(4_050)));
    let actions = run_until(&mut p, ms(4_049));
    assert!(actions.is_empty(), "{actions:?}");
    assert_eq!(p.in_flight(), 1);
    assert_eq!(
        p.tick(ms(4_050)),
        vec![Action::TimedOut(0, Step::Open), Action::Start(1)]
    );
}

/// Finding A11-3: relays that complete the outer handshake and then sit on `Open` share the
/// deadline: each gets the time left divided by the relays left (itself included), so a
/// healthy third relay is still reached, with as much time as the others.
#[test]
fn stalling_relays_share_the_deadline() {
    let mut p = plan(3);
    p.start();
    ready(&mut p, Duration::ZERO, 0);
    // 8 s for three relays.
    let first = p.next_wake().unwrap();
    assert!(first > ms(2_666) && first < ms(2_667), "{first:?}");
    assert_eq!(
        p.tick(first),
        vec![Action::TimedOut(0, Step::Open), Action::Start(1)]
    );
    ready(&mut p, first, 1);
    // The 5.33 s left for two relays.
    let second = p.next_wake().unwrap();
    assert!(second > ms(5_333) && second < ms(5_334), "{second:?}");
    assert_eq!(
        p.tick(second),
        vec![Action::TimedOut(1, Step::Open), Action::Start(2)]
    );
    ready(&mut p, ms(5_400), 2);
    assert_eq!(
        p.handle(ms(5_500), Event::Acked(2)),
        vec![Action::Proceed(2)]
    );
}

/// Finding A11-3: the shared wait never drops under the stagger (2 s), so a long relay list
/// does not turn a merely slow `OpenAck` into a failure; nor over the open timeout (4 s).
#[test]
fn the_shared_wait_is_bounded() {
    let mut p = plan(8);
    p.start();
    ready(&mut p, Duration::ZERO, 0);
    assert_eq!(p.next_wake(), Some(secs(2)));
    let mut p = FailoverPlan::new(
        FailoverConfig {
            deadline: secs(60),
            ..FailoverConfig::default()
        },
        2,
        0,
    );
    p.start();
    ready(&mut p, Duration::ZERO, 0);
    assert_eq!(p.next_wake(), Some(secs(4)));
}

/// Finding A11-2: with two relays and the defaults, whatever way the first relay fails (black
/// hole, accept and silence, handshake then no `OpenAck`, at any moment before the stagger),
/// a healthy second relay (300 ms handshake, 100 ms `OpenAck`) gives `Proceed` within 6.5 s:
/// inside the 10 s `ConnectTimeout` that Ansible passes to `ssh` by default, with room left for
/// the end-to-end handshake and the SSH banner.
#[test]
fn one_failed_relay_fits_ansibles_connect_timeout() {
    // When relay 1 completes its handshake (None: never) and whether it connects at all.
    let mut cases: Vec<(Option<Duration>, bool)> = vec![(None, false), (None, true)];
    for t in [10, 500, 1_000, 1_999] {
        cases.push((Some(ms(t)), true));
    }
    for (handshake, connects) in cases {
        for jitter in [0, 250, 500] {
            let mut p = FailoverPlan::new(FailoverConfig::default(), 2, jitter);
            let mut actions = p.start();
            if connects {
                actions.extend(p.handle(ms(5), Event::Connected(0)));
            }
            if let Some(t) = handshake {
                actions.extend(p.handle(t, Event::OuterReady(0)));
            }
            let mut started = actions
                .contains(&Action::Start(1))
                .then_some(Duration::ZERO);
            while started.is_none() {
                let wake = p.next_wake().unwrap();
                if p.tick(wake).contains(&Action::Start(1)) {
                    started = Some(wake);
                }
            }
            let at = started.unwrap();
            ready(&mut p, at + ms(300), 1);
            let done = at + ms(400);
            assert!(
                p.handle(done, Event::Acked(1))
                    .contains(&Action::Proceed(1)),
                "{handshake:?} {connects}"
            );
            assert!(done <= ms(6_500), "{handshake:?} {connects}: {done:?}");
        }
    }
}

/// Per-step timeouts: connect 3 s from the start, handshake 5 s from the connect.
#[test]
fn step_timeouts_are_tight() {
    // Connect.
    let mut p = plan(1);
    p.start();
    let actions = run_until(&mut p, secs(3));
    assert_eq!(
        actions,
        vec![
            (secs(3), Action::TimedOut(0, Step::Connect)),
            (secs(3), Action::GiveUp(GiveUp::Exhausted)),
        ]
    );
    // Handshake.
    let mut p = plan(1);
    p.start();
    p.handle(ms(500), Event::Connected(0));
    assert_eq!(p.next_wake(), Some(ms(5_500)));
    assert_eq!(
        p.tick(ms(5_500)),
        vec![
            Action::TimedOut(0, Step::Handshake),
            Action::GiveUp(GiveUp::Exhausted)
        ]
    );
}

/// A failure before the stagger starts the next relay at once (sequential failover, as before
/// R-4), not at the stagger.
#[test]
fn a_failure_starts_the_next_relay_at_once() {
    let mut p = plan(3);
    p.start();
    assert_eq!(
        p.handle(ms(5), Event::Failed(0, Failure::Unavailable)),
        vec![Action::Start(1)]
    );
    assert_eq!(p.in_flight(), 1);
}

/// When the first of two attempts fails, the other may be hedged in turn if it is past its own
/// stagger and still before its handshake.
#[test]
fn a_failure_with_a_stale_attempt_in_flight_hedges_it() {
    let mut p = plan(3);
    p.start();
    assert_eq!(p.tick(secs(2)), vec![Action::Start(1)]);
    // Relay 1 times out at 3 s; relay 2 started at 2 s is not yet past its stagger.
    assert_eq!(p.tick(secs(3)), vec![Action::TimedOut(0, Step::Connect)]);
    assert_eq!(p.next_wake(), Some(secs(4)));
    assert_eq!(p.tick(secs(4)), vec![Action::Start(2)]);
}

/// With the attempt in flight past its handshake, a failure of the other does not start a
/// third one (that would be a hedge against a slow `OpenAck`, AP-10).
#[test]
fn no_replacement_hedge_against_a_slow_open_ack() {
    let mut p = plan(3);
    p.start();
    assert_eq!(p.tick(secs(2)), vec![Action::Start(1)]);
    ready(&mut p, ms(2_100), 1);
    assert_eq!(p.tick(secs(3)), vec![Action::TimedOut(0, Step::Connect)]);
    // Relay 2 waits (8 - 2.1) / 2 s: relay 3 is still to come.
    let actions = run_until(&mut p, ms(5_049));
    assert!(actions.is_empty(), "{actions:?}");
    assert_eq!(
        p.tick(ms(5_050)),
        vec![Action::TimedOut(1, Step::Open), Action::Start(2)]
    );
}

/// The deadline ends establishment: every attempt is cancelled and the plan gives up.
#[test]
fn the_deadline_gives_up() {
    let mut p = plan(2);
    p.start();
    ready(&mut p, ms(100), 0);
    p.tick(ms(4_050));
    ready(&mut p, ms(4_150), 1);
    assert_eq!(p.next_wake(), Some(secs(8)));
    assert_eq!(
        p.tick(secs(8)),
        vec![Action::Cancel(1), Action::GiveUp(GiveUp::Deadline)]
    );
    assert!(p.is_finished());
    assert!(p.handle(secs(9), Event::Acked(1)).is_empty());
}

/// A configured deadline shorter than the steps wins over them.
#[test]
fn a_short_deadline_wins_over_the_steps() {
    let mut p = FailoverPlan::new(
        FailoverConfig {
            deadline: secs(1),
            ..FailoverConfig::default()
        },
        3,
        0,
    );
    p.start();
    assert_eq!(p.next_wake(), Some(secs(1)));
    assert_eq!(
        p.tick(secs(1)),
        vec![Action::Cancel(0), Action::GiveUp(GiveUp::Deadline)]
    );
}

/// Every relay failed before the deadline: give up at once, without waiting for it.
#[test]
fn all_relays_failed_gives_up_before_the_deadline() {
    let mut p = plan(2);
    p.start();
    p.handle(ms(1), Event::Failed(0, Failure::Unavailable));
    assert_eq!(
        p.handle(ms(2), Event::Failed(1, Failure::Unavailable)),
        vec![Action::GiveUp(GiveUp::Exhausted)]
    );
}

/// An empty list gives up at the start.
#[test]
fn no_relay_gives_up_at_once() {
    let mut p = plan(0);
    assert_eq!(p.start(), vec![Action::GiveUp(GiveUp::Exhausted)]);
}

/// The stagger is delayed by a deterministic jitter of at most a quarter of it, derived from
/// the sample: a fleet that starts together does not hedge together.
#[test]
fn the_stagger_has_a_bounded_deterministic_jitter() {
    let mut seen = std::collections::BTreeSet::new();
    for sample in [0_u64, 1, 77, 499, 500, 501, u64::MAX] {
        let a = FailoverPlan::new(FailoverConfig::default(), 2, sample);
        let b = FailoverPlan::new(FailoverConfig::default(), 2, sample);
        assert_eq!(a.hedge_delay(), b.hedge_delay(), "deterministic");
        assert!(a.hedge_delay() >= secs(2));
        assert!(a.hedge_delay() <= ms(2_500), "{:?}", a.hedge_delay());
        seen.insert(a.hedge_delay());
    }
    assert!(seen.len() > 2, "the sample must matter: {seen:?}");
}
