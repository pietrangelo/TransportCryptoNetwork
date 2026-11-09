//! R-4 attacks and failures: the client's failover plan (docs/analysis/resilience.md §5.3,
//! catalogue R4-F1..R4-F7; review 0007 AP-10 and D-4; backlog A5-4). Sans-IO: time enters as the
//! time elapsed since the plan started, the jitter as a sample passed in.
//!
//! - an overall deadline (20 s) for establishment only;
//! - per-step timeouts: connect 3 s, outer handshake 5 s, `OpenAck` 10 s;
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

use proptest::prelude::*;

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

// ---------- attacks and failures ----------

/// R4-F2: two `OpenAck`s race. Exactly one `Proceed`: msg1 of the end-to-end channel is sent on
/// one relay only; the other is cancelled.
#[test]
fn hedged_attempts_never_send_two_msg1() {
    let mut p = plan(2);
    p.start();
    p.tick(secs(2));
    ready(&mut p, ms(2_010), 0);
    ready(&mut p, ms(2_020), 1);
    assert_eq!(
        p.handle(ms(2_030), Event::Acked(1)),
        vec![Action::Proceed(1), Action::Cancel(0)]
    );
    assert!(p.handle(ms(2_031), Event::Acked(0)).is_empty());
}

/// R4-F3: relay 1 answers with a policy refusal before relay 2's `OpenAck`: every attempt
/// ends (fail closed), the client does not look for a more permissive relay.
#[test]
fn a_policy_answer_aborts_all_hedged_attempts() {
    let mut p = plan(3);
    p.start();
    p.tick(secs(2));
    ready(&mut p, ms(2_100), 0);
    assert_eq!(
        p.handle(ms(2_200), Event::Failed(0, Failure::Refused)),
        vec![Action::Cancel(1), Action::GiveUp(GiveUp::Refused(0))]
    );
    assert!(p.is_finished());
    assert!(p.handle(ms(2_300), Event::Acked(1)).is_empty());
    assert_eq!(p.next_wake(), None);
}

/// R4-F4: relay 2 acknowledges first; a later refusal from relay 1 is ignored (accepted and
/// documented in resilience §5.3).
#[test]
fn late_policy_answer_after_proceed_is_ignored() {
    let mut p = plan(2);
    p.start();
    p.tick(secs(2));
    ready(&mut p, ms(2_100), 1);
    assert_eq!(
        p.handle(ms(2_200), Event::Acked(1)),
        vec![Action::Proceed(1), Action::Cancel(0)]
    );
    assert!(
        p.handle(ms(2_300), Event::Failed(0, Failure::Refused))
            .is_empty()
    );
}

/// Events about relays never started, already cancelled or out of range change nothing.
#[test]
fn events_about_other_relays_are_ignored() {
    let mut p = plan(2);
    p.start();
    for e in [
        Event::Acked(1),
        Event::Failed(1, Failure::Refused),
        Event::OuterReady(7),
        Event::Acked(usize::MAX),
    ] {
        assert!(p.handle(ms(1), e).is_empty(), "{e:?}");
    }
    assert_eq!(p.in_flight(), 1);
    assert!(!p.is_finished());
}

/// R4-F6: the deadline is for establishment only: after `Proceed` nothing is retried and no
/// timer is left.
#[test]
fn deadline_applies_to_establishment_only() {
    let mut p = plan(2);
    p.start();
    ready(&mut p, secs(19), 0);
    assert_eq!(
        p.handle(ms(19_900), Event::Acked(0)),
        vec![Action::Proceed(0)]
    );
    assert_eq!(p.next_wake(), None);
    assert!(p.tick(secs(25)).is_empty());
    assert!(
        p.handle(secs(30), Event::Failed(0, Failure::Unavailable))
            .is_empty()
    );
}

/// A clock that goes backwards (the driver passes elapsed time; a bug must not hedge early).
#[test]
fn time_going_backwards_starts_nothing() {
    let mut p = plan(2);
    p.start();
    p.handle(secs(1), Event::Connected(0));
    assert!(p.tick(ms(500)).is_empty());
    assert_eq!(p.in_flight(), 1);
}

#[derive(Debug, Clone)]
enum Op {
    Tick(u64),
    Connected(usize),
    Ready(usize),
    Acked(usize),
    Failed(usize, bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0_u64..4_000).prop_map(Op::Tick),
        (0_usize..9).prop_map(Op::Connected),
        (0_usize..9).prop_map(Op::Ready),
        (0_usize..9).prop_map(Op::Acked),
        ((0_usize..9), any::<bool>()).prop_map(|(i, r)| Op::Failed(i, r)),
    ]
}

proptest! {
    /// R4-F7 and the invariants of §5.3 under arbitrary event sequences: at most two attempts
    /// in flight, each relay started at most once (handshakes ≤ relays), at most one `Proceed`,
    /// nothing after `Proceed` or `GiveUp`, a hedge only while the attempt in flight is before
    /// its outer handshake, and nothing past the deadline.
    #[test]
    fn hedging_stays_within_admission_budget(
        relays in 1_usize..=8,
        sample in any::<u64>(),
        ops in proptest::collection::vec(op(), 0..60),
    ) {
        let mut p = FailoverPlan::new(FailoverConfig::default(), relays, sample);
        let mut now = Duration::ZERO;
        let mut started = vec![false; relays];
        let mut flying: Vec<usize> = Vec::new();
        let mut outer_ready = vec![false; relays];
        let mut proceeded = 0;
        let mut finished = false;
        let mut apply = |actions: Vec<Action>,
                         now: Duration,
                         flying: &mut Vec<usize>,
                         outer_ready: &[bool],
                         started: &mut Vec<bool>,
                         proceeded: &mut i32,
                         finished: &mut bool| {
            for a in actions {
                prop_assert!(!*finished, "action after the end: {a:?}");
                match a {
                    Action::Start(i) => {
                        prop_assert!(!started[i], "relay {i} started twice");
                        prop_assert!(now < FailoverConfig::default().deadline);
                        // A hedge: the other attempt in flight must be before its handshake.
                        for &other in flying.iter() {
                            prop_assert!(!outer_ready[other], "hedge against a slow OpenAck");
                        }
                        started[i] = true;
                        flying.push(i);
                        prop_assert!(flying.len() <= MAX_IN_FLIGHT);
                    }
                    Action::Cancel(i) | Action::TimedOut(i, _) => {
                        prop_assert!(flying.contains(&i), "cancel of {i} not in flight");
                        flying.retain(|&f| f != i);
                    }
                    Action::Proceed(i) => {
                        prop_assert!(flying.contains(&i));
                        flying.retain(|&f| f != i);
                        *proceeded += 1;
                    }
                    Action::GiveUp(_) => {
                        *finished = true;
                    }
                }
                if *proceeded > 0 && flying.is_empty() {
                    *finished = true;
                }
            }
            prop_assert!(*proceeded <= 1);
            Ok(())
        };
        apply(p.start(), now, &mut flying, &outer_ready, &mut started, &mut proceeded, &mut finished)?;
        for o in ops {
            let actions = match o {
                Op::Tick(d) => { now += ms(d); p.tick(now) }
                Op::Connected(i) => p.handle(now, Event::Connected(i)),
                Op::Ready(i) => {
                    let out = p.handle(now, Event::OuterReady(i));
                    if flying.contains(&i) { outer_ready[i] = true; }
                    out
                }
                Op::Acked(i) => p.handle(now, Event::Acked(i)),
                Op::Failed(i, refused) => {
                    let f = if refused { Failure::Refused } else { Failure::Unavailable };
                    let out = p.handle(now, Event::Failed(i, f));
                    // A reported failure leaves flight without an action of the plan.
                    flying.retain(|&f| f != i);
                    out
                }
            };
            apply(actions, now, &mut flying, &outer_ready, &mut started, &mut proceeded, &mut finished)?;
            prop_assert_eq!(p.in_flight(), if p.is_finished() { 0 } else { flying.len() });
            if let Some(w) = p.next_wake() {
                prop_assert!(w <= FailoverConfig::default().deadline);
            }
        }
    }
}
