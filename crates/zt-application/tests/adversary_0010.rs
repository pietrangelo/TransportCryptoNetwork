//! Regression tests for adversary review 0010 (Phase 3) on the sans-IO layer:
//!
//! - A10-3: the progress watchdog takes its first observation as a baseline (no stall at
//!   every start) and reports a stall only after two checks in a row without progress;
//! - A10-4: after a session that lived, the spread window stays the floor of the jitter
//!   ceiling for the failures that follow (a relay that is still down), so the fleet does not
//!   pile up when it comes back; checked with a deterministic Monte Carlo of the policy;
//! - A10-5: a draining relay core turns new streams away with `NodeOffline`, also on
//!   connections that were open before the drain, and keeps the open ones.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use zt_application::lifecycle::{ProgressWatchdog, WatchdogAction};
use zt_application::reconnect::{ReconnectConfig, ReconnectPolicy, SessionEnd};
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::{
    AccessPolicy, AllowedNodes, ClientGrant, Fingerprint, Frame, NodeId, RejectReason, SessionId,
    StreamId,
};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// A10-3: the first check after the start sees a counter that may still be zero (the hub has
/// not ticked yet). It is a baseline: the watchdog is kicked and no stall is reported.
#[test]
fn the_first_observation_is_a_baseline() {
    for start in [0, 1, 42] {
        let mut w = ProgressWatchdog::new();
        assert_eq!(w.observe(start), WatchdogAction::Kick, "start at {start}");
    }
}

/// A10-3: one check without progress (a check that came just before the hub's tick) holds the
/// kick but is not a stall; the second in a row is, and it is reported once.
#[test]
fn a_stall_is_reported_after_two_checks_without_progress() {
    let mut w = ProgressWatchdog::new();
    assert_eq!(w.observe(0), WatchdogAction::Kick);
    assert_eq!(w.observe(0), WatchdogAction::Hold);
    assert_eq!(w.observe(1), WatchdogAction::Kick);
    assert_eq!(w.observe(1), WatchdogAction::Hold);
    assert_eq!(w.observe(1), WatchdogAction::Stalled);
    // Still stalled: no kick, no second report.
    assert_eq!(w.observe(1), WatchdogAction::Hold);
    assert_eq!(w.observe(1), WatchdogAction::Hold);
    // Progress again.
    assert_eq!(w.observe(2), WatchdogAction::Kick);
    assert_eq!(w.observe(2), WatchdogAction::Hold);
    assert_eq!(w.observe(2), WatchdogAction::Stalled);
}

/// A10-4: after a session that lived, a failure (the relay is still down) draws from at least
/// the spread window, not from the one-second base.
#[test]
fn the_spread_stays_the_floor_after_a_lived_session() {
    let mut p = ReconnectPolicy::new(ReconnectConfig::default());
    assert_eq!(
        p.next(SessionEnd::Ended { lived: secs(3_600) }, u64::MAX),
        secs(10)
    );
    for ceiling in [10, 10, 10, 10, 16, 30, 30] {
        assert_eq!(
            p.clone().next(SessionEnd::Failed, u64::MAX),
            secs(ceiling),
            "after {} failures",
            p.failures()
        );
        p.next(SessionEnd::Failed, 1);
    }
    // Before any lived session (a fleet that boots), the base still applies.
    let mut fresh = ReconnectPolicy::new(ReconnectConfig::default());
    assert_eq!(fresh.next(SessionEnd::Failed, u64::MAX), secs(1));
}

/// A deterministic 64-bit generator (splitmix64) for the Monte Carlo below.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The peak of reconnects per second, against the ideal `n / spread`, for a fleet whose
/// relay dropped every session at 0 and refuses connections until `down`.
fn herd_peak(n: usize, down: Duration, seed: u64) -> f64 {
    let config = ReconnectConfig::default();
    let mut rng = SplitMix(seed);
    let mut per_second = vec![0_usize; 600];
    for _ in 0..n {
        let mut p = ReconnectPolicy::new(config);
        let mut t = p.next(SessionEnd::Ended { lived: secs(3_600) }, rng.next());
        while t < down {
            t += p.next(SessionEnd::Failed, rng.next());
        }
        per_second[t.as_secs() as usize] += 1;
    }
    let ideal = n as f64 / config.spread.as_secs_f64();
    *per_second.iter().max().unwrap() as f64 / ideal
}

/// A10-4 (R2-L1 with downtime): with the relay down for a few seconds after the sessions
/// dropped, the peak of reconnects per second stays within 2.5 times the ideal (it reached 3.7
/// times with the base as the only floor).
#[test]
fn reconnects_stay_spread_when_the_relay_is_down_for_a_while() {
    for down in [0, 2, 3, 5, 8, 10, 15, 30] {
        let peak = herd_peak(4_000, secs(down), 0x0010_0004 + down);
        assert!(
            peak <= 2.5,
            "relay down {down} s: peak {peak:.2} times the ideal"
        );
    }
}

struct Ids(u8);

impl SessionIds for Ids {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

fn opens_to(out: &[Output], conn: ConnId) -> Vec<StreamId> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send {
                conn: c,
                frame: Frame::Open { stream, .. },
            } if *c == conn => Some(*stream),
            _ => None,
        })
        .collect()
}

/// A10-5: once the drain started, an `Open` on a connection that was established before it is
/// rejected with `NodeOffline` (the client tries another relay) and never reaches the agent;
/// the stream opened before the drain keeps flowing.
#[test]
fn a_draining_core_rejects_new_streams_and_keeps_the_open_ones() {
    let agent = Fingerprint::from_bytes([1; 32]);
    let client = Fingerprint::from_bytes([2; 32]);
    let web = NodeId::try_from("web-01").unwrap();
    let mut policy = AccessPolicy::new();
    policy.add_agent(agent, web.clone()).unwrap();
    policy
        .add_client(
            client,
            ClientGrant {
                name: NodeId::try_from("ops").unwrap(),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
    let mut core = RelayCore::new(Arc::new(policy), RelayLimits::default(), Ids(0));
    let now = Now {
        instant: Instant::now(),
        unix: zt_domain::UnixTime::from_secs(1_800_000_000),
    };
    let (a, c) = (ConnId(1), ConnId(2));
    for (conn, peer) in [(a, agent), (c, client)] {
        core.handle(
            Input::Connected {
                conn,
                peer,
                certificate: None,
            },
            now,
        );
    }
    core.handle(
        Input::Received {
            conn: a,
            frame: Frame::Register { node: web.clone() },
        },
        now,
    );
    let first = StreamId::try_from(1).unwrap();
    let out = core.handle(
        Input::Received {
            conn: c,
            frame: Frame::Open {
                stream: first,
                target: web.clone(),
            },
        },
        now,
    );
    let agent_stream = opens_to(&out, a)[0];
    core.handle(
        Input::Received {
            conn: a,
            frame: Frame::OpenAck {
                stream: agent_stream,
            },
        },
        now,
    );
    assert_eq!(core.client_stream_count(), 1);

    let out = core.handle(Input::DrainStarted, now);
    assert!(
        out.is_empty(),
        "the start of a drain closes nothing: {out:?}"
    );

    let late = StreamId::try_from(3).unwrap();
    let out = core.handle(
        Input::Received {
            conn: c,
            frame: Frame::Open {
                stream: late,
                target: web,
            },
        },
        now,
    );
    assert!(
        opens_to(&out, a).is_empty(),
        "routed during the drain: {out:?}"
    );
    assert!(
        out.contains(&Output::Send {
            conn: c,
            frame: Frame::Reject {
                stream: late,
                reason: RejectReason::NodeOffline,
            },
        }),
        "{out:?}"
    );
    assert_eq!(core.client_stream_count(), 1);
    // The open stream still carries data.
    let payload = zt_domain::FramePayload::try_from(vec![7_u8; 16]).unwrap();
    let out = core.handle(
        Input::Received {
            conn: c,
            frame: Frame::Data {
                stream: first,
                payload: payload.clone(),
            },
        },
        now,
    );
    assert!(
        out.contains(&Output::Send {
            conn: a,
            frame: Frame::Data {
                stream: agent_stream,
                payload,
            },
        }),
        "{out:?}"
    );
}
