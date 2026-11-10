//! R-3 specification: the sans-IO parts of the lifecycle (resilience.md §5.4; review 0007
//! AP-4, AP-21): the watchdog's progress counter, the drain controller, the clock-jump
//! detector and the relay core's shutdown (catalogue R3-C1, R3-C6, R3-C10).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use zt_application::lifecycle::{
    ClockJumpDetector, DrainController, DrainStep, ProgressWatchdog, WatchdogAction,
};
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::{
    AccessPolicy, AllowedNodes, ClientGrant, CloseReason, DomainEvent, Fingerprint, Frame, NodeId,
    SessionId, StreamId,
};

fn s(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// AP-4: the watchdog is kicked whenever the hub processed *anything* since the last check,
/// not only a `Tick`: a busy hub is healthy.
#[test]
fn watchdog_does_not_fire_on_a_busy_but_progressing_hub() {
    let mut w = ProgressWatchdog::new();
    let mut counter = 0_u64;
    for _ in 0..100 {
        counter += 1_000;
        assert_eq!(w.observe(counter), WatchdogAction::Kick);
    }
}

/// R3-C6: a hub that stopped processing (deadlock, livelock) stops the kicks.
#[test]
fn a_stalled_hub_stops_the_kicks() {
    let mut w = ProgressWatchdog::new();
    assert_eq!(w.observe(1), WatchdogAction::Kick);
    assert_eq!(w.observe(1), WatchdogAction::Hold);
    assert_eq!(w.observe(1), WatchdogAction::Stalled);
    assert_eq!(w.observe(2), WatchdogAction::Kick);
}

#[test]
fn the_drain_ends_with_the_last_client_stream_or_at_its_deadline() {
    let t0 = Instant::now();
    let d = DrainController::new(t0, s(60));
    assert_eq!(d.step(t0, 3), DrainStep::Wait);
    assert_eq!(d.step(t0 + s(30), 1), DrainStep::Wait);
    assert_eq!(
        d.step(t0 + s(31), 0),
        DrainStep::Finished { expired: false }
    );
    assert_eq!(d.step(t0 + s(60), 5), DrainStep::Finished { expired: true });
    // No stream at all: the drain is over at once.
    assert_eq!(
        DrainController::new(t0, s(60)).step(t0, 0),
        DrainStep::Finished { expired: false }
    );
    assert_eq!(d.deadline(), t0 + s(60));
}

/// R3-C10: a wall-clock step against the monotonic clock is reported, with its sign
/// (a backward step makes expired certificates valid again).
#[test]
fn backward_clock_step_is_reported() {
    let wall = SystemTime::UNIX_EPOCH + s(1_800_000_000);
    let mono = Instant::now();
    let mut c = ClockJumpDetector::new(s(5), wall, mono);
    // One second on both clocks: nothing.
    assert_eq!(c.observe(wall + s(1), mono + s(1)), None);
    // The wall clock goes back an hour while one second passes.
    let jump = c.observe(wall + s(2) - s(3_600), mono + s(2)).unwrap();
    assert_eq!(jump.delta_secs, -3_600);
    // Forward, too.
    let jump = c
        .observe(wall + s(3) - s(3_600) + s(600), mono + s(3))
        .unwrap();
    assert_eq!(jump.delta_secs, 600);
    // Small drift below the threshold is not a jump.
    assert_eq!(
        c.observe(wall + s(4) - s(3_600) + s(600) + s(3), mono + s(4)),
        None
    );
}

struct Ids(u8);
impl SessionIds for Ids {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

/// R3-C1: at the end of a drain the core closes every stream with `Close Drained` on both
/// sides and every connection, and audits each session as drained.
#[test]
fn shutdown_closes_every_stream_with_drained() {
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
    core.handle(
        Input::Connected {
            conn: a,
            peer: agent,
            hybrid: None,
            certificate: None,
        },
        now,
    );
    core.handle(
        Input::Received {
            conn: a,
            frame: Frame::Register { node: web.clone() },
        },
        now,
    );
    core.handle(
        Input::Connected {
            conn: c,
            peer: client,
            hybrid: None,
            certificate: None,
        },
        now,
    );
    let stream = StreamId::try_from(1).unwrap();
    let out = core.handle(
        Input::Received {
            conn: c,
            frame: Frame::Open {
                stream,
                target: web,
            },
        },
        now,
    );
    let agent_stream = out
        .iter()
        .find_map(|o| match o {
            Output::Send {
                conn,
                frame: Frame::Open { stream, .. },
            } if *conn == a => Some(*stream),
            _ => None,
        })
        .unwrap();
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
    let out = core.handle(Input::Shutdown, now);
    let drained = |conn: ConnId, s: StreamId| {
        out.contains(&Output::Send {
            conn,
            frame: Frame::Close {
                stream: s,
                reason: CloseReason::Drained,
            },
        })
    };
    assert!(drained(c, stream), "{out:?}");
    assert!(drained(a, agent_stream), "{out:?}");
    assert!(out.contains(&Output::Close { conn: a }));
    assert!(out.contains(&Output::Close { conn: c }));
    assert_eq!(
        out.iter()
            .filter(|o| matches!(
                o,
                Output::Audit(DomainEvent::ConnectionDrained {
                    reason: CloseReason::Drained,
                    ..
                })
            ))
            .count(),
        1
    );
    assert_eq!(core.client_stream_count(), 0);
    assert_eq!(core.connection_count(), 0);
}
