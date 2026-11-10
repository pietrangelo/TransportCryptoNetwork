//! R-2 specification and attack: duplicate agents (a cloned VM with the same key) take the
//! node from each other; the relay reports it as `agent_flapping` without blocking anyone
//! (resilience.md §5.2, catalogue R2-L6).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use zt_application::flapping::{FlapConfig, FlapDetector};
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::{AccessPolicy, DomainEvent, Fingerprint, Frame, NodeId, SessionId};

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

#[test]
fn takeovers_above_the_threshold_within_the_window_are_reported_once_per_window() {
    let t0 = Instant::now();
    let mut f = FlapDetector::new(FlapConfig {
        window: Duration::from_secs(60),
        threshold: 3,
    });
    let web = node("web-01");
    assert_eq!(f.on_takeover(&web, t0), None);
    assert_eq!(f.on_takeover(&web, t0 + Duration::from_secs(1)), None);
    assert_eq!(f.on_takeover(&web, t0 + Duration::from_secs(2)), Some(3));
    // Reported, then quiet until the window has passed (no log flood).
    for k in 3..50 {
        assert_eq!(f.on_takeover(&web, t0 + Duration::from_secs(k)), None);
    }
    let later = f.on_takeover(&web, t0 + Duration::from_secs(63));
    assert!(later.is_some_and(|n| n >= 3), "{later:?}");
    // Another node is counted separately.
    assert_eq!(f.on_takeover(&node("db-01"), t0), None);
}

#[test]
fn takeovers_spread_beyond_the_window_are_not_flapping() {
    let t0 = Instant::now();
    let mut f = FlapDetector::new(FlapConfig::default());
    let web = node("web-01");
    for k in 0..20 {
        assert_eq!(f.on_takeover(&web, t0 + Duration::from_secs(k * 120)), None);
    }
}

struct Ids(u8);
impl SessionIds for Ids {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

/// Two connections with the same agent key alternate: every registration still succeeds (no
/// lockout, whoever holds the key could use one to deny service) and the relay audits
/// `agent_flapping` with the node and the count.
#[test]
fn duplicate_agents_are_reported() {
    let agent = Fingerprint::from_bytes([1; 32]);
    let mut policy = AccessPolicy::new();
    policy.add_agent(agent, node("web-01")).unwrap();
    let mut core = RelayCore::new(Arc::new(policy), RelayLimits::default(), Ids(0));
    let t0 = Instant::now();
    let mut flapping = Vec::new();
    let mut registered = 0;
    for k in 0..6_u64 {
        let now = Now {
            instant: t0 + Duration::from_secs(k),
            unix: zt_domain::UnixTime::from_secs(1_800_000_000 + k),
        };
        let conn = ConnId(k + 1);
        core.handle(
            Input::Connected {
                conn,
                peer: agent,
                hybrid: None,
                certificate: None,
            },
            now,
        );
        for out in core.handle(
            Input::Received {
                conn,
                frame: Frame::Register {
                    node: node("web-01"),
                },
            },
            now,
        ) {
            match out {
                Output::Audit(DomainEvent::AgentRegistered { .. }) => registered += 1,
                Output::Audit(e @ DomainEvent::AgentFlapping { .. }) => flapping.push(e),
                _ => {}
            }
        }
    }
    assert_eq!(registered, 6, "a flapping agent is never locked out");
    assert_eq!(flapping.len(), 1, "{flapping:?}");
    let DomainEvent::AgentFlapping {
        node: n,
        count,
        fingerprint,
    } = &flapping[0]
    else {
        unreachable!()
    };
    assert_eq!(n, &node("web-01"));
    assert_eq!(*fingerprint, agent);
    assert!(*count >= 3);
    assert_eq!(flapping[0].kind(), "agent_flapping");
    assert!(flapping[0].is_security_alert());
}
