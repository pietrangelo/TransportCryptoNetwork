//! PQ-AUTH in the relay core (PROTOCOL §7.5.3; findings AP-6, AP-12 of review 0007): the
//! connection carries the hybrid identity its handshake proved (the core sees it only after
//! key confirmation), v2 pins are rechecked on every policy update, a hybrid peer admitted
//! through a v1 entry is reported, and sessions name the hybrid identity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::time::Instant;

use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthFailureReason, ClientGrant, DomainEvent, Fingerprint, Frame,
    HybridFingerprint, NodeId, SessionId, StreamId,
};

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn hfp(b: u8) -> HybridFingerprint {
    HybridFingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

struct Counter(u8);
impl SessionIds for Counter {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

const AGENT: u8 = 1;
const ALICE: u8 = 10;
const BOB: u8 = 11;

fn policy(pin_alice: bool) -> AccessPolicy {
    let mut p = AccessPolicy::new();
    p.add_agent(fp(AGENT), node("web-01")).unwrap();
    for (who, name) in [(ALICE, "alice"), (BOB, "bob")] {
        p.add_client(
            fp(who),
            ClientGrant {
                name: node(name),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
    }
    if pin_alice {
        p.pin_hybrid(fp(ALICE), hfp(ALICE)).unwrap();
    }
    p
}

struct Harness {
    core: RelayCore<Counter>,
}

impl Harness {
    fn new(pin_alice: bool) -> Self {
        Self {
            core: RelayCore::new(Arc::new(policy(pin_alice)), RelayLimits::default(), Counter(0)),
        }
    }
    fn input(&mut self, input: Input) -> Vec<Output> {
        self.core.handle(
            input,
            Now {
                instant: Instant::now(),
                unix: zt_domain::UnixTime::from_secs(1_800_000_000),
            },
        )
    }
    fn connect(&mut self, conn: u64, peer: u8, hybrid: Option<u8>) -> Vec<Output> {
        self.input(Input::Connected {
            conn: ConnId(conn),
            peer: fp(peer),
            hybrid: hybrid.map(hfp),
            certificate: None,
        })
    }
}

fn events(out: &[Output]) -> Vec<&DomainEvent> {
    out.iter()
        .filter_map(|o| match o {
            Output::Audit(e) => Some(e),
            _ => None,
        })
        .collect()
}

fn closed(out: &[Output], conn: u64) -> bool {
    out.iter()
        .any(|o| matches!(o, Output::Close { conn: c } if *c == ConnId(conn)))
}

/// Spec: a v2-pinned client is admitted with its hybrid identity, refused without it
/// (`identity_downgrade`) or with another one.
#[test]
fn the_core_checks_v2_pins() {
    let mut h = Harness::new(true);
    assert!(!closed(&h.connect(1, ALICE, Some(ALICE)), 1));
    for (conn, hybrid) in [(2, None), (3, Some(BOB))] {
        let out = h.connect(conn, ALICE, hybrid);
        assert!(closed(&out, conn));
        assert!(events(&out).iter().any(|e| matches!(
            e,
            DomainEvent::AuthenticationFailed {
                reason: AuthFailureReason::IdentityDowngrade,
                ..
            }
        )));
    }
}

/// Spec (D13 / pq.md §4.6): a hybrid peer admitted by a v1 entry is authenticated only
/// classically: `classical_identity_match` names it, after key confirmation.
#[test]
fn a_hybrid_peer_matched_by_a_v1_entry_is_reported() {
    let mut h = Harness::new(false);
    let out = h.connect(1, BOB, Some(BOB));
    assert!(!closed(&out, 1));
    let found = events(&out)
        .into_iter()
        .find_map(|e| match e {
            DomainEvent::ClassicalIdentityMatch { peer, peer_v2 } => Some((*peer, *peer_v2)),
            _ => None,
        })
        .expect("classical_identity_match");
    assert_eq!(found, (fp(BOB), hfp(BOB)));
    let event = DomainEvent::ClassicalIdentityMatch {
        peer: fp(BOB),
        peer_v2: hfp(BOB),
    };
    assert_eq!(event.kind(), "classical_identity_match");
    // A classical handshake on a v1 entry is the ordinary case: no line.
    let out = h.connect(2, ALICE, None);
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, DomainEvent::ClassicalIdentityMatch { .. }))
    );
}

/// Attack (Downgrade, State): a reload that pins a key in v2 closes its classical
/// connections; its hybrid ones stay.
#[test]
fn a_reload_that_pins_v2_closes_classical_connections() {
    let mut h = Harness::new(false);
    h.connect(1, ALICE, None);
    h.connect(2, ALICE, Some(ALICE));
    let out = h.input(Input::PolicyUpdated {
        policy: Arc::new(policy(true)),
    });
    assert!(closed(&out, 1));
    assert!(!closed(&out, 2));
}

/// Spec: a session names the client's hybrid identity.
#[test]
fn sessions_name_the_hybrid_identity() {
    let mut h = Harness::new(true);
    h.connect(1, AGENT, None);
    h.input(Input::Received {
        conn: ConnId(1),
        frame: Frame::Register {
            node: node("web-01"),
        },
    });
    h.connect(2, ALICE, Some(ALICE));
    let out = h.input(Input::Received {
        conn: ConnId(2),
        frame: Frame::Open {
            stream: StreamId::try_from(1).unwrap(),
            target: node("web-01"),
        },
    });
    let mut agent_stream = None;
    for o in &out {
        if let Output::Send {
            conn,
            frame: Frame::Open { stream, .. },
        } = o
            && *conn == ConnId(1)
        {
            agent_stream = Some(*stream);
        }
    }
    let out = h.input(Input::Received {
        conn: ConnId(1),
        frame: Frame::OpenAck {
            stream: agent_stream.expect("open forwarded"),
        },
    });
    let session = events(&out)
        .into_iter()
        .find_map(|e| match e {
            DomainEvent::SessionEstablished { client_v2, .. } => Some(*client_v2),
            _ => None,
        })
        .expect("session_established");
    assert_eq!(session, Some(hfp(ALICE)));
}
