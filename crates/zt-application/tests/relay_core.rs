//! Specifica e attacchi del relay core (Adversarial TDD, Fase 2).
//!
//! Il relay core è una macchina a stati sans-IO: riceve `Input` e produce `Output`. Questi test
//! ne fissano il comportamento senza rete, orologio reale o casualità.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::panic
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW, MIN_CHARGE};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthFailureReason, ClientGrant, CloseReason, Credit, DomainEvent,
    Fingerprint, Frame, FramePayload, NodeId, RejectReason, SessionId, StreamId,
};

// ---------- fixture ----------

const WEB_AGENT: u8 = 1;
const DB_AGENT: u8 = 2;
const ANSIBLE: u8 = 10;
const ADMIN: u8 = 11;
const STRANGER: u8 = 99;

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn sid(n: u32) -> StreamId {
    StreamId::try_from(n).unwrap()
}
fn data(n: usize) -> FramePayload {
    FramePayload::try_from(vec![0xab; n]).unwrap()
}

struct Counter(u8);
impl SessionIds for Counter {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

struct Harness {
    core: RelayCore<Counter>,
    now: Instant,
}

impl Harness {
    fn new() -> Self {
        Self::with_limits(RelayLimits::default())
    }

    fn with_limits(limits: RelayLimits) -> Self {
        let mut p = AccessPolicy::new();
        p.add_agent(fp(WEB_AGENT), node("web-01")).unwrap();
        p.add_agent(fp(DB_AGENT), node("db-01")).unwrap();
        p.add_client(
            fp(ANSIBLE),
            ClientGrant {
                name: node("ansible"),
                allowed: AllowedNodes::Only([node("web-01")].into_iter().collect()),
            },
        )
        .unwrap();
        p.add_client(
            fp(ADMIN),
            ClientGrant {
                name: node("admin"),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
        Self {
            core: RelayCore::new(Arc::new(p), limits, Counter(0)),
            now: Instant::now(),
        }
    }

    fn input(&mut self, input: Input) -> Vec<Output> {
        self.core.handle(
            input,
            Now {
                instant: self.now,
                unix: zt_domain::UnixTime::from_secs(1_800_000_000),
            },
        )
    }
    fn connect(&mut self, conn: u64, peer: u8) -> Vec<Output> {
        self.input(Input::Connected {
            conn: ConnId(conn),
            peer: fp(peer),
            certificate: None,
        })
    }
    fn recv(&mut self, conn: u64, frame: Frame) -> Vec<Output> {
        self.input(Input::Received {
            conn: ConnId(conn),
            frame,
        })
    }
    fn disconnect(&mut self, conn: u64) -> Vec<Output> {
        self.input(Input::Disconnected { conn: ConnId(conn) })
    }
    fn tick(&mut self, after: Duration) -> Vec<Output> {
        self.now += after;
        self.input(Input::Tick)
    }

    /// Agent `web-01` su conn 1, registrato.
    fn with_web_agent() -> Self {
        let mut h = Self::new();
        assert!(h.connect(1, WEB_AGENT).is_empty());
        h.recv(
            1,
            Frame::Register {
                node: node("web-01"),
            },
        );
        h
    }

    /// Agent web-01 (conn 1) + client ansible (conn 2) con lo stream 7 aperto.
    /// Restituisce lo stream assegnato dal relay sul lato agent.
    fn with_open_session() -> (Self, StreamId) {
        let mut h = Self::with_web_agent();
        h.connect(2, ANSIBLE);
        let out = h.recv(
            2,
            Frame::Open {
                stream: sid(7),
                target: node("web-01"),
            },
        );
        let agent_stream = sent_to(&out, 1)
            .iter()
            .find_map(|f| match f {
                Frame::Open { stream, .. } => Some(*stream),
                _ => None,
            })
            .expect("Open forwarded to the agent");
        h.recv(
            1,
            Frame::OpenAck {
                stream: agent_stream,
            },
        );
        (h, agent_stream)
    }
}

fn sent_to(out: &[Output], conn: u64) -> Vec<Frame> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send { conn: c, frame } if *c == ConnId(conn) => Some(frame.clone()),
            _ => None,
        })
        .collect()
}
fn closed(out: &[Output]) -> Vec<u64> {
    out.iter()
        .filter_map(|o| match o {
            Output::Close { conn } => Some(conn.0),
            _ => None,
        })
        .collect()
}
fn audits(out: &[Output]) -> Vec<DomainEvent> {
    out.iter()
        .filter_map(|o| match o {
            Output::Audit(e) => Some(e.clone()),
            _ => None,
        })
        .collect()
}
fn is_violation_of(out: &[Output], conn: u64) -> bool {
    closed(out) == vec![conn]
        && audits(out)
            .iter()
            .any(|e| matches!(e, DomainEvent::ProtocolViolation { .. }))
}

// ======================= specifica =======================

#[test]
fn agent_registration_is_audited() {
    let mut h = Harness::new();
    assert!(h.connect(1, WEB_AGENT).is_empty());
    let out = h.recv(
        1,
        Frame::Register {
            node: node("web-01"),
        },
    );
    assert_eq!(
        audits(&out),
        vec![DomainEvent::AgentRegistered {
            node: node("web-01"),
            fingerprint: fp(WEB_AGENT)
        }]
    );
    assert!(closed(&out).is_empty());
}

#[test]
fn full_session_lifecycle_is_routed_and_audited() {
    let mut h = Harness::with_web_agent();
    h.connect(2, ANSIBLE);

    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(7),
            target: node("web-01"),
        },
    );
    let opens = sent_to(&out, 1);
    let [Frame::Open { stream: a, target }] = opens.as_slice() else {
        panic!("expected one Open to the agent, got {out:?}")
    };
    assert_eq!(target, &node("web-01"));
    let a = *a;

    let out = h.recv(1, Frame::OpenAck { stream: a });
    assert_eq!(sent_to(&out, 2), vec![Frame::OpenAck { stream: sid(7) }]);
    let session = match audits(&out).as_slice() {
        [
            DomainEvent::SessionEstablished {
                session,
                client,
                target,
                certificate: None,
            },
        ] => {
            assert_eq!(client, &fp(ANSIBLE));
            assert_eq!(target, &node("web-01"));
            *session
        }
        other => panic!("expected SessionEstablished, got {other:?}"),
    };

    // Data nei due sensi, con traduzione degli stream id.
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(7),
            payload: data(1000),
        },
    );
    assert_eq!(
        sent_to(&out, 1),
        vec![Frame::Data {
            stream: a,
            payload: data(1000)
        }]
    );
    let out = h.recv(
        1,
        Frame::Data {
            stream: a,
            payload: data(10),
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Data {
            stream: sid(7),
            payload: data(10)
        }]
    );

    // WindowUpdate inoltrato.
    let credit = Credit::try_from(4096).unwrap();
    let out = h.recv(1, Frame::WindowUpdate { stream: a, credit });
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::WindowUpdate {
            stream: sid(7),
            credit
        }]
    );

    // Chiusura ordinata.
    let out = h.recv(
        2,
        Frame::Close {
            stream: sid(7),
            reason: CloseReason::Normal,
        },
    );
    assert_eq!(
        sent_to(&out, 1),
        vec![Frame::Close {
            stream: a,
            reason: CloseReason::Normal
        }]
    );
    assert_eq!(
        audits(&out),
        vec![DomainEvent::ConnectionDrained {
            session,
            reason: CloseReason::Normal
        }]
    );
    assert_eq!(h.core.route_count(), 0);
}

#[test]
fn agent_reject_is_forwarded_and_frees_the_route() {
    let mut h = Harness::with_web_agent();
    h.connect(2, ANSIBLE);
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    let Some(Frame::Open { stream: a, .. }) = sent_to(&out, 1).pop() else {
        panic!()
    };
    let out = h.recv(
        1,
        Frame::Reject {
            stream: a,
            reason: RejectReason::ResourceExhausted,
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Reject {
            stream: sid(1),
            reason: RejectReason::ResourceExhausted
        }]
    );
    assert_eq!(h.core.route_count(), 0);
}

#[test]
fn ping_is_answered_with_pong() {
    let mut h = Harness::with_web_agent();
    let out = h.recv(1, Frame::Ping { nonce: 77 });
    assert_eq!(sent_to(&out, 1), vec![Frame::Pong { nonce: 77 }]);
}

#[test]
fn offline_node_is_rejected() {
    let mut h = Harness::new();
    h.connect(2, ANSIBLE);
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Reject {
            stream: sid(1),
            reason: RejectReason::NodeOffline
        }]
    );
}

#[test]
fn agent_disconnect_closes_its_streams_on_the_client_side() {
    let (mut h, _) = Harness::with_open_session();
    let out = h.disconnect(1);
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Close {
            stream: sid(7),
            reason: CloseReason::PeerGone
        }]
    );
    assert!(
        audits(&out)
            .iter()
            .any(|e| matches!(e, DomainEvent::ConnectionDrained { .. }))
    );
    assert_eq!(h.core.route_count(), 0);
    // Il nodo ora è offline.
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(8),
            target: node("web-01"),
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Reject {
            stream: sid(8),
            reason: RejectReason::NodeOffline
        }]
    );
}

#[test]
fn client_disconnect_closes_its_streams_on_the_agent_side() {
    let (mut h, a) = Harness::with_open_session();
    let out = h.disconnect(2);
    assert_eq!(
        sent_to(&out, 1),
        vec![Frame::Close {
            stream: a,
            reason: CloseReason::PeerGone
        }]
    );
    assert_eq!(h.core.route_count(), 0);
}

#[test]
fn reconnecting_agent_replaces_the_previous_connection() {
    let (mut h, _) = Harness::with_open_session();
    h.connect(3, WEB_AGENT);
    let out = h.recv(
        3,
        Frame::Register {
            node: node("web-01"),
        },
    );
    assert_eq!(closed(&out), vec![1], "old agent connection drained");
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Close {
            stream: sid(7),
            reason: CloseReason::PeerGone
        }]
    );
    // I nuovi stream vanno sulla nuova connessione.
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(9),
            target: node("web-01"),
        },
    );
    assert_eq!(sent_to(&out, 3).len(), 1);
}

// ======================= attacchi: identità e ruoli =======================

#[test]
fn unknown_key_is_dropped_and_audited() {
    let mut h = Harness::new();
    let out = h.connect(5, STRANGER);
    assert_eq!(closed(&out), vec![5]);
    assert_eq!(
        audits(&out),
        vec![DomainEvent::AuthenticationFailed {
            peer: Some(fp(STRANGER)),
            reason: AuthFailureReason::UnknownPeer
        }]
    );
}

#[test]
fn agent_cannot_register_as_another_node() {
    let mut h = Harness::new();
    h.connect(1, WEB_AGENT);
    let out = h.recv(
        1,
        Frame::Register {
            node: node("db-01"),
        },
    );
    assert_eq!(closed(&out), vec![1]);
    assert!(audits(&out).iter().any(|e| matches!(
        e,
        DomainEvent::AuthenticationFailed {
            reason: AuthFailureReason::NodeIdMismatch,
            ..
        }
    )));
}

#[test]
fn agent_cannot_register_twice() {
    let mut h = Harness::with_web_agent();
    let out = h.recv(
        1,
        Frame::Register {
            node: node("web-01"),
        },
    );
    assert!(is_violation_of(&out, 1));
}

#[test]
fn agent_cannot_open_streams() {
    let mut h = Harness::with_web_agent();
    let out = h.recv(
        1,
        Frame::Open {
            stream: sid(1),
            target: node("db-01"),
        },
    );
    assert!(is_violation_of(&out, 1));
}

#[test]
fn unregistered_agent_may_only_ping() {
    let mut h = Harness::new();
    h.connect(1, WEB_AGENT);
    let out = h.recv(1, Frame::Ping { nonce: 1 });
    assert_eq!(sent_to(&out, 1), vec![Frame::Pong { nonce: 1 }]);
    let out = h.recv(1, Frame::OpenAck { stream: sid(1) });
    assert!(is_violation_of(&out, 1));
}

#[test]
fn agent_that_never_registers_is_dropped() {
    let mut h = Harness::new();
    h.connect(1, WEB_AGENT);
    assert!(h.tick(Duration::from_secs(1)).is_empty());
    let out = h.tick(RelayLimits::default().register_timeout);
    assert_eq!(closed(&out), vec![1]);
}

#[test]
fn client_cannot_register() {
    let mut h = Harness::new();
    h.connect(2, ADMIN);
    let out = h.recv(
        2,
        Frame::Register {
            node: node("web-01"),
        },
    );
    assert!(is_violation_of(&out, 2));
}

#[test]
fn unauthorized_and_nonexistent_nodes_are_indistinguishable() {
    let mut h = Harness::with_web_agent();
    h.connect(4, DB_AGENT);
    h.recv(
        4,
        Frame::Register {
            node: node("db-01"),
        },
    );
    h.connect(2, ANSIBLE);
    // db-01 esiste ed è online ma non è concesso; ghost non esiste.
    let denied = h.recv(
        2,
        Frame::Open {
            stream: sid(1),
            target: node("db-01"),
        },
    );
    let ghost = h.recv(
        2,
        Frame::Open {
            stream: sid(2),
            target: node("ghost"),
        },
    );
    assert_eq!(
        sent_to(&denied, 2),
        vec![Frame::Reject {
            stream: sid(1),
            reason: RejectReason::NotAuthorized
        }]
    );
    assert_eq!(
        sent_to(&ghost, 2),
        vec![Frame::Reject {
            stream: sid(2),
            reason: RejectReason::NotAuthorized
        }]
    );
    assert!(
        sent_to(&denied, 4).is_empty(),
        "nothing reaches the protected agent"
    );
    assert!(
        audits(&denied)
            .iter()
            .any(|e| matches!(e, DomainEvent::AccessDenied { .. }))
    );
}

// ======================= attacchi: stato degli stream =======================

#[test]
fn reusing_an_open_stream_id_is_a_violation() {
    let (mut h, _) = Harness::with_open_session();
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(7),
            target: node("web-01"),
        },
    );
    assert!(is_violation_of(&out, 2));
}

#[test]
fn stream_limit_per_client_is_enforced() {
    let limits = RelayLimits {
        max_streams_per_client: 2,
        ..RelayLimits::default()
    };
    let mut h = Harness::with_limits(limits);
    h.connect(1, WEB_AGENT);
    h.recv(
        1,
        Frame::Register {
            node: node("web-01"),
        },
    );
    h.connect(2, ADMIN);
    h.recv(
        2,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    h.recv(
        2,
        Frame::Open {
            stream: sid(2),
            target: node("web-01"),
        },
    );
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(3),
            target: node("web-01"),
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Reject {
            stream: sid(3),
            reason: RejectReason::ResourceExhausted
        }]
    );
}

#[test]
fn stream_limit_per_agent_is_enforced() {
    let limits = RelayLimits {
        max_streams_per_agent: 1,
        ..RelayLimits::default()
    };
    let mut h = Harness::with_limits(limits);
    h.connect(1, WEB_AGENT);
    h.recv(
        1,
        Frame::Register {
            node: node("web-01"),
        },
    );
    h.connect(2, ADMIN);
    h.connect(3, ANSIBLE);
    h.recv(
        2,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    let out = h.recv(
        3,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    assert_eq!(
        sent_to(&out, 3),
        vec![Frame::Reject {
            stream: sid(1),
            reason: RejectReason::ResourceExhausted
        }]
    );
}

#[test]
fn data_on_unknown_or_unacknowledged_streams_is_a_violation() {
    let mut h = Harness::with_web_agent();
    h.connect(2, ANSIBLE);
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(3),
            payload: data(1),
        },
    );
    assert!(is_violation_of(&out, 2));

    let mut h = Harness::with_web_agent();
    h.connect(2, ANSIBLE);
    h.recv(
        2,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(1),
            payload: data(1),
        },
    );
    assert!(is_violation_of(&out, 2), "data before OpenAck");
}

#[test]
fn agent_cannot_ack_unknown_streams_or_ack_twice() {
    let (mut h, a) = Harness::with_open_session();
    let out = h.recv(1, Frame::OpenAck { stream: a });
    assert!(is_violation_of(&out, 1), "double ack");
    let (mut h, _) = Harness::with_open_session();
    let out = h.recv(1, Frame::OpenAck { stream: sid(999) });
    assert!(is_violation_of(&out, 1), "unknown stream");
}

#[test]
fn agent_cannot_inject_into_streams_it_does_not_own() {
    let (mut h, _) = Harness::with_open_session();
    // Un secondo agent (db-01) prova a scrivere sullo stream di web-01.
    h.connect(4, DB_AGENT);
    h.recv(
        4,
        Frame::Register {
            node: node("db-01"),
        },
    );
    let out = h.recv(
        4,
        Frame::Data {
            stream: sid(1),
            payload: data(8),
        },
    );
    assert!(is_violation_of(&out, 4));
    assert!(sent_to(&out, 2).is_empty());
}

// ======================= attacchi: risorse =======================

#[test]
fn data_beyond_the_window_kills_the_sender() {
    let (mut h, a) = Harness::with_open_session();
    let chunk = 60 * 1024;
    let mut sent = 0_u32;
    loop {
        let out = h.recv(
            2,
            Frame::Data {
                stream: sid(7),
                payload: data(chunk),
            },
        );
        if closed(&out).contains(&2) {
            assert!(is_violation_of(&out, 2));
            assert_eq!(
                sent_to(&out, 1),
                vec![Frame::Close {
                    stream: a,
                    reason: CloseReason::PeerGone
                }]
            );
            break;
        }
        sent += u32::try_from(chunk).unwrap();
        assert!(sent <= INITIAL_WINDOW, "relay forwarded beyond the window");
    }
    assert_eq!(h.core.route_count(), 0);
}

#[test]
fn tiny_frames_pay_the_minimum_charge() {
    let (mut h, _) = Harness::with_open_session();
    let allowed = INITIAL_WINDOW / MIN_CHARGE;
    for i in 0..allowed {
        let out = h.recv(
            2,
            Frame::Data {
                stream: sid(7),
                payload: data(1),
            },
        );
        assert!(closed(&out).is_empty(), "frame {i} wrongly rejected");
    }
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(7),
            payload: data(1),
        },
    );
    assert!(is_violation_of(&out, 2));
}

#[test]
fn window_updates_restore_credit() {
    let (mut h, a) = Harness::with_open_session();
    let chunk = 60 * 1024;
    for _ in 0..4 {
        assert!(
            closed(&h.recv(
                2,
                Frame::Data {
                    stream: sid(7),
                    payload: data(chunk)
                }
            ))
            .is_empty()
        );
    }
    // 240 KiB consumati: l'agent restituisce credito e il client può proseguire.
    let credit = Credit::try_from(u32::try_from(4 * chunk).unwrap()).unwrap();
    h.recv(1, Frame::WindowUpdate { stream: a, credit });
    for _ in 0..4 {
        assert!(
            closed(&h.recv(
                2,
                Frame::Data {
                    stream: sid(7),
                    payload: data(chunk)
                }
            ))
            .is_empty()
        );
    }
}

#[test]
fn tiny_or_overflowing_window_updates_are_violations() {
    let (mut h, a) = Harness::with_open_session();
    let out = h.recv(
        1,
        Frame::WindowUpdate {
            stream: a,
            credit: Credit::try_from(1).unwrap(),
        },
    );
    assert!(is_violation_of(&out, 1), "below minimum");

    let (mut h, a) = Harness::with_open_session();
    let out = h.recv(
        1,
        Frame::WindowUpdate {
            stream: a,
            credit: Credit::try_from(MAX_WINDOW).unwrap(),
        },
    );
    assert!(is_violation_of(&out, 1), "beyond maximum");
}

#[test]
fn ping_flood_is_a_violation() {
    let mut h = Harness::with_web_agent();
    let burst = RelayLimits::default().ping_burst;
    for n in 0..u64::from(burst) {
        assert_eq!(sent_to(&h.recv(1, Frame::Ping { nonce: n }), 1).len(), 1);
    }
    let out = h.recv(1, Frame::Ping { nonce: 999 });
    assert!(is_violation_of(&out, 1));
}

#[test]
fn pings_are_allowed_again_after_the_bucket_refills() {
    let mut h = Harness::with_web_agent();
    let burst = RelayLimits::default().ping_burst;
    for n in 0..u64::from(burst) {
        h.recv(1, Frame::Ping { nonce: n });
    }
    h.now += Duration::from_secs(60);
    assert_eq!(sent_to(&h.recv(1, Frame::Ping { nonce: 1 }), 1).len(), 1);
}

#[test]
fn unsolicited_pong_is_a_violation() {
    let mut h = Harness::with_web_agent();
    let out = h.recv(1, Frame::Pong { nonce: 1 });
    assert!(is_violation_of(&out, 1));
}

// ======================= robustezza =======================

#[test]
fn events_for_unknown_or_closed_connections_are_ignored() {
    let mut h = Harness::new();
    assert!(h.disconnect(42).is_empty());
    assert!(h.recv(42, Frame::Ping { nonce: 1 }).is_empty());
    let (mut h, _) = Harness::with_open_session();
    h.disconnect(2);
    assert!(h.disconnect(2).is_empty(), "double disconnect");
    assert!(
        h.recv(2, Frame::Ping { nonce: 1 }).is_empty(),
        "frame after disconnect"
    );
}

#[test]
fn nothing_leaks_after_everyone_leaves() {
    let (mut h, _) = Harness::with_open_session();
    h.connect(3, ADMIN);
    h.recv(
        3,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    h.disconnect(1);
    h.disconnect(2);
    h.disconnect(3);
    assert_eq!(h.core.route_count(), 0);
    assert_eq!(h.core.connection_count(), 0);
}

// ======================= regressioni dell'adversary review 0002 =======================

/// Seconda sessione innocente: admin (conn 3) → web-01. Restituisce lo stream lato agent.
fn add_innocent_session(h: &mut Harness) -> StreamId {
    h.connect(3, ADMIN);
    let out = h.recv(
        3,
        Frame::Open {
            stream: sid(1),
            target: node("web-01"),
        },
    );
    let a = sent_to(&out, 1)
        .iter()
        .find_map(|f| match f {
            Frame::Open { stream, .. } => Some(*stream),
            _ => None,
        })
        .unwrap();
    h.recv(1, Frame::OpenAck { stream: a });
    a
}

fn untouched(out: &[Output]) -> bool {
    closed(out).is_empty() && out.iter().all(|o| !matches!(o, Output::Send { .. }))
}

/// Finding 0002-1/2: un `Close` incrociato è normale e non deve far cadere l'agent.
#[test]
fn crossing_close_is_dropped_silently() {
    let (mut h, a) = Harness::with_open_session();
    add_innocent_session(&mut h);
    h.recv(
        2,
        Frame::Close {
            stream: sid(7),
            reason: CloseReason::Normal,
        },
    );
    let out = h.recv(
        1,
        Frame::Close {
            stream: a,
            reason: CloseReason::Timeout,
        },
    );
    assert!(untouched(&out), "{out:?}");
}

/// Finding 0002-2: dati o credito dell'agent in volo dopo la chiusura del client.
#[test]
fn agent_frames_in_flight_after_client_close_are_dropped() {
    let (mut h, a) = Harness::with_open_session();
    add_innocent_session(&mut h);
    h.recv(
        2,
        Frame::Close {
            stream: sid(7),
            reason: CloseReason::Normal,
        },
    );
    let credit = Credit::try_from(4096).unwrap();
    for frame in [
        Frame::Data {
            stream: a,
            payload: data(100),
        },
        Frame::WindowUpdate { stream: a, credit },
    ] {
        let out = h.recv(1, frame);
        assert!(untouched(&out), "{out:?}");
    }
}

/// Finding 0002-2: `Open` seguito da `Close` prima dell'`OpenAck`.
#[test]
fn late_open_ack_or_reject_after_client_close_is_dropped() {
    for late in [true, false] {
        let mut h = Harness::with_web_agent();
        add_innocent_session(&mut h);
        h.connect(2, ANSIBLE);
        let out = h.recv(
            2,
            Frame::Open {
                stream: sid(9),
                target: node("web-01"),
            },
        );
        let Some(Frame::Open { stream: a, .. }) = sent_to(&out, 1).pop() else {
            panic!()
        };
        h.recv(
            2,
            Frame::Close {
                stream: sid(9),
                reason: CloseReason::Normal,
            },
        );
        let frame = if late {
            Frame::OpenAck { stream: a }
        } else {
            Frame::Reject {
                stream: a,
                reason: RejectReason::ResourceExhausted,
            }
        };
        assert!(untouched(&h.recv(1, frame)));
    }
}

/// Finding 0002-6: dati del client in volo dopo la chiusura dell'agent.
#[test]
fn client_frames_in_flight_after_agent_close_are_dropped() {
    let (mut h, a) = Harness::with_open_session();
    h.recv(
        1,
        Frame::Close {
            stream: a,
            reason: CloseReason::Normal,
        },
    );
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(7),
            payload: data(100),
        },
    );
    assert!(untouched(&out), "{out:?}");
    // Lo stesso id può poi essere riaperto.
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(7),
            target: node("web-01"),
        },
    );
    assert_eq!(sent_to(&out, 1).len(), 1);
}

/// Il perdono vale solo per stream davvero esistiti: id mai aperti restano violazioni.
#[test]
fn frames_on_never_opened_streams_are_still_violations() {
    let (mut h, _) = Harness::with_open_session();
    assert!(is_violation_of(
        &h.recv(
            1,
            Frame::Data {
                stream: sid(999),
                payload: data(1)
            }
        ),
        1
    ));
    let (mut h, _) = Harness::with_open_session();
    assert!(is_violation_of(
        &h.recv(
            2,
            Frame::Data {
                stream: sid(8),
                payload: data(1)
            }
        ),
        2
    ));
}

/// Finding 0002-4: un flood di `Open`/`Close` non arriva all'agent oltre il rate concesso.
#[test]
fn open_floods_are_rate_limited() {
    let mut h = Harness::with_web_agent();
    h.connect(2, ANSIBLE);
    let limits = RelayLimits::default();
    let mut forwarded = 0_u32;
    let mut rate_limited = 0_u32;
    for i in 0..10_000_u32 {
        let s = sid(1 + (i % 4));
        let mut out = h.recv(
            2,
            Frame::Open {
                stream: s,
                target: node("web-01"),
            },
        );
        out.extend(h.recv(
            2,
            Frame::Close {
                stream: s,
                reason: CloseReason::Normal,
            },
        ));
        if sent_to(&out, 2).contains(&Frame::Reject {
            stream: s,
            reason: RejectReason::RateLimited,
        }) {
            rate_limited += 1;
        }
        forwarded += u32::try_from(
            sent_to(&out, 1)
                .iter()
                .filter(|f| matches!(f, Frame::Open { .. }))
                .count(),
        )
        .unwrap();
    }
    assert!(
        forwarded <= limits.open_burst,
        "{forwarded} opens reached the agent"
    );
    assert!(rate_limited > 9_000);
}
