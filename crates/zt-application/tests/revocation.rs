//! Revoca a caldo (Fase 4): una nuova policy si applica alle connessioni già aperte.
//!
//! Regola: chi perde il proprio ruolo, o un agent la cui chiave ora appartiene a un altro nodo,
//! viene disconnesso; un client che perde l'accesso a un nodo perde gli stream verso quel nodo
//! (`Close Unauthorized` da entrambi i lati) e conserva gli altri. Ogni revoca è registrata.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::sync::Arc;
use std::time::Instant;

use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthFailureReason, ClientGrant, CloseReason, DomainEvent,
    Fingerprint, Frame, FramePayload, NodeId, SessionId, StreamId,
};

const WEB: u8 = 1;
const DB: u8 = 2;
const ANSIBLE: u8 = 10;
const ADMIN: u8 = 11;

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn sid(n: u32) -> StreamId {
    StreamId::try_from(n).unwrap()
}

struct Counter(u8);
impl SessionIds for Counter {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

/// Policy di partenza: web-01, db-01; ansible → web-01, db-01; admin → tutti.
fn policy(edit: impl FnOnce(&mut Spec)) -> Arc<AccessPolicy> {
    let mut spec = Spec {
        agents: vec![(WEB, "web-01"), (DB, "db-01")],
        clients: vec![
            (ANSIBLE, "ansible", Some(vec!["web-01", "db-01"])),
            (ADMIN, "admin", None),
        ],
    };
    edit(&mut spec);
    let mut p = AccessPolicy::new();
    for (k, n) in &spec.agents {
        p.add_agent(fp(*k), node(n)).unwrap();
    }
    for (k, name, allow) in &spec.clients {
        let allowed = match allow {
            None => AllowedNodes::All,
            Some(list) => AllowedNodes::Only(list.iter().map(|n| node(n)).collect()),
        };
        p.add_client(
            fp(*k),
            ClientGrant {
                name: node(name),
                allowed,
            },
        )
        .unwrap();
    }
    Arc::new(p)
}

struct Spec {
    agents: Vec<(u8, &'static str)>,
    clients: Vec<(u8, &'static str, Option<Vec<&'static str>>)>,
}

struct H {
    core: RelayCore<Counter>,
    now: Instant,
}

impl H {
    /// web-01 (conn 1), db-01 (conn 3); ansible (conn 2) con stream 7 → web-01 e 9 → db-01;
    /// admin (conn 4) con stream 5 → web-01.
    fn fleet() -> (Self, Sessions) {
        let mut h = Self {
            core: RelayCore::new(policy(|_| {}), RelayLimits::default(), Counter(0)),
            now: Instant::now(),
        };
        h.connect(1, WEB);
        h.recv(
            1,
            Frame::Register {
                node: node("web-01"),
            },
        );
        h.connect(3, DB);
        h.recv(
            3,
            Frame::Register {
                node: node("db-01"),
            },
        );
        h.connect(2, ANSIBLE);
        h.connect(4, ADMIN);
        let s = Sessions {
            ansible_web: h.open(2, 7, "web-01", 1),
            ansible_db: h.open(2, 9, "db-01", 3),
            admin_web: h.open(4, 5, "web-01", 1),
        };
        (h, s)
    }
    fn input(&mut self, i: Input) -> Vec<Output> {
        self.core.handle(
            i,
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
    fn update(&mut self, p: Arc<AccessPolicy>) -> Vec<Output> {
        self.input(Input::PolicyUpdated { policy: p })
    }
    /// Apre `stream` dal client `conn` verso `target` servito da `agent`; restituisce lo
    /// stream lato agent.
    fn open(&mut self, conn: u64, stream: u32, target: &str, agent: u64) -> StreamId {
        let out = self.recv(
            conn,
            Frame::Open {
                stream: sid(stream),
                target: node(target),
            },
        );
        let a = sent_to(&out, agent)
            .into_iter()
            .find_map(|f| match f {
                Frame::Open { stream, .. } => Some(stream),
                _ => None,
            })
            .expect("open forwarded");
        self.recv(agent, Frame::OpenAck { stream: a });
        a
    }
}

struct Sessions {
    ansible_web: StreamId,
    ansible_db: StreamId,
    admin_web: StreamId,
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
    let mut v: Vec<u64> = out
        .iter()
        .filter_map(|o| match o {
            Output::Close { conn } => Some(conn.0),
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v
}
fn revoked(out: &[Output]) -> Vec<(Fingerprint, Option<NodeId>)> {
    out.iter()
        .filter_map(|o| match o {
            Output::Audit(DomainEvent::AccessRevoked { peer, target, .. }) => {
                Some((*peer, target.clone()))
            }
            _ => None,
        })
        .collect()
}
fn payload() -> FramePayload {
    FramePayload::try_from(vec![1_u8; 32]).unwrap()
}

#[test]
fn an_identical_policy_changes_nothing() {
    let (mut h, _) = H::fleet();
    let out = h.update(policy(|_| {}));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(h.core.route_count(), 6);
}

#[test]
fn a_client_removed_from_the_policy_is_disconnected_with_all_its_sessions() {
    let (mut h, s) = H::fleet();
    let out = h.update(policy(|p| p.clients.retain(|c| c.0 != ANSIBLE)));
    assert_eq!(closed(&out), vec![2]);
    assert_eq!(revoked(&out), vec![(fp(ANSIBLE), None)]);
    // Gli agent vedono chiudersi gli stream di ansible, non quelli di admin.
    assert!(sent_to(&out, 1).contains(&Frame::Close {
        stream: s.ansible_web,
        reason: CloseReason::PeerGone
    }));
    assert!(sent_to(&out, 3).contains(&Frame::Close {
        stream: s.ansible_db,
        reason: CloseReason::PeerGone
    }));
    assert!(
        !sent_to(&out, 1)
            .iter()
            .any(|f| matches!(f, Frame::Close { stream, .. } if *stream == s.admin_web))
    );
    assert_eq!(h.core.route_count(), 2);
    assert_eq!(h.core.connection_count(), 3);
    // E non può riconnettersi.
    let out = h.connect(20, ANSIBLE);
    assert_eq!(closed(&out), vec![20]);
    assert!(out.iter().any(|o| matches!(
        o,
        Output::Audit(DomainEvent::AuthenticationFailed {
            reason: AuthFailureReason::UnknownPeer,
            ..
        })
    )));
}

#[test]
fn a_narrowed_grant_closes_only_the_streams_it_no_longer_allows() {
    let (mut h, s) = H::fleet();
    let out = h.update(policy(|p| p.clients[0].2 = Some(vec!["web-01"])));
    assert!(closed(&out).is_empty(), "the client keeps its connection");
    assert_eq!(revoked(&out), vec![(fp(ANSIBLE), Some(node("db-01")))]);
    assert_eq!(
        sent_to(&out, 2),
        vec![Frame::Close {
            stream: sid(9),
            reason: CloseReason::Unauthorized
        }]
    );
    assert_eq!(
        sent_to(&out, 3),
        vec![Frame::Close {
            stream: s.ansible_db,
            reason: CloseReason::Unauthorized
        }]
    );
    assert!(sent_to(&out, 1).is_empty());
    assert_eq!(h.core.route_count(), 4);
    // Lo stream verso web-01 funziona ancora; uno nuovo verso db-01 è negato.
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(7),
            payload: payload(),
        },
    );
    assert!(matches!(sent_to(&out, 1).as_slice(), [Frame::Data { .. }]));
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(11),
            target: node("db-01"),
        },
    );
    assert!(matches!(
        sent_to(&out, 2).as_slice(),
        [Frame::Reject { .. }]
    ));
    // I frame in volo sullo stream revocato non sono violazioni.
    let out = h.recv(
        2,
        Frame::Data {
            stream: sid(9),
            payload: payload(),
        },
    );
    assert!(out.is_empty(), "{out:?}");
    let out = h.recv(
        3,
        Frame::Data {
            stream: s.ansible_db,
            payload: payload(),
        },
    );
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_removed_agent_is_disconnected_and_its_clients_see_peer_gone() {
    let (mut h, s) = H::fleet();
    let out = h.update(policy(|p| p.agents.retain(|a| a.0 != WEB)));
    assert_eq!(closed(&out), vec![1]);
    assert_eq!(revoked(&out), vec![(fp(WEB), None)]);
    assert!(sent_to(&out, 2).contains(&Frame::Close {
        stream: sid(7),
        reason: CloseReason::PeerGone
    }));
    assert!(sent_to(&out, 4).contains(&Frame::Close {
        stream: sid(5),
        reason: CloseReason::PeerGone
    }));
    let _ = s;
    // web-01 non è più raggiungibile; db-01 sì.
    let out = h.recv(
        4,
        Frame::Open {
            stream: sid(13),
            target: node("web-01"),
        },
    );
    assert!(matches!(
        sent_to(&out, 4).as_slice(),
        [Frame::Reject { .. }]
    ));
}

#[test]
fn an_agent_key_moved_to_another_node_is_disconnected() {
    // La stessa chiave ora è db-02: la connessione registrata come web-01 non vale più.
    let (mut h, _) = H::fleet();
    let out = h.update(policy(|p| p.agents[0] = (WEB, "web-02")));
    assert_eq!(closed(&out), vec![1]);
    assert_eq!(revoked(&out), vec![(fp(WEB), None)]);
    // Può ricollegarsi e registrarsi con il nuovo nome.
    assert!(h.connect(30, WEB).is_empty());
    let out = h.recv(
        30,
        Frame::Register {
            node: node("web-02"),
        },
    );
    assert!(closed(&out).is_empty());
}

#[test]
fn a_client_key_turned_into_an_agent_key_is_disconnected() {
    let (mut h, _) = H::fleet();
    let out = h.update(policy(|p| {
        p.clients.retain(|c| c.0 != ADMIN);
        p.agents.push((ADMIN, "admin-box"));
    }));
    assert_eq!(closed(&out), vec![4]);
    assert_eq!(revoked(&out), vec![(fp(ADMIN), None)]);
}

#[test]
fn a_key_added_by_the_update_can_connect() {
    let (mut h, _) = H::fleet();
    assert_eq!(closed(&h.connect(40, 77)), vec![40]);
    h.update(policy(|p| p.clients.push((77, "newcomer", None))));
    assert!(h.connect(41, 77).is_empty());
}

#[test]
fn an_unregistered_agent_is_checked_against_the_new_policy_too() {
    let (mut h, _) = H::fleet();
    h.connect(50, 55); // chiave sconosciuta: rifiutata
    h.update(policy(|p| p.agents.push((55, "new-01"))));
    assert!(h.connect(51, 55).is_empty());
    // Revocata prima di registrarsi.
    let out = h.update(policy(|_| {}));
    assert_eq!(closed(&out), vec![51]);
    let out = h.recv(
        51,
        Frame::Register {
            node: node("new-01"),
        },
    );
    assert!(
        out.is_empty(),
        "frames of a revoked connection are ignored: {out:?}"
    );
}
