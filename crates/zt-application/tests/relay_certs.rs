//! Fase 6, passo 6: il relay core con i client certificati (PROTOCOL §15.4 ricontrollo nel
//! core, §15.5, §15.7 scadenza in sessione, §15.8 revoca alla ricarica).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::trust::{CertTrust, Revocations, TrustedCaKey};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthFailureReason, CertBody, CertClaims, CertKey, CertRejection,
    CertScope, CertSerial, ClientGrant, CloseReason, DomainEvent, Fingerprint, Frame, NodeId,
    RejectReason, SessionId, StreamId, UnixTime,
};

// ---------- fixture ----------

const WEB_AGENT: u8 = 1;
const DB_AGENT: u8 = 2;
const ANSIBLE: u8 = 10;
const ALICE: u8 = 50;
const BOB: u8 = 51;
const CA: u8 = 0xa1;

const NB: u64 = 1_800_000_000;
const NA: u64 = NB + 3_600;
const START: u64 = NB + 60;
const EIGHT_HOURS: u64 = 8 * 3_600;

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn sid(n: u32) -> StreamId {
    StreamId::try_from(n).unwrap()
}
fn nodes(list: &[&str]) -> BTreeSet<NodeId> {
    list.iter().map(|n| node(n)).collect()
}

/// Claims «verificate» di un certificato della CA per `subject`.
fn claims_with(subject: u8, list: &[&str], nb: u64, na: u64) -> Arc<CertClaims> {
    let body = CertBody::new(
        CertKey::from_bytes([CA; 32]),
        CertKey::from_bytes([subject; 32]),
        CertSerial::try_from([subject; 16]).unwrap(),
        UnixTime::from_secs(nb),
        UnixTime::from_secs(na),
        node("alice"),
        CertScope::Only(nodes(list)),
    )
    .unwrap();
    Arc::new(CertClaims::from_verified(body, fp(CA), fp(subject)))
}
fn claims(subject: u8, list: &[&str]) -> Arc<CertClaims> {
    claims_with(subject, list, NB, NA)
}

/// Come è configurata la CA in una versione della policy.
#[derive(Clone)]
struct Ca {
    present: bool,
    allow: AllowedNodes,
    max_lifetime: u64,
    serials: Vec<u8>,
    keys: Vec<u8>,
}

impl Default for Ca {
    fn default() -> Self {
        Self {
            present: true,
            allow: AllowedNodes::Only(nodes(&["web-01", "db-01"])),
            max_lifetime: EIGHT_HOURS,
            serials: Vec::new(),
            keys: Vec::new(),
        }
    }
}

/// Agent web-01 e db-01, `ansible` nella whitelist (web-01, db-01), la CA come indicato.
fn policy(ca: &Ca) -> Arc<AccessPolicy> {
    let mut p = AccessPolicy::new();
    p.add_agent(fp(WEB_AGENT), node("web-01")).unwrap();
    p.add_agent(fp(DB_AGENT), node("db-01")).unwrap();
    p.add_client(
        fp(ANSIBLE),
        ClientGrant {
            name: node("ansible"),
            allowed: AllowedNodes::Only(nodes(&["web-01", "db-01"])),
        },
    )
    .unwrap();
    let mut t = CertTrust::new();
    if ca.present {
        t.add_authority(
            node("ops-ca"),
            &[TrustedCaKey {
                key: CertKey::from_bytes([CA; 32]),
                fingerprint: fp(CA),
            }],
            ca.allow.clone(),
            ca.max_lifetime,
        )
        .unwrap();
    }
    let serials = ca
        .serials
        .iter()
        .map(|b| CertSerial::try_from([*b; 16]).unwrap());
    let keys = ca.keys.iter().map(|b| fp(*b));
    t.set_revocations(Revocations::new(serials, keys).unwrap());
    p.set_cert_trust(t).unwrap();
    Arc::new(p)
}

struct Counter(u8);
impl SessionIds for Counter {
    fn next_session_id(&mut self) -> SessionId {
        self.0 = self.0.wrapping_add(1).max(1);
        SessionId::from_bytes([self.0; 16]).unwrap()
    }
}

struct H {
    core: RelayCore<Counter>,
    instant: Instant,
    unix: u64,
}

impl H {
    /// Agent web-01 (conn 1) e db-01 (conn 3) registrati.
    fn new() -> Self {
        let mut h = Self {
            core: RelayCore::new(policy(&Ca::default()), RelayLimits::default(), Counter(0)),
            instant: Instant::now(),
            unix: START,
        };
        for (conn, peer, name) in [(1, WEB_AGENT, "web-01"), (3, DB_AGENT, "db-01")] {
            assert!(h.connect(conn, peer, None).is_empty());
            h.recv(conn, Frame::Register { node: node(name) });
        }
        h
    }
    fn input(&mut self, input: Input) -> Vec<Output> {
        self.core.handle(
            input,
            Now {
                instant: self.instant,
                unix: UnixTime::from_secs(self.unix),
            },
        )
    }
    fn connect(&mut self, conn: u64, peer: u8, cert: Option<Arc<CertClaims>>) -> Vec<Output> {
        self.input(Input::Connected {
            conn: ConnId(conn),
            peer: fp(peer),
            certificate: cert,
        })
    }
    fn recv(&mut self, conn: u64, frame: Frame) -> Vec<Output> {
        self.input(Input::Received {
            conn: ConnId(conn),
            frame,
        })
    }
    fn tick_at(&mut self, unix: u64) -> Vec<Output> {
        self.unix = unix;
        self.input(Input::Tick)
    }
    fn reload(&mut self, ca: &Ca) -> Vec<Output> {
        self.input(Input::PolicyUpdated { policy: policy(ca) })
    }
    /// Apre `stream` da `conn` verso `target` (servito da `agent`) e conferma: restituisce lo
    /// stream lato agent e le uscite dell'`OpenAck`.
    fn open(
        &mut self,
        conn: u64,
        stream: u32,
        target: &str,
        agent: u64,
    ) -> (StreamId, Vec<Output>) {
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
            .unwrap_or_else(|| panic!("open to {target} not forwarded: {out:?}"));
        let ack = self.recv(agent, Frame::OpenAck { stream: a });
        (a, ack)
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
fn audits(out: &[Output]) -> Vec<DomainEvent> {
    out.iter()
        .filter_map(|o| match o {
            Output::Audit(e) => Some(e.clone()),
            _ => None,
        })
        .collect()
}
fn unauthorized(stream: StreamId) -> Frame {
    Frame::Close {
        stream,
        reason: CloseReason::Unauthorized,
    }
}
fn refused_with(out: &[Output], peer: u8, rejection: CertRejection) {
    // Finding 0006-3: un rifiuto dopo la firma (passi 7–12) riporta il certificato, uno
    // precedente mai.
    assert!(
        audits(out).iter().any(|e| matches!(
            e,
            DomainEvent::AuthenticationFailed {
                peer: Some(p),
                reason: AuthFailureReason::Certificate(r),
                certificate,
            } if *p == fp(peer)
                && *r == rejection
                && certificate.is_some() == rejection.after_signature()
        )),
        "expected {rejection:?}: {out:?}"
    );
    assert_eq!(closed(out), [7], "{out:?}");
}

// ======================= specifica =======================

#[test]
fn a_certified_client_opens_streams_within_its_effective_scope() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01"]);
    let out = h.connect(2, ALICE, Some(Arc::clone(&alice)));
    assert!(closed(&out).is_empty(), "{out:?}");
    assert_eq!(h.core.connection_count(), 3);
    let (_, ack) = h.open(2, 7, "web-01", 1);
    assert_eq!(sent_to(&ack, 2), [Frame::OpenAck { stream: sid(7) }]);
    // db-01 è nella CA ma non nel certificato.
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(9),
            target: node("db-01"),
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        [Frame::Reject {
            stream: sid(9),
            reason: RejectReason::NotAuthorized
        }]
    );
    assert!(sent_to(&out, 3).is_empty());
    assert_eq!(
        audits(&out),
        [DomainEvent::AccessDenied {
            client: fp(ALICE),
            target: node("db-01"),
            certificate: Some(alice.reference()),
        }]
    );
}

#[test]
fn session_established_carries_the_certificate_reference() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    let (_, ack) = h.open(2, 7, "web-01", 1);
    match audits(&ack).as_slice() {
        [
            DomainEvent::SessionEstablished {
                client,
                target,
                certificate,
                ..
            },
        ] => {
            assert_eq!(client, &fp(ALICE));
            assert_eq!(target, &node("web-01"));
            assert_eq!(certificate.as_ref(), Some(&alice.reference()));
        }
        other => panic!("expected SessionEstablished, got {other:?}"),
    }
    // La whitelist non porta un certificato, anche se il client ne ha presentato uno valido.
    h.connect(4, ANSIBLE, Some(claims(ANSIBLE, &["web-01"])));
    let (_, ack) = h.open(4, 7, "web-01", 1);
    assert!(matches!(
        audits(&ack).as_slice(),
        [DomainEvent::SessionEstablished {
            certificate: None,
            ..
        }]
    ));
}

#[test]
fn a_certified_connection_closes_at_not_after() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01", "db-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    let (web, _) = h.open(2, 7, "web-01", 1);
    let (db, _) = h.open(2, 9, "db-01", 3);
    assert_eq!(h.core.route_count(), 4);
    // Un secondo prima: niente.
    let out = h.tick_at(NA - 1);
    assert!(out.is_empty(), "{out:?}");
    // Alla scadenza: Close Unauthorized a entrambi i lati di ogni stream, poi la connessione.
    let out = h.tick_at(NA);
    let mut to_client = sent_to(&out, 2);
    to_client.sort_by_key(|f| f.stream().map(StreamId::get));
    assert_eq!(to_client, [unauthorized(sid(7)), unauthorized(sid(9))]);
    assert_eq!(sent_to(&out, 1), [unauthorized(web)]);
    assert_eq!(sent_to(&out, 3), [unauthorized(db)]);
    let events = audits(&out);
    let drained = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                DomainEvent::ConnectionDrained {
                    reason: CloseReason::Unauthorized,
                    ..
                }
            )
        })
        .count();
    assert_eq!(drained, 2, "{events:?}");
    assert!(events.contains(&DomainEvent::CertificateExpired {
        peer: fp(ALICE),
        certificate: alice.reference(),
    }));
    assert_eq!(closed(&out), [2]);
    assert_eq!(h.core.route_count(), 0);
    assert_eq!(h.core.connection_count(), 2, "only the agents remain");
    // Una volta sola.
    assert!(h.tick_at(NA + 1).is_empty());
}

#[test]
fn a_whitelisted_client_never_expires() {
    let mut h = H::new();
    // `ansible` è nella whitelist e presenta anche un certificato valido: vale la whitelist.
    h.connect(2, ANSIBLE, Some(claims(ANSIBLE, &["web-01"])));
    h.open(2, 7, "web-01", 1);
    h.connect(4, ANSIBLE, None);
    h.open(4, 7, "web-01", 1);
    for unix in [NA - 1, NA, NA + 1, NA + 10 * EIGHT_HOURS, u64::MAX] {
        let out = h.tick_at(unix);
        assert!(out.is_empty(), "at {unix}: {out:?}");
    }
    assert_eq!(h.core.route_count(), 4);
}

// ======================= attacchi =======================

#[test]
fn expiry_follows_wall_time_not_monotonic_time() {
    let mut h = H::new();
    h.connect(2, ALICE, Some(claims(ALICE, &["web-01"])));
    h.open(2, 7, "web-01", 1);
    // L'orologio monotono non si muove (VM sospesa, test): conta solo quello di sistema.
    let frozen = h.instant;
    let out = h.tick_at(NA + 3_600);
    assert_eq!(h.instant, frozen);
    assert_eq!(closed(&out), [2], "{out:?}");
    // Ogni input porta l'orologio: anche un frame dopo la scadenza non passa.
    let mut h = H::new();
    h.connect(2, ALICE, Some(claims(ALICE, &["web-01"])));
    h.unix = NA;
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(7),
            target: node("web-01"),
        },
    );
    assert!(sent_to(&out, 1).is_empty(), "opened after expiry: {out:?}");
}

#[test]
fn a_certificate_already_expired_when_it_reaches_the_core_is_refused() {
    let mut h = H::new();
    h.unix = NA;
    let out = h.connect(7, ALICE, Some(claims(ALICE, &["web-01"])));
    refused_with(&out, ALICE, CertRejection::Expired);
    // E uno non ancora valido oltre la tolleranza.
    let mut h = H::new();
    h.unix = NB - 121;
    let out = h.connect(7, ALICE, Some(claims(ALICE, &["web-01"])));
    refused_with(&out, ALICE, CertRejection::NotYetValid);
    // Controllo: entro la tolleranza passa.
    let mut h = H::new();
    h.unix = NB - 120;
    assert!(closed(&h.connect(7, ALICE, Some(claims(ALICE, &["web-01"])))).is_empty());
}

#[test]
fn a_connection_racing_a_reload_that_removes_its_authority_is_refused() {
    let mut h = H::new();
    // Il task di rete ha verificato il certificato con la policy vecchia; la ricarica arriva
    // al core prima della connessione.
    let verified = claims(ALICE, &["web-01"]);
    h.reload(&Ca {
        present: false,
        ..Ca::default()
    });
    let out = h.connect(7, ALICE, Some(verified));
    refused_with(&out, ALICE, CertRejection::UnknownAuthority);
    // Lo stesso per una serie revocata nel frattempo.
    let mut h = H::new();
    h.reload(&Ca {
        serials: vec![ALICE],
        ..Ca::default()
    });
    let out = h.connect(7, ALICE, Some(claims(ALICE, &["web-01"])));
    refused_with(&out, ALICE, CertRejection::SerialRevoked);
}

#[test]
fn revoking_a_serial_on_reload_cuts_the_connection() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    let (web, _) = h.open(2, 7, "web-01", 1);
    h.connect(4, BOB, Some(claims(BOB, &["web-01"])));
    h.open(4, 7, "web-01", 1);
    let out = h.reload(&Ca {
        serials: vec![ALICE],
        ..Ca::default()
    });
    assert!(audits(&out).contains(&DomainEvent::AccessRevoked {
        peer: fp(ALICE),
        target: None,
        certificate: Some(alice.reference()),
    }));
    assert!(sent_to(&out, 1).contains(&unauthorized(web)), "{out:?}");
    assert_eq!(closed(&out), [2]);
    // Bob ha un'altra serie: resta.
    assert!(sent_to(&out, 4).is_empty());
    assert_eq!(h.core.route_count(), 2);
}

#[test]
fn revoking_a_key_on_reload_cuts_static_and_certified_clients() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    h.open(2, 7, "web-01", 1);
    h.connect(4, ANSIBLE, None);
    h.open(4, 7, "web-01", 1);
    h.connect(5, BOB, Some(claims(BOB, &["web-01"])));
    h.open(5, 7, "web-01", 1);
    let out = h.reload(&Ca {
        keys: vec![ALICE, ANSIBLE],
        ..Ca::default()
    });
    let events = audits(&out);
    assert!(events.contains(&DomainEvent::AccessRevoked {
        peer: fp(ALICE),
        target: None,
        certificate: Some(alice.reference()),
    }));
    assert!(events.contains(&DomainEvent::AccessRevoked {
        peer: fp(ANSIBLE),
        target: None,
        certificate: None,
    }));
    assert_eq!(closed(&out), [2, 4]);
    assert_eq!(h.core.route_count(), 2, "bob survives");
    // Una riconnessione della chiave revocata è rifiutata, con o senza certificato.
    let out = h.connect(9, ANSIBLE, None);
    assert!(audits(&out).contains(&DomainEvent::AuthenticationFailed {
        peer: Some(fp(ANSIBLE)),
        reason: AuthFailureReason::KeyRevoked,
        certificate: None,
    }));
    assert_eq!(closed(&out), [9]);
}

#[test]
fn removing_the_authority_cuts_all_its_connections() {
    let mut h = H::new();
    h.connect(2, ALICE, Some(claims(ALICE, &["web-01"])));
    h.open(2, 7, "web-01", 1);
    h.connect(4, BOB, Some(claims(BOB, &["db-01"])));
    h.open(4, 7, "db-01", 3);
    h.connect(5, ANSIBLE, None);
    h.open(5, 7, "web-01", 1);
    let out = h.reload(&Ca {
        present: false,
        ..Ca::default()
    });
    assert_eq!(closed(&out), [2, 4]);
    let revoked: Vec<Fingerprint> = audits(&out)
        .iter()
        .filter_map(|e| match e {
            DomainEvent::AccessRevoked {
                peer, target: None, ..
            } => Some(*peer),
            _ => None,
        })
        .collect();
    assert_eq!(revoked.len(), 2);
    assert!(revoked.contains(&fp(ALICE)) && revoked.contains(&fp(BOB)));
    assert_eq!(h.core.route_count(), 2, "the whitelisted client survives");
}

#[test]
fn narrowing_the_authority_allow_closes_only_the_lost_streams() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01", "db-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    let _ = h.open(2, 7, "web-01", 1);
    let (db, _) = h.open(2, 9, "db-01", 3);
    let out = h.reload(&Ca {
        allow: AllowedNodes::Only(nodes(&["web-01"])),
        ..Ca::default()
    });
    assert_eq!(sent_to(&out, 2), [unauthorized(sid(9))]);
    assert_eq!(sent_to(&out, 3), [unauthorized(db)]);
    assert!(sent_to(&out, 1).is_empty());
    assert!(closed(&out).is_empty(), "the connection stays: {out:?}");
    assert!(audits(&out).contains(&DomainEvent::AccessRevoked {
        peer: fp(ALICE),
        target: Some(node("db-01")),
        certificate: Some(alice.reference()),
    }));
    assert_eq!(h.core.route_count(), 2);
    // E un nuovo Open verso db-01 è negato.
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(11),
            target: node("db-01"),
        },
    );
    assert_eq!(
        sent_to(&out, 2),
        [Frame::Reject {
            stream: sid(11),
            reason: RejectReason::NotAuthorized
        }]
    );
}

#[test]
fn shrinking_max_lifetime_below_the_certificate_cuts_it() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    h.open(2, 7, "web-01", 1);
    // Il certificato dura un'ora; la CA ora ne ammette 60 secondi.
    let out = h.reload(&Ca {
        max_lifetime: 60,
        ..Ca::default()
    });
    assert_eq!(closed(&out), [2], "{out:?}");
    assert!(audits(&out).contains(&DomainEvent::AccessRevoked {
        peer: fp(ALICE),
        target: None,
        certificate: Some(alice.reference()),
    }));
    // Controllo: con un'ora esatta resta.
    let mut h = H::new();
    h.connect(2, ALICE, Some(claims(ALICE, &["web-01"])));
    h.open(2, 7, "web-01", 1);
    assert!(
        closed(&h.reload(&Ca {
            max_lifetime: 3_600,
            ..Ca::default()
        }))
        .is_empty()
    );
}

#[test]
fn a_certificate_for_an_agent_key_is_refused_in_the_core() {
    let mut h = H::new();
    let out = h.connect(7, WEB_AGENT, Some(claims(WEB_AGENT, &["web-01"])));
    refused_with(&out, WEB_AGENT, CertRejection::RoleConflict);
    // La connessione non esiste: un Register successivo non produce nulla.
    let out = h.recv(
        7,
        Frame::Register {
            node: node("web-01"),
        },
    );
    assert!(out.is_empty(), "{out:?}");
}

/// Finding 0006-4: l'operatore aggiunge alla whitelist la chiave di un client già connesso con
/// certificato, con un `allow` più stretto (§15.5: la whitelist ha la precedenza). La
/// connessione aperta passa alla credenziale `Key`: perde gli stream fuori dalla whitelist
/// (`Close Unauthorized`, `access_revoked`), un nuovo `Open` fuori è negato, quelli dentro
/// restano, e la scadenza del certificato non la chiude più.
#[test]
fn whitelisting_a_certified_connection_applies_the_whitelist_scope() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01", "db-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    let _ = h.open(2, 5, "web-01", 1);
    let (db, _) = h.open(2, 7, "db-01", 3);
    // Nuova policy: alice nella whitelist solo per web-01, CA invariata.
    let base = policy(&Ca::default());
    let mut p = AccessPolicy::new();
    p.add_agent(fp(WEB_AGENT), node("web-01")).unwrap();
    p.add_agent(fp(DB_AGENT), node("db-01")).unwrap();
    p.add_client(
        fp(ALICE),
        ClientGrant {
            name: node("alice"),
            allowed: AllowedNodes::Only(nodes(&["web-01"])),
        },
    )
    .unwrap();
    p.set_cert_trust(base.cert_trust().clone()).unwrap();
    let out = h.input(Input::PolicyUpdated {
        policy: Arc::new(p),
    });
    assert_eq!(sent_to(&out, 2), [unauthorized(sid(7))], "{out:?}");
    assert_eq!(sent_to(&out, 3), [unauthorized(db)]);
    assert!(sent_to(&out, 1).is_empty(), "web-01 stays: {out:?}");
    assert!(closed(&out).is_empty(), "the connection stays: {out:?}");
    assert!(audits(&out).contains(&DomainEvent::AccessRevoked {
        peer: fp(ALICE),
        target: Some(node("db-01")),
        certificate: Some(alice.reference()),
    }));
    // Un nuovo Open verso db-01 sulla stessa connessione è negato, verso web-01 no.
    let out = h.recv(
        2,
        Frame::Open {
            stream: sid(9),
            target: node("db-01"),
        },
    );
    assert!(sent_to(&out, 3).is_empty(), "{out:?}");
    assert_eq!(
        sent_to(&out, 2),
        [Frame::Reject {
            stream: sid(9),
            reason: RejectReason::NotAuthorized
        }]
    );
    let _ = h.open(2, 11, "web-01", 1);
    // Come una connessione nuova con lo stesso certificato.
    h.connect(4, ALICE, Some(Arc::clone(&alice)));
    let out = h.recv(
        4,
        Frame::Open {
            stream: sid(7),
            target: node("db-01"),
        },
    );
    assert!(sent_to(&out, 3).is_empty(), "{out:?}");
    // La whitelist non scade in sessione (§15.5): la scadenza del certificato non la chiude.
    let out = h.tick_at(NA + 10);
    assert!(!closed(&out).contains(&2), "{out:?}");
}
