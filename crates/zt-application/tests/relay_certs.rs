//! Phase 6, step 6: the relay core with certified clients (PROTOCOL §15.4 recheck in the
//! core, §15.5, §15.7 in-session expiry, §15.8 revocation on reload).
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

/// "Verified" claims of a certificate from the CA for `subject`.
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

/// How the CA is configured in a version of the policy.
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

/// Agents web-01 and db-01, `ansible` in the whitelist (web-01, db-01), the CA as specified.
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
    /// Agents web-01 (conn 1) and db-01 (conn 3) registered.
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
    /// Opens `stream` from `conn` toward `target` (served by `agent`) and confirms: returns the
    /// agent-side stream and the outputs of the `OpenAck`.
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
    // Finding 0006-3: a rejection after the signature (steps 7–12) reports the certificate, an
    // earlier one never does.
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

// ======================= specification =======================

#[test]
fn a_certified_client_opens_streams_within_its_effective_scope() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01"]);
    let out = h.connect(2, ALICE, Some(Arc::clone(&alice)));
    assert!(closed(&out).is_empty(), "{out:?}");
    assert_eq!(h.core.connection_count(), 3);
    let (_, ack) = h.open(2, 7, "web-01", 1);
    assert_eq!(sent_to(&ack, 2), [Frame::OpenAck { stream: sid(7) }]);
    // db-01 is in the CA but not in the certificate.
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
    // The whitelist does not carry a certificate, even if the client presented a valid one.
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
    // One second before: nothing.
    let out = h.tick_at(NA - 1);
    assert!(out.is_empty(), "{out:?}");
    // At expiry: Close Unauthorized on both sides of every stream, then the connection.
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
    // Only once.
    assert!(h.tick_at(NA + 1).is_empty());
}

#[test]
fn a_whitelisted_client_never_expires() {
    let mut h = H::new();
    // `ansible` is in the whitelist and also presents a valid certificate: the whitelist wins.
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

// ======================= attacks =======================

#[test]
fn expiry_follows_wall_time_not_monotonic_time() {
    let mut h = H::new();
    h.connect(2, ALICE, Some(claims(ALICE, &["web-01"])));
    h.open(2, 7, "web-01", 1);
    // The monotonic clock does not move (suspended VM, test): only the system one counts.
    let frozen = h.instant;
    let out = h.tick_at(NA + 3_600);
    assert_eq!(h.instant, frozen);
    assert_eq!(closed(&out), [2], "{out:?}");
    // Every input carries the clock: even a frame after expiry does not pass.
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
    // And one not yet valid beyond the tolerance.
    let mut h = H::new();
    h.unix = NB - 121;
    let out = h.connect(7, ALICE, Some(claims(ALICE, &["web-01"])));
    refused_with(&out, ALICE, CertRejection::NotYetValid);
    // Control: within the tolerance it passes.
    let mut h = H::new();
    h.unix = NB - 120;
    assert!(closed(&h.connect(7, ALICE, Some(claims(ALICE, &["web-01"])))).is_empty());
}

#[test]
fn a_connection_racing_a_reload_that_removes_its_authority_is_refused() {
    let mut h = H::new();
    // The network task verified the certificate with the old policy; the reload reaches the
    // core before the connection.
    let verified = claims(ALICE, &["web-01"]);
    h.reload(&Ca {
        present: false,
        ..Ca::default()
    });
    let out = h.connect(7, ALICE, Some(verified));
    refused_with(&out, ALICE, CertRejection::UnknownAuthority);
    // The same for a serial revoked in the meantime.
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
    // Bob has another serial: he stays.
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
    // A reconnection of the revoked key is rejected, with or without a certificate.
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
    // And a new Open toward db-01 is denied.
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
    // The certificate lasts one hour; the CA now allows 60 seconds.
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
    // Control: with exactly one hour it stays.
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
    // The connection does not exist: a subsequent Register produces nothing.
    let out = h.recv(
        7,
        Frame::Register {
            node: node("web-01"),
        },
    );
    assert!(out.is_empty(), "{out:?}");
}

/// Finding 0006-4: the operator adds to the whitelist the key of a client already connected
/// with a certificate, with a narrower `allow` (§15.5: the whitelist takes precedence). The
/// open connection switches to the `Key` credential: it loses the streams outside the
/// whitelist (`Close Unauthorized`, `access_revoked`), a new `Open` outside is denied, those
/// inside stay, and the certificate expiry no longer closes it.
#[test]
fn whitelisting_a_certified_connection_applies_the_whitelist_scope() {
    let mut h = H::new();
    let alice = claims(ALICE, &["web-01", "db-01"]);
    h.connect(2, ALICE, Some(Arc::clone(&alice)));
    let _ = h.open(2, 5, "web-01", 1);
    let (db, _) = h.open(2, 7, "db-01", 3);
    // New policy: alice in the whitelist only for web-01, CA unchanged.
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
    // A new Open toward db-01 on the same connection is denied, toward web-01 it is not.
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
    // Like a new connection with the same certificate.
    h.connect(4, ALICE, Some(Arc::clone(&alice)));
    let out = h.recv(
        4,
        Frame::Open {
            stream: sid(7),
            target: node("db-01"),
        },
    );
    assert!(sent_to(&out, 3).is_empty(), "{out:?}");
    // The whitelist does not expire in session (§15.5): the certificate expiry does not close it.
    let out = h.tick_at(NA + 10);
    assert!(!closed(&out).contains(&2), "{out:?}");
}
