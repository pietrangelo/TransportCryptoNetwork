//! The relay core on arbitrary sequences of events: connections of known and unknown peers,
//! frames of every type, disconnections, clock ticks and **policy reloads**.
//!
//! Properties: no panic; the core never writes to a connection that does not exist or that it
//! has already closed; after a reload no connection stays open for a peer without a role in
//! the new policy (hot revocation, finding 0004-6).
//!
//! Phase 6 (PROTOCOL §15.4, §15.7, §15.8): also connections with a certificate (claims already
//! verified), a Unix clock that advances and jumps, and reloads that remove the CA or add
//! serials and keys to the denylist. No certificate connection survives past `not_after`, a
//! revoked serial or key, or the removed CA; no per-key connection survives the revocation of
//! the key.
#![no_main]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::trust::{CertTrust, Revocations, TrustedCaKey};
use zt_domain::{
    AccessPolicy, AllowedNodes, CertBody, CertClaims, CertKey, CertScope, CertSerial, ClientGrant,
    CloseReason, Credit, Fingerprint, Frame, FramePayload, NodeId, PeerRole, RejectReason,
    SessionId, StreamId, UnixTime,
};

const NODES: [&str; 4] = ["web-01", "db-01", "app-01", "ghost"];
/// Agents 1..=3 (one per node), clients 10 and 11, 99 never in the policy, 20 and 21 with a
/// certificate.
const PEERS: [u8; 8] = [1, 2, 3, 10, 11, 99, 20, 21];
/// The CA (bytes of the key and of the fingerprint).
const CA: u8 = 0xca;
/// The Unix clock at the start.
const START: u64 = 1_800_000_000;

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}

fn node(i: u8) -> NodeId {
    NodeId::try_from(NODES[usize::from(i) % NODES.len()]).expect("valid node")
}

struct Counter(u64);
impl SessionIds for Counter {
    fn next_session_id(&mut self) -> SessionId {
        self.0 += 1;
        let mut b = [0_u8; 16];
        b[..8].copy_from_slice(&self.0.to_be_bytes());
        SessionId::from_bytes(b).expect("non-zero")
    }
}

/// Serial of the certificate of `peer`.
fn serial(peer: u8) -> CertSerial {
    CertSerial::try_from([peer; 16]).expect("non-zero")
}

/// Verified claims of a certificate from the CA for `peer`, valid in `[nb, na)`.
fn claims(peer: u8, nb: u64, na: u64, all: bool) -> Arc<CertClaims> {
    let scope = if all {
        CertScope::All
    } else {
        CertScope::Only([node(0), node(1)].into_iter().collect())
    };
    let body = CertBody::new(
        CertKey::from_bytes([CA; 32]),
        CertKey::from_bytes([peer; 32]),
        serial(peer),
        UnixTime::from_secs(nb),
        UnixTime::from_secs(na),
        NodeId::try_from("cert").expect("valid"),
        scope,
    )
    .expect("valid body");
    Arc::new(CertClaims::from_verified(body, fp(CA), fp(peer)))
}

/// Trust chosen by a byte: bit 0 the CA is pinned (bit 1: only for `web-01`; bit 2:
/// `max_lifetime` of 60 s), bit 3 the serial of 20 is revoked, bit 4 the key of 20, bit 5 the
/// key of 10, bit 6 the serial of 21.
fn trust(bits: u8) -> CertTrust {
    let mut t = CertTrust::new();
    if bits & 0x01 != 0 {
        let allowed = if bits & 0x02 != 0 {
            AllowedNodes::Only([node(0)].into_iter().collect())
        } else {
            AllowedNodes::All
        };
        let lifetime = if bits & 0x04 != 0 { 60 } else { 28_800 };
        let _ = t.add_authority(
            NodeId::try_from("ops-ca").expect("valid"),
            &[TrustedCaKey {
                key: CertKey::from_bytes([CA; 32]),
                fingerprint: fp(CA),
                composite: None,
            }],
            allowed,
            lifetime,
        );
    }
    let mut serials = Vec::new();
    let mut keys = Vec::new();
    if bits & 0x08 != 0 {
        serials.push(serial(20));
    }
    if bits & 0x40 != 0 {
        serials.push(serial(21));
    }
    if bits & 0x10 != 0 {
        keys.push(fp(20));
    }
    if bits & 0x20 != 0 {
        keys.push(fp(10));
    }
    if let Ok(r) = Revocations::new(serials, keys) {
        t.set_revocations(r);
    }
    t
}

/// Policy chosen by two bytes: one bit per agent and per client, plus the node assigned to
/// agent 1 and the breadth of the permissions of client 10; `ca` chooses the trust
/// ([`trust`]).
fn policy(bits: u8, ca: u8) -> Arc<AccessPolicy> {
    let mut p = AccessPolicy::new();
    for (i, agent) in [1_u8, 2, 3].into_iter().enumerate() {
        if bits & (1 << i) != 0 {
            // With bit 6 agent 1 moves to another agent's node (name change).
            let n = if agent == 1 && bits & 0x40 != 0 {
                2
            } else {
                agent - 1
            };
            let _ = p.add_agent(fp(agent), node(n));
        }
    }
    if bits & 0x08 != 0 {
        let allowed = if bits & 0x80 != 0 {
            AllowedNodes::All
        } else {
            AllowedNodes::Only([node(0)].into_iter().collect())
        };
        let _ = p.add_client(
            fp(10),
            ClientGrant {
                name: NodeId::try_from("ansible").expect("valid"),
                allowed,
            },
        );
    }
    if bits & 0x10 != 0 {
        let _ = p.add_client(
            fp(11),
            ClientGrant {
                name: NodeId::try_from("admin").expect("valid"),
                allowed: AllowedNodes::All,
            },
        );
    }
    let _ = p.set_cert_trust(trust(ca));
    Arc::new(p)
}

/// Can the connection of `peer` (with `cert`) stay open with `policy` at instant `unix`?
fn may_stay(
    policy: &AccessPolicy,
    peer: &Fingerprint,
    cert: Option<&CertClaims>,
    unix: u64,
) -> bool {
    let trust = policy.cert_trust();
    let Some(cert) = cert else {
        return policy.role(peer).is_some() && !trust.is_key_revoked(peer);
    };
    match policy.role(peer) {
        // A key has a single role: an agent with a certificate is rejected (§15.4 step 11).
        Some(PeerRole::Agent { .. }) => return false,
        // Whitelist: the certificate was verified on entry, then the key counts.
        Some(_) => return !trust.is_key_revoked(peer),
        None => {}
    }
    let Some(authority) = trust.authority_for(cert.authority_key()) else {
        return false;
    };
    let nb = cert.not_before().as_secs();
    let na = cert.not_after().as_secs();
    !trust.is_key_revoked(peer)
        && !trust
            .revocations()
            .is_some_and(|r| r.is_serial_revoked(&cert.serial()))
        && unix < na
        && na.saturating_sub(nb) <= authority.max_lifetime_secs()
}

fn frame(bytes: &mut impl Iterator<Item = u8>) -> Option<Frame> {
    let kind = bytes.next()?;
    let a = bytes.next()?;
    let stream = || StreamId::try_from(u32::from(a % 8) + 1).ok();
    Some(match kind % 9 {
        0 => Frame::Register { node: node(a) },
        1 => Frame::Open {
            stream: stream()?,
            target: node(bytes.next()?),
        },
        2 => Frame::OpenAck { stream: stream()? },
        3 => Frame::Reject {
            stream: stream()?,
            reason: RejectReason::try_from(bytes.next()? % 8).ok()?,
        },
        4 => {
            let len = usize::from(bytes.next()?) * 64 + 1;
            Frame::Data {
                stream: stream()?,
                payload: FramePayload::try_from(vec![0xa5; len]).ok()?,
            }
        }
        5 => Frame::WindowUpdate {
            stream: stream()?,
            credit: Credit::try_from(u32::from(bytes.next()?) << 12).ok()?,
        },
        6 => Frame::Close {
            stream: stream()?,
            reason: CloseReason::try_from(bytes.next()? % 8).ok()?,
        },
        7 => Frame::Ping {
            nonce: u64::from(a),
        },
        _ => Frame::Pong {
            nonce: u64::from(a),
        },
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let Some((&first_ca, rest)) = rest.split_first() else {
        return;
    };
    let mut current = policy(first, first_ca);
    let mut core = RelayCore::new(Arc::clone(&current), RelayLimits::default(), Counter(0));
    let mut now = Instant::now();
    let mut unix = START;
    // The adapter model: live connections, their peer and the certificate.
    let mut live: HashMap<u64, (Fingerprint, Option<Arc<CertClaims>>)> = HashMap::new();
    let mut bytes = rest.iter().copied();
    let mut steps = 0;
    while let Some(op) = bytes.next() {
        steps += 1;
        if steps > 512 {
            return;
        }
        let input = match op % 7 {
            0 => {
                let Some(c) = bytes.next() else { return };
                let Some(p) = bytes.next() else { return };
                let Some(shape) = bytes.next() else { return };
                let conn = u64::from(c % 8);
                if live.contains_key(&conn) {
                    continue;
                }
                let b = PEERS[usize::from(p) % PEERS.len()];
                let peer = fp(b);
                // The certificate (already verified by the adapter): bit 0 present; the others
                // choose its window relative to the clock, even expired or in the future.
                let certificate = (shape & 1 != 0).then(|| {
                    let nb = unix.saturating_sub(u64::from(shape >> 4) * 600);
                    let na = nb.saturating_add(u64::from((shape >> 1) & 0x07) * 300 + 1);
                    claims(b, nb, na, shape & 0x80 != 0)
                });
                live.insert(conn, (peer, certificate.clone()));
                Input::Connected {
                    conn: ConnId(conn),
                    peer,
                    certificate,
                }
            }
            1 => {
                let Some(c) = bytes.next() else { return };
                let conn = u64::from(c % 8);
                let Some(frame) = frame(&mut bytes) else {
                    return;
                };
                if !live.contains_key(&conn) {
                    continue;
                }
                Input::Received {
                    conn: ConnId(conn),
                    frame,
                }
            }
            2 => {
                let Some(c) = bytes.next() else { return };
                let conn = u64::from(c % 8);
                if live.remove(&conn).is_none() {
                    continue;
                }
                Input::Disconnected { conn: ConnId(conn) }
            }
            3 => {
                let Some(secs) = bytes.next() else { return };
                now += Duration::from_secs(u64::from(secs));
                unix = unix.saturating_add(u64::from(secs));
                Input::Tick
            }
            4 => {
                // The system clock jumps (NTP, suspended VM) forward or backward; the monotonic
                // one does not.
                let Some(jump) = bytes.next() else { return };
                // A zero jump starts the drain instead (finding A10-5): new streams are
                // rejected from then on.
                if jump == 0 {
                    Input::DrainStarted
                } else {
                    let delta = u64::from(jump & 0x7f) * 3_600;
                    unix = if jump & 0x80 != 0 {
                        unix.saturating_sub(delta)
                    } else {
                        unix.saturating_add(delta)
                    };
                    Input::Tick
                }
            }
            _ => {
                let Some(bits) = bytes.next() else { return };
                let Some(ca) = bytes.next() else { return };
                current = policy(bits, ca);
                Input::PolicyUpdated {
                    policy: Arc::clone(&current),
                }
            }
        };
        let reload = matches!(input, Input::PolicyUpdated { .. });
        let mut pending = vec![input];
        while let Some(input) = pending.pop() {
            let at = Now {
                instant: now,
                unix: UnixTime::from_secs(unix),
            };
            for output in core.handle(input, at) {
                match output {
                    Output::Send { conn, .. } => {
                        assert!(
                            live.contains_key(&conn.0),
                            "send to a closed or unknown connection {}",
                            conn.0
                        );
                    }
                    Output::Close { conn } => {
                        // Like the adapter: the closed connection is then reported as dropped.
                        if live.remove(&conn.0).is_some() {
                            pending.push(Input::Disconnected { conn });
                        }
                    }
                    Output::Audit(_) => {}
                }
            }
        }
        if reload {
            for (conn, (peer, cert)) in &live {
                assert!(
                    current.role(peer).is_some() || cert.is_some(),
                    "connection {conn} of a peer without role survived a reload"
                );
            }
        }
        // After every input (ticks included): no connection beyond its entitlement.
        for (conn, (peer, cert)) in &live {
            assert!(
                may_stay(&current, peer, cert.as_deref(), unix),
                "connection {conn} survived past its certificate or a revocation"
            );
        }
    }
});
