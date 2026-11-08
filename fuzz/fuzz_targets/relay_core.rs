//! Il core del relay su sequenze arbitrarie di eventi: connessioni di peer noti e sconosciuti,
//! frame di ogni tipo, disconnessioni, scatti dell'orologio e **ricariche della policy**.
//!
//! Proprietà: nessun panic; il core non scrive mai su una connessione che non esiste o che ha
//! già chiuso; dopo una ricarica non resta aperta nessuna connessione di un peer senza ruolo
//! nella policy nuova (revoca a caldo, finding 0004-6).
#![no_main]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use zt_application::relay::{ConnId, Input, Output, RelayCore, RelayLimits, SessionIds};
use zt_domain::{
    AccessPolicy, AllowedNodes, ClientGrant, CloseReason, Credit, Fingerprint, Frame,
    FramePayload, NodeId, RejectReason, SessionId, StreamId,
};

const NODES: [&str; 4] = ["web-01", "db-01", "app-01", "ghost"];
/// Agent 1..=3 (uno per nodo), client 10 e 11, 99 mai in policy.
const PEERS: [u8; 6] = [1, 2, 3, 10, 11, 99];

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

/// Policy scelta da un byte: un bit per agent e per client, più il nodo assegnato all'agent 1
/// e l'ampiezza dei permessi del client 10.
fn policy(bits: u8) -> Arc<AccessPolicy> {
    let mut p = AccessPolicy::new();
    for (i, agent) in [1_u8, 2, 3].into_iter().enumerate() {
        if bits & (1 << i) != 0 {
            // Con il bit 6 l'agent 1 passa al nodo di un altro (cambio di nome).
            let n = if agent == 1 && bits & 0x40 != 0 { 2 } else { agent - 1 };
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
    Arc::new(p)
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
        7 => Frame::Ping { nonce: u64::from(a) },
        _ => Frame::Pong { nonce: u64::from(a) },
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let mut current = policy(first);
    let mut core = RelayCore::new(Arc::clone(&current), RelayLimits::default(), Counter(0));
    let mut now = Instant::now();
    // Il modello dell'adapter: connessioni vive e il loro peer.
    let mut live: HashMap<u64, Fingerprint> = HashMap::new();
    let mut bytes = rest.iter().copied();
    let mut steps = 0;
    while let Some(op) = bytes.next() {
        steps += 1;
        if steps > 512 {
            return;
        }
        let input = match op % 6 {
            0 => {
                let Some(c) = bytes.next() else { return };
                let Some(p) = bytes.next() else { return };
                let conn = u64::from(c % 8);
                if live.contains_key(&conn) {
                    continue;
                }
                let peer = fp(PEERS[usize::from(p) % PEERS.len()]);
                live.insert(conn, peer);
                Input::Connected {
                    conn: ConnId(conn),
                    peer,
                }
            }
            1 => {
                let Some(c) = bytes.next() else { return };
                let conn = u64::from(c % 8);
                let Some(frame) = frame(&mut bytes) else { return };
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
                Input::Tick
            }
            _ => {
                let Some(bits) = bytes.next() else { return };
                current = policy(bits);
                Input::PolicyUpdated {
                    policy: Arc::clone(&current),
                }
            }
        };
        let reload = matches!(input, Input::PolicyUpdated { .. });
        let mut pending = vec![input];
        while let Some(input) = pending.pop() {
            for output in core.handle(input, now) {
                match output {
                    Output::Send { conn, .. } => {
                        assert!(
                            live.contains_key(&conn.0),
                            "send to a closed or unknown connection {}",
                            conn.0
                        );
                    }
                    Output::Close { conn } => {
                        // Come l'adapter: la connessione chiusa viene poi segnalata come caduta.
                        if live.remove(&conn.0).is_some() {
                            pending.push(Input::Disconnected { conn });
                        }
                    }
                    Output::Audit(_) => {}
                }
            }
        }
        if reload {
            for (conn, peer) in &live {
                assert!(
                    current.role(peer).is_some(),
                    "connection {conn} of a peer without role survived a reload"
                );
            }
        }
    }
});
