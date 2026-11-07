//! Il relay core: chi può fare cosa, e dove va ogni frame.
//!
//! Invarianti mantenute (e coperte da `tests/relay_core.rs`):
//! - un peer sconosciuto non ottiene nulla; un agent registra solo il proprio nome;
//! - un client raggiunge solo i nodi concessi, e non distingue «negato» da «inesistente»;
//! - ogni `Data` inoltrato rientra nel credito concesso dal destinatario, quindi la memoria
//!   in coda verso un peer è limitata a `stream × finestra`;
//! - ogni violazione chiude la connessione del colpevole e libera tutte le sue risorse;
//! - nessuna tabella cresce oltre i limiti configurati.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zt_domain::flow::Window;
use zt_domain::{
    AccessPolicy, AuthFailureReason, CloseReason, DomainEvent, Fingerprint, Frame, NodeId,
    PeerRole, RejectReason, SessionId, StreamId,
};

use crate::ratelimit::TokenBucket;

/// Identificativo di una connessione autenticata, assegnato dall'adapter di rete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// Eventi in ingresso al relay core.
#[derive(Debug)]
pub enum Input {
    /// Handshake completato: `peer` è l'identità provata da Noise.
    Connected {
        /// La connessione.
        conn: ConnId,
        /// L'identità del peer.
        peer: Fingerprint,
    },
    /// Frame ben formato ricevuto su una connessione.
    Received {
        /// La connessione.
        conn: ConnId,
        /// Il frame.
        frame: Frame,
    },
    /// La connessione è caduta.
    Disconnected {
        /// La connessione.
        conn: ConnId,
    },
    /// Scatto periodico dell'orologio, per le scadenze.
    Tick,
}

/// Azioni che l'adapter di rete deve eseguire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Invia un frame.
    Send {
        /// La connessione di destinazione.
        conn: ConnId,
        /// Il frame.
        frame: Frame,
    },
    /// Chiudi la connessione. Il core ha già liberato le sue risorse.
    Close {
        /// La connessione.
        conn: ConnId,
    },
    /// Registra un evento di audit.
    Audit(DomainEvent),
}

/// Porta verso una sorgente di identificativi di sessione (CSPRNG nell'adapter).
pub trait SessionIds {
    /// Un nuovo identificativo, unico con probabilità schiacciante.
    fn next_session_id(&mut self) -> SessionId;
}

/// Limiti del relay. I default sono pensati per una flotta Ansible.
#[derive(Debug, Clone)]
pub struct RelayLimits {
    /// Stream contemporanei per connessione client.
    pub max_streams_per_client: usize,
    /// Stream contemporanei per agent.
    pub max_streams_per_agent: usize,
    /// Tempo concesso a un agent per inviare `Register`.
    pub register_timeout: Duration,
    /// `Ping` ammessi a raffica.
    pub ping_burst: u32,
    /// Un `Ping` in più ogni `ping_refill`.
    pub ping_refill: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_streams_per_client: 32,
            max_streams_per_agent: 64,
            register_timeout: Duration::from_secs(10),
            ping_burst: 10,
            ping_refill: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
enum Role {
    Agent {
        node: NodeId,
        registered: bool,
        since: Instant,
        next_stream: u32,
    },
    Client,
}

#[derive(Debug)]
struct Conn {
    peer: Fingerprint,
    role: Role,
    streams: BTreeSet<StreamId>,
    pings: TokenBucket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Opening,
    Open,
}

/// Una direzione di una rotta: dal lato `(conn, stream)` verso `peer`.
#[derive(Debug)]
struct Route {
    peer: (ConnId, StreamId),
    state: StreamState,
    session: SessionId,
    client: Fingerprint,
    target: NodeId,
    /// Credito che questo lato ha per inviare `Data` verso `peer`.
    send: Window,
}

type Violation = &'static str;

/// Macchina a stati del relay. Vedi la documentazione del modulo.
#[derive(Debug)]
pub struct RelayCore<S> {
    policy: Arc<AccessPolicy>,
    limits: RelayLimits,
    ids: S,
    conns: HashMap<ConnId, Conn>,
    agents: HashMap<NodeId, ConnId>,
    routes: HashMap<(ConnId, StreamId), Route>,
}

impl<S: SessionIds> RelayCore<S> {
    /// Un relay senza connessioni.
    pub fn new(policy: Arc<AccessPolicy>, limits: RelayLimits, ids: S) -> Self {
        Self {
            policy,
            limits,
            ids,
            conns: HashMap::new(),
            agents: HashMap::new(),
            routes: HashMap::new(),
        }
    }

    /// Numero di direzioni di rotta attive (due per stream).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Numero di connessioni tracciate.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    /// Elabora un evento e restituisce le azioni da eseguire, in ordine.
    pub fn handle(&mut self, input: Input, now: Instant) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Connected { conn, peer } => self.on_connected(conn, peer, now, &mut out),
            Input::Received { conn, frame } => {
                if self.conns.contains_key(&conn)
                    && let Err(rule) = self.on_frame(conn, frame, now, &mut out)
                {
                    self.violation(conn, rule, &mut out);
                }
            }
            Input::Disconnected { conn } => self.teardown(conn, &mut out),
            Input::Tick => self.on_tick(now, &mut out),
        }
        out
    }

    fn on_connected(
        &mut self,
        conn: ConnId,
        peer: Fingerprint,
        now: Instant,
        out: &mut Vec<Output>,
    ) {
        if self.conns.contains_key(&conn) {
            return;
        }
        let role = match self.policy.role(&peer) {
            None => {
                out.push(Output::Audit(DomainEvent::AuthenticationFailed {
                    peer: Some(peer),
                    reason: AuthFailureReason::UnknownPeer,
                }));
                out.push(Output::Close { conn });
                return;
            }
            Some(PeerRole::Agent { node }) => Role::Agent {
                node: node.clone(),
                registered: false,
                since: now,
                next_stream: 1,
            },
            Some(PeerRole::Client { .. }) => Role::Client,
        };
        let pings = TokenBucket::new(self.limits.ping_burst, self.limits.ping_refill, now);
        self.conns.insert(
            conn,
            Conn {
                peer,
                role,
                streams: BTreeSet::new(),
                pings,
            },
        );
    }

    fn on_tick(&mut self, now: Instant, out: &mut Vec<Output>) {
        let timeout = self.limits.register_timeout;
        let expired: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| {
                matches!(c.role, Role::Agent { registered: false, since, .. }
                    if now.saturating_duration_since(since) >= timeout)
            })
            .map(|(id, _)| *id)
            .collect();
        for conn in expired {
            self.violation(conn, "agent did not register in time", out);
        }
    }

    fn on_frame(
        &mut self,
        conn: ConnId,
        frame: Frame,
        now: Instant,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        let c = self.conns.get_mut(&conn).ok_or("unknown connection")?;
        match frame {
            Frame::Ping { nonce } => {
                if !c.pings.try_take(now) {
                    return Err("ping rate exceeded");
                }
                out.push(Output::Send {
                    conn,
                    frame: Frame::Pong { nonce },
                });
                Ok(())
            }
            Frame::Pong { .. } => Err("unsolicited pong"),
            Frame::Register { node } => self.on_register(conn, node, out),
            other => {
                let is_agent = match &c.role {
                    Role::Agent {
                        registered: false, ..
                    } => return Err("frame before register"),
                    Role::Agent { .. } => true,
                    Role::Client => false,
                };
                match other {
                    Frame::Open { stream, target } if !is_agent => {
                        self.on_open(conn, stream, target, out)
                    }
                    Frame::Open { .. } => Err("agents cannot open streams"),
                    Frame::OpenAck { stream } if is_agent => self.on_open_ack(conn, stream, out),
                    Frame::Reject { stream, reason } if is_agent => {
                        self.on_reject(conn, stream, reason, out)
                    }
                    Frame::OpenAck { .. } | Frame::Reject { .. } => {
                        Err("clients cannot answer opens")
                    }
                    Frame::Data { stream, payload } => {
                        let route = self.open_route_mut(conn, stream)?;
                        route.send.consume(payload.len())?;
                        let (peer, peer_stream) = route.peer;
                        out.push(Output::Send {
                            conn: peer,
                            frame: Frame::Data {
                                stream: peer_stream,
                                payload,
                            },
                        });
                        Ok(())
                    }
                    Frame::WindowUpdate { stream, credit } => {
                        let (peer, peer_stream) = self.open_route_mut(conn, stream)?.peer;
                        // Il credito concesso da questo lato abilita l'invio del lato opposto.
                        self.routes
                            .get_mut(&(peer, peer_stream))
                            .ok_or("route without peer")?
                            .send
                            .grant(credit.get())?;
                        out.push(Output::Send {
                            conn: peer,
                            frame: Frame::WindowUpdate {
                                stream: peer_stream,
                                credit,
                            },
                        });
                        Ok(())
                    }
                    Frame::Close { stream, reason } => {
                        let route = self
                            .remove_route(conn, stream)
                            .ok_or("close on unknown stream")?;
                        let (peer, peer_stream) = route.peer;
                        out.push(Output::Send {
                            conn: peer,
                            frame: Frame::Close {
                                stream: peer_stream,
                                reason,
                            },
                        });
                        out.push(Output::Audit(DomainEvent::ConnectionDrained {
                            session: route.session,
                            reason,
                        }));
                        Ok(())
                    }
                    Frame::Ping { .. } | Frame::Pong { .. } | Frame::Register { .. } => {
                        Err("unreachable frame kind")
                    }
                }
            }
        }
    }

    fn on_register(
        &mut self,
        conn: ConnId,
        node: NodeId,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        let c = self.conns.get_mut(&conn).ok_or("unknown connection")?;
        let peer = c.peer;
        let Role::Agent {
            node: expected,
            registered,
            ..
        } = &mut c.role
        else {
            return Err("clients cannot register");
        };
        if *registered {
            return Err("duplicate register");
        }
        if *expected != node {
            out.push(Output::Audit(DomainEvent::AuthenticationFailed {
                peer: Some(peer),
                reason: AuthFailureReason::NodeIdMismatch,
            }));
            self.teardown(conn, out);
            out.push(Output::Close { conn });
            return Ok(());
        }
        *registered = true;
        if let Some(old) = self.agents.insert(node.clone(), conn)
            && old != conn
        {
            // Nuova connessione dello stesso agent (riconnessione): la vecchia viene drenata.
            self.teardown_except_agent_entry(old, out);
            out.push(Output::Close { conn: old });
        }
        out.push(Output::Audit(DomainEvent::AgentRegistered {
            node,
            fingerprint: peer,
        }));
        Ok(())
    }

    fn on_open(
        &mut self,
        conn: ConnId,
        stream: StreamId,
        target: NodeId,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        let c = self.conns.get(&conn).ok_or("unknown connection")?;
        let client = c.peer;
        if c.streams.contains(&stream) {
            return Err("stream id reuse");
        }
        let reject = |reason| Output::Send {
            conn,
            frame: Frame::Reject { stream, reason },
        };
        // Prima l'autorizzazione: «negato» e «inesistente» devono essere indistinguibili.
        if !self.policy.may_open(&client, &target) {
            out.push(Output::Audit(DomainEvent::AccessDenied { client, target }));
            out.push(reject(RejectReason::NotAuthorized));
            return Ok(());
        }
        if c.streams.len() >= self.limits.max_streams_per_client {
            out.push(reject(RejectReason::ResourceExhausted));
            return Ok(());
        }
        let Some(&agent) = self.agents.get(&target) else {
            out.push(reject(RejectReason::NodeOffline));
            return Ok(());
        };
        let max_agent = self.limits.max_streams_per_agent;
        let Some(agent_stream) = self
            .conns
            .get_mut(&agent)
            .and_then(|a| allocate_stream(a, max_agent))
        else {
            out.push(reject(RejectReason::ResourceExhausted));
            return Ok(());
        };
        let session = self.ids.next_session_id();
        let route = |peer| Route {
            peer,
            state: StreamState::Opening,
            session,
            client,
            target: target.clone(),
            send: Window::initial(),
        };
        self.routes
            .insert((conn, stream), route((agent, agent_stream)));
        self.routes
            .insert((agent, agent_stream), route((conn, stream)));
        if let Some(c) = self.conns.get_mut(&conn) {
            c.streams.insert(stream);
        }
        out.push(Output::Send {
            conn: agent,
            frame: Frame::Open {
                stream: agent_stream,
                target,
            },
        });
        Ok(())
    }

    fn on_open_ack(
        &mut self,
        conn: ConnId,
        stream: StreamId,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        let route = self
            .routes
            .get_mut(&(conn, stream))
            .ok_or("ack for unknown stream")?;
        if route.state != StreamState::Opening {
            return Err("duplicate open ack");
        }
        route.state = StreamState::Open;
        let (peer, peer_stream) = route.peer;
        let event = DomainEvent::SessionEstablished {
            session: route.session,
            client: route.client,
            target: route.target.clone(),
        };
        if let Some(back) = self.routes.get_mut(&(peer, peer_stream)) {
            back.state = StreamState::Open;
        }
        out.push(Output::Send {
            conn: peer,
            frame: Frame::OpenAck {
                stream: peer_stream,
            },
        });
        out.push(Output::Audit(event));
        Ok(())
    }

    fn on_reject(
        &mut self,
        conn: ConnId,
        stream: StreamId,
        reason: RejectReason,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        match self.routes.get(&(conn, stream)) {
            Some(r) if r.state == StreamState::Opening => {}
            Some(_) => return Err("reject after open ack"),
            None => return Err("reject for unknown stream"),
        }
        let route = self
            .remove_route(conn, stream)
            .ok_or("reject for unknown stream")?;
        let (peer, peer_stream) = route.peer;
        out.push(Output::Send {
            conn: peer,
            frame: Frame::Reject {
                stream: peer_stream,
                reason,
            },
        });
        Ok(())
    }

    fn open_route_mut(&mut self, conn: ConnId, stream: StreamId) -> Result<&mut Route, Violation> {
        match self.routes.get_mut(&(conn, stream)) {
            Some(r) if r.state == StreamState::Open => Ok(r),
            Some(_) => Err("stream not yet acknowledged"),
            None => Err("unknown stream"),
        }
    }

    /// Rimuove entrambe le direzioni di una rotta e la restituisce (lato `conn`).
    fn remove_route(&mut self, conn: ConnId, stream: StreamId) -> Option<Route> {
        let route = self.routes.remove(&(conn, stream))?;
        let (peer, peer_stream) = route.peer;
        self.routes.remove(&(peer, peer_stream));
        if let Some(c) = self.conns.get_mut(&conn) {
            c.streams.remove(&stream);
        }
        if let Some(p) = self.conns.get_mut(&peer) {
            p.streams.remove(&peer_stream);
        }
        Some(route)
    }

    fn violation(&mut self, conn: ConnId, rule: Violation, out: &mut Vec<Output>) {
        if let Some(c) = self.conns.get(&conn) {
            out.push(Output::Audit(DomainEvent::ProtocolViolation {
                peer: c.peer,
                rule,
            }));
        }
        self.teardown(conn, out);
        out.push(Output::Close { conn });
    }

    /// Libera tutte le risorse di una connessione e avvisa le controparti dei suoi stream.
    fn teardown(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        if let Some(Conn {
            role:
                Role::Agent {
                    node,
                    registered: true,
                    ..
                },
            ..
        }) = self.conns.get(&conn)
            && self.agents.get(node) == Some(&conn)
        {
            let node = node.clone();
            self.agents.remove(&node);
        }
        self.teardown_except_agent_entry(conn, out);
    }

    fn teardown_except_agent_entry(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        let Some(c) = self.conns.remove(&conn) else {
            return;
        };
        for stream in c.streams {
            let Some(route) = self.routes.remove(&(conn, stream)) else {
                continue;
            };
            let (peer, peer_stream) = route.peer;
            self.routes.remove(&(peer, peer_stream));
            if let Some(p) = self.conns.get_mut(&peer) {
                p.streams.remove(&peer_stream);
            }
            out.push(Output::Send {
                conn: peer,
                frame: Frame::Close {
                    stream: peer_stream,
                    reason: CloseReason::PeerGone,
                },
            });
            out.push(Output::Audit(DomainEvent::ConnectionDrained {
                session: route.session,
                reason: CloseReason::PeerGone,
            }));
        }
    }
}

/// Assegna un nuovo stream sulla connessione di un agent, se c'è posto.
fn allocate_stream(agent: &mut Conn, max_streams: usize) -> Option<StreamId> {
    if agent.streams.len() >= max_streams {
        return None;
    }
    let Role::Agent { next_stream, .. } = &mut agent.role else {
        return None;
    };
    // Gli id crescono e non vengono riusati: nessuna confusione con frame in ritardo di uno
    // stream chiuso. A 2^32 stream la connessione va ricreata.
    let id = StreamId::try_from(*next_stream).ok()?;
    *next_stream = next_stream.checked_add(1)?;
    agent.streams.insert(id);
    Some(id)
}
