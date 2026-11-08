//! Il relay core: chi può fare cosa, e dove va ogni frame.
//!
//! Invarianti mantenute (e coperte da `tests/relay_core.rs`):
//! - un peer sconosciuto non ottiene nulla; un agent registra solo il proprio nome;
//! - un client raggiunge solo i nodi concessi, e non distingue «negato» da «inesistente»;
//! - ogni `Data` inoltrato rientra nel credito concesso dal destinatario, quindi la memoria
//!   in coda verso un peer è limitata a `stream × finestra`;
//! - ogni violazione chiude la connessione del colpevole e libera tutte le sue risorse;
//! - nessuna tabella cresce oltre i limiti configurati.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zt_domain::flow::Window;
use zt_domain::{
    AccessPolicy, Admission, AuthFailureReason, CertClaims, CertRef, ClientCredential, CloseReason,
    DomainEvent, Fingerprint, Frame, NodeId, RejectReason, SessionId, StreamId, UnixTime,
};

use crate::ratelimit::TokenBucket;

/// Identificativo di una connessione autenticata, assegnato dall'adapter di rete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// L'orologio visto dal core: monotono per i timeout, di sistema (UTC) per i certificati
/// (PROTOCOL §15.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Tempo monotono.
    pub instant: Instant,
    /// Tempo di sistema, in secondi Unix.
    pub unix: UnixTime,
}

/// Eventi in ingresso al relay core.
#[derive(Debug)]
pub enum Input {
    /// Handshake completato: `peer` è l'identità provata da Noise.
    Connected {
        /// La connessione.
        conn: ConnId,
        /// L'identità del peer.
        peer: Fingerprint,
        /// Il certificato presentato nel messaggio 1, già verificato (passi 3–6 di
        /// PROTOCOL §15.4); `None` senza certificato.
        certificate: Option<Arc<CertClaims>>,
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
    /// È stata caricata una nuova policy: si applica anche alle connessioni già aperte.
    PolicyUpdated {
        /// La nuova policy.
        policy: Arc<AccessPolicy>,
    },
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
    /// `Open` ammessi a raffica per connessione client.
    pub open_burst: u32,
    /// Un `Open` in più ogni `open_refill`.
    pub open_refill: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_streams_per_client: 32,
            max_streams_per_agent: 64,
            register_timeout: Duration::from_secs(10),
            ping_burst: 10,
            ping_refill: Duration::from_secs(5),
            open_burst: 64,
            open_refill: Duration::from_millis(100),
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
    Client {
        /// La credenziale con cui il client è stato ammesso: una connessione con certificato
        /// tiene solo i dati verificati, mai i byte del certificato.
        credential: ClientCredential,
    },
}

/// Il riferimento di audit di una credenziale: `None` per la whitelist.
fn cert_ref(credential: &ClientCredential) -> Option<CertRef> {
    match credential {
        ClientCredential::Key => None,
        ClientCredential::Certificate(claims) => Some(claims.reference()),
    }
}

/// Stream chiusi di recente da un client, per cui frame in volo vanno scartati in silenzio.
///
/// Gli stream lato agent non ne hanno bisogno: i loro id crescono e non vengono riusati, quindi
/// ogni id sotto `next_stream` non più aperto è per forza uno stream chiuso.
#[derive(Debug, Default)]
struct RecentlyClosed {
    order: VecDeque<StreamId>,
    set: HashSet<StreamId>,
}

impl RecentlyClosed {
    /// Quanti id ricordare. Un client che ne chiude di più in volo perde solo il proprio stream.
    const CAPACITY: usize = 256;

    fn insert(&mut self, stream: StreamId) {
        if !self.set.insert(stream) {
            return;
        }
        self.order.push_back(stream);
        if self.order.len() > Self::CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
    }

    fn contains(&self, stream: StreamId) -> bool {
        self.set.contains(&stream)
    }

    fn reopen(&mut self, stream: StreamId) {
        if self.set.remove(&stream) {
            self.order.retain(|s| *s != stream);
        }
    }
}

#[derive(Debug)]
struct Conn {
    peer: Fingerprint,
    role: Role,
    streams: BTreeSet<StreamId>,
    pings: TokenBucket,
    opens: TokenBucket,
    closed: RecentlyClosed,
}

impl Conn {
    /// `true` se `stream` è esistito su questa connessione ed è stato chiuso: un frame su di esso
    /// è un normale frame in volo, non una violazione (finding 0002-1, -2, -6).
    fn is_stale(&self, stream: StreamId) -> bool {
        match &self.role {
            Role::Agent { next_stream, .. } => stream.get() < *next_stream,
            Role::Client { .. } => self.closed.contains(stream),
        }
    }

    fn forget(&mut self, stream: StreamId) {
        self.streams.remove(&stream);
        self.closed.insert(stream);
    }
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
    /// Il certificato del client, per l'audit (`None` per la whitelist).
    certificate: Option<CertRef>,
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
    pub fn handle(&mut self, input: Input, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Connected {
                conn,
                peer,
                certificate,
            } => self.on_connected(conn, peer, certificate.as_ref(), now, &mut out),
            Input::Received { conn, frame } => {
                if self.conns.contains_key(&conn)
                    && let Err(rule) = self.on_frame(conn, frame, now, &mut out)
                {
                    self.violation(conn, rule, &mut out);
                }
            }
            Input::Disconnected { conn } => self.teardown(conn, &mut out),
            Input::Tick => self.on_tick(now, &mut out),
            Input::PolicyUpdated { policy } => self.on_policy(policy, now.unix, &mut out),
        }
        out
    }

    fn on_connected(
        &mut self,
        conn: ConnId,
        peer: Fingerprint,
        certificate: Option<&Arc<CertClaims>>,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        if self.conns.contains_key(&conn) {
            return;
        }
        // Passi 1, 5 e 7–11 di PROTOCOL §15.4 ricontrollati con la policy e l'orologio del
        // momento in cui la connessione arriva al core: una ricarica nel frattempo non si perde.
        let role = match self.policy.admit(&peer, certificate, now.unix) {
            Err(reason) => {
                out.push(Output::Audit(DomainEvent::AuthenticationFailed {
                    peer: Some(peer),
                    reason,
                }));
                out.push(Output::Close { conn });
                return;
            }
            Ok(Admission::Agent { node }) => Role::Agent {
                node: node.clone(),
                registered: false,
                since: now.instant,
                next_stream: 1,
            },
            Ok(Admission::Client { credential }) => Role::Client { credential },
        };
        let now = now.instant;
        let pings = TokenBucket::new(self.limits.ping_burst, self.limits.ping_refill, now);
        let opens = TokenBucket::new(self.limits.open_burst, self.limits.open_refill, now);
        self.conns.insert(
            conn,
            Conn {
                peer,
                role,
                streams: BTreeSet::new(),
                pings,
                opens,
                closed: RecentlyClosed::default(),
            },
        );
    }

    fn on_tick(&mut self, now: Now, out: &mut Vec<Output>) {
        let timeout = self.limits.register_timeout;
        let mut expired: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| {
                matches!(c.role, Role::Agent { registered: false, since, .. }
                    if now.instant.saturating_duration_since(since) >= timeout)
            })
            .map(|(id, _)| *id)
            .collect();
        expired.sort_unstable();
        for conn in expired {
            self.violation(conn, "agent did not register in time", out);
        }
        // PROTOCOL §15.7: una sessione autorizzata da un certificato finisce alla scadenza,
        // secondo l'orologio di sistema (non quello monotono).
        let mut lapsed: Vec<(ConnId, Fingerprint, CertRef)> = self
            .conns
            .iter()
            .filter_map(|(id, c)| match &c.role {
                Role::Client {
                    credential: ClientCredential::Certificate(claims),
                } if now.unix >= claims.not_after() => Some((*id, c.peer, claims.reference())),
                _ => None,
            })
            .collect();
        lapsed.sort_unstable_by_key(|(id, _, _)| *id);
        for (conn, peer, certificate) in lapsed {
            self.close_streams_unauthorized(conn, out);
            out.push(Output::Audit(DomainEvent::CertificateExpired {
                peer,
                certificate,
            }));
            self.teardown(conn, out);
            out.push(Output::Close { conn });
        }
    }

    /// Chiude con `Close Unauthorized`, a entrambi i lati, ogni stream di `conn` verso un nodo
    /// per cui `keep` è falso; restituisce i nodi persi.
    fn close_streams_where(
        &mut self,
        conn: ConnId,
        keep: impl Fn(&NodeId) -> bool,
        out: &mut Vec<Output>,
    ) -> BTreeSet<NodeId> {
        let Some(c) = self.conns.get(&conn) else {
            return BTreeSet::new();
        };
        let lost: Vec<(StreamId, NodeId)> = c
            .streams
            .iter()
            .filter_map(|s| self.routes.get(&(conn, *s)).map(|r| (*s, r.target.clone())))
            .filter(|(_, target)| !keep(target))
            .collect();
        let mut targets = BTreeSet::new();
        for (stream, target) in lost {
            let Some(route) = self.remove_route(conn, stream) else {
                continue;
            };
            let (agent, agent_stream) = route.peer;
            for (to, s) in [(conn, stream), (agent, agent_stream)] {
                out.push(Output::Send {
                    conn: to,
                    frame: Frame::Close {
                        stream: s,
                        reason: CloseReason::Unauthorized,
                    },
                });
            }
            out.push(Output::Audit(DomainEvent::ConnectionDrained {
                session: route.session,
                reason: CloseReason::Unauthorized,
            }));
            targets.insert(target);
        }
        targets
    }

    fn close_streams_unauthorized(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        self.close_streams_where(conn, |_| false, out);
    }

    fn on_frame(
        &mut self,
        conn: ConnId,
        frame: Frame,
        now: Now,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        let c = self.conns.get_mut(&conn).ok_or("unknown connection")?;
        match frame {
            Frame::Ping { nonce } => {
                if !c.pings.try_take(now.instant) {
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
                if let Some(stream) = other.stream()
                    && !matches!(other, Frame::Open { .. })
                    && !self.routes.contains_key(&(conn, stream))
                    && c.is_stale(stream)
                {
                    // Frame in volo su uno stream già chiuso: si scarta.
                    return Ok(());
                }
                let is_agent = match &c.role {
                    Role::Agent {
                        registered: false, ..
                    } => return Err("frame before register"),
                    Role::Agent { .. } => true,
                    Role::Client { .. } => false,
                };
                match other {
                    Frame::Open { stream, target } if !is_agent => {
                        self.on_open(conn, stream, target, now, out)
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
        now: Now,
        out: &mut Vec<Output>,
    ) -> Result<(), Violation> {
        let c = self.conns.get_mut(&conn).ok_or("unknown connection")?;
        let client = c.peer;
        if c.streams.contains(&stream) {
            return Err("stream id reuse");
        }
        let Role::Client { credential } = &c.role else {
            return Err("agents cannot open streams");
        };
        let credential = credential.clone();
        let certificate = cert_ref(&credential);
        let reject = |reason| Output::Send {
            conn,
            frame: Frame::Reject { stream, reason },
        };
        // Ogni `Open` costa lavoro all'agent e una riga di audit: se ne limita la frequenza,
        // prima di qualsiasi altro controllo (finding 0002-4).
        if !c.opens.try_take(now.instant) {
            out.push(reject(RejectReason::RateLimited));
            return Ok(());
        }
        c.closed.reopen(stream);
        // Prima l'autorizzazione: «negato» e «inesistente» devono essere indistinguibili.
        if !self
            .policy
            .may_open_with(&client, &credential, &target, now.unix)
        {
            out.push(Output::Audit(DomainEvent::AccessDenied {
                client,
                target,
                certificate,
            }));
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
            certificate: certificate.clone(),
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
            certificate: route.certificate.clone(),
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
            c.forget(stream);
        }
        if let Some(p) = self.conns.get_mut(&peer) {
            p.forget(peer_stream);
        }
        Some(route)
    }

    /// Applica una nuova policy alle connessioni aperte (revoca a caldo, PROTOCOL §12 e §15.8).
    fn on_policy(&mut self, policy: Arc<AccessPolicy>, now: UnixTime, out: &mut Vec<Output>) {
        self.policy = policy;
        let mut ids: Vec<ConnId> = self.conns.keys().copied().collect();
        ids.sort_unstable();
        for conn in ids {
            let Some(c) = self.conns.get(&conn) else {
                continue;
            };
            let peer = c.peer;
            // La credenziale salvata vale ancora con la policy nuova? (denylist, CA ancora
            // pinnata per chiave, durata massima, ruolo.)
            let (keeps, credential) = match &c.role {
                Role::Agent { node, .. } => (
                    matches!(
                        self.policy.admit(&peer, None, now),
                        Ok(Admission::Agent { node: current }) if current == node
                    ),
                    None,
                ),
                Role::Client { credential } => {
                    let keeps = match credential {
                        ClientCredential::Key => matches!(
                            self.policy.admit(&peer, None, now),
                            Ok(Admission::Client {
                                credential: ClientCredential::Key
                            })
                        ),
                        ClientCredential::Certificate(claims) => matches!(
                            self.policy.admit(&peer, Some(claims), now),
                            Ok(Admission::Client { .. })
                        ),
                    };
                    (keeps, Some(credential.clone()))
                }
            };
            let certificate = credential.as_ref().and_then(cert_ref);
            if !keeps {
                out.push(Output::Audit(DomainEvent::AccessRevoked {
                    peer,
                    target: None,
                    certificate,
                }));
                // Un certificato revocato chiude i suoi stream con `Close Unauthorized` (PROTOCOL
                // §15.8); un peer che perde la voce della whitelist li chiude come prima (§12).
                if matches!(credential, Some(ClientCredential::Certificate(_))) {
                    self.close_streams_unauthorized(conn, out);
                }
                self.teardown(conn, out);
                out.push(Output::Close { conn });
                continue;
            }
            let Some(credential) = credential else {
                continue;
            };
            let policy = Arc::clone(&self.policy);
            let targets = self.close_streams_where(
                conn,
                |target| policy.may_open_with(&peer, &credential, target, now),
                out,
            );
            for target in targets {
                out.push(Output::Audit(DomainEvent::AccessRevoked {
                    peer,
                    target: Some(target),
                    certificate: certificate.clone(),
                }));
            }
        }
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
                p.forget(peer_stream);
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
