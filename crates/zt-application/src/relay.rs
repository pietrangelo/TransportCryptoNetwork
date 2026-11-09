//! The relay core: who can do what, and where each frame goes.
//!
//! Invariants maintained (and covered by `tests/relay_core.rs`):
//! - an unknown peer gets nothing; an agent registers only its own name;
//! - a client reaches only the nodes it is granted, and cannot tell "denied" from
//!   "nonexistent";
//! - every forwarded `Data` falls within the credit granted by the recipient, so the memory
//!   queued toward a peer is bounded by `streams × window`;
//! - every violation closes the offender's connection and frees all its resources;
//! - no table grows beyond the configured limits.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zt_domain::flow::Window;
use zt_domain::{
    AccessPolicy, Admission, AuthFailureReason, CertClaims, CertRef, ClientCredential, CloseReason,
    DomainEvent, Fingerprint, Frame, NodeId, RejectReason, SessionId, StreamId, UnixTime,
};

use crate::ratelimit::TokenBucket;

/// Identifier of an authenticated connection, assigned by the network adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// The clock as seen by the core: monotonic for timeouts, system (UTC) for certificates
/// (PROTOCOL §15.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Monotonic time.
    pub instant: Instant,
    /// System time, in Unix seconds.
    pub unix: UnixTime,
}

/// Input events to the relay core.
#[derive(Debug)]
pub enum Input {
    /// Handshake completed: `peer` is the identity proven by Noise.
    Connected {
        /// The connection.
        conn: ConnId,
        /// The peer's identity.
        peer: Fingerprint,
        /// The certificate presented in message 1, already verified (steps 3–6 of
        /// PROTOCOL §15.4); `None` without a certificate.
        certificate: Option<Arc<CertClaims>>,
    },
    /// Well-formed frame received on a connection.
    Received {
        /// The connection.
        conn: ConnId,
        /// The frame.
        frame: Frame,
    },
    /// The connection dropped.
    Disconnected {
        /// The connection.
        conn: ConnId,
    },
    /// Periodic clock tick, for deadlines.
    Tick,
    /// A new policy was loaded: it also applies to connections already open.
    PolicyUpdated {
        /// The new policy.
        policy: Arc<AccessPolicy>,
    },
}

/// Actions the network adapter must execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send a frame.
    Send {
        /// The destination connection.
        conn: ConnId,
        /// The frame.
        frame: Frame,
    },
    /// Close the connection. The core has already freed its resources.
    Close {
        /// The connection.
        conn: ConnId,
    },
    /// Record an audit event.
    Audit(DomainEvent),
}

/// Port to a source of session identifiers (CSPRNG in the adapter).
pub trait SessionIds {
    /// A new identifier, unique with overwhelming probability.
    fn next_session_id(&mut self) -> SessionId;
}

/// Relay limits. The defaults are designed for an Ansible fleet.
#[derive(Debug, Clone)]
pub struct RelayLimits {
    /// Concurrent streams per client connection.
    pub max_streams_per_client: usize,
    /// Concurrent streams per agent.
    pub max_streams_per_agent: usize,
    /// Time granted to an agent to send `Register`.
    pub register_timeout: Duration,
    /// `Ping`s allowed in a burst.
    pub ping_burst: u32,
    /// One more `Ping` every `ping_refill`.
    pub ping_refill: Duration,
    /// `Open`s allowed in a burst per client connection.
    pub open_burst: u32,
    /// One more `Open` every `open_refill`.
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
        /// The credential with which the client was admitted: a connection with a certificate
        /// keeps only the verified data, never the certificate bytes.
        credential: ClientCredential,
    },
}

/// The audit reference of a credential: `None` for the whitelist.
fn cert_ref(credential: &ClientCredential) -> Option<CertRef> {
    match credential {
        ClientCredential::Key => None,
        ClientCredential::Certificate(claims) => Some(claims.reference()),
    }
}

/// Streams recently closed by a client, for which in-flight frames are to be silently
/// discarded.
///
/// Agent-side streams do not need this: their ids increase and are never reused, so every id
/// below `next_stream` that is no longer open is necessarily a closed stream.
#[derive(Debug, Default)]
struct RecentlyClosed {
    order: VecDeque<StreamId>,
    set: HashSet<StreamId>,
}

impl RecentlyClosed {
    /// How many ids to remember. A client that closes more while in flight only loses its own
    /// stream.
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
    /// `true` if `stream` existed on this connection and was closed: a frame on it is a
    /// normal in-flight frame, not a violation (finding 0002-1, -2, -6).
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

/// One direction of a route: from side `(conn, stream)` toward `peer`.
#[derive(Debug)]
struct Route {
    peer: (ConnId, StreamId),
    state: StreamState,
    session: SessionId,
    client: Fingerprint,
    target: NodeId,
    /// The client's certificate, for audit (`None` for the whitelist).
    certificate: Option<CertRef>,
    /// Credit this side has to send `Data` toward `peer`.
    send: Window,
}

type Violation = &'static str;

/// Relay state machine. See the module documentation.
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
    /// A relay with no connections.
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

    /// Number of active route directions (two per stream).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Number of tracked connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    /// Processes an event and returns the actions to execute, in order.
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
        // Steps 1, 5 and 7–11 of PROTOCOL §15.4 rechecked with the policy and clock at the
        // moment the connection reaches the core: a reload in the meantime is not lost.
        let role = match self.policy.admit(&peer, certificate, now.unix) {
            Err(reason) => {
                out.push(Output::Audit(DomainEvent::AuthenticationFailed {
                    peer: Some(peer),
                    reason,
                    // The claims come from the signature verification in `zt-crypto`.
                    certificate: reason.certificate_ref(certificate.map(AsRef::as_ref)),
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
        // PROTOCOL §15.7: a session authorized by a certificate ends at expiry, according to
        // the system clock (not the monotonic one).
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

    /// Closes with `Close Unauthorized`, on both sides, every stream of `conn` toward a node
    /// for which `keep` is false; returns the lost nodes.
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
                    // In-flight frame on an already closed stream: discard it.
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
                        // The credit granted by this side enables sending on the opposite side.
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
                certificate: None,
            }));
            self.teardown(conn, out);
            out.push(Output::Close { conn });
            return Ok(());
        }
        *registered = true;
        if let Some(old) = self.agents.insert(node.clone(), conn)
            && old != conn
        {
            // New connection from the same agent (reconnection): the old one is drained.
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
        // Every `Open` costs the agent work and an audit line: its rate is limited, before
        // any other check (finding 0002-4).
        if !c.opens.try_take(now.instant) {
            out.push(reject(RejectReason::RateLimited));
            return Ok(());
        }
        c.closed.reopen(stream);
        // Authorization first: "denied" and "nonexistent" must be indistinguishable.
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

    /// Removes both directions of a route and returns it (`conn` side).
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

    /// Applies a new policy to the open connections (hot revocation, PROTOCOL §12 and §15.8).
    fn on_policy(&mut self, policy: Arc<AccessPolicy>, now: UnixTime, out: &mut Vec<Output>) {
        self.policy = policy;
        let mut ids: Vec<ConnId> = self.conns.keys().copied().collect();
        ids.sort_unstable();
        for conn in ids {
            let Some(c) = self.conns.get(&conn) else {
                continue;
            };
            let peer = c.peer;
            // Is the saved credential still valid with the new policy? (denylist, CA still
            // pinned per key, maximum lifetime, role.)
            let (keeps, credential) = match &c.role {
                Role::Agent { node, .. } => (
                    matches!(
                        self.policy.admit(&peer, None, now),
                        Ok(Admission::Agent { node: current }) if current == node
                    ),
                    None,
                ),
                Role::Client { credential } => match credential {
                    ClientCredential::Key => (
                        matches!(
                            self.policy.admit(&peer, None, now),
                            Ok(Admission::Client {
                                credential: ClientCredential::Key
                            })
                        ),
                        Some(ClientCredential::Key),
                    ),
                    // The whitelist takes precedence over open connections too (PROTOCOL §15.5,
                    // finding 0006-4): if the key has entered the whitelist the connection switches
                    // to the `Key` credential and its permissions, even if they are narrower than
                    // the certificate's.
                    ClientCredential::Certificate(claims) => {
                        match self.policy.admit(&peer, Some(claims), now) {
                            Ok(Admission::Client { credential }) => (true, Some(credential)),
                            _ => (false, Some(credential.clone())),
                        }
                    }
                },
            };
            // The certificate fields with which the connection has been authorized so far.
            let certificate = match &c.role {
                Role::Client { credential } => cert_ref(credential),
                Role::Agent { .. } => None,
            };
            if !keeps {
                out.push(Output::Audit(DomainEvent::AccessRevoked {
                    peer,
                    target: None,
                    certificate,
                }));
                // A revoked certificate closes its streams with `Close Unauthorized` (PROTOCOL
                // §15.8); a peer that loses its whitelist entry closes them as before (§12).
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
            if let Some(Conn {
                role: Role::Client { credential: held },
                ..
            }) = self.conns.get_mut(&conn)
            {
                // A connection switched to the whitelist no longer expires with the certificate.
                held.clone_from(&credential);
            }
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

    /// Frees all resources of a connection and notifies the counterparts of its streams.
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

/// Allocates a new stream on an agent's connection, if there is room.
fn allocate_stream(agent: &mut Conn, max_streams: usize) -> Option<StreamId> {
    if agent.streams.len() >= max_streams {
        return None;
    }
    let Role::Agent { next_stream, .. } = &mut agent.role else {
        return None;
    };
    // Ids increase and are never reused: no confusion with late frames from a closed
    // stream. At 2^32 streams the connection must be recreated.
    let id = StreamId::try_from(*next_stream).ok()?;
    *next_stream = next_stream.checked_add(1)?;
    agent.streams.insert(id);
    Some(id)
}
