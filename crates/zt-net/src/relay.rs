//! Relay server.
//!
//! ```text
//!  accept ─▶ admission (pre-auth pool, per-source ─▶ connection task: message 1, policy,
//!            budget, PROTOCOL §10.1)                 suite, message 2, first authentic frame
//!                                                    (key confirmation), recv/send
//!                         Input ▼  ▲ Frame (bounded queue per connection)
//!                          hub: RelayCore (sole owner of the state)
//! ```
//!
//! The hub never waits on a connection: if a connection's queue is full (impossible for a peer
//! that respects the credit) that connection is closed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio::time::{timeout, timeout_at};
use zt_application::admission::{
    Admission, AdmissionConfig, IdentityEvent, PreauthFailure, PreauthSummary, Refusal,
    RepeatedEvent, Ticket, is_known_identity,
};
use zt_application::efficiency::{Backlog, Shed, ShedLimits, shed_victim};
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_crypto::Keyring;
use zt_crypto::noise::Channel;
use zt_domain::flow::{MAX_WINDOW, MIN_CHARGE, MIN_WINDOW_UPDATE};
use zt_domain::{
    AccessPolicy, AuthFailureReason, CertClaims, CertRef, CloseReason, DomainEvent, Fingerprint,
    Frame, HandshakeSuite, HybridFingerprint, InitiatorRole, PeerRole, RejectReason, SessionId,
    SuitePolicy,
};

use crate::budget::{ByteBudget, Charge};
use crate::lifecycle::Progress;
use crate::metrics::{RelayMetrics, RoleLabel, auth_reason};
use crate::net::Acceptor;
use crate::{NetError, Timeouts, channel, lock};
use zt_application::lifecycle::{DrainController, DrainStep};

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Relay core limits.
    pub limits: RelayLimits,
    /// Network timeouts (write and idle; the handshake deadlines are in `admission`).
    pub timeouts: Timeouts,
    /// Admission limits (PROTOCOL §10.1).
    pub admission: AdmissionConfig,
    /// Handshake suites accepted per role (PROTOCOL §7.5).
    pub suites: SuitePolicy,
    /// Idle timeout of agent connections; `None`: `timeouts.idle` (resilience R-2).
    pub agent_idle: Option<Duration>,
    /// Idle timeout of client connections; `None`: `timeouts.idle`.
    pub client_idle: Option<Duration>,
    /// Where the relay counts what it does (R-5): written as a textfile by
    /// [`crate::metrics::export`], never served on a socket.
    pub metrics: Arc<RelayMetrics>,
    /// The global byte budget of the frames queued towards peers (R-6, D-13): past it, the
    /// identity holding the most of it (the slowest reader) loses its largest connection, and
    /// no identity may hold more than a quarter of it (review 0013, A13-1).
    pub queue_budget: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            limits: RelayLimits::default(),
            timeouts: Timeouts::default(),
            admission: AdmissionConfig::default(),
            suites: SuitePolicy::classical(),
            agent_idle: None,
            client_idle: None,
            metrics: RelayMetrics::new(),
            queue_budget: crate::budget::default_queue_budget(),
        }
    }
}

/// The monotonic clock of the runtime, as `std`: the real clock in production, the simulated
/// one under `turmoil` or paused tokio time, so that every deadline of the relay follows the
/// same clock.
fn mono_now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

/// An audit line (`target: "zt_audit"`), at WARN level for an alarm and INFO otherwise.
macro_rules! audit_line {
    ($alert:expr, $kind:expr, $($fields:tt)*) => {
        if $alert {
            tracing::warn!(target: "zt_audit", event_kind = $kind, $($fields)*);
        } else {
            tracing::info!(target: "zt_audit", event_kind = $kind, $($fields)*);
        }
    };
}

/// `authentication_failed`: the certificate fields only after the signature has been verified
/// (PROTOCOL §15.11, finding 0006-3); without a certificate they are empty and do not appear.
fn authentication_failed(
    alert: bool,
    kind: &'static str,
    peer: Option<&Fingerprint>,
    reason: AuthFailureReason,
    certificate: Option<&CertRef>,
) {
    let (reason, cert_check) = failure_fields(reason);
    let peer = peer.map(ToString::to_string);
    let c = CertFields::of(certificate);
    audit_line!(
        alert,
        kind,
        peer = peer.as_deref(),
        reason = reason.as_str(),
        cert_check,
        ca = c.ca.as_deref(),
        serial = c.serial.as_deref(),
        cert_name = c.cert_name.as_deref(),
        cert_version = c.cert_version,
        not_after = c.not_after,
        "authentication failed"
    );
}

/// Logs an audit event. Events contain only identities and metadata.
///
/// `event_kind` is the stable name of the event ([`DomainEvent::kind`]), for a SIEM to filter
/// on; the other data are separate fields (`peer`, `node`, `session`, `reason`, `rule`), not a
/// `Debug` string to be parsed (finding 0004-4).
#[allow(clippy::too_many_lines)] // one flat arm per event kind
pub(crate) fn audit(event: &DomainEvent) {
    let kind = event.kind();
    let alert = event.is_security_alert();
    macro_rules! emit {
        ($($fields:tt)*) => { audit_line!(alert, kind, $($fields)*) };
    }
    match event {
        DomainEvent::AgentRegistered { node, fingerprint } => {
            emit!(peer = %fingerprint, %node, "agent registered");
        }
        DomainEvent::SessionEstablished {
            session,
            client,
            client_v2,
            target,
            certificate,
        } => {
            let c = CertFields::of(certificate.as_ref());
            let peer_v2 = client_v2.as_ref().map(ToString::to_string);
            emit!(
                session = %session_hex(session),
                peer = %client,
                peer_v2 = peer_v2.as_deref(),
                node = %target,
                credential = c.credential,
                ca = c.ca.as_deref(),
                serial = c.serial.as_deref(),
                cert_name = c.cert_name.as_deref(),
                cert_version = c.cert_version,
                not_after = c.not_after,
                "session established"
            );
        }
        DomainEvent::AuthenticationFailed {
            peer,
            reason,
            certificate,
        } => authentication_failed(alert, kind, peer.as_ref(), *reason, certificate.as_ref()),
        DomainEvent::AccessDenied {
            client,
            target,
            certificate,
        } => {
            let c = CertFields::of(certificate.as_ref());
            emit!(
                peer = %client,
                node = %target,
                credential = c.credential,
                ca = c.ca.as_deref(),
                serial = c.serial.as_deref(),
                cert_name = c.cert_name.as_deref(),
                cert_version = c.cert_version,
                not_after = c.not_after,
                "access denied"
            );
        }
        DomainEvent::ProtocolViolation { peer, rule } => {
            emit!(%peer, rule = *rule, "protocol violation");
        }
        DomainEvent::ConnectionDrained { session, reason } => {
            emit!(session = %session_hex(session), ?reason, "connection drained");
        }
        DomainEvent::AccessRevoked {
            peer,
            target,
            certificate,
        } => {
            let c = CertFields::of(certificate.as_ref());
            let node = target.as_ref().map(ToString::to_string);
            emit!(
                %peer,
                node = node.as_deref(),
                credential = c.credential,
                ca = c.ca.as_deref(),
                serial = c.serial.as_deref(),
                cert_name = c.cert_name.as_deref(),
                cert_version = c.cert_version,
                not_after = c.not_after,
                "access revoked"
            );
        }
        DomainEvent::CertificateExpired { peer, certificate } => {
            let c = CertFields::of(Some(certificate));
            emit!(
                %peer,
                ca = c.ca.as_deref(),
                serial = c.serial.as_deref(),
                cert_name = c.cert_name.as_deref(),
                cert_version = c.cert_version,
                not_after = c.not_after,
                "certificate expired"
            );
        }
        // Written before any proof that the peer is live (there is no message 2, so no
        // confirmation): a replayed message 1 produces it too (finding A9-2).
        DomainEvent::HandshakeSuiteRejected { peer, suite } => {
            emit!(
                %peer,
                suite = suite.protocol_name(),
                confirmed = false,
                "handshake suite rejected"
            );
        }
        // A hybrid peer admitted by a v1 entry (pq.md §4.6): the configuration checked only
        // its X25519 key. Written after key confirmation.
        DomainEvent::ClassicalIdentityMatch { peer, peer_v2 } => {
            emit!(%peer, %peer_v2, "hybrid identity matched by a classical entry");
        }
        DomainEvent::AgentFlapping {
            node,
            fingerprint,
            count,
        } => {
            emit!(peer = %fingerprint, %node, count = *count, "agent flapping");
        }
        // `DomainEvent` is `non_exhaustive`: a new event at least stays readable.
        other => emit!(event = ?other, "audit event"),
    }
}

/// The audit fields of a credential (PROTOCOL §15.11): never the certificate bytes, only the
/// CA, the serial, the name and the expiry.
pub(crate) struct CertFields {
    /// `key` or `certificate`.
    pub(crate) credential: &'static str,
    pub(crate) ca: Option<String>,
    pub(crate) serial: Option<String>,
    pub(crate) cert_name: Option<String>,
    pub(crate) not_after: Option<u64>,
    /// 1 or 2 (PQ-AUTH): which certificate format admitted the peer.
    pub(crate) cert_version: Option<u8>,
}

impl CertFields {
    pub(crate) fn of(certificate: Option<&CertRef>) -> Self {
        match certificate {
            None => Self {
                credential: "key",
                ca: None,
                serial: None,
                cert_name: None,
                not_after: None,
                cert_version: None,
            },
            Some(c) => Self {
                credential: "certificate",
                ca: Some(c.ca.to_string()),
                serial: Some(c.serial.to_string()),
                cert_name: Some(c.name.to_string()),
                not_after: Some(c.not_after.as_secs()),
                cert_version: Some(c.version),
            },
        }
    }
}

/// `reason` and `cert_check` of an `authentication_failed`. Reasons that predate Phase 6 keep
/// their usual form (`UnknownPeer`, ...), so as not to break existing filters.
fn failure_fields(reason: AuthFailureReason) -> (String, Option<&'static str>) {
    match reason {
        AuthFailureReason::KeyRevoked => ("key_revoked".into(), None),
        AuthFailureReason::IdentityDowngrade => ("identity_downgrade".into(), None),
        AuthFailureReason::Certificate(check) => ("certificate".into(), Some(check.as_str())),
        other => (format!("{other:?}"), None),
    }
}

/// The session id in hexadecimal, as it appears in the logs.
pub(crate) fn session_hex(session: &SessionId) -> String {
    session
        .as_bytes()
        .iter()
        .fold(String::with_capacity(32), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Session id from the system CSPRNG.
struct RandomIds {
    fallback: u64,
}

impl SessionIds for RandomIds {
    fn next_session_id(&mut self) -> SessionId {
        let mut bytes = [0_u8; SessionId::LEN];
        loop {
            if getrandom::fill(&mut bytes).is_err() {
                // Without a CSPRNG a counter is used: unique within the process, not secret
                // (the session id is an audit identifier, not a credential).
                self.fallback = self.fallback.wrapping_add(1);
                bytes = [0; SessionId::LEN];
                if let Some(head) = bytes.get_mut(..8) {
                    head.copy_from_slice(&self.fallback.to_be_bytes());
                }
            }
            if let Ok(id) = SessionId::from_bytes(bytes) {
                return id;
            }
        }
    }
}

enum HubEvent {
    Connected {
        conn: ConnId,
        peer: Fingerprint,
        hybrid: Option<HybridFingerprint>,
        certificate: Option<Arc<CertClaims>>,
        queue: PeerQueue,
    },
    Core(Input),
}

/// A frame queued towards a peer, charged to the global byte budget until written.
struct Queued {
    frame: Frame,
    _charge: QueueCharge,
}

/// Bytes of a queued frame, counted in the global budget, in its connection's backlog and in
/// its identity's.
struct QueueCharge {
    _global: Charge,
    backlog: Arc<AtomicUsize>,
    identity: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for QueueCharge {
    fn drop(&mut self) {
        self.backlog.fetch_sub(self.bytes, Ordering::AcqRel);
        self.identity.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// The hub's side of a connection's outbound queue.
struct PeerQueue {
    /// The authenticated identity of the peer: the budget is shared fairly per identity.
    identity: Fingerprint,
    tx: mpsc::Sender<Queued>,
    /// Bytes queued and not yet written.
    backlog: Arc<AtomicUsize>,
    /// Bytes queued towards every connection of the identity (set by [`Queues::connected`]).
    identity_backlog: Arc<AtomicUsize>,
    /// Wakes the connection task when the budget sheds it, even in the middle of a write.
    shed: Arc<Notify>,
}

/// The connection task's side of its outbound queue.
struct OwnQueue {
    rx: mpsc::Receiver<Queued>,
    shed: Arc<Notify>,
}

impl PeerQueue {
    fn new(identity: Fingerprint, frames: usize) -> (Self, OwnQueue) {
        let (tx, rx) = mpsc::channel(frames);
        let shed = Arc::new(Notify::new());
        (
            Self {
                identity,
                tx,
                backlog: Arc::new(AtomicUsize::new(0)),
                identity_backlog: Arc::new(AtomicUsize::new(0)),
                shed: Arc::clone(&shed),
            },
            OwnQueue { rx, shed },
        )
    }

    fn backlog(&self) -> usize {
        self.backlog.load(Ordering::Acquire)
    }
}

/// What a queued frame weighs in the budget: a `Data` payload (at least the minimum charge of
/// the flow control); control frames are bounded by their count and weigh nothing.
fn queued_bytes(frame: &Frame) -> usize {
    match frame {
        Frame::Data { payload, .. } => {
            usize::try_from(zt_domain::flow::charge(payload.len())).unwrap_or(usize::MAX)
        }
        _ => 0,
    }
}

/// The relay's outbound queues against the global byte budget.
struct Queues {
    peers: HashMap<ConnId, PeerQueue>,
    budget: Arc<ByteBudget>,
    limits: ShedLimits,
    /// Bytes queued per identity, shared by its connections' queues.
    identities: HashMap<Fingerprint, Arc<AtomicUsize>>,
    /// Shed connections whose queued frames are not released yet: not counted twice, so one
    /// slow reader never costs another connection its place.
    shedding: Vec<(ConnId, Arc<AtomicUsize>)>,
}

impl Queues {
    fn new(budget: Arc<ByteBudget>, limits: ShedLimits) -> Self {
        Self {
            peers: HashMap::new(),
            budget,
            limits,
            identities: HashMap::new(),
            shedding: Vec::new(),
        }
    }

    /// A connection joined: its queue counts towards its identity's backlog.
    fn connected(&mut self, conn: ConnId, mut queue: PeerQueue) {
        queue.identity_backlog = Arc::clone(
            self.identities
                .entry(queue.identity)
                .or_insert_with(|| Arc::new(AtomicUsize::new(0))),
        );
        self.peers.insert(conn, queue);
    }

    /// Detaches a connection: its queued frames are still written, then it closes.
    fn detach(&mut self, conn: ConnId) {
        self.peers.remove(&conn);
    }

    /// Forgets the identities with no connection and nothing queued (every tick).
    fn sweep(&mut self) {
        self.identities.retain(|_, b| Arc::strong_count(b) > 1);
    }

    /// Queues `frame` for `conn`; `false` if the queue is full or gone.
    fn send(&self, conn: ConnId, frame: Frame) -> Option<bool> {
        let peer = self.peers.get(&conn)?;
        let bytes = queued_bytes(&frame);
        peer.backlog.fetch_add(bytes, Ordering::AcqRel);
        peer.identity_backlog.fetch_add(bytes, Ordering::AcqRel);
        let charge = QueueCharge {
            _global: self.budget.charge(bytes),
            backlog: Arc::clone(&peer.backlog),
            identity: Arc::clone(&peer.identity_backlog),
            bytes,
        };
        Some(
            peer.tx
                .try_send(Queued {
                    frame,
                    _charge: charge,
                })
                .is_ok(),
        )
    }

    /// Past the budget, or past an identity's share of it, the largest connection of the
    /// identity that holds the most ([`shed_victim`]), detached and woken; with its backlog.
    /// `is_agent` tells the agents, whose normal credit is shed only as a last resort.
    /// `sent_to` is the connection a frame was just queued for: only its identity can have
    /// gone over its share, so the full scan runs only then or past the budget.
    fn shed(
        &mut self,
        sent_to: ConnId,
        is_agent: impl Fn(ConnId) -> bool,
    ) -> Option<(Shed<Fingerprint>, usize)> {
        let over_share = self
            .peers
            .get(&sent_to)
            .is_some_and(|p| p.identity_backlog.load(Ordering::Acquire) > self.limits.identity_cap);
        if !over_share && !self.budget.exceeded() {
            return None;
        }
        self.shedding.retain(|(_, b)| b.load(Ordering::Acquire) > 0);
        let releasing: usize = self
            .shedding
            .iter()
            .map(|(_, b)| b.load(Ordering::Acquire))
            .sum();
        let total = self.budget.used().saturating_sub(releasing);
        let victim = shed_victim(
            total,
            &self.limits,
            self.peers.iter().map(|(&conn, p)| Backlog {
                conn,
                identity: p.identity,
                agent: is_agent(conn),
                bytes: p.backlog(),
            }),
        )?;
        let peer = self.peers.remove(&victim.conn)?;
        let backlog = peer.backlog();
        peer.shed.notify_one();
        self.shedding.push((victim.conn, peer.backlog));
        Some((victim, backlog))
    }
}

/// Reports the queue budget at startup, and warns when it is below two agents' full credit
/// (A13-1): then a single agent holding its normal credit is close to the whole budget.
fn queue_budget_in_use(budget: usize, limits: &RelayLimits) {
    let agent_credit = crate::budget::agent_credit(limits.max_streams_per_agent);
    let shed = shed_limits(budget, limits);
    if budget < agent_credit.saturating_mul(2) {
        audit_line!(
            true,
            "queue_budget_below_agent_credit",
            budget,
            agent_credit,
            identity_cap = shed.identity_cap,
            "the queue budget is below two agents' full credit (OPERATIONS §18)"
        );
    } else {
        tracing::info!(
            budget,
            agent_credit,
            identity_cap = shed.identity_cap,
            "queue budget in use"
        );
    }
}

/// The shedding limits of `budget` under `limits` (review 0013, A13-1): one connection may
/// legitimately hold its streams × the largest window, an agent its own streams'.
fn shed_limits(budget: usize, limits: &RelayLimits) -> ShedLimits {
    let window = usize::try_from(MAX_WINDOW).unwrap_or(usize::MAX);
    let agent = crate::budget::agent_credit(limits.max_streams_per_agent);
    let conn = limits
        .max_streams_per_agent
        .max(limits.max_streams_per_client)
        .saturating_mul(window);
    ShedLimits::new(budget, conn, agent)
}

/// Outbound queue of a connection: the most that the credit allows to be enqueued.
fn outbound_capacity(limits: &RelayLimits) -> usize {
    let per_stream = MAX_WINDOW / MIN_CHARGE + MAX_WINDOW / MIN_WINDOW_UPDATE;
    let streams = limits
        .max_streams_per_agent
        .max(limits.max_streams_per_client);
    streams
        .saturating_mul(usize::try_from(per_stream).unwrap_or(usize::MAX))
        .saturating_add(1024)
}

/// The relay, ready to accept connections from `A` (TCP in production, see [`crate::net`]).
pub struct RelayServer<A = TcpListener> {
    listener: A,
    keys: crate::Revocable<Keyring>,
    policy: crate::Revocable<AccessPolicy>,
    config: RelayConfig,
    progress: Progress,
}

impl RelayServer<TcpListener> {
    /// Opens the listening socket.
    ///
    /// # Errors
    /// Bind error.
    pub async fn bind(
        addr: SocketAddr,
        keys: impl Into<crate::Revocable<Keyring>>,
        policy: impl Into<crate::Revocable<AccessPolicy>>,
        config: RelayConfig,
    ) -> Result<Self, NetError> {
        validate(&config)?;
        let listener = TcpListener::bind(addr).await?;
        RelayServer::with_acceptor(listener, keys, policy, config)
    }
}

/// The relay configuration checks of [`RelayServer::bind`].
fn validate(config: &RelayConfig) -> Result<(), NetError> {
    config.admission.validate()?;
    for set in [config.suites.agents, config.suites.clients] {
        if !set.all_supported(zt_domain::HandshakeChannel::Outer) {
            return Err(NetError::Suite(zt_domain::SuiteError::Unsupported));
        }
    }
    for idle in [config.agent_idle, config.client_idle]
        .into_iter()
        .flatten()
        .chain([config.timeouts.idle])
    {
        if idle.is_zero() {
            return Err(NetError::Protocol("an idle timeout must not be zero"));
        }
    }
    Ok(())
}

impl<A: Acceptor> RelayServer<A> {
    /// A relay on an already listening `acceptor` (the network port: TCP in production, a
    /// simulated network in tests).
    ///
    /// # Errors
    /// An invalid configuration.
    pub fn with_acceptor(
        listener: A,
        keys: impl Into<crate::Revocable<Keyring>>,
        policy: impl Into<crate::Revocable<AccessPolicy>>,
        config: RelayConfig,
    ) -> Result<Self, NetError> {
        validate(&config)?;
        let policy = policy.into();
        let keys = keys.into();
        // The socket already accepts connections (queued until `run`): it is announced here,
        // so whatever the process logs after `bind` always comes after this line.
        if let Ok(addr) = listener.local_addr() {
            tracing::info!(%addr, relay = %keys.current().current().fingerprint(), "relay listening");
        }
        Ok(Self {
            listener,
            keys,
            policy,
            progress: config.metrics.process().progress().clone(),
            config,
        })
    }

    /// The actual listening address.
    ///
    /// # Errors
    /// Operating system error.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.listener.local_addr()?)
    }

    /// The hub's progress counter, for the systemd watchdog (AP-4): it moves with every event
    /// the hub handles, its own one-second tick included.
    #[must_use]
    pub fn progress(&self) -> Progress {
        self.progress.clone()
    }

    /// Serves connections until the process exits.
    ///
    /// # Errors
    /// The hub stopped (see [`RelayServer::run_until`]).
    pub async fn run(self) -> Result<(), NetError> {
        self.run_until(
            std::future::pending(),
            crate::lifecycle::DEFAULT_DRAIN_TIMEOUT,
        )
        .await
    }

    /// Serves connections until `shutdown` resolves, then drains (PROTOCOL §13, OPERATIONS
    /// §14): the listening socket is closed at once, new streams on open connections are
    /// rejected with `NodeOffline`, open sessions go on (the policy and its revocations still
    /// apply) until the last one ends or `drain_timeout` passes; then the
    /// remaining streams get `Close Drained` and every connection is closed.
    ///
    /// # Errors
    /// The hub stopped on its own (a panic): the relay can no longer route anything, so it
    /// must not keep accepting connections.
    pub async fn run_until(
        self,
        shutdown: impl std::future::Future<Output = ()>,
        drain_timeout: Duration,
    ) -> Result<(), NetError> {
        let Self {
            mut listener,
            keys,
            policy,
            config,
            progress,
        } = self;
        let (hub_tx, hub_rx) = mpsc::channel(4096);
        let (drain_tx, drain_rx) = mpsc::channel(1);
        let core = RelayCore::new(
            policy.current(),
            config.limits.clone(),
            RandomIds { fallback: 0 },
        );
        let metrics = Arc::clone(&config.metrics);
        let mut hub_task = tokio::spawn(hub(
            core,
            hub_rx,
            policy.clone(),
            progress,
            drain_rx,
            Arc::clone(&metrics),
            shed_limits(config.queue_budget, &config.limits),
        ));
        // One clone per live connection task: the drain waits for them to flush.
        let live = Arc::new(());
        tokio::pin!(shutdown);

        audit_line!(
            false,
            "handshake_suites_in_use",
            agent_suites = config.suites.agents.names(),
            client_suites = config.suites.clients.names(),
            "handshake suites in use"
        );
        admission_limits_in_use(&config.admission);
        queue_budget_in_use(config.queue_budget, &config.limits);
        let admission = Arc::new(Mutex::new(Admission::new(
            config.admission.clone(),
            mono_now(),
        )));
        let confirmed = Arc::new(ConfirmedSuites::default());
        tokio::spawn(summaries(
            Arc::downgrade(&admission),
            Arc::clone(&confirmed),
            config.admission.summary_interval,
        ));
        let capacity = outbound_capacity(&config.limits);
        let mut next_conn: u64 = 0;
        loop {
            let accepted = tokio::select! {
                () = &mut shutdown => break,
                joined = &mut hub_task => {
                    tracing::error!(?joined, "relay hub stopped");
                    return Err(NetError::Stopped("relay hub"));
                }
                accepted = listener.accept() => accepted,
            };
            let (tcp, addr) = match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // E.g. EMFILE: back off instead of spinning.
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // A refusal is counted in the summary; the connection is dropped without a reply.
            let admitted = lock(&admission).on_accept(addr.ip(), mono_now());
            let Ok(ticket) = admitted.inspect_err(|r| metrics.preauth_failure(r.as_str())) else {
                tracing::debug!(%addr, "connection not admitted");
                continue;
            };
            let admitted = Admitted {
                admission: Arc::clone(&admission),
                ticket,
                source: addr.ip(),
                metrics: Arc::clone(&metrics),
            };
            next_conn = next_conn.wrapping_add(1);
            let conn = ConnId(next_conn);
            let task = Connection {
                conn,
                // The keys in force at accept time: a reload applies to subsequent
                // connections.
                keys: keys.current(),
                policy: policy.clone(),
                hub: hub_tx.clone(),
                timeouts: config.timeouts.clone(),
                admission: config.admission.clone(),
                suites: config.suites,
                agent_idle: config.agent_idle.unwrap_or(config.timeouts.idle),
                client_idle: config.client_idle.unwrap_or(config.timeouts.idle),
                confirmed: Arc::clone(&confirmed),
                metrics: Arc::clone(&metrics),
                _live: Arc::clone(&live),
                capacity,
            };
            tokio::spawn(task.serve(tcp, addr, admitted));
        }
        metrics.process().set_draining(true);
        let drained = drain(listener, hub_task, &drain_tx, drain_timeout, &live).await;
        // The last interval's confirmed handshakes are not lost at shutdown (A10-10).
        confirmed.flush();
        drained
    }
}

/// The drain after `shutdown` (see [`RelayServer::run_until`]).
async fn drain<A>(
    listener: A,
    hub_task: tokio::task::JoinHandle<DrainOutcome>,
    drain_tx: &mpsc::Sender<Duration>,
    drain_timeout: Duration,
    live: &Arc<()>,
) -> Result<(), NetError> {
    // New connections are refused from now on (connection refused, not a timeout): clients
    // and agents go to another relay at once.
    drop(listener);
    crate::systemd::notify("STOPPING=1");
    crate::systemd::status("draining");
    audit_line!(
        false,
        "relay_draining",
        timeout_secs = drain_timeout.as_secs(),
        "relay draining: no new connections"
    );
    if drain_tx.send(drain_timeout).await.is_err() {
        return Err(NetError::Stopped("relay hub"));
    }
    let outcome = hub_task.await.map_err(|_| NetError::Stopped("relay hub"))?;
    // The connection tasks flush what the hub queued (the `Close Drained` frames) and end.
    let flushed = crate::deadline(Duration::from_secs(2));
    while Arc::strong_count(live) > 1 && tokio::time::Instant::now() < flushed {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    audit_line!(
        false,
        "relay_drained",
        expired = outcome.expired,
        streams_closed = outcome.closed,
        "relay drained"
    );
    Ok(())
}

struct Connection {
    conn: ConnId,
    keys: Arc<Keyring>,
    policy: crate::Revocable<AccessPolicy>,
    hub: mpsc::Sender<HubEvent>,
    timeouts: Timeouts,
    admission: AdmissionConfig,
    suites: SuitePolicy,
    agent_idle: Duration,
    client_idle: Duration,
    confirmed: Arc<ConfirmedSuites>,
    metrics: Arc<RelayMetrics>,
    /// Counts the live connection tasks for the drain.
    _live: Arc<()>,
    capacity: usize,
}

/// Confirmed outer handshakes per role and suite in the current summary interval: the
/// sunset signal of OPERATIONS §13, without identities. Only key confirmation counts, so a
/// replayed message 1 cannot inflate it.
#[derive(Default)]
struct ConfirmedSuites {
    counts: Mutex<HashMap<(InitiatorRole, HandshakeSuite), u64>>,
}

impl ConfirmedSuites {
    fn note(&self, role: InitiatorRole, suite: HandshakeSuite) {
        let mut counts = lock(&self.counts);
        let n = counts.entry((role, suite)).or_insert(0);
        *n = n.saturating_add(1);
    }

    /// `outer_suites_confirmed` for the interval that ended, if anything was confirmed.
    fn flush(&self) {
        let counts = std::mem::take(&mut *lock(&self.counts));
        if counts.is_empty() {
            return;
        }
        let n = |role, suite| counts.get(&(role, suite)).copied();
        let (agent, client) = (InitiatorRole::Agent, InitiatorRole::Client);
        let (classical, hybrid) = (
            HandshakeSuite::NoiseIk25519,
            HandshakeSuite::NoiseIkhfs25519MlKem768,
        );
        tracing::info!(
            target: "zt_audit",
            event_kind = "outer_suites_confirmed",
            agents_classical = n(agent, classical),
            agents_hybrid = n(agent, hybrid),
            clients_classical = n(client, classical),
            clients_hybrid = n(client, hybrid),
            "confirmed outer handshakes per role and suite"
        );
    }
}

/// One admitted connection: its admission ticket is released when the connection ends, on
/// every path.
struct Admitted {
    admission: Arc<Mutex<Admission>>,
    ticket: Ticket,
    source: IpAddr,
    metrics: Arc<RelayMetrics>,
}

impl Admitted {
    fn record(&self, failure: PreauthFailure, key: Option<Fingerprint>) {
        self.metrics.preauth_failure(failure.as_str());
        lock(&self.admission).record(failure, self.source, key);
    }

    /// Key confirmation: `Ok` if the connection may join the established pool.
    fn confirm(&self, peer: Fingerprint, role: InitiatorRole) -> Result<(), Refusal> {
        lock(&self.admission).on_confirmed(self.ticket, peer, role, mono_now())
    }

    /// `true` if an audit event about the known identity `peer` is to be logged in full now
    /// (finding A8-2); otherwise it is counted for the `_repeated` line of the interval.
    fn log_identity(&self, peer: Fingerprint, event: IdentityEvent) -> bool {
        lock(&self.admission).note_identity_event(peer, event)
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        lock(&self.admission).release(self.ticket);
    }
}

/// How a failed message 1 is counted.
fn msg1_failure(err: &NetError) -> PreauthFailure {
    match err {
        NetError::Timeout(_) => PreauthFailure::Timeout,
        NetError::Oversized => PreauthFailure::Oversized,
        NetError::Closed | NetError::Io(_) => PreauthFailure::Aborted,
        _ => PreauthFailure::HandshakeFailed,
    }
}

/// The role of an admitted initiator: an agent if its key is an agent's, otherwise a client
/// (by key or certificate).
fn initiator_role(policy: &AccessPolicy, peer: &Fingerprint) -> InitiatorRole {
    match policy.role(peer) {
        Some(PeerRole::Agent { .. }) => InitiatorRole::Agent,
        _ => InitiatorRole::Client,
    }
}

/// The metrics label of an initiator role.
const fn role_label(role: InitiatorRole) -> RoleLabel {
    match role {
        InitiatorRole::Agent => RoleLabel::Agent,
        InitiatorRole::Client => RoleLabel::Client,
    }
}

/// Emits the aggregated `preauth_summary` (finding AP-3) until the relay goes away.
async fn summaries(
    admission: std::sync::Weak<Mutex<Admission>>,
    confirmed: Arc<ConfirmedSuites>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut next_flush = crate::deadline(interval);
    loop {
        tick.tick().await;
        if tokio::time::Instant::now() >= next_flush {
            confirmed.flush();
            next_flush = crate::deadline(interval);
        }
        let Some(admission) = admission.upgrade() else {
            return;
        };
        let summary = lock(&admission).poll_summary(mono_now());
        if let Some(summary) = summary {
            if summary.has_failures() {
                preauth_summary(&summary);
            }
            for repeated in &summary.repeated {
                repeated_line(repeated);
            }
        }
    }
}

/// The admission limits in force, once at startup (finding A8-8), like
/// `handshake_suites_in_use`.
fn admission_limits_in_use(c: &AdmissionConfig) {
    tracing::info!(
        target: "zt_audit",
        event_kind = "admission_limits_in_use",
        max_preauth = c.max_preauth,
        max_pending_per_source = c.max_pending_per_source,
        max_pending_per_wide = c.max_pending_per_wide,
        max_established = c.max_established,
        agent_reserve_percent = c.agent_reserve_percent,
        max_per_identity = c.max_per_identity,
        source_burst = c.source_burst,
        source_refill_secs = c.source_refill.as_secs(),
        wide_burst = c.wide_burst,
        wide_refill_secs = c.wide_refill.as_secs(),
        identity_refund_burst = c.identity_refund_burst,
        identity_refund_refill_ms = u64::try_from(c.identity_refund_refill.as_millis())
            .unwrap_or(u64::MAX),
        msg1_deadline_secs = c.msg1_deadline.as_secs(),
        handshake_timeout_secs = c.handshake_timeout.as_secs(),
        first_frame_deadline_secs = c.first_frame_deadline.as_secs(),
        summary_interval_secs = c.summary_interval.as_secs(),
        "admission limits in use"
    );
}

/// The `_repeated` line of an identity event (finding A8-2): who, what, and how many times
/// after the line logged in full during the interval. Also used by the agent (finding A9-2).
pub(crate) fn repeated_line(r: &RepeatedEvent) {
    let peer = r.peer.to_string();
    match r.event {
        IdentityEvent::AuthenticationFailed(reason) => {
            let (reason, cert_check) = failure_fields(reason);
            tracing::warn!(
                target: "zt_audit",
                event_kind = "authentication_failed_repeated",
                peer = %peer,
                reason = reason.as_str(),
                cert_check,
                count = r.count,
                "authentication failed, repeated"
            );
        }
        IdentityEvent::SuiteRejected(suite) => {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "handshake_suite_rejected_repeated",
                peer = %peer,
                suite = suite.protocol_name(),
                confirmed = false,
                count = r.count,
                "handshake suite rejected, repeated"
            );
        }
        IdentityEvent::AdmissionRefused(refusal) => {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "admission_refused_repeated",
                peer = %peer,
                reason = refusal.as_str(),
                count = r.count,
                "admission refused, repeated"
            );
        }
        // `IdentityEvent` is `non_exhaustive`: a new event at least stays readable.
        other => {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "identity_event_repeated",
                peer = %peer,
                event = ?other,
                count = r.count,
                "identity event, repeated"
            );
        }
    }
}

/// One flat field per failure kind (absent when zero), the distinct counts, never an
/// identity or an address.
fn preauth_summary(s: &PreauthSummary) {
    let n = |kind: PreauthFailure| {
        s.counts
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, count)| *count)
    };
    tracing::info!(
        target: "zt_audit",
        event_kind = "preauth_summary",
        rate_limited = n(PreauthFailure::RateLimited),
        source_limit = n(PreauthFailure::SourceLimit),
        preauth_pool_full = n(PreauthFailure::PreauthPoolFull),
        established_pool_full = n(PreauthFailure::EstablishedPoolFull),
        identity_limit = n(PreauthFailure::IdentityLimit),
        handshake_failed = n(PreauthFailure::HandshakeFailed),
        timeout = n(PreauthFailure::Timeout),
        oversized = n(PreauthFailure::Oversized),
        unknown_peer = n(PreauthFailure::UnknownPeer),
        unverified_certificate = n(PreauthFailure::UnverifiedCertificate),
        unconfirmed = n(PreauthFailure::Unconfirmed),
        aborted = n(PreauthFailure::Aborted),
        distinct_sources = s.distinct_sources,
        distinct_keys = s.distinct_keys,
        saturated = s.saturated,
        suppressed_identities = s.suppressed_identities,
        "pre-authentication failures"
    );
}

impl Connection {
    async fn serve<IO>(self, tcp: IO, addr: SocketAddr, admitted: Admitted)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let Some((ch, peer, certificate, first, role)) = self.handshake(tcp, addr, &admitted).await
        else {
            return;
        };
        // The idle timeout of the role (resilience R-2): agents ping every 10 s since R-2,
        // older ones every 30 s, so the agents' value is lowered only after the fleet upgrade.
        let idle = match role {
            InitiatorRole::Agent => self.agent_idle,
            InitiatorRole::Client => self.client_idle,
        };
        let _connected = self.metrics.connection(role_label(role));
        self.run(ch, peer, certificate, first, idle).await;
        drop(admitted);
    }

    /// Message 1 to key confirmation (PROTOCOL §10.1). Failures of unknown identities are only
    /// counted; a known identity gets its own audit line (finding AP-3).
    async fn handshake<IO>(
        &self,
        tcp: IO,
        addr: SocketAddr,
        admitted: &Admitted,
    ) -> Option<(
        channel::Established<IO>,
        Peer,
        Option<Arc<CertClaims>>,
        Frame,
        InitiatorRole,
    )>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let handshake_deadline = crate::deadline(self.admission.handshake_timeout);
        let deadlines = channel::AcceptDeadlines {
            msg1: self.admission.msg1_deadline,
        };
        let accepted = self.suites.any_role();
        let pending = match timeout_at(
            handshake_deadline,
            channel::accept_suites(tcp, &self.keys, Channel::Outer, accepted, deadlines),
        )
        .await
        {
            Ok(Ok(pending)) => pending,
            Ok(Err(err)) => {
                tracing::debug!(%addr, error = %err, "handshake failed");
                admitted.record(msg1_failure(&err), None);
                return None;
            }
            Err(_) => {
                admitted.record(PreauthFailure::Timeout, None);
                return None;
            }
        };
        let peer = pending.peer();
        // Claimed in message 1, proved at key confirmation (finding AP-12): before message 2
        // it can only refuse, never grant more than the X25519 key.
        let hybrid = pending.hybrid_peer();
        let policy = self.policy.current();
        // PROTOCOL §15.4, before message 2: a rejection is equivalent to an unknown key, which
        // does not even receive the second handshake message.
        let certificate = match admit(&policy, &peer, hybrid.as_ref(), pending.payload()) {
            Ok(certificate) => certificate,
            Err((reason, certificate)) => {
                if is_known_identity(&policy, &peer, reason) {
                    self.metrics.auth_failed(auth_reason(reason));
                    // Known, but a recorded message 1 replays it at will (finding A8-2).
                    if admitted.log_identity(peer, IdentityEvent::AuthenticationFailed(reason)) {
                        audit(&DomainEvent::AuthenticationFailed {
                            peer: Some(peer),
                            reason,
                            certificate,
                        });
                    }
                } else if matches!(reason, AuthFailureReason::Certificate(_)) {
                    admitted.record(PreauthFailure::UnverifiedCertificate, Some(peer));
                } else {
                    admitted.record(PreauthFailure::UnknownPeer, Some(peer));
                }
                return None;
            }
        };
        // The suite must be accepted for the role, not only for some role (PROTOCOL §7.5).
        let suite = pending.suite();
        let role = initiator_role(&policy, &peer);
        if self.suites.check(role, suite).is_err() {
            self.metrics.auth_failed("suite_rejected");
            if admitted.log_identity(peer, IdentityEvent::SuiteRejected(suite)) {
                audit(&DomainEvent::HandshakeSuiteRejected { peer, suite });
            }
            return None;
        }
        let mut ch = match timeout_at(handshake_deadline, pending.establish(&self.timeouts)).await {
            Ok(Ok(ch)) => ch,
            // Message 2 not written in time is a timeout, not a cut-off (finding A8-10).
            Ok(Err(NetError::Timeout(_))) | Err(_) => {
                admitted.record(PreauthFailure::Timeout, None);
                return None;
            }
            Ok(Err(_)) => {
                admitted.record(PreauthFailure::Aborted, None);
                return None;
            }
        };
        // Key confirmation (finding AP-1): message 2 proves nothing about the initiator, whose
        // message 1 may be a recording. Only an authentic transport frame does, and until then
        // the channel buffers no more than the largest legitimate first frame (finding A8-4).
        let first = match timeout(self.admission.first_frame_deadline, ch.recv()).await {
            Ok(Ok(Some(first))) => first,
            Ok(Err(NetError::Oversized)) => {
                admitted.record(PreauthFailure::Oversized, None);
                return None;
            }
            _ => {
                admitted.record(PreauthFailure::Unconfirmed, None);
                return None;
            }
        };
        if let Err(refusal) = admitted.confirm(peer, role) {
            tracing::debug!(%addr, %peer, "established pool or identity limit reached");
            self.refuse_confirmed(&mut ch, admitted, peer, refusal, &first)
                .await;
            return None;
        }
        ch.confirmed();
        self.confirmed.note(role, suite);
        self.metrics.handshake_confirmed(role_label(role), suite);
        tracing::debug!(%addr, %peer, conn = self.conn.0, ?suite, "peer connected");
        Some((
            ch,
            Peer {
                fingerprint: peer,
                hybrid,
            },
            certificate,
            first,
            role,
        ))
    }

    /// A confirmed identity refused at admission (finding A8-10): one rate-limited audit line
    /// that names it, and an answer to its `Open` (`Reject RateLimited`, which lets a client
    /// try the next relay) instead of a bare close.
    async fn refuse_confirmed<IO>(
        &self,
        ch: &mut channel::Established<IO>,
        admitted: &Admitted,
        peer: Fingerprint,
        refusal: Refusal,
        first: &Frame,
    ) where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.metrics.admission_refused(refusal.as_str());
        if admitted.log_identity(peer, IdentityEvent::AdmissionRefused(refusal)) {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "admission_refused",
                peer = %peer,
                reason = refusal.as_str(),
                "admission refused"
            );
        }
        if let Frame::Open { stream, .. } = first {
            let reject = Frame::Reject {
                stream: *stream,
                reason: RejectReason::RateLimited,
            };
            let _ = ch.send(&reject, &self.timeouts).await;
        }
    }

    async fn run<IO>(
        self,
        mut ch: channel::Established<IO>,
        peer: Peer,
        certificate: Option<Arc<CertClaims>>,
        first: Frame,
        idle: Duration,
    ) where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (queue, own) = PeerQueue::new(peer.fingerprint, self.capacity);
        let OwnQueue { mut rx, shed } = own;
        let conn = self.conn;
        if self
            .hub
            .send(HubEvent::Connected {
                conn,
                peer: peer.fingerprint,
                hybrid: peer.hybrid,
                certificate,
                queue,
            })
            .await
            .is_err()
        {
            return;
        }
        if self
            .hub
            .send(HubEvent::Core(Input::Received { conn, frame: first }))
            .await
            .is_err()
        {
            return;
        }
        let mut deadline = crate::deadline(idle);
        // Reads and writes stay in this one task (G11): while a write to a slow reader blocks,
        // its `WindowUpdate`s are not read either, so its queue stays within the credit.
        loop {
            tokio::select! {
                () = shed.notified() => break,
                inbound = timeout_at(deadline, ch.recv()) => {
                    let frame = match inbound {
                        Ok(Ok(Some(frame))) => frame,
                        Ok(Ok(None)) => break,
                        Ok(Err(err)) => {
                            tracing::debug!(conn = conn.0, error = %err, "connection error");
                            break;
                        }
                        Err(_) => {
                            tracing::debug!(conn = conn.0, "idle timeout");
                            break;
                        }
                    };
                    deadline = crate::deadline(idle);
                    if self.hub.send(HubEvent::Core(Input::Received { conn, frame })).await.is_err() {
                        break;
                    }
                }
                outbound = rx.recv() => {
                    let Some(queued) = outbound else { break };
                    // Shed by the byte budget: stop at once, even in the middle of a write.
                    let written = tokio::select! {
                        r = ch.send(&queued.frame, &self.timeouts) => r.is_ok(),
                        () = shed.notified() => false,
                    };
                    drop(queued);
                    if !written {
                        break;
                    }
                }
            }
        }
        // The queued frames give their bytes back to the budget now.
        drop(rx);
        let _ = self
            .hub
            .send(HubEvent::Core(Input::Disconnected { conn }))
            .await;
    }
}

/// The identities a confirmed initiator proved: its X25519-level fingerprint and, with the
/// hybrid IK suite, its fingerprint v2.
#[derive(Clone, Copy)]
struct Peer {
    fingerprint: Fingerprint,
    hybrid: Option<HybridFingerprint>,
}

/// The rejection from [`admit`]: the reason and, after signature verification, the certificate
/// (PROTOCOL §15.11).
type AdmitRefusal = (AuthFailureReason, Option<CertRef>);

/// Steps 1–11 of PROTOCOL §15.4 on the outer channel: key denylist, certificate verification
/// (if the payload is not empty) and policy decision. Returns the verified certificate data,
/// which the core re-checks against the current policy.
fn admit(
    policy: &AccessPolicy,
    peer: &Fingerprint,
    hybrid: Option<&HybridFingerprint>,
    payload: &[u8],
) -> Result<Option<Arc<CertClaims>>, AdmitRefusal> {
    let trust = policy.cert_trust();
    // Step 1, even without a certificate.
    if trust.is_key_revoked(peer) {
        return Err((AuthFailureReason::KeyRevoked, None));
    }
    // Steps 3–6 (step 2: empty payload, no certificate). A rejection here never names the CA
    // and serial: the signature has not been verified.
    let certificate = if payload.is_empty() {
        None
    } else {
        let claims = zt_crypto::verify_certificate_hybrid(payload, peer, hybrid, trust)
            .map_err(|check| (AuthFailureReason::Certificate(check), None))?;
        Some(Arc::new(claims))
    };
    // Steps 5 and 7–11 and the precedence of the whitelist.
    policy
        .admit_hybrid(
            peer,
            hybrid,
            certificate.as_ref(),
            crate::lifecycle::certificate_now(),
        )
        .map_err(|reason| (reason, reason.certificate_ref(certificate.as_deref())))?;
    Ok(certificate)
}

/// How a drain ended.
#[derive(Debug, Clone, Copy, Default)]
struct DrainOutcome {
    /// Streams were still open at the deadline.
    expired: bool,
    /// The streams closed with `Close Drained`.
    closed: usize,
}

/// Every how many ticks the hub writes its `STATUS=` line.
const STATUS_TICKS: u64 = 10;

async fn hub(
    mut core: RelayCore<RandomIds>,
    mut events: mpsc::Receiver<HubEvent>,
    mut policy: crate::Revocable<AccessPolicy>,
    progress: Progress,
    mut drain_rx: mpsc::Receiver<Duration>,
    metrics: Arc<RelayMetrics>,
    limits: ShedLimits,
) -> DrainOutcome {
    let budget = ByteBudget::new(limits.budget);
    metrics.attach_queue(&budget);
    let mut peers = Queues::new(budget, limits);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // A late tick is not caught up in a burst (A10-10): one tick per second of progress.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut drain: Option<DrainController> = None;
    let mut ticks: u64 = 0;
    loop {
        let input = tokio::select! {
            // Policy first: a connection authenticated under the new policy must not reach the
            // core before the policy itself. Then the tick, before the events: under a
            // saturated event queue a `biased` select would never reach it, and deadlines,
            // the drain and the watchdog's progress all depend on it (AP-4).
            biased;
            () = policy.changed() => Input::PolicyUpdated { policy: policy.current() },
            _ = tick.tick() => {
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(STATUS_TICKS) {
                    crate::systemd::status(&format!(
                        "{}: {} connections, {} streams",
                        if drain.is_some() { "draining" } else { "serving" },
                        core.connection_count(),
                        core.client_stream_count()
                    ));
                }
                peers.sweep();
                Input::Tick
            }
            Some(timeout) = drain_rx.recv(), if drain.is_none() => {
                drain = Some(DrainController::new(mono_now(), timeout));
                // From now on new streams are rejected, also on open connections (A10-5).
                Input::DrainStarted
            }
            event = events.recv() => match event {
                None => return DrainOutcome::default(),
                Some(HubEvent::Connected { conn, peer, hybrid, certificate, queue }) => {
                    peers.connected(conn, queue);
                    Input::Connected { conn, peer, hybrid, certificate }
                }
                Some(HubEvent::Core(input)) => {
                    if let Input::Disconnected { conn } = &input {
                        peers.detach(*conn);
                    }
                    input
                }
            },
        };
        execute(&mut core, &mut peers, input, &progress, &metrics);
        if let Some(d) = &drain
            && let DrainStep::Finished { expired } = d.step(mono_now(), core.client_stream_count())
        {
            let closed = core.client_stream_count();
            execute(&mut core, &mut peers, Input::Shutdown, &progress, &metrics);
            // Dropping the senders closes every connection after its queued frames.
            return DrainOutcome { expired, closed };
        }
    }
}

/// Hands `input` to the core and executes its outputs (and the disconnections they cause).
fn execute(
    core: &mut RelayCore<RandomIds>,
    peers: &mut Queues,
    input: Input,
    progress: &Progress,
    metrics: &RelayMetrics,
) {
    let mut pending = vec![input];
    while let Some(input) = pending.pop() {
        let now = Now {
            instant: mono_now(),
            unix: crate::lifecycle::certificate_now(),
        };
        for output in core.handle(input, now) {
            match output {
                Output::Send { conn, frame } => {
                    let sent = Sent::of(&frame);
                    match peers.send(conn, frame) {
                        // Counted once queued, not before: a frame dropped on overflow or for a
                        // connection already gone was never forwarded (review 0013, A13-11).
                        Some(true) => sent.count(metrics),
                        None => {}
                        Some(false) => {
                            // Queue full or connection already closed: detach it.
                            tracing::warn!(conn = conn.0, "outbound queue overflow");
                            metrics.queue_overflow.inc();
                            peers.detach(conn);
                            pending.push(Input::Disconnected { conn });
                        }
                    }
                    if let Some((victim, backlog)) = peers.shed(conn, |c| core.is_agent(c)) {
                        // The identity is named (A13-1): an abuser that spreads its backlog
                        // over many connections is visible in one line per shed connection.
                        audit_line!(
                            true,
                            "queue_budget_exceeded",
                            conn = victim.conn.0,
                            peer = %victim.identity,
                            role = if victim.agent { "agent" } else { "client" },
                            cause = victim.cause.as_str(),
                            backlog,
                            identity_backlog = victim.identity_bytes,
                            budget = peers.limits.budget,
                            identity_cap = peers.limits.identity_cap,
                            "byte budget exceeded: the slowest reader's identity loses a connection"
                        );
                        metrics.queue_shed.inc();
                        pending.push(Input::Disconnected { conn: victim.conn });
                    }
                }
                Output::Close { conn } => {
                    // Dropping the sender closes the connection after the frames already
                    // queued.
                    peers.detach(conn);
                }
                Output::Audit(event) => audit(&event),
            }
        }
    }
    metrics.streams.set_usize(core.client_stream_count());
    metrics.agents_registered.set_usize(core.agent_count());
    progress.advance();
}

/// What a frame the hub sends says for the metrics: forwarded bytes, reject and close reasons.
#[derive(Clone, Copy)]
enum Sent {
    Data(usize),
    Reject(RejectReason),
    Close(CloseReason),
    Other,
}

impl Sent {
    fn of(frame: &Frame) -> Self {
        match frame {
            Frame::Data { payload, .. } => Self::Data(payload.len()),
            Frame::Reject { reason, .. } => Self::Reject(*reason),
            Frame::Close { reason, .. } => Self::Close(*reason),
            _ => Self::Other,
        }
    }

    fn count(self, metrics: &RelayMetrics) {
        match self {
            Self::Data(len) => metrics
                .forwarded_bytes
                .add(u64::try_from(len).unwrap_or(u64::MAX)),
            Self::Reject(reason) => metrics.open_rejected(reason),
            Self::Close(reason) => metrics.stream_closed(reason),
            Self::Other => {}
        }
    }
}
