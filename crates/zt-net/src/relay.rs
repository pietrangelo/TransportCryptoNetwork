//! Relay server.
//!
//! ```text
//!  accept ─▶ limits (connections, per-IP rate) ─▶ connection task: handshake, policy,
//!                                                  recv/send with timeouts
//!                         Input ▼  ▲ Frame (bounded queue per connection)
//!                          hub: RelayCore (sole owner of the state)
//! ```
//!
//! The hub never waits on a connection: if a connection's queue is full (impossible for a peer
//! that respects the credit) that connection is closed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout_at;
use zt_application::ratelimit::HandshakeGate;
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_crypto::Keyring;
use zt_crypto::noise::Channel;
use zt_domain::flow::{MAX_WINDOW, MIN_CHARGE, MIN_WINDOW_UPDATE};
use zt_domain::{
    AccessPolicy, AuthFailureReason, CertClaims, CertRef, DomainEvent, Fingerprint, Frame,
    SessionId,
};

use crate::{NetError, Timeouts, channel};

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Relay core limits.
    pub limits: RelayLimits,
    /// Network timeouts.
    pub timeouts: Timeouts,
    /// Concurrent connections (including those in the handshake).
    pub max_connections: usize,
    /// Handshakes allowed in a burst per IP address.
    pub handshake_burst: u32,
    /// One more handshake per IP every `handshake_refill`.
    pub handshake_refill: Duration,
    /// IP addresses tracked by the rate limiter.
    pub max_tracked_ips: usize,
    /// Handshakes allowed in a burst per IPv6 /48 prefix.
    pub wide_handshake_burst: u32,
    /// One more handshake per /48 every `wide_handshake_refill`.
    pub wide_handshake_refill: Duration,
    /// Tracked /48 prefixes.
    pub max_tracked_wide: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            limits: RelayLimits::default(),
            timeouts: Timeouts::default(),
            max_connections: 4096,
            handshake_burst: 20,
            handshake_refill: Duration::from_secs(3),
            max_tracked_ips: 65_536,
            wide_handshake_burst: 64,
            wide_handshake_refill: Duration::from_secs(1),
            max_tracked_wide: 16_384,
        }
    }
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
        not_after = c.not_after,
        "authentication failed"
    );
}

/// Logs an audit event. Events contain only identities and metadata.
///
/// `event_kind` is the stable name of the event ([`DomainEvent::kind`]), for a SIEM to filter
/// on; the other data are separate fields (`peer`, `node`, `session`, `reason`, `rule`), not a
/// `Debug` string to be parsed (finding 0004-4).
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
            target,
            certificate,
        } => {
            let c = CertFields::of(certificate.as_ref());
            emit!(
                session = %session_hex(session),
                peer = %client,
                node = %target,
                credential = c.credential,
                ca = c.ca.as_deref(),
                serial = c.serial.as_deref(),
                cert_name = c.cert_name.as_deref(),
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
                not_after = c.not_after,
                "certificate expired"
            );
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
            },
            Some(c) => Self {
                credential: "certificate",
                ca: Some(c.ca.to_string()),
                serial: Some(c.serial.to_string()),
                cert_name: Some(c.name.to_string()),
                not_after: Some(c.not_after.as_secs()),
            },
        }
    }
}

/// `reason` and `cert_check` of an `authentication_failed`. Reasons that predate Phase 6 keep
/// their usual form (`UnknownPeer`, ...), so as not to break existing filters.
fn failure_fields(reason: AuthFailureReason) -> (String, Option<&'static str>) {
    match reason {
        AuthFailureReason::KeyRevoked => ("key_revoked".into(), None),
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
        certificate: Option<Arc<CertClaims>>,
        tx: mpsc::Sender<Frame>,
    },
    Core(Input),
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

/// The relay, ready to accept connections.
pub struct RelayServer {
    listener: TcpListener,
    keys: crate::Revocable<Keyring>,
    policy: crate::Revocable<AccessPolicy>,
    config: RelayConfig,
}

impl RelayServer {
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
        let policy = policy.into();
        let keys = keys.into();
        let listener = TcpListener::bind(addr).await?;
        // The socket already accepts connections (queued until `run`): it is announced here,
        // so whatever the process logs after `bind` always comes after this line.
        if let Ok(addr) = listener.local_addr() {
            tracing::info!(%addr, relay = %keys.current().current().fingerprint(), "relay listening");
        }
        Ok(Self {
            listener,
            keys,
            policy,
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

    /// Serves connections until the process exits.
    ///
    /// # Errors
    /// Only fatal errors of the listening socket.
    pub async fn run(self) -> Result<(), NetError> {
        let Self {
            listener,
            keys,
            policy,
            config,
        } = self;
        let (hub_tx, hub_rx) = mpsc::channel(4096);
        let core = RelayCore::new(
            policy.current(),
            config.limits.clone(),
            RandomIds { fallback: 0 },
        );
        tokio::spawn(hub(core, hub_rx, policy.clone()));

        let slots = Arc::new(Semaphore::new(config.max_connections));
        let mut gate = HandshakeGate::new(
            config.max_tracked_ips,
            config.handshake_burst,
            config.handshake_refill,
            config.wide_handshake_burst,
            config.wide_handshake_refill,
            config.max_tracked_wide,
        );
        let capacity = outbound_capacity(&config.limits);
        let mut next_conn: u64 = 0;
        loop {
            let (tcp, addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    // E.g. EMFILE: back off instead of spinning.
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                tracing::warn!(%addr, "connection limit reached");
                continue;
            };
            if !gate.admit(addr.ip(), std::time::Instant::now()) {
                tracing::warn!(%addr, "handshake rate limit");
                continue;
            }
            let _ = tcp.set_nodelay(true);
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
                capacity,
            };
            tokio::spawn(async move {
                task.serve(tcp, addr).await;
                drop(permit);
            });
        }
    }
}

struct Connection {
    conn: ConnId,
    keys: Arc<Keyring>,
    policy: crate::Revocable<AccessPolicy>,
    hub: mpsc::Sender<HubEvent>,
    timeouts: Timeouts,
    capacity: usize,
}

impl Connection {
    async fn serve(self, tcp: TcpStream, addr: SocketAddr) {
        let pending = match channel::accept(tcp, &self.keys, Channel::Outer, &self.timeouts).await {
            Ok(pending) => pending,
            Err(err) => {
                audit(&DomainEvent::AuthenticationFailed {
                    peer: None,
                    reason: AuthFailureReason::HandshakeFailed,
                    certificate: None,
                });
                tracing::debug!(%addr, error = %err, "handshake failed");
                return;
            }
        };
        let peer = pending.peer();
        // PROTOCOL §15.4, before message 2: a rejection is equivalent to an unknown key, which
        // does not even receive the second handshake message.
        let certificate = match admit(&self.policy.current(), &peer, pending.payload()) {
            Ok(certificate) => certificate,
            Err((reason, certificate)) => {
                audit(&DomainEvent::AuthenticationFailed {
                    peer: Some(peer),
                    reason,
                    certificate,
                });
                return;
            }
        };
        let Ok(mut ch) = pending.establish(&self.timeouts).await else {
            return;
        };
        tracing::debug!(%addr, %peer, conn = self.conn.0, "peer connected");

        let (tx, mut rx) = mpsc::channel(self.capacity);
        let conn = self.conn;
        if self
            .hub
            .send(HubEvent::Connected {
                conn,
                peer,
                certificate,
                tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let mut deadline = crate::deadline(self.timeouts.idle);
        loop {
            tokio::select! {
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
                    deadline = crate::deadline(self.timeouts.idle);
                    if self.hub.send(HubEvent::Core(Input::Received { conn, frame })).await.is_err() {
                        break;
                    }
                }
                outbound = rx.recv() => {
                    let Some(frame) = outbound else { break };
                    if ch.send(&frame, &self.timeouts).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = self
            .hub
            .send(HubEvent::Core(Input::Disconnected { conn }))
            .await;
    }
}

/// Steps 1–11 of PROTOCOL §15.4 on the outer channel: key denylist, certificate verification
/// (if the payload is not empty) and policy decision. Returns the verified certificate data,
/// which the core re-checks against the current policy.
/// The rejection from [`admit`]: the reason and, after signature verification, the certificate
/// (PROTOCOL §15.11).
type Refusal = (AuthFailureReason, Option<CertRef>);

fn admit(
    policy: &AccessPolicy,
    peer: &Fingerprint,
    payload: &[u8],
) -> Result<Option<Arc<CertClaims>>, Refusal> {
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
        let claims = zt_crypto::verify_certificate(payload, peer, trust)
            .map_err(|check| (AuthFailureReason::Certificate(check), None))?;
        Some(Arc::new(claims))
    };
    // Steps 5 and 7–11 and the precedence of the whitelist.
    policy
        .admit(peer, certificate.as_ref(), crate::unix_now())
        .map_err(|reason| (reason, reason.certificate_ref(certificate.as_deref())))?;
    Ok(certificate)
}

async fn hub(
    mut core: RelayCore<RandomIds>,
    mut events: mpsc::Receiver<HubEvent>,
    mut policy: crate::Revocable<AccessPolicy>,
) {
    let mut peers: HashMap<ConnId, mpsc::Sender<Frame>> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let input = tokio::select! {
            // Policy first: a connection authenticated under the new policy must not reach the
            // core before the policy itself.
            biased;
            () = policy.changed() => Input::PolicyUpdated { policy: policy.current() },
            event = events.recv() => match event {
                None => return,
                Some(HubEvent::Connected { conn, peer, certificate, tx }) => {
                    peers.insert(conn, tx);
                    Input::Connected { conn, peer, certificate }
                }
                Some(HubEvent::Core(input)) => {
                    if let Input::Disconnected { conn } = &input {
                        peers.remove(conn);
                    }
                    input
                }
            },
            _ = tick.tick() => Input::Tick,
        };
        let mut pending = vec![input];
        while let Some(input) = pending.pop() {
            let now = Now {
                instant: std::time::Instant::now(),
                unix: crate::unix_now(),
            };
            for output in core.handle(input, now) {
                match output {
                    Output::Send { conn, frame } => {
                        let Some(tx) = peers.get(&conn) else { continue };
                        if tx.try_send(frame).is_err() {
                            // Queue full or connection already closed: detach it.
                            tracing::warn!(conn = conn.0, "outbound queue overflow");
                            peers.remove(&conn);
                            pending.push(Input::Disconnected { conn });
                        }
                    }
                    Output::Close { conn } => {
                        // Dropping the sender closes the connection after the frames already
                        // queued.
                        peers.remove(&conn);
                    }
                    Output::Audit(event) => audit(&event),
                }
            }
        }
    }
}
