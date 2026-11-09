//! The agent: runs on the target servers, opens no ports, connects outbound to the relay.
//!
//! Defense in depth: even if the relay authorizes a stream, the agent itself verifies the
//! client's end-to-end identity against its own list. A compromised relay therefore cannot
//! open SSH sessions to the nodes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};
use zt_application::identity_lines::{IdentityEvent, IdentityLines};
use zt_crypto::noise::{self, Channel, Responded};
use zt_crypto::{CryptoError, Keyring};
use zt_domain::flow::Window;
use zt_domain::{
    AcceptedSuites, AuthFailureReason, AuthorizedClients, CertClaims, CertRef, CertRejection,
    ClientCredential, CloseReason, DomainEvent, Fingerprint, Frame, HandshakeChannel,
    HandshakeSuite, NodeId, RejectReason, StreamId,
};

use crate::relay::{CertFields, audit, repeated_line};
use crate::stream::{STREAM_QUEUE, StreamIo, pump};
use crate::{NetError, Timeouts, channel};

/// Agent configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Relays to stay connected to, all at once (at most [`crate::MAX_RELAYS`]).
    pub relays: Vec<crate::RelayEndpoint>,
    /// Name of this node.
    pub node: NodeId,
    /// Local SSH daemon.
    pub ssh_target: String,
    /// Clients accepted end-to-end.
    pub authorized_clients: crate::Revocable<AuthorizedClients>,
    /// Network timeouts.
    pub timeouts: Timeouts,
    /// Concurrent streams, from 1 to [`MAX_STREAMS`].
    pub max_streams: usize,
    /// Handshake suites accepted from clients on the end-to-end channel (PROTOCOL §7.5).
    pub client_suites: zt_domain::AcceptedSuites,
    /// The interval of the per-identity audit lines (finding A9-2): an event about a client is
    /// logged in full once per client and interval, the repeats are counted in one
    /// `<event>_repeated` line. Normally [`IDENTITY_LOG_INTERVAL`]; at least one second.
    pub identity_log_interval: Duration,
}

/// The default [`AgentConfig::identity_log_interval`], the relay's `summary_interval`.
pub const IDENTITY_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// What the agent's stream tasks share, across all relays.
#[derive(Clone)]
struct Shared {
    /// Sessions to sshd for the whole agent.
    sessions: Arc<Semaphore>,
    /// The per-identity audit lines of the current interval (finding A9-2).
    lines: Arc<Mutex<IdentityLines>>,
}

impl Shared {
    /// Logs `event`; an event about a named client only if it is the first of its kind for
    /// that client in the interval (finding A9-2: a compromised relay replays a recorded
    /// message 1 at will). The others are counted for the `_repeated` line.
    fn audit(&self, event: &DomainEvent) {
        let key = match event {
            DomainEvent::AuthenticationFailed {
                peer: Some(peer),
                reason,
                ..
            } => Some((*peer, IdentityEvent::AuthenticationFailed(*reason))),
            DomainEvent::HandshakeSuiteRejected { peer, suite } => {
                Some((*peer, IdentityEvent::SuiteRejected(*suite)))
            }
            _ => None,
        };
        let full = key.is_none_or(|(peer, ev)| crate::lock(&self.lines).note(peer, ev));
        if full {
            audit(event);
        }
    }
}

/// Every `interval`: the `_repeated` lines of the interval that ended, and how many events
/// were not even counted per identity (beyond the table's bound).
async fn identity_summaries(lines: Arc<Mutex<IdentityLines>>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;
    loop {
        tick.tick().await;
        let ended = crate::lock(&lines).take();
        for repeated in &ended.repeated {
            repeated_line(repeated);
        }
        if ended.suppressed_identities > 0 {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "identity_events_suppressed",
                count = ended.suppressed_identities,
                "audit events about further identities only counted"
            );
        }
    }
}

/// The suites in use, once at startup (finding AP-7): those accepted from clients end to end
/// and those pinned towards the relays.
fn handshake_suites_in_use(config: &AgentConfig) {
    let mut relay_suites: Vec<&str> = Vec::new();
    for relay in &config.relays {
        let name = relay.suite.protocol_name();
        if !relay_suites.contains(&name) {
            relay_suites.push(name);
        }
    }
    tracing::info!(
        target: "zt_audit",
        event_kind = "handshake_suites_in_use",
        role = "agent",
        client_suites = config.client_suites.names(),
        relay_suites = relay_suites.join(","),
        "handshake suites in use"
    );
}

/// Maximum of `max_streams`: well below the limit of the tokio semaphore, which panics beyond
/// its maximum (finding 0005b-4).
pub const MAX_STREAMS: usize = 4096;

/// Keeps the agent connected to every relay in the list forever, each with its own exponential
/// backoff and jitter (PROTOCOL §13). Towards the relays it uses the current key; on the
/// end-to-end channel it also accepts the previous one (PROTOCOL §14).
///
/// `max_streams` limits two things: the streams of **each** relay (including those that have
/// not yet completed the end-to-end handshake) and the sshd sessions of the **whole** agent.
/// The global permit is taken only after the client's confirmation, which a relay cannot
/// forge: a compromised relay exhausts only its own quota and does not block the sessions
/// that go through the others (finding 0005-1).
pub async fn run(keys: Arc<Keyring>, config: AgentConfig) {
    if config.relays.is_empty() || config.relays.len() > crate::MAX_RELAYS {
        tracing::error!(
            relays = config.relays.len(),
            "the agent needs between 1 and 8 relays"
        );
        return;
    }
    // The CLI already validates it; here we protect library users, without panicking.
    if config.max_streams == 0 || config.max_streams > MAX_STREAMS {
        tracing::error!(
            max_streams = config.max_streams,
            "the agent needs between 1 and 4096 concurrent streams"
        );
        return;
    }
    if config.identity_log_interval < Duration::from_secs(1) {
        tracing::error!("the agent's identity log interval must be at least one second");
        return;
    }
    // The CLI validates these too (PROTOCOL §7.5): a library user cannot run a suite on a
    // channel that does not support it.
    if !config
        .client_suites
        .all_supported(HandshakeChannel::EndToEnd)
        || config
            .relays
            .iter()
            .any(|r| !r.suite.is_supported(HandshakeChannel::Outer))
    {
        tracing::error!("a handshake suite is not supported on its channel");
        return;
    }
    handshake_suites_in_use(&config);
    let shared = Shared {
        sessions: Arc::new(Semaphore::new(config.max_streams)),
        lines: Arc::new(Mutex::new(IdentityLines::default())),
    };
    let mut sessions = tokio::task::JoinSet::new();
    sessions.spawn(identity_summaries(
        Arc::clone(&shared.lines),
        config.identity_log_interval,
    ));
    for relay in config.relays.clone() {
        sessions.spawn(run_one(
            Arc::clone(&keys),
            relay,
            config.clone(),
            shared.clone(),
        ));
    }
    // The loops never terminate; if one panicked the others would keep going.
    while sessions.join_next().await.is_some() {}
}

async fn run_one(
    identity: Arc<Keyring>,
    relay: crate::RelayEndpoint,
    config: AgentConfig,
    shared: Shared,
) {
    const MAX_DELAY: Duration = Duration::from_secs(60);
    let mut delay = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        match run_session(&identity, &relay, &config, &shared).await {
            Ok(()) => tracing::info!(relay = %relay.address, "relay closed the connection"),
            Err(err) => tracing::warn!(relay = %relay.address, error = %err, "relay session ended"),
        }
        if started.elapsed() > MAX_DELAY {
            delay = Duration::from_secs(1);
        }
        // Jitter up to half the delay, so that a whole fleet does not reconnect at once.
        let half = u64::try_from(delay.as_millis() / 2)
            .unwrap_or(u64::MAX)
            .max(1);
        let jitter = getrandom::u64().unwrap_or(0).checked_rem(half).unwrap_or(0);
        tokio::time::sleep(delay.saturating_add(Duration::from_millis(jitter))).await;
        delay = delay.saturating_mul(2).min(MAX_DELAY);
    }
}

/// A single session with the relay: connects, registers and serves streams as long as the
/// connection stays up.
///
/// # Errors
/// Any network, handshake or protocol error from the relay.
async fn run_session(
    identity: &Arc<Keyring>,
    relay: &crate::RelayEndpoint,
    config: &AgentConfig,
    shared: &Shared,
) -> Result<(), NetError> {
    let t = &config.timeouts;
    let tcp = timeout(t.handshake, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| NetError::Timeout("connect"))??;
    let _ = tcp.set_nodelay(true);
    let mut ch = channel::connect_suite(
        tcp,
        identity.current(),
        &relay.public_key,
        Channel::Outer,
        relay.suite,
        &[],
        t,
    )
    .await?;
    ch.send(
        &Frame::Register {
            node: config.node.clone(),
        },
        t,
    )
    .await?;
    tracing::info!(node = %config.node, relay = %relay.address, "registered with relay");

    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(1024);
    let (done_tx, mut done_rx) = mpsc::channel::<StreamId>(config.max_streams.saturating_add(1));
    let mut streams = Streams::default();
    let mut keepalive = tokio::time::interval(t.keepalive);
    keepalive.tick().await;
    let mut deadline = crate::deadline(t.idle);
    let mut nonce: u64 = 0;
    loop {
        tokio::select! {
            inbound = timeout_at(deadline, ch.recv()) => {
                let frame = inbound.map_err(|_| NetError::Timeout("relay idle"))??.ok_or(NetError::Closed)?;
                deadline = crate::deadline(t.idle);
                if let Some(reply) = on_relay_frame(frame, identity, config, shared, &mut streams, &out_tx, &done_tx)? {
                    ch.send(&reply, t).await?;
                }
            }
            Some(frame) = out_rx.recv() => {
                streams.on_outbound(&frame);
                ch.send(&frame, t).await?;
            }
            Some(stream) = done_rx.recv() => {
                // Ids increase and are never reused (a repeated id closes the session), and
                // `done` belongs to this session: it cannot remove the slot of a newer stream.
                streams.slots.remove(&stream);
            }
            _ = keepalive.tick() => {
                nonce = nonce.wrapping_add(1);
                ch.send(&Frame::Ping { nonce }, t).await?;
            }
        }
    }
}

/// Inbound queue and credit of a stream.
///
/// The slot lives as long as the stream's task, not as long as the stream on the wire: only
/// the `done` channel removes it, at the end of the task. This way the per-relay quota counts
/// the tasks that are actually alive, and a compromised relay that alternates `Open`, garbage
/// `msg1` and `Close` cannot accumulate tasks beyond `max_streams` (finding 0005b-1).
struct Slot {
    /// `None` after the relay's `Close` (or a violation by it): the task has already received
    /// everything it was due, and later frames for this id are discarded.
    tx: Option<mpsc::Sender<Frame>>,
    /// Credit the relay has towards this stream: it is enforced **before** enqueuing, so a
    /// compromised relay cannot fill the queue beyond the window (finding 0002-14).
    recv: Window,
}

/// The streams open on the connection with the relay.
#[derive(Default)]
struct Streams {
    slots: HashMap<StreamId, Slot>,
    /// The last accepted id: the relay assigns increasing ids and never reuses them.
    last: u32,
}

impl Streams {
    /// Returns credit to the relay when the stream grants it.
    fn on_outbound(&mut self, frame: &Frame) {
        if let Frame::WindowUpdate { stream, credit } = frame
            && let Some(slot) = self.slots.get_mut(stream)
        {
            // The stream's task enforces the same limits: this cannot fail here.
            let _ = slot.recv.grant(credit.get());
        }
    }
}

fn on_relay_frame(
    frame: Frame,
    identity: &Arc<Keyring>,
    config: &AgentConfig,
    shared: &Shared,
    streams: &mut Streams,
    out_tx: &mpsc::Sender<Frame>,
    done_tx: &mpsc::Sender<StreamId>,
) -> Result<Option<Frame>, NetError> {
    match frame {
        Frame::Open { stream, target } => {
            if target != config.node {
                return Ok(Some(Frame::Reject {
                    stream,
                    reason: RejectReason::NotAuthorized,
                }));
            }
            if stream.get() <= streams.last {
                return Err(NetError::Protocol("relay reused a stream id"));
            }
            streams.last = stream.get();
            // Per-relay quota: it also counts streams not yet confirmed.
            if streams.slots.len() >= config.max_streams {
                return Ok(Some(Frame::Reject {
                    stream,
                    reason: RejectReason::ResourceExhausted,
                }));
            }
            let (tx, rx) = mpsc::channel(STREAM_QUEUE);
            streams.slots.insert(
                stream,
                Slot {
                    tx: Some(tx),
                    recv: Window::initial(),
                },
            );
            let task = StreamTask {
                io: StreamIo::new(stream, rx, out_tx.clone()),
                identity: Arc::clone(identity),
                shared: shared.clone(),
                authorized: config.authorized_clients.clone(),
                node: config.node.clone(),
                ssh_target: config.ssh_target.clone(),
                timeouts: config.timeouts.clone(),
                client_suites: config.client_suites,
            };
            let done = done_tx.clone();
            tokio::spawn(async move {
                task.serve().await;
                let _ = done.send(stream).await;
            });
            Ok(Some(Frame::OpenAck { stream }))
        }
        Frame::Data { stream, .. }
        | Frame::WindowUpdate { stream, .. }
        | Frame::Close { stream, .. } => {
            let closing = matches!(frame, Frame::Close { .. });
            // Stream already closed on this side (slot removed by `done`) or already closed by
            // the relay (queue detached): an in-flight or repeated frame, discard it.
            let Some(slot) = streams.slots.get_mut(&stream) else {
                return Ok(None);
            };
            let Some(tx) = &slot.tx else {
                return Ok(None);
            };
            let within_credit = match &frame {
                Frame::Data { payload, .. } => slot.recv.consume(payload.len()).is_ok(),
                _ => true,
            };
            let queued = within_credit
                && match tx.try_send(frame) {
                    Ok(()) => true,
                    // The stream's task has already finished and its `Close` is on its way:
                    // the frame was in flight, discard it. Replying `ProtocolViolation` here
                    // could overtake that `Close` and hide the real reason from the client
                    // (e.g. `Drained` for the session limit). `done` removes the slot.
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(None),
                    Err(mpsc::error::TrySendError::Full(_)) => false,
                };
            if !queued {
                // Only a relay that does not enforce the credit can get here. Detaching the
                // queue makes the task finish; the slot stays (and counts against the quota)
                // until it finishes.
                slot.tx = None;
                return Ok(Some(Frame::Close {
                    stream,
                    reason: CloseReason::ProtocolViolation,
                }));
            }
            if closing {
                // The `Close` is already queued: the task reads it, then sees the queue closed.
                // Only `done` removes the slot, when the task has really finished (finding
                // 0005b-1).
                slot.tx = None;
            }
            Ok(None)
        }
        Frame::Pong { .. } => Ok(None),
        Frame::Register { .. }
        | Frame::OpenAck { .. }
        | Frame::Reject { .. }
        | Frame::Ping { .. } => Err(NetError::Protocol("unexpected frame from relay")),
    }
}

struct StreamTask {
    io: StreamIo,
    identity: Arc<Keyring>,
    /// Sessions to sshd and audit lines, for the whole agent (all relays).
    shared: Shared,
    authorized: crate::Revocable<AuthorizedClients>,
    /// This agent's node: it must be within the effective scope of a certificate.
    node: NodeId,
    ssh_target: String,
    timeouts: Timeouts,
    /// Suites accepted from clients (PROTOCOL §7.5).
    client_suites: AcceptedSuites,
}

/// Steps 1–10 and 12 of PROTOCOL §15.4 on the end-to-end channel, with this agent's CAs,
/// denylist and clock (not the relay's).
fn admit_client(
    clients: &AuthorizedClients,
    client: &Fingerprint,
    payload: &[u8],
    node: &NodeId,
) -> Result<ClientCredential, (AuthFailureReason, Option<CertRef>)> {
    let trust = clients.cert_trust();
    if trust.is_key_revoked(client) {
        return Err((AuthFailureReason::KeyRevoked, None));
    }
    // A rejection before the signature is verified never names the CA and serial (PROTOCOL
    // §15.11).
    let certificate: Option<Arc<CertClaims>> = if payload.is_empty() {
        None
    } else {
        let claims = zt_crypto::verify_certificate(payload, client, trust)
            .map_err(|check| (AuthFailureReason::Certificate(check), None))?;
        Some(Arc::new(claims))
    };
    // After the signature, the rejection carries the certificate (finding 0006-3).
    clients
        .admit(client, certificate.as_ref(), node, crate::unix_now())
        .map_err(|reason| (reason, reason.certificate_ref(certificate.as_deref())))
}

/// Reads message 1 and runs the responder side up to the authorization decision. On failure
/// the stream is closed (and audited) here.
async fn read_msg1(
    io: &mut StreamIo,
    identity: &Keyring,
    timeouts: &Timeouts,
    client_suites: AcceptedSuites,
) -> Option<Responded> {
    let msg1 = match io.recv_message(timeouts).await {
        Ok(msg1) => msg1,
        // The client has already closed: replying with another `Close` is pointless
        // (finding 0002-1).
        Err(NetError::StreamClosed(_)) => return None,
        Err(err) => {
            tracing::debug!(error = %err, "stream ended before handshake");
            io.close(CloseReason::Timeout).await;
            return None;
        }
    };
    // A message 1 longer than the one with the largest certificate is not even parsed
    // (PROTOCOL §15.3): it is a rejected certificate, not a handshake to attempt. The bound is
    // that of every suite this build runs end to end, not only the accepted ones, so that a
    // known client with a large certificate and an unaccepted suite is still named (finding
    // A9-5); the per-suite bounds apply inside `respond_or_identify`.
    let supported = AcceptedSuites::supported(HandshakeChannel::EndToEnd);
    let responded = if msg1.len() > supported.max_msg1_len() {
        Err(CryptoError::Handshake)
    } else {
        noise::respond_or_identify(identity, &msg1, Channel::EndToEnd, client_suites)
    };
    let Ok(responded) = responded else {
        // Longer than any accepted message 1: reported as before, a malformed certificate.
        let reason = if msg1.len() > client_suites.max_msg1_len() {
            AuthFailureReason::Certificate(CertRejection::Malformed)
        } else {
            AuthFailureReason::HandshakeFailed
        };
        audit(&DomainEvent::AuthenticationFailed {
            peer: None,
            reason,
            certificate: None,
        });
        let close = if matches!(reason, AuthFailureReason::HandshakeFailed) {
            CloseReason::ProtocolViolation
        } else {
            CloseReason::Unauthorized
        };
        io.close(close).await;
        return None;
    };
    Some(responded)
}

impl StreamTask {
    async fn serve(self) {
        let Self {
            mut io,
            identity,
            shared,
            authorized,
            node,
            ssh_target,
            timeouts,
            client_suites,
        } = self;
        let Some(responded) = read_msg1(&mut io, &identity, &timeouts, client_suites).await else {
            return;
        };
        let (client, suite, payload) = match &responded {
            Responded::Pending(pending) => (pending.peer(), pending.suite(), pending.payload()),
            Responded::Unaccepted(found) => (found.peer(), found.suite(), found.payload()),
        };
        // Before message 2: a rejected client does not complete the handshake and does not
        // reach sshd (like an unknown client, PROTOCOL §8 item 3).
        let credential = match admit_client(&authorized.current(), &client, payload, &node) {
            Ok(credential) => credential,
            Err((reason, certificate)) => {
                shared.audit(&DomainEvent::AuthenticationFailed {
                    peer: Some(client),
                    reason,
                    certificate,
                });
                io.close(CloseReason::Unauthorized).await;
                return;
            }
        };
        // A known client whose suite this agent does not accept (review 0008, A8-11): no
        // message 2, and the suite is named so that the operator sees a client pinned ahead
        // of (or behind) the agent's configuration. `Unaccepted` has no `accept` (finding
        // A9-3), and the line is rate-limited and says it is unconfirmed (finding A9-2).
        let pending = match responded {
            Responded::Pending(pending) => pending,
            Responded::Unaccepted(_) => {
                shared.audit(&DomainEvent::HandshakeSuiteRejected {
                    peer: client,
                    suite,
                });
                io.close(CloseReason::Unauthorized).await;
                return;
            }
        };
        let Ok((msg2, mut transport)) = pending.accept() else {
            // An invalid `e1` (FIPS 203 §7.2) from the key holder of an authorized client, or
            // a failure of this host's random number generator (finding A9-4).
            if getrandom::u64().is_err() {
                tracing::error!("the system random number generator failed");
            }
            shared.audit(&DomainEvent::AuthenticationFailed {
                peer: Some(client),
                reason: AuthFailureReason::HandshakeFailed,
                certificate: None,
            });
            io.close(CloseReason::ProtocolViolation).await;
            return;
        };
        if io.send_data(msg2).await.is_err() {
            return;
        }
        // The first IK message can be replayed: a compromised relay that records it can replay
        // it. Only the real client can produce a valid transport message, so sshd is contacted
        // and the session is registered only after the confirmation (finding 0002-3).
        match io.recv_message(&timeouts).await {
            Ok(confirm)
                if transport
                    .decrypt(&confirm)
                    .is_ok_and(|p| p == suite.confirmation()) => {}
            Ok(_) => {
                shared.audit(&DomainEvent::AuthenticationFailed {
                    peer: Some(client),
                    reason: AuthFailureReason::HandshakeFailed,
                    certificate: None,
                });
                io.close(CloseReason::ProtocolViolation).await;
                return;
            }
            Err(NetError::StreamClosed(_)) => return,
            Err(_) => {
                io.close(CloseReason::Timeout).await;
                return;
            }
        }
        // Only now, with a real client, is one of the `max_streams` global slots taken; it
        // stays taken until the end of this function.
        let Ok(_session) = Arc::clone(&shared.sessions).try_acquire_owned() else {
            tracing::warn!(peer = %client, "too many sessions on this agent");
            io.close(CloseReason::Drained).await;
            return;
        };
        let Ok(Ok(ssh)) = timeout(timeouts.ssh_connect, TcpStream::connect(&ssh_target)).await
        else {
            tracing::warn!(target = %ssh_target, "cannot reach local ssh daemon");
            io.close(CloseReason::PeerGone).await;
            return;
        };
        let _ = ssh.set_nodelay(true);
        let session = Session {
            client,
            credential,
            node,
            suite,
        };
        bridge(io, transport, ssh, session, authorized, &timeouts).await;
    }
}

/// Who the client of an end-to-end session is, with which credential it was admitted and
/// which handshake suite it used.
struct Session {
    client: Fingerprint,
    credential: ClientCredential,
    node: NodeId,
    suite: HandshakeSuite,
}

/// The maximum interval at which the system clock is re-read for a certificate's expiry
/// (PROTOCOL §15.7): a clock jump or a suspended VM does not extend the session by more.
const EXPIRY_RECHECK: Duration = Duration::from_secs(60);

/// Why a session must end before the parties decide so.
enum Cut {
    Revoked,
    Expired,
}

/// Waits until the session's credential stops being valid: on every change of the authorized
/// clients and, for a certificate, at `min(not_after, now + 60 s)`.
async fn until_cut(session: &Session, authorized: &mut crate::Revocable<AuthorizedClients>) -> Cut {
    loop {
        let now = crate::unix_now();
        let clients = authorized.current();
        if !clients.still_admits(&session.client, &session.credential, &session.node, now) {
            return match &session.credential {
                ClientCredential::Certificate(claims) if now >= claims.not_after() => Cut::Expired,
                _ => Cut::Revoked,
            };
        }
        match &session.credential {
            ClientCredential::Key => authorized.changed().await,
            ClientCredential::Certificate(claims) => {
                let left = claims.not_after().as_secs().saturating_sub(now.as_secs());
                let wait = Duration::from_secs(left).min(EXPIRY_RECHECK);
                tokio::select! {
                    () = authorized.changed() => {}
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
}

/// Connects the end-to-end session to sshd until the end, or until the client is revoked.
async fn bridge(
    io: StreamIo,
    transport: zt_crypto::noise::Transport,
    ssh: TcpStream,
    session: Session,
    mut authorized: crate::Revocable<AuthorizedClients>,
    timeouts: &Timeouts,
) {
    let stream = io.id();
    let client = session.client;
    let certificate = match &session.credential {
        ClientCredential::Key => None,
        ClientCredential::Certificate(claims) => Some(claims.reference()),
    };
    let c = CertFields::of(certificate.as_ref());
    tracing::info!(
        target: "zt_audit",
        event_kind = "e2e_session_started",
        peer = %client,
        %stream,
        suite = session.suite.protocol_name(),
        credential = c.credential,
        ca = c.ca.as_deref(),
        serial = c.serial.as_deref(),
        cert_name = c.cert_name.as_deref(),
        not_after = c.not_after,
        "end-to-end session started"
    );
    let closer = io.closer();
    // Hot revocation and expiry: if the credential stops being valid the session is closed
    // immediately, without waiting for the relay (which might never do so). The current value
    // is checked before every wait, so a revocation that arrives during the handshake is not
    // lost.
    let cut = until_cut(&session, &mut authorized);
    let outcome = tokio::select! {
        result = pump(io, transport, ssh, Some(timeouts.write)) => match result {
            Ok(()) => "closed",
            Err(err) => {
                tracing::debug!(error = %err, "stream ended with error");
                "error"
            }
        },
        cut = cut => {
            let outcome = match (cut, certificate) {
                (Cut::Expired, Some(certificate)) => {
                    audit(&DomainEvent::CertificateExpired { peer: client, certificate });
                    "expired"
                }
                (_, certificate) => {
                    audit(&DomainEvent::AccessRevoked {
                        peer: client,
                        target: None,
                        certificate,
                    });
                    "revoked"
                }
            };
            closer.close(CloseReason::Unauthorized).await;
            outcome
        }
    };
    tracing::info!(
        target: "zt_audit",
        event_kind = "e2e_session_ended",
        peer = %client,
        %stream,
        outcome,
        "end-to-end session ended"
    );
}
