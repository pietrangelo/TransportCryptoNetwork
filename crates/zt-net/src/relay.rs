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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{timeout, timeout_at};
use zt_application::admission::{
    Admission, AdmissionConfig, IdentityEvent, PreauthFailure, PreauthSummary, Refusal,
    RepeatedEvent, Ticket, is_known_identity,
};
use zt_application::relay::{ConnId, Input, Now, Output, RelayCore, RelayLimits, SessionIds};
use zt_crypto::Keyring;
use zt_crypto::noise::Channel;
use zt_domain::flow::{MAX_WINDOW, MIN_CHARGE, MIN_WINDOW_UPDATE};
use zt_domain::{
    AccessPolicy, AuthFailureReason, CertClaims, CertRef, DomainEvent, Fingerprint, Frame,
    InitiatorRole, PeerRole, RejectReason, SessionId, SuitePolicy,
};

use crate::{NetError, Timeouts, channel};

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
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            limits: RelayLimits::default(),
            timeouts: Timeouts::default(),
            admission: AdmissionConfig::default(),
            suites: SuitePolicy::classical(),
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
        config.admission.validate()?;
        for set in [config.suites.agents, config.suites.clients] {
            if !set.all_supported(zt_domain::HandshakeChannel::Outer) {
                return Err(NetError::Suite(zt_domain::SuiteError::Unsupported));
            }
        }
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

        audit_line!(
            false,
            "handshake_suites_in_use",
            agent_suites = config.suites.agents.names(),
            client_suites = config.suites.clients.names(),
            "handshake suites in use"
        );
        admission_limits_in_use(&config.admission);
        let admission = Arc::new(Mutex::new(Admission::new(
            config.admission.clone(),
            std::time::Instant::now(),
        )));
        tokio::spawn(summaries(Arc::downgrade(&admission)));
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
            // A refusal is counted in the summary; the connection is dropped without a reply.
            let admitted = lock(&admission).on_accept(addr.ip(), std::time::Instant::now());
            let Ok(ticket) = admitted else {
                tracing::debug!(%addr, "connection not admitted");
                continue;
            };
            let admitted = Admitted {
                admission: Arc::clone(&admission),
                ticket,
                source: addr.ip(),
            };
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
                admission: config.admission.clone(),
                suites: config.suites,
                capacity,
            };
            tokio::spawn(task.serve(tcp, addr, admitted));
        }
    }
}

struct Connection {
    conn: ConnId,
    keys: Arc<Keyring>,
    policy: crate::Revocable<AccessPolicy>,
    hub: mpsc::Sender<HubEvent>,
    timeouts: Timeouts,
    admission: AdmissionConfig,
    suites: SuitePolicy,
    capacity: usize,
}

/// `lock` that survives a poisoned mutex: the admission state stays consistent across a panic
/// (each operation is a few map updates), and refusing every connection would be worse.
fn lock(admission: &Mutex<Admission>) -> MutexGuard<'_, Admission> {
    admission.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One admitted connection: its admission ticket is released when the connection ends, on
/// every path.
struct Admitted {
    admission: Arc<Mutex<Admission>>,
    ticket: Ticket,
    source: IpAddr,
}

impl Admitted {
    fn record(&self, failure: PreauthFailure, key: Option<Fingerprint>) {
        lock(&self.admission).record(failure, self.source, key);
    }

    /// Key confirmation: `Ok` if the connection may join the established pool.
    fn confirm(&self, peer: Fingerprint, role: InitiatorRole) -> Result<(), Refusal> {
        lock(&self.admission).on_confirmed(self.ticket, peer, role, std::time::Instant::now())
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

/// Emits the aggregated `preauth_summary` (finding AP-3) until the relay goes away.
async fn summaries(admission: std::sync::Weak<Mutex<Admission>>) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tick.tick().await;
        let Some(admission) = admission.upgrade() else {
            return;
        };
        let summary = lock(&admission).poll_summary(std::time::Instant::now());
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
    async fn serve(self, tcp: TcpStream, addr: SocketAddr, admitted: Admitted) {
        let Some((ch, peer, certificate, first)) = self.handshake(tcp, addr, &admitted).await
        else {
            return;
        };
        self.run(ch, peer, certificate, first).await;
        drop(admitted);
    }

    /// Message 1 to key confirmation (PROTOCOL §10.1). Failures of unknown identities are only
    /// counted; a known identity gets its own audit line (finding AP-3).
    async fn handshake(
        &self,
        tcp: TcpStream,
        addr: SocketAddr,
        admitted: &Admitted,
    ) -> Option<(
        channel::Established<TcpStream>,
        Fingerprint,
        Option<Arc<CertClaims>>,
        Frame,
    )> {
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
        let policy = self.policy.current();
        // PROTOCOL §15.4, before message 2: a rejection is equivalent to an unknown key, which
        // does not even receive the second handshake message.
        let certificate = match admit(&policy, &peer, pending.payload()) {
            Ok(certificate) => certificate,
            Err((reason, certificate)) => {
                if is_known_identity(&policy, &peer, reason) {
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
        tracing::debug!(%addr, %peer, conn = self.conn.0, "peer connected");
        Some((ch, peer, certificate, first))
    }

    /// A confirmed identity refused at admission (finding A8-10): one rate-limited audit line
    /// that names it, and an answer to its `Open` (`Reject RateLimited`, which lets a client
    /// try the next relay) instead of a bare close.
    async fn refuse_confirmed(
        &self,
        ch: &mut channel::Established<TcpStream>,
        admitted: &Admitted,
        peer: Fingerprint,
        refusal: Refusal,
        first: &Frame,
    ) {
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

    async fn run(
        self,
        mut ch: channel::Established<TcpStream>,
        peer: Fingerprint,
        certificate: Option<Arc<CertClaims>>,
        first: Frame,
    ) {
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
        if self
            .hub
            .send(HubEvent::Core(Input::Received { conn, frame: first }))
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

/// The rejection from [`admit`]: the reason and, after signature verification, the certificate
/// (PROTOCOL §15.11).
type AdmitRefusal = (AuthFailureReason, Option<CertRef>);

/// Steps 1–11 of PROTOCOL §15.4 on the outer channel: key denylist, certificate verification
/// (if the payload is not empty) and policy decision. Returns the verified certificate data,
/// which the core re-checks against the current policy.
fn admit(
    policy: &AccessPolicy,
    peer: &Fingerprint,
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
