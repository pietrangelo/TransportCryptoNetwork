//! Server del relay.
//!
//! ```text
//!  accept ─▶ limiti (connessioni, rate per IP) ─▶ task connessione: handshake, policy,
//!                                                  recv/send con timeout
//!                         Input ▼  ▲ Frame (coda limitata per connessione)
//!                          hub: RelayCore (unico proprietario dello stato)
//! ```
//!
//! L'hub non attende mai una connessione: se la coda di una connessione è piena (impossibile
//! per un peer che rispetta il credito) quella connessione viene chiusa.

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

/// Configurazione del relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Limiti del relay core.
    pub limits: RelayLimits,
    /// Timeout di rete.
    pub timeouts: Timeouts,
    /// Connessioni contemporanee (incluse quelle in handshake).
    pub max_connections: usize,
    /// Handshake ammessi a raffica per indirizzo IP.
    pub handshake_burst: u32,
    /// Un handshake in più per IP ogni `handshake_refill`.
    pub handshake_refill: Duration,
    /// Indirizzi IP tracciati dal rate limiter.
    pub max_tracked_ips: usize,
    /// Handshake ammessi a raffica per prefisso IPv6 /48.
    pub wide_handshake_burst: u32,
    /// Un handshake in più per /48 ogni `wide_handshake_refill`.
    pub wide_handshake_refill: Duration,
    /// Prefissi /48 tracciati.
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

/// Registra un evento di audit. Gli eventi contengono solo identità e metadati.
///
/// `event_kind` è il nome stabile dell'evento ([`DomainEvent::kind`]), su cui filtrare un SIEM;
/// gli altri dati sono campi separati (`peer`, `node`, `session`, `reason`, `rule`), non una
/// stringa `Debug` da analizzare (finding 0004-4).
pub(crate) fn audit(event: &DomainEvent) {
    let kind = event.kind();
    let alert = event.is_security_alert();
    macro_rules! emit {
        ($($fields:tt)*) => {
            if alert {
                tracing::warn!(target: "zt_audit", event_kind = kind, $($fields)*);
            } else {
                tracing::info!(target: "zt_audit", event_kind = kind, $($fields)*);
            }
        };
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
        DomainEvent::AuthenticationFailed { peer, reason } => {
            let (reason, cert_check) = failure_fields(*reason);
            let peer = peer.as_ref().map(ToString::to_string);
            emit!(
                peer = peer.as_deref(),
                reason = reason.as_str(),
                cert_check,
                "authentication failed"
            );
        }
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
        // `DomainEvent` è `non_exhaustive`: un evento nuovo resta almeno leggibile.
        other => emit!(event = ?other, "audit event"),
    }
}

/// I campi di audit di una credenziale (PROTOCOL §15.11): mai i byte del certificato, solo
/// la CA, la serie, il nome e la scadenza.
pub(crate) struct CertFields {
    /// `key` o `certificate`.
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

/// `reason` e `cert_check` di un `authentication_failed`. I motivi precedenti alla Fase 6
/// restano nella forma di sempre (`UnknownPeer`, ...), per non rompere i filtri esistenti.
fn failure_fields(reason: AuthFailureReason) -> (String, Option<&'static str>) {
    match reason {
        AuthFailureReason::KeyRevoked => ("key_revoked".into(), None),
        AuthFailureReason::Certificate(check) => ("certificate".into(), Some(check.as_str())),
        other => (format!("{other:?}"), None),
    }
}

/// Il session id in esadecimale, come compare nei log.
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

/// Session id dal CSPRNG del sistema.
struct RandomIds {
    fallback: u64,
}

impl SessionIds for RandomIds {
    fn next_session_id(&mut self) -> SessionId {
        let mut bytes = [0_u8; SessionId::LEN];
        loop {
            if getrandom::fill(&mut bytes).is_err() {
                // Senza CSPRNG si usa un contatore: unico nel processo, non segreto (il session
                // id è un identificativo di audit, non una credenziale).
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

/// Coda in uscita di una connessione: il massimo che il credito permette di accodare.
fn outbound_capacity(limits: &RelayLimits) -> usize {
    let per_stream = MAX_WINDOW / MIN_CHARGE + MAX_WINDOW / MIN_WINDOW_UPDATE;
    let streams = limits
        .max_streams_per_agent
        .max(limits.max_streams_per_client);
    streams
        .saturating_mul(usize::try_from(per_stream).unwrap_or(usize::MAX))
        .saturating_add(1024)
}

/// Il relay, pronto ad accettare connessioni.
pub struct RelayServer {
    listener: TcpListener,
    keys: crate::Revocable<Keyring>,
    policy: crate::Revocable<AccessPolicy>,
    config: RelayConfig,
}

impl RelayServer {
    /// Apre il socket di ascolto.
    ///
    /// # Errors
    /// Errore di bind.
    pub async fn bind(
        addr: SocketAddr,
        keys: impl Into<crate::Revocable<Keyring>>,
        policy: impl Into<crate::Revocable<AccessPolicy>>,
        config: RelayConfig,
    ) -> Result<Self, NetError> {
        let policy = policy.into();
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            keys: keys.into(),
            policy,
            config,
        })
    }

    /// L'indirizzo effettivo di ascolto.
    ///
    /// # Errors
    /// Errore del sistema operativo.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve connessioni fino alla chiusura del processo.
    ///
    /// # Errors
    /// Solo errori fatali del socket di ascolto.
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
        if let Ok(addr) = listener.local_addr() {
            tracing::info!(%addr, relay = %keys.current().current().fingerprint(), "relay listening");
        }
        loop {
            let (tcp, addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Per esempio EMFILE: si rallenta invece di girare a vuoto.
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
                // Le chiavi in vigore al momento dell'accept: una ricarica vale per le
                // connessioni successive.
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
                });
                tracing::debug!(%addr, error = %err, "handshake failed");
                return;
            }
        };
        let peer = pending.peer();
        // PROTOCOL §15.4, prima del messaggio 2: un rifiuto equivale a una chiave sconosciuta,
        // che non riceve nemmeno il secondo messaggio dell'handshake.
        let certificate = match admit(&self.policy.current(), &peer, pending.payload()) {
            Ok(certificate) => certificate,
            Err(reason) => {
                audit(&DomainEvent::AuthenticationFailed {
                    peer: Some(peer),
                    reason,
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

/// Passi 1–11 di PROTOCOL §15.4 sul canale esterno: denylist della chiave, verifica del
/// certificato (se il payload non è vuoto) e decisione della policy. Restituisce i dati
/// verificati del certificato, che il core ricontrolla con la policy del momento.
fn admit(
    policy: &AccessPolicy,
    peer: &Fingerprint,
    payload: &[u8],
) -> Result<Option<Arc<CertClaims>>, AuthFailureReason> {
    let trust = policy.cert_trust();
    // Passo 1, anche senza certificato.
    if trust.is_key_revoked(peer) {
        return Err(AuthFailureReason::KeyRevoked);
    }
    // Passi 3–6 (passo 2: payload vuoto, nessun certificato).
    let certificate = if payload.is_empty() {
        None
    } else {
        let claims = zt_crypto::verify_certificate(payload, peer, trust)
            .map_err(AuthFailureReason::Certificate)?;
        Some(Arc::new(claims))
    };
    // Passi 5 e 7–11 e la precedenza della whitelist.
    policy.admit(peer, certificate.as_ref(), crate::unix_now())?;
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
            // Prima la policy: una connessione autenticata con la policy nuova non deve
            // arrivare al core prima della policy stessa.
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
                            // Coda piena o connessione già chiusa: la si stacca.
                            tracing::warn!(conn = conn.0, "outbound queue overflow");
                            peers.remove(&conn);
                            pending.push(Input::Disconnected { conn });
                        }
                    }
                    Output::Close { conn } => {
                        // Lasciar cadere il sender chiude la connessione dopo i frame già in coda.
                        peers.remove(&conn);
                    }
                    Output::Audit(event) => audit(&event),
                }
            }
        }
    }
}
