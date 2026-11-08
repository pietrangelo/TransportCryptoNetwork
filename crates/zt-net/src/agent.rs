//! L'agent: gira sui server target, non apre porte, si connette in uscita al relay.
//!
//! Difesa in profondità: anche se il relay autorizza uno stream, l'agent verifica da sé
//! l'identità end-to-end del client contro il proprio elenco. Un relay compromesso non può
//! quindi aprire sessioni SSH verso i nodi.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};
use zt_crypto::Keyring;
use zt_crypto::noise::{self, Channel, MAX_HANDSHAKE_PAYLOAD_LEN};
use zt_domain::flow::Window;
use zt_domain::limits::NOISE_MSG1_OVERHEAD;
use zt_domain::{
    AuthFailureReason, AuthorizedClients, CertClaims, CertRejection, ClientCredential, CloseReason,
    DomainEvent, Fingerprint, Frame, NodeId, RejectReason, StreamId,
};

use crate::relay::{CertFields, audit};
use crate::stream::{CONFIRM, STREAM_QUEUE, StreamIo, pump};
use crate::{NetError, Timeouts, channel};

/// Configurazione dell'agent.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Relay a cui restare connessi, tutti insieme (al massimo [`crate::MAX_RELAYS`]).
    pub relays: Vec<crate::RelayEndpoint>,
    /// Nome di questo nodo.
    pub node: NodeId,
    /// Demone SSH locale.
    pub ssh_target: String,
    /// Client accettati end-to-end.
    pub authorized_clients: crate::Revocable<AuthorizedClients>,
    /// Timeout di rete.
    pub timeouts: Timeouts,
    /// Stream contemporanei, da 1 a [`MAX_STREAMS`].
    pub max_streams: usize,
}

/// Massimo di `max_streams`: ben sotto il limite del semaforo di tokio, che oltre il suo
/// massimo va in panic (finding 0005b-4).
pub const MAX_STREAMS: usize = 4096;

/// Mantiene l'agent connesso a ogni relay dell'elenco per sempre, ciascuno con il proprio
/// backoff esponenziale e jitter (PROTOCOL §13). Verso i relay usa la chiave corrente; sul
/// canale end-to-end accetta anche quella precedente (PROTOCOL §14).
///
/// `max_streams` limita due cose: gli stream di **ciascun** relay (anche quelli che non hanno
/// ancora completato l'handshake end-to-end) e le sessioni verso sshd dell'agent **intero**.
/// Il permesso globale si prende solo dopo la conferma del client, che un relay non sa
/// falsificare: un relay compromesso esaurisce solo la propria quota e non blocca le
/// sessioni che passano dagli altri (finding 0005-1).
pub async fn run(keys: Arc<Keyring>, config: AgentConfig) {
    if config.relays.is_empty() || config.relays.len() > crate::MAX_RELAYS {
        tracing::error!(
            relays = config.relays.len(),
            "the agent needs between 1 and 8 relays"
        );
        return;
    }
    // La CLI lo valida già; qui si difende chi usa la libreria, senza panic.
    if config.max_streams == 0 || config.max_streams > MAX_STREAMS {
        tracing::error!(
            max_streams = config.max_streams,
            "the agent needs between 1 and 4096 concurrent streams"
        );
        return;
    }
    let slots = Arc::new(Semaphore::new(config.max_streams));
    let mut sessions = tokio::task::JoinSet::new();
    for relay in config.relays.clone() {
        sessions.spawn(run_one(
            Arc::clone(&keys),
            relay,
            config.clone(),
            Arc::clone(&slots),
        ));
    }
    // I cicli non terminano mai; se uno andasse in panic gli altri continuano.
    while sessions.join_next().await.is_some() {}
}

async fn run_one(
    identity: Arc<Keyring>,
    relay: crate::RelayEndpoint,
    config: AgentConfig,
    slots: Arc<Semaphore>,
) {
    const MAX_DELAY: Duration = Duration::from_secs(60);
    let mut delay = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        match run_session(&identity, &relay, &config, &slots).await {
            Ok(()) => tracing::info!(relay = %relay.address, "relay closed the connection"),
            Err(err) => tracing::warn!(relay = %relay.address, error = %err, "relay session ended"),
        }
        if started.elapsed() > MAX_DELAY {
            delay = Duration::from_secs(1);
        }
        // Jitter fino a metà del ritardo, per non far riconnettere una flotta tutta insieme.
        let half = u64::try_from(delay.as_millis() / 2)
            .unwrap_or(u64::MAX)
            .max(1);
        let jitter = getrandom::u64().unwrap_or(0).checked_rem(half).unwrap_or(0);
        tokio::time::sleep(delay.saturating_add(Duration::from_millis(jitter))).await;
        delay = delay.saturating_mul(2).min(MAX_DELAY);
    }
}

/// Una singola sessione con il relay: si connette, si registra e serve gli stream finché la
/// connessione resta in piedi.
///
/// # Errors
/// Qualsiasi errore di rete, handshake o protocollo del relay.
async fn run_session(
    identity: &Arc<Keyring>,
    relay: &crate::RelayEndpoint,
    config: &AgentConfig,
    slots: &Arc<Semaphore>,
) -> Result<(), NetError> {
    let t = &config.timeouts;
    let tcp = timeout(t.handshake, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| NetError::Timeout("connect"))??;
    let _ = tcp.set_nodelay(true);
    let mut ch = channel::connect(
        tcp,
        identity.current(),
        &relay.public_key,
        Channel::Outer,
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
                if let Some(reply) = on_relay_frame(frame, identity, config, slots, &mut streams, &out_tx, &done_tx)? {
                    ch.send(&reply, t).await?;
                }
            }
            Some(frame) = out_rx.recv() => {
                streams.on_outbound(&frame);
                ch.send(&frame, t).await?;
            }
            Some(stream) = done_rx.recv() => {
                // Gli id crescono e non si riusano (un id ripetuto chiude la sessione), e
                // `done` è di questa sessione: non può togliere lo slot di uno stream più nuovo.
                streams.slots.remove(&stream);
            }
            _ = keepalive.tick() => {
                nonce = nonce.wrapping_add(1);
                ch.send(&Frame::Ping { nonce }, t).await?;
            }
        }
    }
}

/// Coda e credito in ingresso di uno stream.
///
/// Lo slot vive quanto il task dello stream, non quanto lo stream sul filo: lo toglie solo il
/// canale `done`, alla fine del task. Così la quota per relay conta i task davvero vivi e un
/// relay compromesso che alterna `Open`, `msg1` spazzatura e `Close` non può accumulare task
/// oltre `max_streams` (finding 0005b-1).
struct Slot {
    /// `None` dopo il `Close` del relay (o una sua violazione): il task ha già ricevuto tutto
    /// quello che doveva e i frame successivi per questo id si scartano.
    tx: Option<mpsc::Sender<Frame>>,
    /// Credito che il relay ha verso questo stream: si applica **prima** di accodare, così un
    /// relay compromesso non può riempire la coda oltre la finestra (finding 0002-14).
    recv: Window,
}

/// Gli stream aperti sulla connessione con il relay.
#[derive(Default)]
struct Streams {
    slots: HashMap<StreamId, Slot>,
    /// L'ultimo id accettato: il relay assegna id crescenti e non li riusa.
    last: u32,
}

impl Streams {
    /// Restituisce credito al relay quando lo stream lo concede.
    fn on_outbound(&mut self, frame: &Frame) {
        if let Frame::WindowUpdate { stream, credit } = frame
            && let Some(slot) = self.slots.get_mut(stream)
        {
            // Il task dello stream applica gli stessi limiti: qui non può fallire.
            let _ = slot.recv.grant(credit.get());
        }
    }
}

fn on_relay_frame(
    frame: Frame,
    identity: &Arc<Keyring>,
    config: &AgentConfig,
    slots: &Arc<Semaphore>,
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
            // Quota per relay: conta anche gli stream non ancora confermati.
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
                sessions: Arc::clone(slots),
                authorized: config.authorized_clients.clone(),
                node: config.node.clone(),
                ssh_target: config.ssh_target.clone(),
                timeouts: config.timeouts.clone(),
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
            // Stream già chiuso da questa parte (slot tolto da `done`) o già chiuso dal relay
            // (coda staccata): frame in volo o ripetuto, si scarta.
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
                    // Il task dello stream ha già finito e il suo `Close` è in viaggio: il
                    // frame era in volo, si scarta. Rispondere `ProtocolViolation` qui poteva
                    // sorpassare quel `Close` e nascondere al client il motivo vero (es.
                    // `Drained` per il limite di sessioni). Lo slot lo toglie `done`.
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(None),
                    Err(mpsc::error::TrySendError::Full(_)) => false,
                };
            if !queued {
                // Solo un relay che non applica il credito può arrivare qui. Staccare la coda
                // fa finire il task; lo slot resta (e conta nella quota) finché non finisce.
                slot.tx = None;
                return Ok(Some(Frame::Close {
                    stream,
                    reason: CloseReason::ProtocolViolation,
                }));
            }
            if closing {
                // Il `Close` è già in coda: il task lo legge, poi vede la coda chiusa. Lo slot
                // lo toglie solo `done`, quando il task è davvero finito (finding 0005b-1).
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
    /// Sessioni verso sshd dell'agent intero (tutti i relay).
    sessions: Arc<Semaphore>,
    authorized: crate::Revocable<AuthorizedClients>,
    /// Il nodo di questo agent: deve essere nell'ambito effettivo di un certificato.
    node: NodeId,
    ssh_target: String,
    timeouts: Timeouts,
}

/// Passi 1–10 e 12 di PROTOCOL §15.4 sul canale end-to-end, con le CA, la denylist e
/// l'orologio di questo agent (non quelli del relay).
fn admit_client(
    clients: &AuthorizedClients,
    client: &Fingerprint,
    payload: &[u8],
    node: &NodeId,
) -> Result<ClientCredential, AuthFailureReason> {
    let trust = clients.cert_trust();
    if trust.is_key_revoked(client) {
        return Err(AuthFailureReason::KeyRevoked);
    }
    let certificate: Option<Arc<CertClaims>> = if payload.is_empty() {
        None
    } else {
        let claims = zt_crypto::verify_certificate(payload, client, trust)
            .map_err(AuthFailureReason::Certificate)?;
        Some(Arc::new(claims))
    };
    clients.admit(client, certificate.as_ref(), node, crate::unix_now())
}

impl StreamTask {
    async fn serve(self) {
        let Self {
            mut io,
            identity,
            sessions,
            authorized,
            node,
            ssh_target,
            timeouts,
        } = self;
        let pending = match io.recv_message(&timeouts).await {
            // Un messaggio 1 più lungo di quello con il certificato più grande non si
            // interpreta nemmeno (PROTOCOL §15.3): è un certificato rifiutato, non un handshake
            // da tentare.
            Ok(msg1) if msg1.len() > MAX_MSG1_LEN => {
                audit(&DomainEvent::AuthenticationFailed {
                    peer: None,
                    reason: AuthFailureReason::Certificate(CertRejection::Malformed),
                });
                io.close(CloseReason::Unauthorized).await;
                return;
            }
            Ok(msg1) => noise::respond_any(&identity, &msg1, Channel::EndToEnd),
            // Il client ha già chiuso: rispondere con un altro `Close` non serve (finding 0002-1).
            Err(NetError::StreamClosed(_)) => return,
            Err(err) => {
                tracing::debug!(error = %err, "stream ended before handshake");
                io.close(CloseReason::Timeout).await;
                return;
            }
        };
        let Ok(pending) = pending else {
            audit(&DomainEvent::AuthenticationFailed {
                peer: None,
                reason: AuthFailureReason::HandshakeFailed,
            });
            io.close(CloseReason::ProtocolViolation).await;
            return;
        };
        let client = pending.peer();
        // Prima del messaggio 2: un client rifiutato non completa l'handshake e non raggiunge
        // sshd (come un client sconosciuto, PROTOCOL §8 punto 3).
        let credential =
            match admit_client(&authorized.current(), &client, pending.payload(), &node) {
                Ok(credential) => credential,
                Err(reason) => {
                    audit(&DomainEvent::AuthenticationFailed {
                        peer: Some(client),
                        reason,
                    });
                    io.close(CloseReason::Unauthorized).await;
                    return;
                }
            };
        let Ok((msg2, mut transport)) = pending.accept() else {
            io.close(CloseReason::ProtocolViolation).await;
            return;
        };
        if io.send_data(msg2).await.is_err() {
            return;
        }
        // Il primo messaggio IK si può ripetere: un relay compromesso che lo registra può
        // rigiocarlo. Solo il vero client sa produrre un messaggio di trasporto valido, quindi
        // sshd si contatta e la sessione si registra solo dopo la conferma (finding 0002-3).
        match io.recv_message(&timeouts).await {
            Ok(confirm) if transport.decrypt(&confirm).is_ok_and(|p| p == CONFIRM) => {}
            Ok(_) => {
                audit(&DomainEvent::AuthenticationFailed {
                    peer: Some(client),
                    reason: AuthFailureReason::HandshakeFailed,
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
        // Solo ora, con un client vero, si occupa uno dei `max_streams` posti globali; resta
        // occupato fino alla fine di questa funzione.
        let Ok(_session) = sessions.try_acquire_owned() else {
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
        };
        bridge(io, transport, ssh, session, authorized, &timeouts).await;
    }
}

/// Il messaggio 1 end-to-end più lungo possibile: quello con il certificato più grande.
const MAX_MSG1_LEN: usize = NOISE_MSG1_OVERHEAD.saturating_add(MAX_HANDSHAKE_PAYLOAD_LEN);

/// Chi è il client di una sessione end-to-end e con quale credenziale è stato ammesso.
struct Session {
    client: Fingerprint,
    credential: ClientCredential,
    node: NodeId,
}

/// Al più ogni quanto si rilegge l'orologio di sistema per la scadenza di un certificato
/// (PROTOCOL §15.7): un salto dell'orologio o una VM sospesa non allungano la sessione di più.
const EXPIRY_RECHECK: Duration = Duration::from_secs(60);

/// Perché una sessione deve finire prima che lo decidano le parti.
enum Cut {
    Revoked,
    Expired,
}

/// Attende che la credenziale della sessione smetta di valere: a ogni cambio dei client
/// autorizzati e, per un certificato, a `min(not_after, adesso + 60 s)`.
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

/// Collega la sessione end-to-end a sshd fino alla fine, o fino alla revoca del client.
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
        credential = c.credential,
        ca = c.ca.as_deref(),
        serial = c.serial.as_deref(),
        cert_name = c.cert_name.as_deref(),
        not_after = c.not_after,
        "end-to-end session started"
    );
    let closer = io.closer();
    // Revoca a caldo e scadenza: se la credenziale smette di valere la sessione si chiude
    // subito, senza aspettare il relay (che potrebbe non farlo mai). Si controlla il valore
    // attuale prima di ogni attesa, quindi una revoca arrivata durante l'handshake non si perde.
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
