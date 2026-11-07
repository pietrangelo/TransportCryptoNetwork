//! L'agent: gira sui server target, non apre porte, si connette in uscita al relay.
//!
//! Difesa in profondità: anche se il relay autorizza uno stream, l'agent verifica da sé
//! l'identità end-to-end del client contro il proprio elenco. Un relay compromesso non può
//! quindi aprire sessioni SSH verso i nodi.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, PublicKey};
use zt_domain::{
    AuthFailureReason, CloseReason, DomainEvent, Fingerprint, Frame, NodeId, RejectReason, StreamId,
};

use crate::relay::audit;
use crate::stream::{STREAM_QUEUE, StreamIo, pump};
use crate::{NetError, Timeouts, channel};

/// Configurazione dell'agent.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Indirizzo del relay (`host:porta`).
    pub relay: String,
    /// Chiave pubblica del relay, pinnata.
    pub relay_key: PublicKey,
    /// Nome di questo nodo.
    pub node: NodeId,
    /// Demone SSH locale.
    pub ssh_target: String,
    /// Client accettati end-to-end.
    pub authorized_clients: Arc<HashSet<Fingerprint>>,
    /// Timeout di rete.
    pub timeouts: Timeouts,
    /// Stream contemporanei.
    pub max_streams: usize,
}

/// Mantiene l'agent connesso al relay per sempre, con backoff esponenziale e jitter.
pub async fn run(identity: Arc<Identity>, config: AgentConfig) {
    const MAX_DELAY: Duration = Duration::from_secs(60);
    let mut delay = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        match run_session(&identity, &config).await {
            Ok(()) => tracing::info!("relay closed the connection"),
            Err(err) => tracing::warn!(error = %err, "relay session ended"),
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
pub async fn run_session(identity: &Arc<Identity>, config: &AgentConfig) -> Result<(), NetError> {
    let t = &config.timeouts;
    let tcp = timeout(t.handshake, TcpStream::connect(&config.relay))
        .await
        .map_err(|_| NetError::Timeout("connect"))??;
    let _ = tcp.set_nodelay(true);
    let mut ch = channel::connect(tcp, identity, &config.relay_key, Channel::Outer, t).await?;
    ch.send(
        &Frame::Register {
            node: config.node.clone(),
        },
        t,
    )
    .await?;
    tracing::info!(node = %config.node, relay = %config.relay, "registered with relay");

    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(1024);
    let (done_tx, mut done_rx) = mpsc::channel::<StreamId>(config.max_streams.saturating_add(1));
    let mut streams: HashMap<StreamId, mpsc::Sender<Frame>> = HashMap::new();
    let mut keepalive = tokio::time::interval(t.keepalive);
    keepalive.tick().await;
    let mut deadline = crate::deadline(t.idle);
    let mut nonce: u64 = 0;
    loop {
        tokio::select! {
            inbound = timeout_at(deadline, ch.recv()) => {
                let frame = inbound.map_err(|_| NetError::Timeout("relay idle"))??.ok_or(NetError::Closed)?;
                deadline = crate::deadline(t.idle);
                if let Some(reply) = on_relay_frame(frame, identity, config, &mut streams, &out_tx, &done_tx)? {
                    ch.send(&reply, t).await?;
                }
            }
            Some(frame) = out_rx.recv() => ch.send(&frame, t).await?,
            Some(stream) = done_rx.recv() => {
                streams.remove(&stream);
            }
            _ = keepalive.tick() => {
                nonce = nonce.wrapping_add(1);
                ch.send(&Frame::Ping { nonce }, t).await?;
            }
        }
    }
}

fn on_relay_frame(
    frame: Frame,
    identity: &Arc<Identity>,
    config: &AgentConfig,
    streams: &mut HashMap<StreamId, mpsc::Sender<Frame>>,
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
            if streams.contains_key(&stream) {
                return Err(NetError::Protocol("relay reused a stream id"));
            }
            if streams.len() >= config.max_streams {
                return Ok(Some(Frame::Reject {
                    stream,
                    reason: RejectReason::ResourceExhausted,
                }));
            }
            let (tx, rx) = mpsc::channel(STREAM_QUEUE);
            streams.insert(stream, tx);
            let task = StreamTask {
                io: StreamIo::new(stream, rx, out_tx.clone()),
                identity: Arc::clone(identity),
                authorized: Arc::clone(&config.authorized_clients),
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
            if let Some(tx) = streams.get(&stream) {
                match tx.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Solo un relay che non applica il credito può riempire la coda.
                        streams.remove(&stream);
                        return Ok(Some(Frame::Close {
                            stream,
                            reason: CloseReason::ProtocolViolation,
                        }));
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        streams.remove(&stream);
                    }
                }
            }
            if closing {
                streams.remove(&stream);
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
    identity: Arc<Identity>,
    authorized: Arc<HashSet<Fingerprint>>,
    ssh_target: String,
    timeouts: Timeouts,
}

impl StreamTask {
    async fn serve(self) {
        let Self {
            mut io,
            identity,
            authorized,
            ssh_target,
            timeouts,
        } = self;
        let pending = match io.recv_message(&timeouts).await {
            Ok(msg1) => noise::respond(&identity, &msg1, Channel::EndToEnd),
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
        if !authorized.contains(&client) {
            audit(&DomainEvent::AuthenticationFailed {
                peer: Some(client),
                reason: AuthFailureReason::UnknownPeer,
            });
            io.close(CloseReason::Unauthorized).await;
            return;
        }
        let Ok((msg2, transport)) = pending.accept() else {
            io.close(CloseReason::ProtocolViolation).await;
            return;
        };
        if io.send_data(msg2).await.is_err() {
            return;
        }
        let Ok(Ok(ssh)) = timeout(timeouts.ssh_connect, TcpStream::connect(&ssh_target)).await
        else {
            tracing::warn!(target = %ssh_target, "cannot reach local ssh daemon");
            io.close(CloseReason::PeerGone).await;
            return;
        };
        let _ = ssh.set_nodelay(true);
        tracing::info!(target: "zt_audit", %client, "end-to-end session started");
        if let Err(err) = pump(io, transport, ssh, &timeouts).await {
            tracing::debug!(error = %err, "stream ended with error");
        }
        tracing::info!(target: "zt_audit", %client, "end-to-end session ended");
    }
}
