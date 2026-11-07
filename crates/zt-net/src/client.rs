//! Libreria client: apre uno stream verso un nodo attraverso il relay e lo collega a un
//! flusso locale (in `zt-client`, stdin/stdout di OpenSSH).

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, timeout_at};
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, PublicKey};
use zt_domain::flow::Window;
use zt_domain::{Frame, NodeId, StreamId};

use crate::channel::Established;
use crate::stream::{CONFIRM, STREAM_QUEUE, StreamIo, pump};
use crate::{NetError, Timeouts, channel};

/// Configurazione di una connessione client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Indirizzo del relay (`host:porta`).
    pub relay: String,
    /// Chiave pubblica del relay, pinnata.
    pub relay_key: PublicKey,
    /// Nodo di destinazione.
    pub node: NodeId,
    /// Chiave pubblica dell'agent del nodo, pinnata per il canale end-to-end.
    pub node_key: PublicKey,
    /// Timeout di rete.
    pub timeouts: Timeouts,
}

/// Si connette al nodo e inoltra `local` finché una delle due parti chiude.
///
/// # Errors
/// [`NetError::Rejected`] se il relay nega lo stream, [`NetError::StreamClosed`] se l'agent
/// rifiuta il client, oltre agli errori di rete e di handshake.
pub async fn connect<L>(
    identity: &Identity,
    config: &ClientConfig,
    local: L,
) -> Result<(), NetError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let t = &config.timeouts;
    let tcp = timeout(t.handshake, TcpStream::connect(&config.relay))
        .await
        .map_err(|_| NetError::Timeout("connect"))??;
    let _ = tcp.set_nodelay(true);
    let mut ch = channel::connect(tcp, identity, &config.relay_key, Channel::Outer, t).await?;
    let stream = StreamId::try_from(1).map_err(|_| NetError::Protocol("stream id"))?;
    ch.send(
        &Frame::Open {
            stream,
            target: config.node.clone(),
        },
        t,
    )
    .await?;
    timeout(t.open, await_ack(&mut ch, stream))
        .await
        .map_err(|_| NetError::Timeout("open"))??;

    let (to_stream, from_driver) = mpsc::channel(STREAM_QUEUE);
    let (out_tx, out_rx) = mpsc::channel(1024);
    let relay_link = drive(ch, stream, to_stream, out_rx, t);
    let session = async {
        let mut io = StreamIo::new(stream, from_driver, out_tx);
        let (msg1, waiting) = noise::initiate(identity, &config.node_key, Channel::EndToEnd)?;
        io.send_data(msg1).await?;
        let msg2 = io.recv_message(t).await?;
        let mut transport = waiting.complete(&msg2)?;
        io.send_data(transport.encrypt(CONFIRM)?).await?;
        pump(io, transport, local, None).await
    };
    let (link, session) = tokio::join!(relay_link, session);
    session.and(link)
}

async fn await_ack(ch: &mut Established<TcpStream>, stream: StreamId) -> Result<(), NetError> {
    loop {
        match ch.recv().await?.ok_or(NetError::Closed)? {
            Frame::OpenAck { stream: s } if s == stream => return Ok(()),
            Frame::Reject { stream: s, reason } if s == stream => {
                return Err(NetError::Rejected(reason));
            }
            Frame::Pong { .. } => {}
            _ => return Err(NetError::Protocol("unexpected frame while opening")),
        }
    }
}

/// Inoltra frame tra la connessione con il relay e lo stream, finché lo stream non termina.
async fn drive(
    mut ch: Established<TcpStream>,
    stream: StreamId,
    to_stream: mpsc::Sender<Frame>,
    mut out_rx: mpsc::Receiver<Frame>,
    t: &Timeouts,
) -> Result<(), NetError> {
    let mut keepalive = tokio::time::interval(t.keepalive);
    keepalive.tick().await;
    let mut deadline = crate::deadline(t.idle);
    let mut nonce: u64 = 0;
    // Credito del relay verso lo stream, applicato prima di accodare (finding 0002-14).
    let mut recv = Window::initial();
    loop {
        tokio::select! {
            inbound = timeout_at(deadline, ch.recv()) => {
                let frame = inbound.map_err(|_| NetError::Timeout("relay idle"))??.ok_or(NetError::Closed)?;
                deadline = crate::deadline(t.idle);
                match &frame {
                    Frame::Data { stream: s, .. } | Frame::WindowUpdate { stream: s, .. } | Frame::Close { stream: s, .. }
                        if *s == stream =>
                    {
                        if let Frame::Data { payload, .. } = &frame {
                            recv.consume(payload.len()).map_err(NetError::Protocol)?;
                        }
                        if to_stream.try_send(frame).is_err() {
                            return Err(NetError::Protocol("stream queue overflow"));
                        }
                    }
                    Frame::Pong { .. } => {}
                    _ => return Err(NetError::Protocol("unexpected frame from relay")),
                }
            }
            outbound = out_rx.recv() => match outbound {
                Some(frame) => {
                    if let Frame::WindowUpdate { credit, .. } = &frame {
                        recv.grant(credit.get()).map_err(NetError::Protocol)?;
                    }
                    ch.send(&frame, t).await?;
                }
                None => return Ok(()),
            },
            _ = keepalive.tick() => {
                nonce = nonce.wrapping_add(1);
                ch.send(&Frame::Ping { nonce }, t).await?;
            }
        }
    }
}
