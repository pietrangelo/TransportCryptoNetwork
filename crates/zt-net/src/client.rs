//! Client library: opens a stream to a node through the relay and connects it to a local
//! stream (in `zt-client`, the stdin/stdout of OpenSSH).

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, timeout_at};
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, PublicKey};
use zt_domain::flow::Window;
use zt_domain::{Frame, NodeId, RejectReason, StreamId};

use crate::channel::Established;
use crate::stream::{STREAM_QUEUE, StreamIo, pump};
use crate::{NetError, Timeouts, channel};

/// Configuration of a client connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Relays to try, in order (at most [`crate::MAX_RELAYS`], PROTOCOL §13).
    pub relays: Vec<crate::RelayEndpoint>,
    /// Destination node.
    pub node: NodeId,
    /// Public key of the node's agent, pinned for the end-to-end channel.
    pub node_key: PublicKey,
    /// Handshake suite pinned for the end-to-end channel with the node (PROTOCOL §7.5).
    pub node_suite: zt_domain::HandshakeSuite,
    /// Client certificate (PROTOCOL §15), sent in message 1 of both channels.
    pub certificate: Option<std::sync::Arc<[u8]>>,
    /// Network timeouts.
    pub timeouts: Timeouts,
}

/// Connects to the node and forwards `local` until either side closes.
///
/// Tries the relays in the order of `config.relays` and moves on to the next one only for
/// failures that precede the `OpenAck` and say nothing about the right of access (PROTOCOL §13).
///
/// # Errors
/// [`NetError::Rejected`] if the relay denies the stream, [`NetError::StreamClosed`] if the
/// agent rejects the client, in addition to network and handshake errors (of the last relay
/// tried).
pub async fn connect<L>(
    identity: &Identity,
    config: &ClientConfig,
    local: L,
) -> Result<(), NetError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let t = &config.timeouts;
    if config.relays.is_empty() || config.relays.len() > crate::MAX_RELAYS {
        return Err(NetError::Protocol(
            "the client needs between 1 and 8 relays",
        ));
    }
    // The same certificate in message 1 of both channels (PROTOCOL §15.3): relay and agent each
    // verify it against their own CAs.
    let certificate: &[u8] = config.certificate.as_deref().unwrap_or(&[]);
    let stream = StreamId::try_from(1).map_err(|_| NetError::Protocol("stream id"))?;
    let mut last = NetError::Closed;
    let mut opened = None;
    for (i, relay) in config.relays.iter().enumerate() {
        match open(identity, relay, &config.node, stream, certificate, t).await {
            Ok(ch) => {
                opened = Some(ch);
                break;
            }
            Err(err) if may_try_next_relay(&err) => {
                if config.relays.get(i.saturating_add(1)).is_some() {
                    tracing::warn!(relay = %relay.address, error = %err, "relay unavailable, trying the next one");
                }
                last = err;
            }
            Err(err) => return Err(err),
        }
    }
    let Some(ch) = opened else {
        return Err(last);
    };

    let (to_stream, from_driver) = mpsc::channel(STREAM_QUEUE);
    let (out_tx, out_rx) = mpsc::channel(1024);
    let relay_link = drive(ch, stream, to_stream, out_rx, t);
    let session = async {
        let mut io = StreamIo::new(stream, from_driver, out_tx);
        let (msg1, waiting) = noise::initiate_suite(
            identity,
            &config.node_key,
            Channel::EndToEnd,
            config.node_suite,
            certificate,
        )?;
        io.send_data(msg1).await?;
        let msg2 = io.recv_message(t).await?;
        let mut transport = waiting.complete(&msg2)?;
        // Proves to the agent that this client completed the handshake (PROTOCOL §7.3): a relay
        // replaying message 1 cannot produce it.
        io.send_data(transport.encrypt(config.node_suite.confirmation())?)
            .await?;
        pump(io, transport, local, None).await
    };
    let (link, session) = tokio::join!(relay_link, session);
    session.and(link)
}

/// Connection, outer handshake and stream opening on one relay.
async fn open(
    identity: &Identity,
    relay: &crate::RelayEndpoint,
    node: &NodeId,
    stream: StreamId,
    certificate: &[u8],
    t: &Timeouts,
) -> Result<Established<TcpStream>, NetError> {
    let tcp = timeout(t.handshake, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| NetError::Timeout("connect"))??;
    let _ = tcp.set_nodelay(true);
    let mut ch = channel::connect_suite(
        tcp,
        identity,
        &relay.public_key,
        Channel::Outer,
        relay.suite,
        certificate,
        t,
    )
    .await?;
    ch.send(
        &Frame::Open {
            stream,
            target: node.clone(),
        },
        t,
    )
    .await?;
    timeout(t.open, await_ack(&mut ch, stream))
        .await
        .map_err(|_| NetError::Timeout("open"))??;
    Ok(ch)
}

/// `true` for a failure, before the `OpenAck`, that justifies trying the next relay. A policy
/// response is final (fail closed): the client does not look for a more permissive relay.
const fn may_try_next_relay(err: &NetError) -> bool {
    match err {
        NetError::Rejected(reason) => matches!(
            reason,
            RejectReason::NodeOffline | RejectReason::RateLimited
        ),
        NetError::Io(_)
        | NetError::Timeout(_)
        | NetError::Crypto(_)
        | NetError::Decode(_)
        | NetError::Protocol(_)
        | NetError::Closed => true,
        _ => false,
    }
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

/// Forwards frames between the relay connection and the stream, until the stream ends.
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
    // Relay credit towards the stream, enforced before enqueuing (finding 0002-14).
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
