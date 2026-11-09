//! Noise channel over a byte transport (TCP).
//!
//! On the wire every Noise message is preceded by its length (big-endian `u16`), as the Noise
//! specification recommends. After the handshake every message contains **exactly one** TCN
//! frame: excess bytes are a violation.
//!
//! Typestate: the only way to obtain an [`Established`] is to complete a handshake; the
//! responder goes through [`Pending`], where it must decide whether to accept the peer.

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use zt_crypto::noise::{self, Channel, MAX_MESSAGE_LEN};
use zt_crypto::{Identity, Keyring, PublicKey};
use zt_domain::{Fingerprint, Frame};
use zt_proto::FrameDecoder;

use crate::{NetError, Timeouts};

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(MAX_MESSAGE_LEN)
        .new_codec()
}

async fn read_message<IO>(
    framed: &mut Framed<IO, LengthDelimitedCodec>,
) -> Result<BytesMut, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match framed.next().await {
        Some(Ok(message)) => Ok(message),
        Some(Err(err)) => Err(NetError::Io(err)),
        None => Err(NetError::Closed),
    }
}

/// Initiator-side handshake (agent, client): pins the responder's key.
///
/// # Errors
/// [`NetError::Timeout`] past `timeouts.handshake`, [`NetError::Crypto`] if the responder does
/// not prove possession of `remote`.
pub async fn connect<IO>(
    io: IO,
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
    timeouts: &Timeouts,
) -> Result<Established<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    connect_with_payload(io, local, remote, channel, &[], timeouts).await
}

/// Like [`connect`], with `payload` in message 1 (the client certificate, PROTOCOL §15.3).
///
/// # Errors
/// Like [`connect`]; [`NetError::Crypto`] for a payload over the maximum.
pub async fn connect_with_payload<IO>(
    io: IO,
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
    payload: &[u8],
    timeouts: &Timeouts,
) -> Result<Established<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(io, codec());
    let handshake = async {
        let (msg1, waiting) = noise::initiate_with_payload(local, remote, channel, payload)?;
        framed.send(Bytes::from(msg1)).await?;
        let msg2 = read_message(&mut framed).await?;
        Ok::<_, NetError>(waiting.complete(&msg2)?)
    };
    let transport = timeout(timeouts.handshake, handshake)
        .await
        .map_err(|_| NetError::Timeout("handshake"))??;
    Ok(Established {
        framed,
        transport,
        decoder: FrameDecoder::new(),
    })
}

/// Responder-side handshake (relay): reads the first message and stops before replying.
///
/// # Errors
/// [`NetError::Timeout`] past `timeouts.handshake`, [`NetError::Crypto`] on invalid messages.
pub async fn accept<IO>(
    io: IO,
    local: &Keyring,
    channel: Channel,
    timeouts: &Timeouts,
) -> Result<Pending<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(io, codec());
    let msg1 = timeout(timeouts.handshake, read_message(&mut framed))
        .await
        .map_err(|_| NetError::Timeout("handshake"))??;
    let pending = noise::respond_any(local, &msg1, channel)?;
    Ok(Pending { framed, pending })
}

/// Deadlines of a responder handshake (PROTOCOL §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptDeadlines {
    /// From the call to a complete message 1.
    pub msg1: std::time::Duration,
}

/// Responder-side handshake that accepts the suites of `accepted` and buffers at most the
/// longest legitimate message 1 of those suites (RED stub: like [`accept`]).
///
/// # Errors
/// Like [`accept`].
pub async fn accept_suites<IO>(
    io: IO,
    local: &Keyring,
    channel: Channel,
    _accepted: zt_domain::AcceptedSuites,
    deadlines: AcceptDeadlines,
    timeouts: &Timeouts,
) -> Result<Pending<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut t = timeouts.clone();
    t.handshake = deadlines.msg1;
    accept(io, local, channel, &t).await
}

/// Half-completed handshake: the responder knows the peer and must decide.
///
/// Dropping this value closes the connection without replying: the peer learns nothing.
#[must_use = "drop to reject, or call `establish`"]
pub struct Pending<IO> {
    framed: Framed<IO, LengthDelimitedCodec>,
    pending: noise::AuthorizationPending,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Pending<IO> {
    /// The identity proven by the peer.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.pending.peer()
    }

    /// The suite the peer used (PROTOCOL §7.5).
    #[must_use]
    pub fn suite(&self) -> zt_domain::HandshakeSuite {
        self.pending.suite()
    }

    /// The payload of message 1 (empty without a certificate).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.pending.payload()
    }

    /// Accepts the peer and completes the handshake.
    ///
    /// # Errors
    /// I/O or timeout errors while sending the response.
    pub async fn establish(self, timeouts: &Timeouts) -> Result<Established<IO>, NetError> {
        let Self {
            mut framed,
            pending,
        } = self;
        let (msg2, transport) = pending.accept()?;
        timeout(timeouts.write, framed.send(Bytes::from(msg2)))
            .await
            .map_err(|_| NetError::Timeout("handshake write"))??;
        Ok(Established {
            framed,
            transport,
            decoder: FrameDecoder::new(),
        })
    }
}

/// Authenticated channel: the only state in which frames can be exchanged.
pub struct Established<IO> {
    framed: Framed<IO, LengthDelimitedCodec>,
    transport: noise::Transport,
    decoder: FrameDecoder,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Established<IO> {
    /// The authenticated identity of the peer.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.transport.peer()
    }

    /// Receives the next frame. `Ok(None)` on a clean close between two messages.
    ///
    /// It is cancellation-safe: it can be used in `tokio::select!`.
    ///
    /// # Errors
    /// Inauthentic message, malformed frame or frame with excess bytes, I/O error.
    pub async fn recv(&mut self) -> Result<Option<Frame>, NetError> {
        let message = match self.framed.next().await {
            Some(Ok(message)) => message,
            Some(Err(err)) => return Err(NetError::Io(err)),
            None => return Ok(None),
        };
        let plaintext = self.transport.decrypt(&message)?;
        let mut buf = BytesMut::from(plaintext.as_slice());
        let frame = self
            .decoder
            .decode(&mut buf)?
            .ok_or(NetError::Protocol("truncated frame"))?;
        if !buf.is_empty() {
            return Err(NetError::Protocol("trailing bytes after frame"));
        }
        Ok(Some(frame))
    }

    /// Sends a frame, within `timeouts.write`.
    ///
    /// # Errors
    /// I/O errors or timeout.
    pub async fn send(&mut self, frame: &Frame, timeouts: &Timeouts) -> Result<(), NetError> {
        let mut plaintext = BytesMut::with_capacity(zt_proto::encoded_len(frame));
        zt_proto::encode(frame, &mut plaintext);
        let message = self.transport.encrypt(&plaintext)?;
        timeout(timeouts.write, self.framed.send(Bytes::from(message)))
            .await
            .map_err(|_| NetError::Timeout("write"))??;
        Ok(())
    }
}
