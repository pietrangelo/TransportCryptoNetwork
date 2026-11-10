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
use tokio_util::codec::{Framed, LengthDelimitedCodec, LengthDelimitedCodecError};
use zt_crypto::noise::{self, Channel, MAX_MESSAGE_LEN};
use zt_crypto::{Identity, Keyring, PeerKey};
use zt_domain::{AcceptedSuites, Fingerprint, Frame, HandshakeSuite, HybridFingerprint};
use zt_proto::FrameDecoder;

use crate::{NetError, Timeouts};

/// The longest legitimate first transport message of an initiator, before its key is
/// confirmed (PROTOCOL §10.1, finding A8-4): the AEAD tag and the largest of `Register` with
/// the longest node name, `Open` with the longest target, and `Ping`. Until key confirmation
/// a responder buffers no more than this.
pub const MAX_FIRST_MESSAGE_LEN: usize = zt_domain::limits::NOISE_TAG_LEN
    + zt_domain::limits::FRAME_HEADER_LEN
    + zt_domain::limits::MAX_NODE_ID_LEN;

// `Register` and `Open` carry one node name; `Ping` an 8-byte nonce. Nothing larger may be a
// first frame, and the cap stays far below the Noise maximum.
const _: () = {
    assert!(8 <= zt_domain::limits::MAX_NODE_ID_LEN);
    assert!(MAX_FIRST_MESSAGE_LEN < 128);
    assert!(MAX_FIRST_MESSAGE_LEN <= MAX_MESSAGE_LEN);
};

fn codec() -> LengthDelimitedCodec {
    codec_capped(MAX_MESSAGE_LEN)
}

/// A codec that refuses, on sight of the length prefix, any message over `max` bytes.
fn codec_capped(max: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(max)
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
    remote: &PeerKey,
    channel: Channel,
    timeouts: &Timeouts,
) -> Result<Established<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    connect_suite(
        io,
        local,
        remote,
        channel,
        HandshakeSuite::NoiseIk25519,
        &[],
        timeouts,
    )
    .await
}

/// Like [`connect`], with `payload` in message 1 (the client certificate, PROTOCOL §15.3).
///
/// # Errors
/// Like [`connect`]; [`NetError::Crypto`] for a payload over the maximum.
pub async fn connect_with_payload<IO>(
    io: IO,
    local: &Identity,
    remote: &PeerKey,
    channel: Channel,
    payload: &[u8],
    timeouts: &Timeouts,
) -> Result<Established<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    connect_suite(
        io,
        local,
        remote,
        channel,
        HandshakeSuite::NoiseIk25519,
        payload,
        timeouts,
    )
    .await
}

/// Like [`connect_with_payload`], with the pinned `suite` (PROTOCOL §7.5). There is no
/// fallback to another suite.
///
/// # Errors
/// Like [`connect`]; [`NetError::Crypto`] for a suite this build cannot run.
pub async fn connect_suite<IO>(
    io: IO,
    local: &Identity,
    remote: &PeerKey,
    channel: Channel,
    suite: HandshakeSuite,
    payload: &[u8],
    timeouts: &Timeouts,
) -> Result<Established<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(io, codec());
    let handshake = async {
        let (msg1, waiting) = noise::initiate_suite(local, remote, channel, suite, payload)?;
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
        scratch: BytesMut::new(),
    })
}

/// Responder-side handshake (relay): reads the first message and stops before replying.
/// Classical suite only, within `timeouts.handshake`.
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
    let mut pending = accept_suites(
        io,
        local,
        channel,
        AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
        AcceptDeadlines {
            msg1: timeouts.handshake,
        },
    )
    .await?;
    // No admission here: the channel is confirmed as soon as it is established.
    pending.confirm_on_establish = true;
    Ok(pending)
}

/// Deadlines of a responder handshake (PROTOCOL §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptDeadlines {
    /// From the call to a complete message 1.
    pub msg1: std::time::Duration,
}

/// Responder-side handshake that accepts the suites of `accepted` (PROTOCOL §7.5) and
/// buffers at most the longest legitimate message 1 of those suites (§10.1, finding G2): a
/// longer length prefix is refused as soon as it is read, before any byte of the message is
/// buffered. Message 1 must be complete within `deadlines.msg1`, however slowly it trickles in
/// (finding AP-20).
///
/// # Errors
/// [`NetError::Timeout`] past `deadlines.msg1`, [`NetError::Oversized`] for a length prefix
/// over the cap, [`NetError::Closed`] or [`NetError::Io`] if the peer goes away first,
/// [`NetError::Crypto`] if message 1 is valid for no accepted suite and key.
pub async fn accept_suites<IO>(
    io: IO,
    local: &Keyring,
    channel: Channel,
    accepted: AcceptedSuites,
    deadlines: AcceptDeadlines,
) -> Result<Pending<IO>, NetError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed = Framed::new(io, codec_capped(accepted.max_msg1_len()));
    let msg1 = match timeout(deadlines.msg1, framed.next()).await {
        Err(_) => return Err(NetError::Timeout("message 1")),
        Ok(None) => return Err(NetError::Closed),
        Ok(Some(Err(err))) if is_too_long(&err) => return Err(NetError::Oversized),
        Ok(Some(Err(err))) => return Err(NetError::Io(err)),
        Ok(Some(Ok(msg1))) => msg1,
    };
    let pending = noise::respond_suites(local, &msg1, channel, accepted)?;
    // Nothing is read until message 2 is sent: `Pending::establish` sets the first-frame cap
    // then (the codec applies its maximum to writes too, and a hybrid message 2 is longer).
    Ok(Pending {
        framed,
        handshake: pending,
        confirm_on_establish: false,
    })
}

/// `true` if `err` is the codec's refusal of a length prefix over its maximum.
fn is_too_long(err: &std::io::Error) -> bool {
    err.get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<LengthDelimitedCodecError>)
}

/// Half-completed handshake: the responder knows the peer and must decide.
///
/// Dropping this value closes the connection without replying: the peer learns nothing.
#[must_use = "drop to reject, or call `establish`"]
pub struct Pending<IO> {
    framed: Framed<IO, LengthDelimitedCodec>,
    handshake: noise::AuthorizationPending,
    /// `true` if [`Pending::establish`] lifts the first-frame cap at once ([`accept`], which
    /// has no admission).
    confirm_on_establish: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Pending<IO> {
    /// The identity proven by the peer.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.handshake.peer()
    }

    /// The suite the peer used (PROTOCOL §7.5).
    #[must_use]
    pub fn suite(&self) -> HandshakeSuite {
        self.handshake.suite()
    }

    /// The peer's fingerprint v2 with the hybrid IK suite (PROTOCOL §7.5.3): its static
    /// ML-KEM key is proved only at key confirmation (finding AP-12).
    #[must_use]
    pub fn hybrid_peer(&self) -> Option<HybridFingerprint> {
        self.handshake.hybrid_peer()
    }

    /// The payload of message 1 (empty without a certificate).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.handshake.payload()
    }

    /// Accepts the peer and completes the handshake. After [`accept_suites`] the channel still
    /// refuses a message over [`MAX_FIRST_MESSAGE_LEN`] until [`Established::confirmed`].
    ///
    /// # Errors
    /// I/O or timeout errors while sending the response.
    pub async fn establish(self, timeouts: &Timeouts) -> Result<Established<IO>, NetError> {
        let Self {
            mut framed,
            handshake,
            confirm_on_establish,
        } = self;
        let (msg2, transport) = handshake.accept()?;
        timeout(timeouts.write, framed.send(Bytes::from(msg2)))
            .await
            .map_err(|_| NetError::Timeout("handshake write"))??;
        // Until the key is confirmed, at most the largest legitimate first frame (finding
        // A8-4); `Established::confirmed` lifts the cap to the Noise maximum. Set only after
        // message 2: the codec checks its maximum on writes as well, and a hybrid message 2
        // (1 152 bytes) is longer than the first-frame cap.
        framed
            .codec_mut()
            .set_max_frame_length(MAX_FIRST_MESSAGE_LEN);
        let mut established = Established {
            framed,
            transport,
            decoder: FrameDecoder::new(),
            scratch: BytesMut::new(),
        };
        if confirm_on_establish {
            established.confirmed();
        }
        Ok(established)
    }
}

/// The send-side scratch buffer keeps at most this much between frames: two `Data` chunks of
/// the streams (16 KiB plus the tag) and their headers. A larger frame's buffer is dropped after
/// it is sent, so a connection does not keep its high-water mark for its whole life, outside
/// every budget (review 0013, A13-9).
pub const SCRATCH_KEEP: usize = 2 * (16 * 1024 + 64);

/// Authenticated channel: the only state in which frames can be exchanged.
pub struct Established<IO> {
    framed: Framed<IO, LengthDelimitedCodec>,
    transport: noise::Transport,
    decoder: FrameDecoder,
    /// The plaintext of the frame being sent, reused from one frame to the next.
    scratch: BytesMut,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Established<IO> {
    /// The capacity the send-side scratch buffer keeps between frames (at most
    /// [`SCRATCH_KEEP`]).
    #[must_use]
    pub fn scratch_capacity(&self) -> usize {
        self.scratch.capacity()
    }

    /// The authenticated identity of the peer.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.transport.peer()
    }

    /// The peer's key is confirmed (PROTOCOL §10.1): messages up to the Noise maximum are
    /// accepted from now on (finding A8-4).
    pub fn confirmed(&mut self) {
        self.framed
            .codec_mut()
            .set_max_frame_length(MAX_MESSAGE_LEN);
    }

    /// Receives the next frame. `Ok(None)` on a clean close between two messages.
    ///
    /// It is cancellation-safe: it can be used in `tokio::select!`.
    ///
    /// # Errors
    /// Inauthentic message, malformed frame or frame with excess bytes, I/O error,
    /// [`NetError::Oversized`] for a length prefix over the current cap.
    pub async fn recv(&mut self) -> Result<Option<Frame>, NetError> {
        let message = match self.framed.next().await {
            Some(Ok(message)) => message,
            Some(Err(err)) if is_too_long(&err) => return Err(NetError::Oversized),
            Some(Err(err)) => return Err(NetError::Io(err)),
            None => return Ok(None),
        };
        // The plaintext buffer, sized to the message, becomes the frame's buffer without a copy:
        // a queued payload keeps only its own message alive (finding 0001-10).
        let plaintext = self.transport.decrypt(&message)?;
        let mut buf = BytesMut::from(Bytes::from(plaintext));
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
        self.scratch.clear();
        zt_proto::encode(frame, &mut self.scratch);
        // Encrypted straight into the write buffer, after its length prefix (the codec's own
        // format: two bytes, big endian): no ciphertext allocation, no copy (R6-E3).
        let len = self.scratch.len().saturating_add(noise::TAG_LEN);
        let prefix = u16::try_from(len).map_err(|_| NetError::Protocol("oversized frame"))?;
        let out = self.framed.write_buffer_mut();
        let start = out.len();
        out.reserve(len.saturating_add(2));
        out.extend_from_slice(&prefix.to_be_bytes());
        out.resize(start.saturating_add(2).saturating_add(len), 0);
        let written = out
            .get_mut(start.saturating_add(2)..)
            .ok_or(NetError::Protocol("write buffer"))
            .and_then(|tail| Ok(self.transport.encrypt_into(&self.scratch, tail)?));
        if self.scratch.capacity() > SCRATCH_KEEP {
            self.scratch = BytesMut::new();
        }
        match written {
            Ok(n) if n == len => {}
            other => {
                out.truncate(start);
                other?;
                return Err(NetError::Protocol("ciphertext length"));
            }
        }
        timeout(timeouts.write, SinkExt::<Bytes>::flush(&mut self.framed))
            .await
            .map_err(|_| NetError::Timeout("write"))??;
        Ok(())
    }
}
