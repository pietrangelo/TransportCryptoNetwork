//! Sans-IO Noise IK handshake with typestate.
//!
//! ```text
//! initiator (agent/client)                          responder (relay/agent)
//!   initiate() ── msg1: e, es, s, ss ──────────────▶ respond()  → AuthorizationPending
//!                                                     peer() → policy decision
//!   AwaitingResponse ◀───────── msg2: e, ee, se ──── accept()  → Transport
//!   complete() → Transport
//! ```
//!
//! IK: the initiator knows and **pins** the static key of the responder; the responder learns
//! the initiator's key from the first message. If the decision is negative the responder
//! simply does not reply: the initiator learns nothing, not even whether its key exists.

use snow::{Builder, HandshakeState, TransportState};
use zt_domain::{AcceptedSuites, Fingerprint, HandshakeSuite};

use crate::error::CryptoError;
use crate::identity::{Identity, PublicKey, fingerprint_of_x25519};
use crate::keyring::Keyring;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Maximum length of a Noise message.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// AEAD tag added to every transport message.
pub const TAG_LEN: usize = 16;

/// Maximum plaintext of a transport message.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - TAG_LEN;

/// Which channel the handshake takes place on. The value goes into the Noise *prologue*, so
/// a message of one channel is never valid on the other (domain separation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Peer ↔ relay.
    Outer,
    /// Client ↔ agent, through the relay (which cannot read it).
    EndToEnd,
}

impl Channel {
    const fn prologue(self) -> &'static [u8] {
        match self {
            Self::Outer => b"TCN/1 outer",
            Self::EndToEnd => b"TCN/1 end-to-end",
        }
    }
}

fn builder(
    local: &Identity,
    channel: Channel,
) -> Result<(Builder<'static>, zeroize::Zeroizing<[u8; 32]>), CryptoError> {
    let params = PATTERN.parse().map_err(|_| CryptoError::Handshake)?;
    let secret = local.x25519_secret();
    let builder = Builder::new(params)
        .prologue(channel.prologue())
        .map_err(|_| CryptoError::Handshake)?;
    Ok((builder, secret))
}

/// Maximum payload of message 1: a client certificate (PROTOCOL §15.3).
pub const MAX_HANDSHAKE_PAYLOAD_LEN: usize = zt_domain::limits::MAX_CERT_LEN;

/// Initiator: produces the first message toward a responder whose key it knows.
///
/// # Errors
/// [`CryptoError::Handshake`] if the Noise state cannot be built.
pub fn initiate(
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    initiate_with_payload(local, remote, channel, &[])
}

/// Like [`initiate`], with `payload` encrypted in message 1 (the client certificate,
/// PROTOCOL §15.3).
///
/// # Errors
/// [`CryptoError::MessageTooLarge`] over [`MAX_HANDSHAKE_PAYLOAD_LEN`],
/// [`CryptoError::Handshake`] if the Noise state cannot be built.
pub fn initiate_with_payload(
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
    payload: &[u8],
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    if payload.len() > MAX_HANDSHAKE_PAYLOAD_LEN {
        return Err(CryptoError::MessageTooLarge);
    }
    let (builder, secret) = builder(local, channel)?;
    let remote_static = remote.x25519();
    let mut state = builder
        .local_private_key(secret.as_ref())
        .and_then(|b| b.remote_public_key(&remote_static))
        .and_then(Builder::build_initiator)
        .map_err(|_| CryptoError::Handshake)?;
    let msg1 = write(&mut state, payload)?;
    Ok((
        msg1,
        AwaitingResponse {
            state,
            responder: remote.fingerprint(),
        },
    ))
}

/// Initiator with an explicit, pinned `suite` (PROTOCOL §7.5): there is no fallback to another
/// suite (RED stub).
///
/// # Errors
/// Always (stub).
pub fn initiate_suite(
    _local: &Identity,
    _remote: &PublicKey,
    _channel: Channel,
    _suite: HandshakeSuite,
    _payload: &[u8],
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    Err(CryptoError::UnsupportedSuite)
}

/// Responder that tries the suites of `accepted` (RED stub).
///
/// # Errors
/// Always (stub).
pub fn respond_suites(
    _keys: &Keyring,
    _msg1: &[u8],
    _channel: Channel,
    _accepted: AcceptedSuites,
) -> Result<AuthorizationPending, CryptoError> {
    Err(CryptoError::Handshake)
}

/// Responder: reads the first message and finds out who the initiator is.
///
/// # Errors
/// [`CryptoError::Handshake`] if the message is not valid for this identity and channel.
pub fn respond(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
) -> Result<AuthorizationPending, CryptoError> {
    if msg1.len() > MAX_MESSAGE_LEN {
        return Err(CryptoError::Handshake);
    }
    let (builder, secret) = builder(local, channel)?;
    let mut state = builder
        .local_private_key(secret.as_ref())
        .and_then(Builder::build_responder)
        .map_err(|_| CryptoError::Handshake)?;
    // The decrypted payload never exceeds `msg1`.
    let mut buffer = vec![0_u8; msg1.len()];
    let len = state
        .read_message(msg1, &mut buffer)
        .map_err(|_| CryptoError::Handshake)?;
    // Over the maximum the payload is not interpreted, and the error is the same as for an
    // invalid message (no oracle).
    if len > MAX_HANDSHAKE_PAYLOAD_LEN {
        return Err(CryptoError::Handshake);
    }
    buffer.truncate(len);
    buffer.shrink_to_fit();
    let peer = remote_fingerprint(&state)?;
    Ok(AuthorizationPending {
        state,
        peer,
        payload: buffer,
    })
}

/// Responder with a [`Keyring`]: accepts a `msg1` encrypted to the current key or to the
/// previous one (PROTOCOL §14).
///
/// # Errors
/// [`CryptoError::Handshake`] if `msg1` is not valid for either of the two keys.
pub fn respond_any(
    keys: &Keyring,
    msg1: &[u8],
    channel: Channel,
) -> Result<AuthorizationPending, CryptoError> {
    // A failed attempt leaves no state: each `respond` builds a new handshake.
    // The timing reveals which key worked; that is not a secret (both are public).
    match (respond(keys.current(), msg1, channel), keys.previous()) {
        (Ok(pending), _) => Ok(pending),
        (Err(_), Some(previous)) => respond(previous, msg1, channel),
        (Err(err), None) => Err(err),
    }
}

/// The initiator has sent `msg1` and awaits the response.
#[derive(Debug)]
#[must_use = "the handshake is not complete until `complete` is called"]
pub struct AwaitingResponse {
    state: HandshakeState,
    responder: Fingerprint,
}

impl AwaitingResponse {
    /// The suite of this handshake (RED stub).
    #[must_use]
    pub fn suite(&self) -> HandshakeSuite {
        HandshakeSuite::NoiseIkhfs25519MlKem768
    }

    /// Completes the handshake with the second message.
    ///
    /// # Errors
    /// [`CryptoError::Handshake`] if `msg2` does not come from the pinned responder.
    pub fn complete(mut self, msg2: &[u8]) -> Result<Transport, CryptoError> {
        if msg2.len() > MAX_MESSAGE_LEN {
            return Err(CryptoError::Handshake);
        }
        let mut payload = vec![0_u8; msg2.len()];
        let len = self
            .state
            .read_message(msg2, &mut payload)
            .map_err(|_| CryptoError::Handshake)?;
        // Message 2 is always empty (PROTOCOL §15.3).
        if len != 0 {
            return Err(CryptoError::Handshake);
        }
        Transport::from_handshake(self.state, self.responder)
    }
}

/// The responder knows the identity of the initiator and must decide whether to accept it.
///
/// Rejecting simply means discarding this value: there is no rejection message.
#[derive(Debug)]
#[must_use = "drop to reject, or call `accept`"]
pub struct AuthorizationPending {
    state: HandshakeState,
    peer: Fingerprint,
    payload: Vec<u8>,
}

impl AuthorizationPending {
    /// The suite the initiator used (RED stub).
    #[must_use]
    pub fn suite(&self) -> HandshakeSuite {
        HandshakeSuite::NoiseIkhfs25519MlKem768
    }

    /// The authenticated identity of the initiator.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.peer
    }

    /// The payload of message 1, authenticated by Noise (empty if the initiator did not send
    /// one).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Accepts the initiator: produces `msg2` and the transport channel.
    ///
    /// # Errors
    /// [`CryptoError::Handshake`] if the Noise state cannot advance.
    pub fn accept(mut self) -> Result<(Vec<u8>, Transport), CryptoError> {
        let msg2 = write(&mut self.state, &[])?;
        let transport = Transport::from_handshake(self.state, self.peer)?;
        Ok((msg2, transport))
    }
}

/// Messages per direction after which both parties perform the Noise rekey.
///
/// The rekey is implicit: no message on the wire, both parties perform it at the same
/// counter (TCP delivers in order and a rejected message closes the channel). Each period has
/// a key derived one-way from the previous one: whoever reads the process memory cannot
/// decrypt the traffic of past periods. With the 30 s keepalive an idle channel changes key
/// every ~8.5 hours; with SSH traffic roughly every 16 MiB.
pub const REKEY_INTERVAL: usize = 1024;

/// Encrypted and authenticated channel after the handshake.
#[derive(Debug)]
pub struct Transport {
    state: TransportState,
    peer: Fingerprint,
    sent: usize,
    received: usize,
}

impl Transport {
    fn from_handshake(state: HandshakeState, peer: Fingerprint) -> Result<Self, CryptoError> {
        let state = state
            .into_transport_mode()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Self {
            state,
            peer,
            sent: 0,
            received: 0,
        })
    }

    /// The authenticated identity of the other party.
    #[must_use]
    pub fn peer(&self) -> Fingerprint {
        self.peer
    }

    /// Rekeys performed on send.
    #[must_use]
    pub const fn send_epoch(&self) -> usize {
        self.sent / REKEY_INTERVAL
    }

    /// Rekeys performed on receive.
    #[must_use]
    pub const fn recv_epoch(&self) -> usize {
        self.received / REKEY_INTERVAL
    }

    /// Encrypts a message.
    ///
    /// # Errors
    /// [`CryptoError::MessageTooLarge`] over [`MAX_PLAINTEXT_LEN`].
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::MessageTooLarge);
        }
        let mut out = vec![0_u8; plaintext.len().saturating_add(TAG_LEN)];
        let len = self
            .state
            .write_message(plaintext, &mut out)
            .map_err(|_| CryptoError::Handshake)?;
        out.truncate(len);
        self.sent = self.sent.wrapping_add(1);
        if self.sent.is_multiple_of(REKEY_INTERVAL) {
            self.state.rekey_outgoing();
        }
        Ok(out)
    }

    /// Decrypts a message into a **new** buffer, sized to the message.
    ///
    /// One buffer per message ensures that a queued frame retains only its own memory, never a
    /// shared read buffer (finding 10 of review 0001).
    ///
    /// # Errors
    /// [`CryptoError::Decrypt`] if the message is not authentic, is out of order or replayed.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let mut out = vec![0_u8; ciphertext.len().saturating_sub(TAG_LEN)];
        let len = self
            .state
            .read_message(ciphertext, &mut out)
            .map_err(|_| CryptoError::Decrypt)?;
        out.truncate(len);
        // Only authentic messages count: a forged one does not move the rekey.
        self.received = self.received.wrapping_add(1);
        if self.received.is_multiple_of(REKEY_INTERVAL) {
            self.state.rekey_incoming();
        }
        Ok(out)
    }
}

fn write(state: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0_u8; MAX_MESSAGE_LEN];
    let len = state
        .write_message(payload, &mut out)
        .map_err(|_| CryptoError::Handshake)?;
    out.truncate(len);
    Ok(out)
}

fn remote_fingerprint(state: &HandshakeState) -> Result<Fingerprint, CryptoError> {
    let raw = state.get_remote_static().ok_or(CryptoError::Handshake)?;
    let key: [u8; 32] = raw.try_into().map_err(|_| CryptoError::Handshake)?;
    Ok(fingerprint_of_x25519(&key))
}
