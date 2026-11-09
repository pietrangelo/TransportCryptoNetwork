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
    /// The prologue of `suite` on this channel (PROTOCOL §7.5). The classical suite keeps the
    /// `TCN/1` prologues, so it is byte for byte the handshake of earlier releases. From PQ-1 on
    /// a new suite has the prologue `TCN/2 <channel>` followed by its id, so a message of one
    /// suite is never valid as another.
    const fn prologue(self, suite: HandshakeSuite) -> Result<&'static [u8], CryptoError> {
        match (suite, self) {
            (HandshakeSuite::NoiseIk25519, Self::Outer) => Ok(b"TCN/1 outer"),
            (HandshakeSuite::NoiseIk25519, Self::EndToEnd) => Ok(b"TCN/1 end-to-end"),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }
}

fn builder(
    local: &Identity,
    channel: Channel,
    suite: HandshakeSuite,
) -> Result<(Builder<'static>, zeroize::Zeroizing<[u8; 32]>), CryptoError> {
    if !suite.is_supported() {
        return Err(CryptoError::UnsupportedSuite);
    }
    let prologue = channel.prologue(suite)?;
    let params = suite
        .protocol_name()
        .parse()
        .map_err(|_| CryptoError::UnsupportedSuite)?;
    let secret = local.x25519_secret();
    let builder = Builder::new(params)
        .prologue(prologue)
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
/// PROTOCOL §15.3). Always the classical suite.
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
    initiate_suite(
        local,
        remote,
        channel,
        HandshakeSuite::NoiseIk25519,
        payload,
    )
}

/// Initiator with an explicit, pinned `suite` (PROTOCOL §7.5). There is no fallback: if the
/// responder does not accept `suite` it does not answer, and the initiator does not retry
/// with another one (no downgrade).
///
/// # Errors
/// [`CryptoError::UnsupportedSuite`] if this build cannot run `suite`,
/// [`CryptoError::MessageTooLarge`] over [`MAX_HANDSHAKE_PAYLOAD_LEN`],
/// [`CryptoError::Handshake`] if the Noise state cannot be built.
pub fn initiate_suite(
    local: &Identity,
    remote: &PublicKey,
    channel: Channel,
    suite: HandshakeSuite,
    payload: &[u8],
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    let (builder, secret) = builder(local, channel, suite)?;
    if payload.len() > MAX_HANDSHAKE_PAYLOAD_LEN {
        return Err(CryptoError::MessageTooLarge);
    }
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
            suite,
        },
    ))
}

/// Responder that tries every supported suite of `accepted`, each with the current key and
/// then the previous one (PROTOCOL §7.5, §14). Nothing on the wire names the suite (AP-11):
/// a suite whose message 1 cannot have this length is skipped without running Noise.
///
/// # Errors
/// [`CryptoError::Handshake`] if `msg1` is not valid for any accepted suite and key. The
/// error is the same whatever the reason (no oracle).
pub fn respond_suites(
    keys: &Keyring,
    msg1: &[u8],
    channel: Channel,
    accepted: AcceptedSuites,
) -> Result<AuthorizationPending, CryptoError> {
    // A failed attempt leaves no state: each try builds a new handshake. The timing reveals
    // which suite and key worked; neither is a secret (the keys are public, and the suite is
    // implied by the length).
    for suite in accepted.iter().filter(|s| s.is_supported()) {
        if msg1.len() < suite.msg1_overhead() || msg1.len() > suite.max_msg1_len() {
            continue;
        }
        if let Ok(pending) = respond_one(keys.current(), msg1, channel, suite) {
            return Ok(pending);
        }
        if let Some(previous) = keys.previous()
            && let Ok(pending) = respond_one(previous, msg1, channel, suite)
        {
            return Ok(pending);
        }
    }
    Err(CryptoError::Handshake)
}

/// Responder: reads the first message and finds out who the initiator is. Always the
/// classical suite.
///
/// # Errors
/// [`CryptoError::Handshake`] if the message is not valid for this identity and channel.
pub fn respond(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
) -> Result<AuthorizationPending, CryptoError> {
    respond_one(local, msg1, channel, HandshakeSuite::NoiseIk25519)
}

fn respond_one(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
    suite: HandshakeSuite,
) -> Result<AuthorizationPending, CryptoError> {
    if msg1.len() > MAX_MESSAGE_LEN {
        return Err(CryptoError::Handshake);
    }
    let (builder, secret) = builder(local, channel, suite).map_err(|_| CryptoError::Handshake)?;
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
        suite,
    })
}

/// Responder with a [`Keyring`]: accepts a classical `msg1` encrypted to the current key or
/// to the previous one (PROTOCOL §14).
///
/// # Errors
/// [`CryptoError::Handshake`] if `msg1` is not valid for either of the two keys.
pub fn respond_any(
    keys: &Keyring,
    msg1: &[u8],
    channel: Channel,
) -> Result<AuthorizationPending, CryptoError> {
    respond_suites(
        keys,
        msg1,
        channel,
        AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
    )
}

/// The initiator has sent `msg1` and awaits the response.
#[derive(Debug)]
#[must_use = "the handshake is not complete until `complete` is called"]
pub struct AwaitingResponse {
    state: HandshakeState,
    responder: Fingerprint,
    suite: HandshakeSuite,
}

impl AwaitingResponse {
    /// The suite of this handshake.
    #[must_use]
    pub const fn suite(&self) -> HandshakeSuite {
        self.suite
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
    suite: HandshakeSuite,
}

impl AuthorizationPending {
    /// The suite the initiator used.
    #[must_use]
    pub const fn suite(&self) -> HandshakeSuite {
        self.suite
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
