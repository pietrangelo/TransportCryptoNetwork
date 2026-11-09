//! Sans-IO Noise IK handshake with typestate, in two suites (PROTOCOL §7.5).
//!
//! ```text
//! initiator (agent/client)                          responder (relay/agent)
//!   initiate() ── msg1: e, es, s, ss ──────────────▶ respond()  → AuthorizationPending
//!                                                     peer() → policy decision
//!   AwaitingResponse ◀───────── msg2: e, ee, se ──── accept()  → Transport
//!   complete() → Transport
//! ```
//!
//! The hybrid suite (`IKhfs`, PQ-1, end-to-end channel) adds `e1` after `es` in message 1 (an
//! ephemeral ML-KEM-768 encapsulation key) and `ekem1` after `ee` in message 2 (its
//! ciphertext, then `MixKey` of the shared secret). The responder encapsulates in `accept`,
//! after the authorization decision; the initiator decapsulates in `complete`.
//!
//! The hybrid IK suite (PQ-AUTH, suite 0x02, PROTOCOL §7.5.3) composes `IKhfs` with two
//! encapsulations to the parties' **static** ML-KEM-768 keys, fed to Noise as pre-shared keys:
//!
//! ```text
//! -> ct1 ‖ [psk0] e, es, e1, s, ss, {ek_i ‖ payload}   psk0 = SHA-256("TCN/3 skem-i\0" ‖ ct1 ‖ ss1)
//! <- ct2 ‖ e, ee, ekem1, se, [psk2], {}                psk2 = SHA-256("TCN/3 skem-r\0" ‖ ct2 ‖ ss2)
//! ```
//!
//! `ct1` is encapsulated to the responder's pinned key (only its holder reads message 1, and
//! the initiator's identity and certificate are protected by ML-KEM from the first byte);
//! `ct2` to the initiator's key, which message 1 carries and the fingerprint v2 binds (only
//! its holder derives the transport keys). The prologue `"TCN/3 <channel>" ‖ 0x02 ‖
//! SHA-256(ek_r) ‖ ct1` binds the channel, the suite, the responder's key and `ct1`. Node keys
//! never sign: authentication is by KEM in both directions, plus DH.
//!
//! IK: the initiator knows and **pins** the static key of the responder; the responder learns
//! the initiator's key from the first message. If the decision is negative the responder
//! simply does not reply: the initiator learns nothing, not even whether its key exists.

use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;
pub use zt_domain::HandshakeChannel as Channel;
use zt_domain::{AcceptedSuites, Fingerprint, HandshakeSuite, HybridFingerprint};

use crate::error::CryptoError;
use crate::hybrid::{EK_LEN, PeerKey, hybrid_fingerprint_of};
use crate::identity::{Identity, fingerprint_of_x25519};
use crate::kem::{ENCAPSULATION_RANDOMNESS_LEN, Kem, MlKem768};
use crate::keyring::Keyring;
use crate::prefilter::{self, Symmetric};

/// Maximum length of a Noise message.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// AEAD tag added to every transport message.
pub const TAG_LEN: usize = 16;

/// Maximum plaintext of a transport message.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - TAG_LEN;

/// The prologue of `suite` on `channel` (PROTOCOL §7.5): a message of one channel or suite is
/// never valid on another (domain separation). The classical suite keeps the `TCN/1`
/// prologues, so it is byte for byte the handshake of earlier releases. The hybrid suite has
/// `TCN/2 <channel>` followed by its id.
/// `None` for a suite this version of `zt-crypto` does not know.
const fn prologue(channel: Channel, suite: HandshakeSuite) -> Option<&'static [u8]> {
    match (suite, channel) {
        (HandshakeSuite::NoiseIk25519, Channel::Outer) => Some(b"TCN/1 outer"),
        (HandshakeSuite::NoiseIk25519, Channel::EndToEnd) => Some(b"TCN/1 end-to-end"),
        (HandshakeSuite::NoiseIkhfs25519MlKem768, Channel::Outer) => Some(b"TCN/2 outer\x01"),
        (HandshakeSuite::NoiseIkhfs25519MlKem768, Channel::EndToEnd) => {
            Some(b"TCN/2 end-to-end\x01")
        }
        // Followed by SHA-256(ek_r) ‖ ct1 (see [`hybrid_prologue`]).
        (HandshakeSuite::NoiseIkHybrid25519MlKem768, Channel::Outer) => Some(b"TCN/3 outer\x02"),
        (HandshakeSuite::NoiseIkHybrid25519MlKem768, Channel::EndToEnd) => {
            Some(b"TCN/3 end-to-end\x02")
        }
        _ => None,
    }
}

/// Length of an ML-KEM-768 ciphertext (`ct1`, `ct2`).
const CT_LEN: usize = 1_088;

/// Domain separation of `psk0`, from the encapsulation to the responder's static key.
const PSK_INITIATOR: &[u8] = b"TCN/3 skem-i\0";
/// Domain separation of `psk2`, from the encapsulation to the initiator's static key.
const PSK_RESPONDER: &[u8] = b"TCN/3 skem-r\0";

/// The full prologue of the hybrid IK suite: `"TCN/3 <channel>" ‖ 0x02 ‖ SHA-256(ek_r) ‖ ct1`.
fn hybrid_prologue(
    channel: Channel,
    responder_ek: &[u8],
    ct1: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let base = prologue(channel, HandshakeSuite::NoiseIkHybrid25519MlKem768)
        .ok_or(CryptoError::UnsupportedSuite)?;
    let mut out = Vec::with_capacity(base.len().saturating_add(32).saturating_add(ct1.len()));
    out.extend_from_slice(base);
    out.extend_from_slice(&Sha256::digest(responder_ek));
    out.extend_from_slice(ct1);
    Ok(out)
}

/// A Noise pre-shared key from a static encapsulation: `SHA-256(label ‖ ct ‖ ss)`.
fn kem_psk(label: &[u8], ct: &[u8], ss: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        Sha256::new()
            .chain_update(label)
            .chain_update(ct)
            .chain_update(ss)
            .finalize()
            .into(),
    )
}

/// Encapsulation with fresh randomness from the system.
fn encapsulate(ek: &[u8]) -> Result<(Vec<u8>, crate::kem::SharedSecret), CryptoError> {
    let mut m = Zeroizing::new([0_u8; ENCAPSULATION_RANDOMNESS_LEN]);
    getrandom::fill(m.as_mut()).map_err(|_| CryptoError::Random)?;
    MlKem768::encapsulate(ek, &m).map_err(|_| CryptoError::Handshake)
}

// The `TCN/2` prologues end with the id of their suite.
const _: () = {
    let suite = HandshakeSuite::NoiseIkhfs25519MlKem768;
    let mut channels = [Channel::Outer, Channel::EndToEnd].as_slice();
    while let [channel, rest @ ..] = channels {
        match prologue(*channel, suite) {
            Some([b'T', b'C', b'N', b'/', b'2', .., id]) => assert!(*id == suite.id()),
            _ => panic!("a TCN/2 prologue"),
        }
        channels = rest;
    }
};

fn builder(
    local: &Identity,
    channel: Channel,
    suite: HandshakeSuite,
) -> Result<(Builder<'static>, zeroize::Zeroizing<[u8; 32]>), CryptoError> {
    let prologue = prologue(channel, suite).ok_or(CryptoError::UnsupportedSuite)?;
    builder_with(local, channel, suite, prologue)
}

fn builder_with<'a>(
    local: &Identity,
    channel: Channel,
    suite: HandshakeSuite,
    prologue: &'a [u8],
) -> Result<(Builder<'a>, zeroize::Zeroizing<[u8; 32]>), CryptoError> {
    if !suite.is_supported(channel) {
        return Err(CryptoError::UnsupportedSuite);
    }
    let params = suite
        .protocol_name()
        .parse()
        .map_err(|_| CryptoError::UnsupportedSuite)?;
    let secret = local.x25519_secret();
    // snow's primitives, and TCN's KEM provider for the hybrid suite.
    let builder = Builder::with_resolver(params, Box::new(crate::resolver::Resolver))
        .prologue(prologue)
        .map_err(|_| CryptoError::Handshake)?;
    Ok((builder, secret))
}

/// Maximum payload of message 1: a client certificate of any version (PROTOCOL §15.3, §15.14).
pub const MAX_HANDSHAKE_PAYLOAD_LEN: usize = zt_domain::limits::MAX_ANY_CERT_LEN;

/// Initiator: produces the first message toward a responder whose key it knows.
///
/// # Errors
/// [`CryptoError::Handshake`] if the Noise state cannot be built.
pub fn initiate(
    local: &Identity,
    remote: impl Into<PeerKey>,
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
    remote: impl Into<PeerKey>,
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
/// [`CryptoError::UnsupportedSuite`] if this build cannot run `suite` on `channel`,
/// [`CryptoError::HybridKeyRequired`] for the hybrid IK suite with a v1 pin,
/// [`CryptoError::MessageTooLarge`] over [`MAX_HANDSHAKE_PAYLOAD_LEN`],
/// [`CryptoError::Handshake`] if the Noise state cannot be built.
pub fn initiate_suite(
    local: &Identity,
    remote: impl Into<PeerKey>,
    channel: Channel,
    suite: HandshakeSuite,
    payload: &[u8],
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    let remote = remote.into();
    if suite.requires_hybrid_identity() {
        return initiate_hybrid(local, &remote, channel, suite, payload);
    }
    let (builder, secret) = builder(local, channel, suite)?;
    if payload.len() > MAX_HANDSHAKE_PAYLOAD_LEN {
        return Err(CryptoError::MessageTooLarge);
    }
    let remote_static = remote.public_key().x25519();
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
            static_dk: None,
        },
    ))
}

/// The initiator of the hybrid IK suite: `ct1 ‖ IKhfs+psk0 message 1`, with the initiator's
/// static encapsulation key in front of `payload`.
fn initiate_hybrid(
    local: &Identity,
    remote: &PeerKey,
    channel: Channel,
    suite: HandshakeSuite,
    payload: &[u8],
) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> {
    let responder = remote.hybrid().ok_or(CryptoError::HybridKeyRequired)?;
    if !suite.is_supported(channel) {
        return Err(CryptoError::UnsupportedSuite);
    }
    if payload.len() > MAX_HANDSHAKE_PAYLOAD_LEN {
        return Err(CryptoError::MessageTooLarge);
    }
    let (ct1, ss1) = encapsulate(responder.encapsulation_key())?;
    let psk0 = kem_psk(PSK_INITIATOR, &ct1, ss1.as_bytes());
    let prologue = hybrid_prologue(channel, responder.encapsulation_key(), &ct1)?;
    let (builder, secret) = builder_with(local, channel, suite, &prologue)?;
    let remote_static = responder.classical().x25519();
    let mut state = builder
        .psk(0, &psk0)
        .and_then(|b| b.local_private_key(secret.as_ref()))
        .and_then(|b| b.remote_public_key(&remote_static))
        .and_then(Builder::build_initiator)
        .map_err(|_| CryptoError::Handshake)?;
    let own = local.static_kem();
    let mut full = Vec::with_capacity(EK_LEN.saturating_add(payload.len()));
    full.extend_from_slice(&own.ek);
    full.extend_from_slice(payload);
    let mut msg1 = ct1;
    msg1.extend_from_slice(&write(&mut state, &full)?);
    Ok((
        msg1,
        AwaitingResponse {
            state,
            responder: responder.fingerprint(),
            suite,
            static_dk: Some(Box::new(local.static_decapsulation_key())),
        },
    ))
}

/// Responder for the suites of `accepted`, with the current key or the previous one (PROTOCOL
/// §7.5, §14). Nothing on the wire names the suite or the key (AP-11): the cheap test of
/// [`select`] picks at most one suite and key, and only that one runs Noise in full.
///
/// The cost of an invalid message 1 (finding A12-6 of review 0012), per key: one X25519
/// multiplication if a pre-PQ-AUTH suite fits its length, plus one static decapsulation and
/// one multiplication if the hybrid IK suite does. Never a Noise state.
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
    // A failed attempt leaves no state. The timing reveals which suite and key passed the
    // test; neither is a secret (the keys are public, and the suite is implied by the length).
    let selected = select(keys, msg1, channel, accepted).ok_or(CryptoError::Handshake)?;
    selected.respond(msg1, channel)
}

/// The suite and key a message 1 is for, by the test of [`prefilter`].
struct Selected<'a> {
    local: &'a Identity,
    suite: HandshakeSuite,
    /// `psk0` of the hybrid IK suite, already derived from the static decapsulation.
    psk0: Option<Zeroizing<[u8; 32]>>,
}

impl Selected<'_> {
    /// The full Noise trial of the selected suite and key.
    fn respond(self, msg1: &[u8], channel: Channel) -> Result<AuthorizationPending, CryptoError> {
        ops::trial();
        match self.psk0 {
            Some(psk0) => respond_hybrid(self.local, msg1, channel, self.suite, &psk0),
            None => respond_one(self.local, msg1, channel, self.suite),
        }
    }
}

/// The length of the first field message 1 encrypts after `es`, tag included: `s` in IK,
/// `e1` in `IKhfs` and in the hybrid IK suite. `None` for a suite this build does not know.
const fn first_ciphertext_len(suite: HandshakeSuite) -> Option<usize> {
    match suite {
        HandshakeSuite::NoiseIk25519 => Some(DH_LEN + TAG_LEN),
        HandshakeSuite::NoiseIkhfs25519MlKem768 | HandshakeSuite::NoiseIkHybrid25519MlKem768 => {
            Some(EK_LEN + TAG_LEN)
        }
        _ => None,
    }
}

/// The first ciphertext of a message that starts with `e`.
fn first_ciphertext(message: &[u8], suite: HandshakeSuite) -> Option<&[u8]> {
    message.get(DH_LEN..DH_LEN.checked_add(first_ciphertext_len(suite)?)?)
}

/// Length of an X25519 public key.
const DH_LEN: usize = 32;

/// Picks the suite of `candidates` and the key of `keys` that `msg1` is for, by the cheap test
/// of [`prefilter`], in a fixed order: the suites without a static KEM first (one X25519
/// multiplication per key serves all of them), then the hybrid IK suite (one decapsulation and
/// one multiplication per key), each with the current key, then the previous one. The first
/// that passes is the only one Noise runs on.
fn select<'a>(
    keys: &'a Keyring,
    msg1: &[u8],
    channel: Channel,
    candidates: AcceptedSuites,
) -> Option<Selected<'a>> {
    if msg1.len() > MAX_MESSAGE_LEN {
        return None;
    }
    let fits = |suite: &HandshakeSuite| {
        suite.is_supported(channel)
            && prologue(channel, *suite).is_some()
            && (suite.msg1_overhead()..=suite.max_msg1_len()).contains(&msg1.len())
    };
    let classical: Vec<HandshakeSuite> = candidates
        .iter()
        .filter(|s| fits(s) && !s.requires_hybrid_identity())
        .collect();
    if let (false, Some(e)) = (classical.is_empty(), first_dh(msg1)) {
        for local in keys.identities() {
            let shared = prefilter::dh(&local.x25519_secret(), &e);
            for &suite in &classical {
                if classical_test(local, msg1, channel, suite, &e, &shared) {
                    return Some(Selected {
                        local,
                        suite,
                        psk0: None,
                    });
                }
            }
        }
    }
    let hybrid = candidates
        .iter()
        .find(|s| fits(s) && s.requires_hybrid_identity())?;
    keys.identities().find_map(|local| {
        let psk0 = hybrid_test(local, msg1, channel, hybrid)?;
        Some(Selected {
            local,
            suite: hybrid,
            psk0: Some(psk0),
        })
    })
}

/// `e` at the start of a message.
fn first_dh(message: &[u8]) -> Option<[u8; DH_LEN]> {
    message.get(..DH_LEN)?.try_into().ok()
}

/// The test of a suite whose message 1 is `e, es, <first ciphertext>`, with `DH(s_r, e)`
/// already computed.
fn classical_test(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
    suite: HandshakeSuite,
    e: &[u8; DH_LEN],
    shared: &[u8; 32],
) -> bool {
    let (Some(prologue), Some(first)) = (prologue(channel, suite), first_ciphertext(msg1, suite))
    else {
        return false;
    };
    let mut state = Symmetric::new(suite.protocol_name(), prologue, local.x25519_public());
    state.mix_hash(e);
    state.mix_key(shared);
    state.decrypts(first)
}

/// The test of the hybrid IK suite: `ct1`, then `psk0, e, es, e1`. Returns `psk0` if it
/// passes, so that Noise does not decapsulate a second time.
fn hybrid_test(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
    suite: HandshakeSuite,
) -> Option<Zeroizing<[u8; 32]>> {
    let (ct1, rest) = (msg1.get(..CT_LEN)?, msg1.get(CT_LEN..)?);
    let e = first_dh(rest)?;
    let first = first_ciphertext(rest, suite)?;
    let own = local.static_kem();
    ops::decaps();
    let ss1 = MlKem768::decapsulate(&own.dk, ct1).ok()?;
    let psk0 = kem_psk(PSK_INITIATOR, ct1, ss1.as_bytes());
    let prologue = hybrid_prologue(channel, &own.ek, ct1).ok()?;
    let mut state = Symmetric::new(suite.protocol_name(), &prologue, local.x25519_public());
    state.mix_key_and_hash(psk0.as_ref());
    state.mix_hash(&e);
    state.mix_key(&e);
    state.mix_key(prefilter::dh(&local.x25519_secret(), &e).as_ref());
    state.decrypts(first).then_some(psk0)
}

/// Counted operations of the responder, for the unit tests of finding A12-6: X25519
/// multiplications of the test, static decapsulations, full Noise trials.
#[cfg(test)]
pub(crate) mod ops {
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct Counts {
        pub(crate) dh: usize,
        pub(crate) decaps: usize,
        pub(crate) trials: usize,
    }

    thread_local! {
        static COUNTS: Cell<Counts> = Cell::new(Counts::default());
    }

    fn bump(f: impl FnOnce(&mut Counts)) {
        COUNTS.with(|c| {
            let mut counts = c.get();
            f(&mut counts);
            c.set(counts);
        });
    }

    pub(crate) fn reset() {
        COUNTS.with(|c| c.set(Counts::default()));
    }

    pub(crate) fn get() -> Counts {
        COUNTS.with(Cell::get)
    }

    pub(crate) fn dh() {
        bump(|c| c.dh = c.dh.saturating_add(1));
    }

    pub(crate) fn decaps() {
        bump(|c| c.decaps = c.decaps.saturating_add(1));
    }

    pub(crate) fn trial() {
        bump(|c| c.trials = c.trials.saturating_add(1));
    }
}

/// Outside the unit tests nothing is counted.
#[cfg(not(test))]
pub(crate) mod ops {
    pub(crate) const fn dh() {}
    pub(crate) const fn decaps() {}
    pub(crate) const fn trial() {}
}

/// What a responder learns from a message 1 (finding A9-3 of review 0009).
#[derive(Debug)]
pub enum Responded {
    /// The suite is accepted: the caller decides on the initiator, then accepts or drops.
    /// Boxed: it holds the whole handshake state.
    Pending(Box<AuthorizationPending>),
    /// A valid message 1 of a suite this build supports on the channel but the caller does
    /// not accept: who sent it, and with which suite. There is no `accept`: it can never
    /// produce a message 2.
    Unaccepted(Identified),
}

/// A valid message 1 of a suite outside the accepted set (see [`Responded::Unaccepted`]).
#[derive(Debug)]
pub struct Identified {
    peer: Fingerprint,
    hybrid: Option<HybridFingerprint>,
    payload: Vec<u8>,
    suite: HandshakeSuite,
}

impl Identified {
    /// The authenticated identity of the initiator. Message 1 can be replayed: this does not
    /// prove that the initiator is live.
    #[must_use]
    pub const fn peer(&self) -> Fingerprint {
        self.peer
    }

    /// The suite the initiator used.
    #[must_use]
    pub const fn suite(&self) -> HandshakeSuite {
        self.suite
    }

    /// The fingerprint v2 the initiator claimed (hybrid IK suite only). Unconfirmed: there
    /// is no message 2, so nothing proved the ML-KEM half.
    #[must_use]
    pub const fn hybrid_peer(&self) -> Option<HybridFingerprint> {
        self.hybrid
    }

    /// The payload of message 1, authenticated by Noise.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Like [`respond_suites`], and the other suites this build supports on `channel` are tested
/// too: a known initiator whose suite is not accepted is then [`Responded::Unaccepted`], so
/// that the caller can name it. Those attempts never produce a message 2.
///
/// A suite that authenticates the static ML-KEM keys (the hybrid IK suite) is identified only
/// if it is accepted: reading its message 1 needs a decapsulation with the responder's
/// long-term key, which a responder that did not opt in never does (finding A12-4 of review
/// 0012). Its initiator gets the generic failure.
///
/// The cost of an invalid message 1 is that of [`respond_suites`] for the accepted suites and
/// the identified ones together: the pre-PQ-AUTH suites share one X25519 multiplication per
/// key, so identifying them adds nothing.
///
/// # Errors
/// [`CryptoError::Handshake`] if `msg1` is valid for no supported suite and key.
pub fn respond_or_identify(
    keys: &Keyring,
    msg1: &[u8],
    channel: Channel,
    accepted: AcceptedSuites,
) -> Result<Responded, CryptoError> {
    let identified = AcceptedSuites::supported(channel)
        .without(accepted)
        .and_then(|others| {
            AcceptedSuites::new(others.iter().filter(|s| !s.requires_hybrid_identity())).ok()
        });
    let candidates = identified.map_or(accepted, |others| accepted.union(others));
    let selected = select(keys, msg1, channel, candidates).ok_or(CryptoError::Handshake)?;
    let is_accepted = accepted.contains(selected.suite);
    let pending = selected.respond(msg1, channel)?;
    if is_accepted {
        return Ok(Responded::Pending(Box::new(pending)));
    }
    // The handshake state is dropped here: nothing can advance it any more.
    Ok(Responded::Unaccepted(Identified {
        peer: pending.peer,
        hybrid: pending.hybrid_peer(),
        payload: pending.payload,
        suite: pending.suite,
    }))
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
    if suite.requires_hybrid_identity() {
        let (Some(ct1), own) = (msg1.get(..CT_LEN), local.static_kem()) else {
            return Err(CryptoError::Handshake);
        };
        let ss1 = MlKem768::decapsulate(&own.dk, ct1).map_err(|_| CryptoError::Handshake)?;
        let psk0 = kem_psk(PSK_INITIATOR, ct1, ss1.as_bytes());
        return respond_hybrid(local, msg1, channel, suite, &psk0);
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
        hybrid: None,
    })
}

/// The responder of the hybrid IK suite, with `psk0` from the decapsulation of `ct1` with the
/// static key (the only KEM operation before the authorization decision): reads message 1,
/// checks the initiator's encapsulation key (FIPS 203 §7.2) and binds it into the fingerprint
/// v2.
fn respond_hybrid(
    local: &Identity,
    msg1: &[u8],
    channel: Channel,
    suite: HandshakeSuite,
    psk0: &[u8; 32],
) -> Result<AuthorizationPending, CryptoError> {
    let (Some(ct1), Some(rest)) = (msg1.get(..CT_LEN), msg1.get(CT_LEN..)) else {
        return Err(CryptoError::Handshake);
    };
    let own = local.static_kem();
    let prologue = hybrid_prologue(channel, &own.ek, ct1)?;
    let (builder, secret) =
        builder_with(local, channel, suite, &prologue).map_err(|_| CryptoError::Handshake)?;
    let mut state = builder
        .psk(0, psk0)
        .and_then(|b| b.local_private_key(secret.as_ref()))
        .and_then(Builder::build_responder)
        .map_err(|_| CryptoError::Handshake)?;
    let mut buffer = Zeroizing::new(vec![0_u8; rest.len()]);
    let len = state
        .read_message(rest, &mut buffer)
        .map_err(|_| CryptoError::Handshake)?;
    let plain = buffer.get(..len).ok_or(CryptoError::Handshake)?;
    let (Some(initiator_ek), Some(payload)) = (plain.get(..EK_LEN), plain.get(EK_LEN..)) else {
        return Err(CryptoError::Handshake);
    };
    // The same error for every reason (no oracle): a bad key, an oversized payload.
    if payload.len() > MAX_HANDSHAKE_PAYLOAD_LEN
        || !MlKem768::is_valid_encapsulation_key(initiator_ek)
    {
        return Err(CryptoError::Handshake);
    }
    let raw = state.get_remote_static().ok_or(CryptoError::Handshake)?;
    let x25519: [u8; 32] = raw.try_into().map_err(|_| CryptoError::Handshake)?;
    Ok(AuthorizationPending {
        peer: fingerprint_of_x25519(&x25519),
        hybrid: Some(HybridPeer {
            fingerprint: hybrid_fingerprint_of(&x25519, initiator_ek),
            encapsulation_key: initiator_ek.to_vec(),
        }),
        payload: payload.to_vec(),
        state,
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
    /// The initiator's static decapsulation key, for `ct2` (hybrid IK suite only).
    static_dk: Option<Box<<MlKem768 as Kem>::DecapsulationKey>>,
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
        let msg2 = match &self.static_dk {
            None => msg2,
            Some(dk) => {
                // `ct2 ‖ message 2`: `psk2` comes from the initiator's own static key.
                let (Some(ct2), Some(rest)) = (msg2.get(..CT_LEN), msg2.get(CT_LEN..)) else {
                    return Err(CryptoError::Handshake);
                };
                let ss2 = MlKem768::decapsulate(dk, ct2).map_err(|_| CryptoError::Handshake)?;
                let psk2 = kem_psk(PSK_RESPONDER, ct2, ss2.as_bytes());
                self.state
                    .set_psk(2, psk2.as_ref())
                    .map_err(|_| CryptoError::Handshake)?;
                rest
            }
        };
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
    /// The initiator's hybrid identity (hybrid IK suite only).
    hybrid: Option<HybridPeer>,
}

/// What message 1 of the hybrid IK suite says about the initiator.
#[derive(Debug)]
struct HybridPeer {
    fingerprint: HybridFingerprint,
    /// Its static encapsulation key, already checked (FIPS 203 §7.2): `accept` encapsulates
    /// `ct2` to it.
    encapsulation_key: Vec<u8>,
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

    /// The initiator's fingerprint v2, with the hybrid IK suite: X25519 proved by Noise, the
    /// ML-KEM half proved only at key confirmation (finding AP-12): the decision taken on it
    /// before message 2 is classical-strength, and a peer that cannot decapsulate `ct2` never
    /// produces an authentic transport message.
    #[must_use]
    pub fn hybrid_peer(&self) -> Option<HybridFingerprint> {
        self.hybrid.as_ref().map(|h| h.fingerprint)
    }

    /// The payload of message 1, authenticated by Noise (empty if the initiator did not send
    /// one).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Accepts the initiator: produces `msg2` and the transport channel. With the hybrid suite
    /// this is where the responder checks the initiator's `e1` (FIPS 203 §7.2) and
    /// encapsulates to it.
    ///
    /// # Errors
    /// [`CryptoError::Handshake`] if the Noise state cannot advance, or if `e1` is not a valid
    /// ML-KEM-768 encapsulation key.
    pub fn accept(mut self) -> Result<(Vec<u8>, Transport), CryptoError> {
        let msg2 = match &self.hybrid {
            None => write(&mut self.state, &[])?,
            Some(hybrid) => {
                let (ct2, ss2) = encapsulate(&hybrid.encapsulation_key)?;
                let psk2 = kem_psk(PSK_RESPONDER, &ct2, ss2.as_bytes());
                self.state
                    .set_psk(2, psk2.as_ref())
                    .map_err(|_| CryptoError::Handshake)?;
                let mut msg2 = ct2;
                msg2.extend_from_slice(&write(&mut self.state, &[])?);
                msg2
            }
        };
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    //! Counted operations of the responder (finding A12-6 of review 0012) and the KEM
    //! authentication of the initiator (A12-9). Unit tests: they need the crate's counters
    //! and its own `psk2` derivation.
    use super::*;

    const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
    const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
    const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;

    fn id(b: u8) -> Identity {
        Identity::from_secret_hex(&hex::encode([b; 32])).unwrap()
    }

    fn all() -> AcceptedSuites {
        AcceptedSuites::new([CLASSIC, HFS, HYBRID]).unwrap()
    }

    /// The operations `f` ran: X25519 multiplications, static decapsulations, full Noise
    /// trials.
    fn counted<T>(f: impl FnOnce() -> T) -> (T, ops::Counts) {
        ops::reset();
        let out = f();
        (out, ops::get())
    }

    /// A12-6: an invalid message 1 that fits the length bounds of every suite costs, per key,
    /// one X25519 multiplication shared by the classical and `IKhfs` suites, plus one
    /// decapsulation and one multiplication for the hybrid IK suite; never a Noise state. The
    /// classical responder alone costs one multiplication per key.
    #[test]
    fn an_invalid_message_1_costs_a_bounded_number_of_operations() {
        let mut garbage = vec![0_u8; 4_000];
        getrandom::fill(&mut garbage).unwrap();
        let one = Keyring::single(id(0x01));
        let two = Keyring::rotating(id(0x02), id(0x03)).unwrap();
        for (keys, n) in [(&one, 1), (&two, 2)] {
            for channel in [Channel::Outer, Channel::EndToEnd] {
                let (r, c) = counted(|| respond_suites(keys, &garbage, channel, all()));
                assert!(r.is_err());
                assert_eq!(
                    c,
                    ops::Counts {
                        dh: 2 * n,
                        decaps: n,
                        trials: 0
                    },
                    "{n} keys"
                );
                let (r, c) = counted(|| {
                    respond_suites(keys, &garbage, channel, AcceptedSuites::only(CLASSIC))
                });
                assert!(r.is_err());
                assert_eq!(
                    c,
                    ops::Counts {
                        dh: n,
                        decaps: 0,
                        trials: 0
                    },
                    "{n} keys"
                );
                // The identify pass of an agent that accepts only the classical suite adds
                // no operation (one multiplication covers both pre-PQ-AUTH suites).
                let (r, c) = counted(|| {
                    respond_or_identify(keys, &garbage, channel, AcceptedSuites::only(CLASSIC))
                });
                assert!(r.is_err());
                assert_eq!(
                    c,
                    ops::Counts {
                        dh: n,
                        decaps: 0,
                        trials: 0
                    },
                    "{n} keys"
                );
            }
        }
        // Too short for the hybrid IK suite: no decapsulation at all.
        let (r, c) = counted(|| respond_suites(&one, &garbage[..3_000], Channel::Outer, all()));
        assert!(r.is_err());
        assert_eq!(
            c,
            ops::Counts {
                dh: 1,
                decaps: 0,
                trials: 0
            }
        );
    }

    /// A12-6: a valid message 1 runs exactly one full Noise trial, whatever its suite and key,
    /// and the hybrid IK suite decapsulates `ct1` once.
    #[test]
    fn a_valid_message_1_runs_one_noise_trial() {
        let (client, previous, current) = (id(0x10), id(0x11), id(0x12));
        let pin = previous.hybrid_public_key();
        let keys = Keyring::rotating(current, previous).unwrap();
        for suite in [CLASSIC, HFS, HYBRID] {
            let (msg1, _) =
                initiate_suite(&client, pin.clone(), Channel::Outer, suite, b"cert").unwrap();
            let (r, c) = counted(|| respond_suites(&keys, &msg1, Channel::Outer, all()));
            let pending = r.unwrap();
            assert_eq!(pending.suite(), suite);
            assert_eq!(pending.payload(), b"cert");
            assert_eq!(c.trials, 1, "{suite:?}");
            assert!(c.decaps <= 2, "{suite:?}: {c:?}");
        }
    }

    /// A12-9 (mutant M4 of review 0012): the CRQC impostor has the victim's X25519 secret and
    /// sends the victim's (public) ML-KEM key, but lacks its decapsulation key. It derives
    /// `psk2` exactly as the product does, from what it can compute (here, a decapsulation
    /// with another key): the handshake must fail at message 2 or at key confirmation.
    #[test]
    fn a_crqc_impostor_without_the_static_key_shares_no_transport_key() {
        let (victim, attacker, agent) = (id(0x21), id(0x22), id(0x23));
        let keys = Keyring::single(id(0x23));
        for channel in [Channel::Outer, Channel::EndToEnd] {
            let (msg1, mut impostor) =
                initiate_suite(&victim, agent.hybrid_public_key(), channel, HYBRID, &[]).unwrap();
            impostor.static_dk = Some(Box::new(attacker.static_decapsulation_key()));
            let pending =
                respond_suites(&keys, &msg1, channel, AcceptedSuites::only(HYBRID)).unwrap();
            assert_eq!(pending.hybrid_peer(), Some(victim.hybrid_fingerprint()));
            let (msg2, mut responder) = pending.accept().unwrap();
            if let Ok(mut transport) = impostor.complete(&msg2) {
                let confirmation = transport.encrypt(b"register").unwrap();
                assert!(
                    responder.decrypt(&confirmation).is_err(),
                    "the impostor confirmed the key"
                );
            }
        }
    }
}
