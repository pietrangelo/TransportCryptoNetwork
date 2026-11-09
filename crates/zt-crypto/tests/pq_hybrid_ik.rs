//! PQ-AUTH, the hybrid IK handshake, suite 0x02 (PROTOCOL §7.5.3; decisions D14, D15;
//! findings AP-11, AP-12 of review 0007).
//!
//! ```text
//! -> ct1 ‖ [psk0] e, es, e1, s, ss, {ek_i ‖ cert}      psk0 = H("TCN/3 skem-i\0" ‖ ct1 ‖ ss1)
//! <- ct2 ‖ e, ee, ekem1, se, [psk2], {}                 psk2 = H("TCN/3 skem-r\0" ‖ ct2 ‖ ss2)
//! ```
//!
//! `ct1` encapsulates to the responder's static ML-KEM key (pinned), `ct2` to the initiator's
//! (sent in message 1, bound to its fingerprint v2). The prologue is
//! `"TCN/3 <channel>" ‖ 0x02 ‖ SHA-256(ek_r) ‖ ct1`.
//!
//! The specification tests interoperate with an **independent** implementation of that
//! construction written here with raw `snow` and the KEM primitive; the attack tests use it to
//! build the malicious peers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    missing_docs
)]

use sha2::{Digest, Sha256};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use snow::{Builder, HandshakeState};
use zt_crypto::kem::{Kem, KemSeed, MlKem768, SEED_LEN};
use zt_crypto::noise::{self, Channel, Responded};
use zt_crypto::{CryptoError, HybridPublicKey, Identity, Keyring, PeerKey};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const NAME: &str = "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const CT: usize = 1_088;
const EK: usize = 1_184;

// --- the independent implementation -----------------------------------------------------

/// ML-KEM-768 for snow's `e1`/`ekem1` tokens (ephemeral, randomness from the OS).
#[derive(Default)]
struct EphemeralKem {
    dk: Option<<MlKem768 as Kem>::DecapsulationKey>,
    ek: Vec<u8>,
}

impl snow::types::Kem for EphemeralKem {
    fn name(&self) -> &'static str {
        "MLKEM768"
    }
    fn pub_len(&self) -> usize {
        EK
    }
    fn ciphertext_len(&self) -> usize {
        CT
    }
    fn shared_secret_len(&self) -> usize {
        32
    }
    fn generate(&mut self, rng: &mut dyn Random) {
        let mut seed = [0_u8; SEED_LEN];
        rng.try_fill_bytes(&mut seed).unwrap();
        let (dk, ek) = MlKem768::generate(&KemSeed::from_bytes(seed));
        self.dk = Some(dk);
        self.ek = ek;
    }
    fn pubkey(&self) -> &[u8] {
        &self.ek
    }
    fn encapsulate(&self, pk: &[u8], ss: &mut [u8], ct: &mut [u8]) -> Result<(usize, usize), snow::Error> {
        let (c, s) = MlKem768::encapsulate(pk, &rnd()).map_err(|_| snow::Error::Kem)?;
        ss[..32].copy_from_slice(s.as_bytes());
        ct[..c.len()].copy_from_slice(&c);
        Ok((32, c.len()))
    }
    fn decapsulate(&self, ct: &[u8], ss: &mut [u8]) -> Result<usize, snow::Error> {
        let s = MlKem768::decapsulate(self.dk.as_ref().ok_or(snow::Error::Kem)?, ct)
            .map_err(|_| snow::Error::Kem)?;
        ss[..32].copy_from_slice(s.as_bytes());
        Ok(32)
    }
}

struct TestResolver;

impl CryptoResolver for TestResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        DefaultResolver.resolve_rng()
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
    fn resolve_kem(&self, _choice: &KemChoice) -> Option<Box<dyn snow::types::Kem>> {
        Some(Box::<EphemeralKem>::default())
    }
}

fn rnd() -> [u8; 32] {
    let mut m = [0_u8; 32];
    getrandom::fill(&mut m).unwrap();
    m
}

/// A node whose seed the test knows: identity, X25519 secret and static ML-KEM keys (D12).
struct Node {
    id: Identity,
    x25519: [u8; 32],
    dk: <MlKem768 as Kem>::DecapsulationKey,
    ek: Vec<u8>,
}

fn node(b: u8) -> Node {
    let seed = [b; 32];
    let mut xof = Shake256::default();
    xof.update(b"TCN ML-KEM-768 seed v1\0");
    xof.update(&seed);
    let mut dz = [0_u8; 64];
    xof.finalize_xof().read(&mut dz);
    let (dk, ek) = MlKem768::generate(&KemSeed::from_bytes(dz));
    Node {
        id: Identity::from_secret_hex(&hex::encode(seed)).unwrap(),
        x25519: ed25519_dalek::SigningKey::from_bytes(&seed).to_scalar_bytes(),
        dk,
        ek,
    }
}

fn label(channel: Channel) -> &'static [u8] {
    match channel {
        Channel::Outer => b"TCN/3 outer",
        Channel::EndToEnd => b"TCN/3 end-to-end",
    }
}

fn prologue(channel: Channel, ek_r: &[u8], ct1: &[u8]) -> Vec<u8> {
    let mut p = label(channel).to_vec();
    p.push(0x02);
    p.extend_from_slice(&Sha256::digest(ek_r));
    p.extend_from_slice(ct1);
    p
}

fn psk(label: &[u8], ct: &[u8], ss: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(label)
        .chain_update(ct)
        .chain_update(ss)
        .finalize()
        .into()
}

/// What a hand-built initiator may get wrong on purpose.
#[derive(Clone, Copy, Default)]
struct Twist {
    /// Encapsulate to this ek instead of the responder's (pinned the wrong key).
    wrong_responder_ek: bool,
    /// Put the victim's X25519 secret with this ek in the payload (CRQC impostor).
    payload_ek_all_ff: bool,
}

/// The hand-built initiator: message 1 and the state that reads message 2.
fn hand_msg1(
    initiator_x25519: &[u8; 32],
    payload_ek: &[u8],
    responder: &Node,
    channel: Channel,
    cert: &[u8],
    twist: Twist,
) -> (Vec<u8>, HandshakeState) {
    let target_ek = if twist.wrong_responder_ek {
        node(0x7e).ek
    } else {
        responder.ek.clone()
    };
    let (ct1, ss1) = MlKem768::encapsulate(&target_ek, &rnd()).unwrap();
    let mut state = Builder::with_resolver(NAME.parse().unwrap(), Box::new(TestResolver))
        .prologue(&prologue(channel, &responder.ek, &ct1))
        .unwrap()
        .psk(0, &psk(b"TCN/3 skem-i\0", &ct1, ss1.as_bytes()))
        .unwrap()
        .local_private_key(initiator_x25519)
        .unwrap()
        .remote_public_key(&responder.id.public_key().x25519())
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut payload = if twist.payload_ek_all_ff {
        vec![0xff; EK]
    } else {
        payload_ek.to_vec()
    };
    payload.extend_from_slice(cert);
    let mut out = vec![0_u8; 65_535];
    let n = state.write_message(&payload, &mut out).unwrap();
    let mut msg1 = ct1;
    msg1.extend_from_slice(&out[..n]);
    (msg1, state)
}

/// The hand-built initiator reads message 2 with its static `dk` (or none: an impostor).
fn hand_complete(
    mut state: HandshakeState,
    dk: Option<&<MlKem768 as Kem>::DecapsulationKey>,
    msg2: &[u8],
) -> Result<snow::TransportState, ()> {
    if msg2.len() < CT {
        return Err(());
    }
    let (ct2, rest) = msg2.split_at(CT);
    let ss2 = match dk {
        Some(dk) => *MlKem768::decapsulate(dk, ct2).unwrap().as_bytes(),
        None => rnd(),
    };
    state.set_psk(2, &psk(b"TCN/3 skem-r\0", ct2, &ss2)).unwrap();
    let mut buf = vec![0_u8; 65_535];
    let n = state.read_message(rest, &mut buf).map_err(|_| ())?;
    if n != 0 {
        return Err(());
    }
    state.into_transport_mode().map_err(|_| ())
}

/// The hand-built responder: reads a message 1 from `zt-crypto` and answers it.
fn hand_respond(responder: &Node, channel: Channel, msg1: &[u8]) -> (Vec<u8>, Vec<u8>, snow::TransportState) {
    let (ct1, rest) = msg1.split_at(CT);
    let ss1 = MlKem768::decapsulate(&responder.dk, ct1).unwrap();
    let mut state = Builder::with_resolver(NAME.parse().unwrap(), Box::new(TestResolver))
        .prologue(&prologue(channel, &responder.ek, ct1))
        .unwrap()
        .psk(0, &psk(b"TCN/3 skem-i\0", ct1, ss1.as_bytes()))
        .unwrap()
        .local_private_key(&responder.x25519)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buf = vec![0_u8; 65_535];
    let n = state.read_message(rest, &mut buf).unwrap();
    let payload = buf[..n].to_vec();
    let (ct2, ss2) = MlKem768::encapsulate(&payload[..EK], &rnd()).unwrap();
    state.set_psk(2, &psk(b"TCN/3 skem-r\0", &ct2, ss2.as_bytes())).unwrap();
    let n = state.write_message(&[], &mut buf).unwrap();
    let mut msg2 = ct2;
    msg2.extend_from_slice(&buf[..n]);
    (msg2, payload[EK..].to_vec(), state.into_transport_mode().unwrap())
}

fn keys(n: &Node) -> Keyring {
    Keyring::single(Identity::from_secret_hex(&n.id.to_secret_hex()).unwrap())
}

fn only(s: HandshakeSuite) -> AcceptedSuites {
    AcceptedSuites::only(s)
}

// --- specification --------------------------------------------------------------------------

/// Spec: the handshake completes on both channels with the sizes of the suite; the responder
/// learns both fingerprints of the initiator and the certificate; both transports talk.
#[test]
fn the_hybrid_ik_handshake_completes_on_both_channels() {
    let (client, agent) = (node(0x11), node(0x22));
    let agent_key = agent.id.hybrid_public_key();
    for channel in [Channel::Outer, Channel::EndToEnd] {
        for cert in [Vec::new(), vec![0x5a; 300]] {
            let (msg1, waiting) =
                noise::initiate_suite(&client.id, &agent_key, channel, HYBRID, &cert).unwrap();
            assert_eq!(msg1.len(), HYBRID.msg1_overhead() + cert.len());
            assert_eq!(waiting.suite(), HYBRID);
            let pending =
                noise::respond_suites(&keys(&agent), &msg1, channel, only(HYBRID)).unwrap();
            assert_eq!(pending.suite(), HYBRID);
            assert_eq!(pending.peer(), client.id.fingerprint());
            assert_eq!(pending.hybrid_peer(), Some(client.id.hybrid_fingerprint()));
            assert_eq!(pending.payload(), cert.as_slice());
            let (msg2, mut responder) = pending.accept().unwrap();
            assert_eq!(msg2.len(), HYBRID.msg2_len());
            let mut initiator = waiting.complete(&msg2).unwrap();
            assert_eq!(initiator.peer(), agent.id.fingerprint());
            let c = initiator.encrypt(HYBRID.confirmation()).unwrap();
            assert_eq!(responder.decrypt(&c).unwrap(), b"TCN/3 ready");
            let r = responder.encrypt(b"pong").unwrap();
            assert_eq!(initiator.decrypt(&r).unwrap(), b"pong");
        }
    }
}

/// Spec (D15 cross-check): `zt-crypto` and the independent implementation interoperate in
/// both roles, so the construction is the one documented, byte for byte.
#[test]
fn an_independent_implementation_interoperates_in_both_roles() {
    let (client, agent) = (node(0x13), node(0x24));
    // Hand-built initiator → zt-crypto responder.
    let (msg1, state) = hand_msg1(
        &client.x25519,
        &client.ek,
        &agent,
        Channel::EndToEnd,
        b"cert",
        Twist::default(),
    );
    let pending =
        noise::respond_suites(&keys(&agent), &msg1, Channel::EndToEnd, only(HYBRID)).unwrap();
    assert_eq!(pending.hybrid_peer(), Some(client.id.hybrid_fingerprint()));
    assert_eq!(pending.payload(), b"cert");
    let (msg2, mut responder) = pending.accept().unwrap();
    let mut hand = hand_complete(state, Some(&client.dk), &msg2).unwrap();
    let mut buf = [0_u8; 64];
    let n = hand.write_message(b"TCN/3 ready", &mut buf).unwrap();
    assert_eq!(responder.decrypt(&buf[..n]).unwrap(), b"TCN/3 ready");
    // zt-crypto initiator → hand-built responder.
    let (msg1, waiting) = noise::initiate_suite(
        &client.id,
        &agent.id.hybrid_public_key(),
        Channel::Outer,
        HYBRID,
        b"c2",
    )
    .unwrap();
    let (msg2, cert, mut hand) = hand_respond(&agent, Channel::Outer, &msg1);
    assert_eq!(cert, b"c2");
    let mut initiator = waiting.complete(&msg2).unwrap();
    let c = initiator.encrypt(b"x").unwrap();
    assert_eq!(hand.read_message(&c, &mut buf).unwrap(), 1);
}

/// Spec (rotation, PROTOCOL §14): a message 1 to the previous key is accepted.
#[test]
fn the_previous_key_still_answers() {
    let (client, old, new) = (node(0x15), node(0x26), node(0x27));
    let ring = Keyring::rotating(
        Identity::from_secret_hex(&new.id.to_secret_hex()).unwrap(),
        Identity::from_secret_hex(&old.id.to_secret_hex()).unwrap(),
    )
    .unwrap();
    let (msg1, _) = noise::initiate_suite(
        &client.id,
        &old.id.hybrid_public_key(),
        Channel::Outer,
        HYBRID,
        &[],
    )
    .unwrap();
    assert!(noise::respond_suites(&ring, &msg1, Channel::Outer, only(HYBRID)).is_ok());
}

/// Spec: the hybrid suite needs the responder's v2 key; a v2 key also pins the classical and
/// IKhfs suites (only its X25519 part is used there).
#[test]
fn the_hybrid_suite_needs_a_v2_pin() {
    let (client, agent) = (node(0x16), node(0x28));
    assert_eq!(
        noise::initiate_suite(&client.id, &agent.id.public_key(), Channel::Outer, HYBRID, &[])
            .err(),
        Some(CryptoError::HybridKeyRequired)
    );
    let v2 = PeerKey::from(agent.id.hybrid_public_key());
    for suite in [CLASSIC, HFS] {
        let (msg1, _) = noise::initiate_suite(&client.id, &v2, Channel::Outer, suite, &[]).unwrap();
        let pending = noise::respond_suites(&keys(&agent), &msg1, Channel::Outer, only(suite)).unwrap();
        assert_eq!(pending.hybrid_peer(), None);
    }
}

/// The v2 public key a test pins is the one the identity derives.
#[test]
fn hybrid_public_keys_match_the_derivation() {
    let n = node(0x40);
    let key: HybridPublicKey = n.id.hybrid_public_key();
    assert_eq!(key.encapsulation_key(), n.ek.as_slice());
}
