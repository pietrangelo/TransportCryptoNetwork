//! PQ-1 attack catalogue for the hybrid handshake (docs/analysis/pq.md §7 PQ-1, review 0007
//! AP-7, AP-11, AP-23).
//!
//! | Category | Rows |
//! | :- | :- |
//! | Downgrade / binding | cross-suite message 1 in both directions; the suite id and the channel in the prologue; the protocol name in the transcript |
//! | Parsing | message 1 and message 2 truncated inside or at the end of `e1` / `ekem1`, extended, bit-flipped in every field |
//! | Malleability | a wrong but well-formed ciphertext (implicit rejection) fails exactly like a forged message 2: no oracle |
//! | Resources | message 1 over the largest legitimate length; an invalid `e1` (FIPS 203 modulus check) never gets a message 2 |
//! | State | a replayed message 1 yields a message 2 whose keys the real initiator does not share |
//!
//! The malicious peers are built with raw `snow` (the vendored copy) and a KEM provider whose
//! behaviour the test chooses.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use snow::Builder;
use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use zt_crypto::kem::{Kem, KemSeed, MlKem768, SEED_LEN};
use zt_crypto::noise::{self, AwaitingResponse, Channel};
use zt_crypto::{CryptoError, Identity, Keyring, PublicKey};
use zt_domain::limits::MAX_CERT_LEN;
use zt_domain::{AcceptedSuites, HandshakeSuite};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const HONEST: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
/// The prologue of the hybrid suite on the end-to-end channel: `TCN/2 end-to-end` and the
/// suite id (PROTOCOL §7.5).
const E2E_PROLOGUE: &[u8] = b"TCN/2 end-to-end\x01";

/// A way of damaging a message.
type Damage = Box<dyn Fn(&[u8]) -> Vec<u8>>;

fn both() -> AcceptedSuites {
    AcceptedSuites::new([CLASSIC, HFS]).unwrap()
}

/// What the test KEM does differently from ML-KEM-768.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Twist {
    None,
    /// `e1` is 1 184 bytes that fail the FIPS 203 §7.2 modulus check.
    InvalidKey,
    /// Encapsulation returns a random, well-formed ciphertext and an unrelated secret.
    WrongCiphertext,
}

/// ML-KEM-768 from `zt-crypto`, in snow's shape, with a twist.
struct TestKem {
    twist: Twist,
    dk: Option<<MlKem768 as Kem>::DecapsulationKey>,
    ek: Vec<u8>,
}

impl snow::types::Kem for TestKem {
    fn name(&self) -> &'static str {
        "MLKEM768"
    }
    fn pub_len(&self) -> usize {
        MlKem768::ENCAPSULATION_KEY_LEN
    }
    fn ciphertext_len(&self) -> usize {
        MlKem768::CIPHERTEXT_LEN
    }
    fn shared_secret_len(&self) -> usize {
        32
    }
    fn generate(&mut self, rng: &mut dyn Random) {
        let mut seed = [0_u8; SEED_LEN];
        rng.try_fill_bytes(&mut seed).unwrap();
        let (dk, ek) = MlKem768::generate(&KemSeed::from_bytes(seed));
        self.dk = Some(dk);
        self.ek = if self.twist == Twist::InvalidKey {
            vec![0xff; ek.len()]
        } else {
            ek
        };
    }
    fn pubkey(&self) -> &[u8] {
        &self.ek
    }
    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), snow::Error> {
        if self.twist == Twist::WrongCiphertext {
            getrandom::fill(&mut ciphertext_out[..MlKem768::CIPHERTEXT_LEN]).unwrap();
            getrandom::fill(&mut shared_secret_out[..32]).unwrap();
            return Ok((32, MlKem768::CIPHERTEXT_LEN));
        }
        let mut m = [0_u8; 32];
        getrandom::fill(&mut m).unwrap();
        let (ct, ss) = MlKem768::encapsulate(pubkey, &m).map_err(|_| snow::Error::Kem)?;
        shared_secret_out[..32].copy_from_slice(ss.as_bytes());
        ciphertext_out[..ct.len()].copy_from_slice(&ct);
        Ok((32, ct.len()))
    }
    fn decapsulate(
        &self,
        ciphertext: &[u8],
        shared_secret_out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        let dk = self.dk.as_ref().ok_or(snow::Error::Kem)?;
        let ss = MlKem768::decapsulate(dk, ciphertext).map_err(|_| snow::Error::Kem)?;
        shared_secret_out[..32].copy_from_slice(ss.as_bytes());
        Ok(32)
    }
}

struct TestResolver(Twist);

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
        // Whatever name the test parsed: the KEM is always ML-KEM-768 (for the label test).
        Some(Box::new(TestKem {
            twist: self.0,
            dk: None,
            ek: Vec::new(),
        }))
    }
}

/// An identity whose seed the test knows, so that raw snow can use its X25519 secret.
fn seeded(b: u8) -> ([u8; 32], Identity) {
    let seed = [b; 32];
    (seed, Identity::from_secret_hex(&hex::encode(seed)).unwrap())
}

fn x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).to_scalar_bytes()
}

/// A raw hybrid message 1 with an arbitrary name, prologue, KEM twist and payload.
fn raw_msg1(
    name: &str,
    prologue: &[u8],
    twist: Twist,
    initiator_seed: &[u8; 32],
    responder: &PublicKey,
    payload: &[u8],
) -> Vec<u8> {
    let mut state = Builder::with_resolver(name.parse().unwrap(), Box::new(TestResolver(twist)))
        .prologue(prologue)
        .unwrap()
        .local_private_key(&x25519_secret(initiator_seed))
        .unwrap()
        .remote_public_key(&responder.x25519())
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut out = vec![0_u8; 65_535];
    let n = state.write_message(payload, &mut out).unwrap();
    out.truncate(n);
    out
}

/// A raw responder (the agent's key) that answers a genuine hybrid message 1 with `payload`
/// in message 2 and a KEM `twist`.
fn raw_msg2(responder_seed: &[u8; 32], msg1: &[u8], twist: Twist, payload: &[u8]) -> Vec<u8> {
    let mut state = Builder::with_resolver(HONEST.parse().unwrap(), Box::new(TestResolver(twist)))
        .prologue(E2E_PROLOGUE)
        .unwrap()
        .local_private_key(&x25519_secret(responder_seed))
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buf = vec![0_u8; 65_535];
    state.read_message(msg1, &mut buf).unwrap();
    let n = state.write_message(payload, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

struct Pair {
    client: Identity,
    client_seed: [u8; 32],
    agent_seed: [u8; 32],
    agent_pk: PublicKey,
    keys: Keyring,
}

fn pair() -> Pair {
    let (client_seed, client) = seeded(0x11);
    let (agent_seed, agent) = seeded(0x22);
    let agent_pk = agent.public_key();
    Pair {
        client,
        client_seed,
        agent_seed,
        agent_pk,
        keys: Keyring::single(agent),
    }
}

fn start(p: &Pair) -> (Vec<u8>, AwaitingResponse) {
    noise::initiate_suite(&p.client, &p.agent_pk, Channel::EndToEnd, HFS, &[]).unwrap()
}

// --- downgrade and binding ------------------------------------------------------------------

/// A message 1 of one suite is never read as the other, in either direction, even by a
/// responder that has the right key.
#[test]
fn a_message_1_of_one_suite_is_never_valid_as_the_other() {
    let p = pair();
    let (classical, _) =
        noise::initiate_suite(&p.client, &p.agent_pk, Channel::EndToEnd, CLASSIC, &[]).unwrap();
    let (hybrid, _) = start(&p);
    assert_eq!(
        noise::respond_suites(
            &p.keys,
            &classical,
            Channel::EndToEnd,
            AcceptedSuites::only(HFS)
        )
        .err(),
        Some(CryptoError::Handshake)
    );
    assert_eq!(
        noise::respond_suites(
            &p.keys,
            &hybrid,
            Channel::EndToEnd,
            AcceptedSuites::only(CLASSIC)
        )
        .err(),
        Some(CryptoError::Handshake)
    );
}

/// The suite id and the channel are in the prologue: a hybrid message 1 written with any other
/// prologue (the classical one, no id, the classical id, the outer channel) is refused. The
/// exact prologue is accepted, which pins its bytes.
#[test]
fn the_prologue_binds_the_suite_id_and_the_channel() {
    let p = pair();
    let genuine = raw_msg1(
        HONEST,
        E2E_PROLOGUE,
        Twist::None,
        &p.client_seed,
        &p.agent_pk,
        &[],
    );
    let pending = noise::respond_suites(&p.keys, &genuine, Channel::EndToEnd, both()).unwrap();
    assert_eq!(pending.suite(), HFS);
    assert_eq!(pending.peer(), p.client.fingerprint());
    for prologue in [
        &b"TCN/1 end-to-end"[..],
        b"TCN/2 end-to-end",
        b"TCN/2 end-to-end\x00",
        b"TCN/2 end-to-end\x02",
        b"TCN/2 outer\x01",
        b"",
    ] {
        let msg1 = raw_msg1(
            HONEST,
            prologue,
            Twist::None,
            &p.client_seed,
            &p.agent_pk,
            &[],
        );
        assert_eq!(
            noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both()).err(),
            Some(CryptoError::Handshake),
            "{prologue:?}"
        );
    }
}

/// The protocol name is hashed into the transcript: ML-KEM-768 under another KEM label (the
/// rejected PQ-0 option (b)) is a different protocol.
#[test]
fn the_protocol_name_binds_the_kem() {
    let p = pair();
    let msg1 = raw_msg1(
        "Noise_IKhfs_25519+Kyber1024_ChaChaPoly_BLAKE2s",
        E2E_PROLOGUE,
        Twist::None,
        &p.client_seed,
        &p.agent_pk,
        &[],
    );
    assert_eq!(
        noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both()).err(),
        Some(CryptoError::Handshake)
    );
}

// --- parsing --------------------------------------------------------------------------------

/// Truncation inside or at the end of `e1`, extension, and a flipped bit in each field
/// (`e`, `e1` and its tag, `s`, the payload tag) all fail like any invalid message.
#[test]
fn a_damaged_message_1_is_refused() {
    let p = pair();
    let (msg1, _) = start(&p);
    assert_eq!(msg1.len(), 1_296);
    let mut bad: Vec<Vec<u8>> = [0, 1, 31, 32, 33, 32 + 1_184, 32 + 1_199, 32 + 1_200, 1_295]
        .iter()
        .map(|&n| msg1[..n].to_vec())
        .collect();
    let mut longer = msg1.clone();
    longer.push(0);
    bad.push(longer);
    for at in [
        0,
        31,
        32,
        600,
        32 + 1_183,
        32 + 1_199,
        32 + 1_200,
        1_247,
        1_280,
        1_295,
    ] {
        let mut flipped = msg1.clone();
        flipped[at] ^= 0x01;
        bad.push(flipped);
    }
    for msg in bad {
        assert_eq!(
            noise::respond_suites(&p.keys, &msg, Channel::EndToEnd, both()).err(),
            Some(CryptoError::Handshake),
            "len {}",
            msg.len()
        );
    }
}

/// Message 2 truncated inside or at the end of `ekem1`, extended, or flipped in `e`, `ekem1`,
/// its tag or the payload tag: the initiator refuses it.
#[test]
fn a_damaged_message_2_is_refused() {
    let p = pair();
    let mut cases: Vec<Damage> = Vec::new();
    for n in [0, 1, 32, 33, 32 + 1_088, 32 + 1_103, 32 + 1_104, 1_151] {
        cases.push(Box::new(move |m: &[u8]| m[..n].to_vec()));
    }
    cases.push(Box::new(|m: &[u8]| {
        let mut v = m.to_vec();
        v.push(0);
        v
    }));
    for at in [0, 31, 32, 500, 32 + 1_087, 32 + 1_103, 32 + 1_104, 1_151] {
        cases.push(Box::new(move |m: &[u8]| {
            let mut v = m.to_vec();
            v[at] ^= 0x80;
            v
        }));
    }
    for (i, damage) in cases.iter().enumerate() {
        let (msg1, waiting) = start(&p);
        let pending = noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both()).unwrap();
        let (msg2, _) = pending.accept().unwrap();
        assert_eq!(msg2.len(), 1_152);
        assert_eq!(
            waiting.complete(&damage(&msg2)).err(),
            Some(CryptoError::Handshake),
            "case {i}"
        );
    }
}

// --- malleability and oracles ---------------------------------------------------------------

/// The raw responder of these tests interoperates with `zt-crypto` (the control for the next
/// tests).
#[test]
fn a_raw_honest_responder_interoperates() {
    let p = pair();
    let (msg1, waiting) = start(&p);
    let msg2 = raw_msg2(&p.agent_seed, &msg1, Twist::None, &[]);
    assert_eq!(
        waiting.complete(&msg2).unwrap().peer(),
        p.agent_pk.fingerprint()
    );
}

/// A responder that knows the static key but sends a well-formed wrong ciphertext (it passes
/// the AEAD under `ee`): the initiator's decapsulation takes ML-KEM's implicit rejection and
/// yields an unrelated secret, so the keys diverge and the handshake fails, with exactly the
/// error of a forged message 2 (no oracle that tells the two apart).
#[test]
fn a_wrong_ciphertext_fails_the_handshake_without_an_oracle() {
    let p = pair();
    let (msg1, waiting) = start(&p);
    let msg2 = raw_msg2(&p.agent_seed, &msg1, Twist::WrongCiphertext, &[]);
    assert_eq!(msg2.len(), 1_152);
    let wrong = waiting.complete(&msg2).err();

    let (msg1, waiting) = start(&p);
    let mut forged = raw_msg2(&p.agent_seed, &msg1, Twist::None, &[]);
    forged[100] ^= 1;
    let forged = waiting.complete(&forged).err();

    assert_eq!(wrong, Some(CryptoError::Handshake));
    assert_eq!(wrong, forged);
}

/// Message 2 MUST be empty (PROTOCOL §7.3): the hybrid suite keeps the rule.
#[test]
fn a_message_2_with_a_payload_is_refused() {
    let p = pair();
    let (msg1, waiting) = start(&p);
    let msg2 = raw_msg2(&p.agent_seed, &msg1, Twist::None, b"x");
    assert_eq!(waiting.complete(&msg2).err(), Some(CryptoError::Handshake));
}

// --- resources ------------------------------------------------------------------------------

/// A message 1 one byte over the largest legitimate one (the largest certificate) is refused
/// before Noise runs, and the initiator API refuses to write it.
#[test]
fn an_oversized_message_1_is_refused() {
    let p = pair();
    let payload = vec![0x5a; MAX_CERT_LEN + 1];
    assert_eq!(
        noise::initiate_suite(&p.client, &p.agent_pk, Channel::EndToEnd, HFS, &payload).err(),
        Some(CryptoError::MessageTooLarge)
    );
    let msg1 = raw_msg1(
        HONEST,
        E2E_PROLOGUE,
        Twist::None,
        &p.client_seed,
        &p.agent_pk,
        &payload,
    );
    assert_eq!(msg1.len(), HFS.max_msg1_len() + 1);
    assert_eq!(
        noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both()).err(),
        Some(CryptoError::Handshake)
    );
}

/// An `e1` that fails the FIPS 203 §7.2 check (coefficients ≥ q) authenticates as message 1
/// (the KEM key is not parsed before the authorization decision), but `accept` refuses to
/// encapsulate to it: no message 2.
#[test]
fn an_invalid_encapsulation_key_never_gets_a_message_2() {
    let p = pair();
    let msg1 = raw_msg1(
        HONEST,
        E2E_PROLOGUE,
        Twist::InvalidKey,
        &p.client_seed,
        &p.agent_pk,
        &[],
    );
    let pending = noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both()).unwrap();
    assert_eq!(pending.peer(), p.client.fingerprint());
    assert_eq!(pending.accept().err(), Some(CryptoError::Handshake));
}

// --- state ----------------------------------------------------------------------------------

/// A replayed message 1 (the relay saw it) still produces a message 2, as in IK; but its keys
/// come from a fresh responder ephemeral and a fresh encapsulation, so the real initiator's
/// confirmation decrypts only on the session it really completed (PROTOCOL §7.3).
#[test]
fn a_replayed_message_1_gets_keys_the_initiator_does_not_have() {
    let p = pair();
    let (msg1, waiting) = start(&p);
    let (msg2_a, mut session_a) = noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both())
        .unwrap()
        .accept()
        .unwrap();
    let (msg2_b, mut session_b) = noise::respond_suites(&p.keys, &msg1, Channel::EndToEnd, both())
        .unwrap()
        .accept()
        .unwrap();
    assert_ne!(msg2_a, msg2_b);
    let mut client = waiting.complete(&msg2_a).unwrap();
    let confirm = client.encrypt(HFS.confirmation()).unwrap();
    assert_eq!(
        session_b.decrypt(&confirm).err(),
        Some(CryptoError::Decrypt)
    );
    assert_eq!(session_a.decrypt(&confirm).unwrap(), b"TCN/2 ready");
}
