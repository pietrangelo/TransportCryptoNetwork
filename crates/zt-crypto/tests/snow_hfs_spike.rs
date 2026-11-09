//! PQ-0 spike for the `snow` decision (docs/pq-snow.md, finding AP-14).
//!
//! Question: can PQ-1 (`Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`) run on stock snow
//! 0.10.0, or does it need a patch, and how big?
//!
//! What the spike shows:
//! 1. stock snow refuses the honest protocol name: `KemChoice` is a closed enum with only
//!    `Kyber1024`, so a patch is unavoidable for an honest transcript;
//! 2. the HFS token path of stock snow (feature `hfs`, no `pqcrypto`) already works with an
//!    ML-KEM-768 provider plugged in through `CryptoResolver::resolve_kem`: the handshake
//!    completes, the sizes are exactly those of PROTOCOL §7.5, and tampering is detected.
//!
//! So the patch is the `KemChoice::MlKem768` variant and its name, nothing in the state
//! machine. The `Kyber1024` label below is a **test-only** device: the label is hashed into the
//! transcript, so shipping it would make the protocol name lie (rejected in pq.md §3.2b).
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
use zt_crypto::kem::{Kem, KemSeed, MlKem768, MlKem768DecapsulationKey, SEED_LEN};

/// The honest name PQ-1 needs.
const HONEST: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
/// The only name stock snow parses with a KEM (spike only).
const LABELLED: &str = "Noise_IKhfs_25519+Kyber1024_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"TCN/2 spike";

/// ML-KEM-768 from `zt-crypto`, in snow's `Kem` shape.
#[derive(Default)]
struct SpikeKem {
    dk: Option<MlKem768DecapsulationKey>,
    ek: Vec<u8>,
}

impl snow::types::Kem for SpikeKem {
    fn name(&self) -> &'static str {
        "Kyber1024"
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
        self.ek = ek;
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

/// The default resolver for DH, cipher and hash, plus the spike KEM.
struct SpikeResolver(DefaultResolver);

impl CryptoResolver for SpikeResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.0.resolve_rng()
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.0.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.0.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.0.resolve_cipher(choice)
    }
    fn resolve_kem(&self, choice: &KemChoice) -> Option<Box<dyn snow::types::Kem>> {
        match choice {
            KemChoice::Kyber1024 => Some(Box::new(SpikeKem::default())),
        }
    }
}

fn builder() -> Builder<'static> {
    Builder::with_resolver(
        LABELLED.parse().unwrap(),
        Box::new(SpikeResolver(DefaultResolver)),
    )
}

fn keypair() -> snow::Keypair {
    Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .generate_keypair()
        .unwrap()
}

struct Run {
    msg1: Vec<u8>,
    msg2: Vec<u8>,
}

fn handshake(payload: &[u8], tamper_msg1: Option<usize>) -> Result<Run, snow::Error> {
    let (i, r) = (keypair(), keypair());
    let mut initiator = builder()
        .prologue(PROLOGUE)?
        .local_private_key(&i.private)?
        .remote_public_key(&r.public)?
        .build_initiator()?;
    let mut responder = builder()
        .prologue(PROLOGUE)?
        .local_private_key(&r.private)?
        .build_responder()?;
    let mut buf = vec![0_u8; 65_535];
    let n = initiator.write_message(payload, &mut buf)?;
    let mut msg1 = buf[..n].to_vec();
    if let Some(at) = tamper_msg1 {
        msg1[at] ^= 0x01;
    }
    let mut read = vec![0_u8; 65_535];
    let p = responder.read_message(&msg1, &mut read)?;
    assert_eq!(&read[..p], payload);
    let n = responder.write_message(&[], &mut buf)?;
    let msg2 = buf[..n].to_vec();
    assert_eq!(initiator.read_message(&msg2, &mut read)?, 0);
    // Both sides derive the same transport keys.
    let mut ti = initiator.into_transport_mode()?;
    let mut tr = responder.into_transport_mode()?;
    let n = ti.write_message(b"TCN/2 ready", &mut buf)?;
    let p = tr.read_message(&buf[..n], &mut read)?;
    assert_eq!(&read[..p], b"TCN/2 ready");
    Ok(Run { msg1, msg2 })
}

#[test]
fn stock_snow_does_not_know_ml_kem_768() {
    // This is what the vendored patch (docs/pq-snow.md) adds. When it lands, this test is
    // inverted.
    assert!(HONEST.parse::<snow::params::NoiseParams>().is_err());
}

#[test]
fn the_hfs_path_of_stock_snow_runs_with_ml_kem_768_plugged_in() {
    let run = handshake(&[], None).unwrap();
    // msg1 = e (32) + e1 (1 184 + 16: placed after `es`, so encrypted, HFS §5) + s (32 + 16)
    // + payload tag (16).
    assert_eq!(run.msg1.len(), 1_296);
    // msg2 = e (32) + ekem1 (1 088 + 16) + payload tag (16).
    assert_eq!(run.msg2.len(), 1_152);
}

#[test]
fn a_certificate_payload_adds_exactly_its_length_to_message_1() {
    let payload = vec![0x5a; 4_328];
    let run = handshake(&payload, None).unwrap();
    assert_eq!(run.msg1.len(), 1_296 + 4_328);
}

#[test]
fn a_modified_e1_is_rejected_by_the_responder() {
    // e1 is encrypted under the `es` key: any modified byte (or its tag) fails the AEAD.
    for at in [32, 32 + 600, 32 + 1_183, 32 + 1_199] {
        assert!(handshake(&[], Some(at)).is_err(), "byte {at}");
    }
}
