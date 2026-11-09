//! PQ-1 specification of the vendored `snow` patch (`vendor/snow/PATCHES.md`, docs/pq-snow.md).
//!
//! PQ-0's spike (this file's predecessor) showed that stock snow 0.10.0 refuses the honest
//! protocol name and that its HFS state machine works with an ML-KEM-768 provider plugged in
//! through `CryptoResolver::resolve_kem`. The patch therefore adds only the `MLKEM768` KEM name
//! and turns the panics of the HFS paths into errors. Each change has a test here:
//!
//! 1. `KemChoice::MlKem768` and its spelling `MLKEM768` (the spike's
//!    `stock_snow_does_not_know_ml_kem_768`, inverted);
//! 2. a KEM provider whose sizes exceed snow's buffers is an error, not an out-of-bounds panic;
//! 3. a key generation that did not produce a full public key (an RNG failure) fails the
//!    handshake instead of sending a short `e1`;
//! 4. the `unwrap()` calls of the `Ekem1` paths are errors (they cannot be reached through the
//!    public API, because the builder refuses a hybrid pattern without a KEM; the fuzz targets
//!    cover them).
//!
//! The KEM itself is never snow's: `zt-crypto` hands it `libcrux-ml-kem` (`noise.rs`). The tests
//! that run the real handshake are in `pq_handshake.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use snow::Builder;
use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};

const HONEST: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"TCN/2 patch test";

#[test]
fn the_vendored_snow_knows_ml_kem_768() {
    let params: NoiseParams = HONEST.parse().unwrap();
    assert_eq!(params.kem, Some(KemChoice::MlKem768));
    assert_eq!(
        "MLKEM768".parse::<KemChoice>().unwrap(),
        KemChoice::MlKem768
    );
    // The upstream name still parses: the patch adds, it does not rename.
    assert_eq!(
        "Kyber1024".parse::<KemChoice>().unwrap(),
        KemChoice::Kyber1024
    );
    for wrong in [
        "mlkem768",
        "MLKEM-768",
        "ML-KEM-768",
        "MLKEM1024",
        "MLKEM768 ",
        "",
    ] {
        assert!(wrong.parse::<KemChoice>().is_err(), "{wrong:?}");
    }
}

/// A KEM with configurable, possibly absurd, sizes: the patch must turn every inconsistency
/// into an error.
struct OddKem {
    pub_len: usize,
    ct_len: usize,
    ss_len: usize,
    /// How many public key bytes `generate` produces (an RNG failure leaves none).
    produced: usize,
    ek: Vec<u8>,
}

impl OddKem {
    fn sized(pub_len: usize, ct_len: usize, ss_len: usize) -> Self {
        Self {
            pub_len,
            ct_len,
            ss_len,
            produced: pub_len,
            ek: Vec::new(),
        }
    }
}

impl snow::types::Kem for OddKem {
    fn name(&self) -> &'static str {
        "MLKEM768"
    }
    fn pub_len(&self) -> usize {
        self.pub_len
    }
    fn ciphertext_len(&self) -> usize {
        self.ct_len
    }
    fn shared_secret_len(&self) -> usize {
        self.ss_len
    }
    fn generate(&mut self, _rng: &mut dyn Random) {
        self.ek = vec![0x42; self.produced];
    }
    fn pubkey(&self) -> &[u8] {
        &self.ek
    }
    fn encapsulate(
        &self,
        _pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), snow::Error> {
        shared_secret_out.fill(7);
        ciphertext_out.fill(9);
        Ok((shared_secret_out.len(), ciphertext_out.len()))
    }
    fn decapsulate(
        &self,
        _ciphertext: &[u8],
        shared_secret_out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        shared_secret_out.fill(7);
        Ok(shared_secret_out.len())
    }
}

/// The default resolver, plus a KEM factory (or none).
struct Resolver(Option<fn() -> OddKem>);

impl CryptoResolver for Resolver {
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
    fn resolve_kem(&self, choice: &KemChoice) -> Option<Box<dyn snow::types::Kem>> {
        match (choice, self.0) {
            (KemChoice::MlKem768, Some(make)) => Some(Box::new(make())),
            _ => None,
        }
    }
}

fn keypair() -> snow::Keypair {
    Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .generate_keypair()
        .unwrap()
}

fn builder(kem: Option<fn() -> OddKem>) -> Builder<'static> {
    Builder::with_resolver(HONEST.parse().unwrap(), Box::new(Resolver(kem)))
        .prologue(PROLOGUE)
        .unwrap()
}

/// Runs the hybrid handshake with `kem` on both sides, up to the first error.
fn run(kem: fn() -> OddKem) -> Result<(), snow::Error> {
    let (i, r) = (keypair(), keypair());
    let mut initiator = builder(Some(kem))
        .local_private_key(&i.private)?
        .remote_public_key(&r.public)?
        .build_initiator()?;
    let mut responder = builder(Some(kem))
        .local_private_key(&r.private)?
        .build_responder()?;
    let mut buf = vec![0_u8; 65_535];
    let mut read = vec![0_u8; 65_535];
    let n = initiator.write_message(&[], &mut buf)?;
    responder.read_message(&buf[..n], &mut read)?;
    let n = responder.write_message(&[], &mut buf)?;
    initiator.read_message(&buf[..n], &mut read)?;
    Ok(())
}

#[test]
fn a_consistent_kem_completes_the_handshake() {
    // The control: sizes within snow's buffers work (the fake KEM is not secure, it only
    // exercises the state machine).
    run(|| OddKem::sized(1_184, 1_088, 32)).unwrap();
}

#[test]
fn a_hybrid_pattern_without_a_kem_is_a_build_error() {
    let r = keypair();
    assert!(
        builder(None)
            .local_private_key(&r.private)
            .unwrap()
            .build_responder()
            .is_err()
    );
}

/// Patch 2: sizes beyond `MAXKEMPUBLEN`, `MAXKEMCTLEN` (4 096) or `MAXKEMSSLEN` (32) used to
/// index snow's stack buffers out of bounds, a panic (an abort in TCN's release builds).
#[test]
fn kem_sizes_beyond_snows_buffers_are_errors_not_panics() {
    assert!(run(|| OddKem::sized(4_097, 1_088, 32)).is_err());
    assert!(run(|| OddKem::sized(1_184, 4_097, 32)).is_err());
    assert!(run(|| OddKem::sized(1_184, 1_088, 33)).is_err());
    assert!(run(|| OddKem::sized(1_184, 1_088, 0)).is_err());
    assert!(run(|| OddKem::sized(0, 1_088, 32)).is_err());
    assert!(run(|| OddKem::sized(1_184, 0, 32)).is_err());
}

/// Patch 3: `Kem::generate` cannot report a failure, so snow checks what it produced. A short
/// public key (an RNG failure in TCN's provider) must not go on the wire.
#[test]
fn a_key_generation_without_a_full_public_key_fails_the_handshake() {
    let (i, r) = (keypair(), keypair());
    let make: fn() -> OddKem = || OddKem {
        produced: 0,
        ..OddKem::sized(1_184, 1_088, 32)
    };
    let mut initiator = builder(Some(make))
        .local_private_key(&i.private)
        .unwrap()
        .remote_public_key(&r.public)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut buf = vec![0_u8; 65_535];
    assert!(initiator.write_message(&[], &mut buf).is_err());
    let make: fn() -> OddKem = || OddKem {
        produced: 1_183,
        ..OddKem::sized(1_184, 1_088, 32)
    };
    assert!(run(make).is_err());
}
