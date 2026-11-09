//! The `snow` resolver of TCN: snow's own primitives for DH, cipher, hash and randomness, and
//! **TCN's** KEM provider ([`crate::kem::MlKem768`], libcrux) for the hybrid suite (PQ-1,
//! docs/pq-snow.md). snow never sees any other KEM implementation: the vendored copy has none
//! for ML-KEM-768, and the `pqclean` features stay off.

use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use zeroize::Zeroizing;

use crate::kem::{
    ENCAPSULATION_RANDOMNESS_LEN, Kem, KemSeed, MlKem768, SHARED_SECRET_LEN, SharedSecret,
};

/// The resolver every TCN handshake is built with.
pub(crate) struct Resolver;

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
        match choice {
            KemChoice::MlKem768 => Some(Box::new(SnowMlKem768::default())),
            // Round-3 Kyber is not a TCN suite.
            KemChoice::Kyber1024 => None,
        }
    }
}

/// ML-KEM-768 in snow's shape. One instance lives inside one handshake state: the initiator's
/// ephemeral decapsulation key is dropped, and wiped, with the handshake (A8-12).
#[derive(Default)]
struct SnowMlKem768 {
    /// The ephemeral decapsulation key (initiator only).
    dk: Option<<MlKem768 as Kem>::DecapsulationKey>,
    /// Its encapsulation key, sent as `e1`. Empty until `generate` succeeds: snow (TCN patch 3)
    /// refuses to write an `e1` of the wrong length, so an RNG failure fails the handshake.
    ek: Vec<u8>,
}

/// Copies `secret` to the start of `out`.
fn put(out: &mut [u8], secret: &SharedSecret) -> Result<usize, snow::Error> {
    let dst = out.get_mut(..SHARED_SECRET_LEN).ok_or(snow::Error::Kem)?;
    dst.copy_from_slice(secret.as_bytes());
    Ok(SHARED_SECRET_LEN)
}

impl snow::types::Kem for SnowMlKem768 {
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
        SHARED_SECRET_LEN
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        self.dk = None;
        self.ek.clear();
        // The seed is written by the RNG directly into its zeroizing heap buffer.
        let Ok(seed) = KemSeed::filled_by(|bytes| rng.try_fill_bytes(bytes)) else {
            return;
        };
        let (dk, ek) = MlKem768::generate(&seed);
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
        let mut m = Zeroizing::new([0_u8; ENCAPSULATION_RANDOMNESS_LEN]);
        getrandom::fill(m.as_mut_slice()).map_err(|_| snow::Error::Rng)?;
        // The FIPS 203 §7.2 check of the peer's key happens here, after the authorization
        // decision (`accept`): an invalid `e1` gets no message 2.
        let (ct, secret) = MlKem768::encapsulate(pubkey, &m).map_err(|_| snow::Error::Kem)?;
        let dst = ciphertext_out.get_mut(..ct.len()).ok_or(snow::Error::Kem)?;
        dst.copy_from_slice(&ct);
        Ok((put(shared_secret_out, &secret)?, ct.len()))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8],
        shared_secret_out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        let dk = self.dk.as_ref().ok_or(snow::Error::Kem)?;
        // A wrong ciphertext of the right length yields a pseudo-random secret (implicit
        // rejection): the handshake then fails at the next AEAD, like a forged message 2.
        let secret = MlKem768::decapsulate(dk, ciphertext).map_err(|_| snow::Error::Kem)?;
        put(shared_secret_out, &secret)
    }
}
