//! Sans-IO key encapsulation (PQ-0): the provider trait and ML-KEM-768.
//!
//! The trait never draws randomness itself: seeds and encapsulation randomness are parameters,
//! so every provider is deterministic, checkable against the NIST ACVP and Wycheproof vectors
//! and against an independent implementation (`tests/kem.rs`). The handshake (PQ-1) draws
//! them from the system CSPRNG ([`KemSeed::random`]) and passes them in.
//!
//! Secret hygiene (review 0008, A8-12): every secret type wipes itself on drop, and the trait
//! requires it of every provider's decapsulation key ([`zeroize::ZeroizeOnDrop`]). The ML-KEM
//! decapsulation key is one heap-allocated `libcrux` value per key, wiped in place on drop and
//! never rebuilt. What safe Rust cannot reach stays: the copy of a by-value argument inside
//! `libcrux` (the seed of key generation, the encapsulation randomness) and moved-from stack
//! slots the compiler does not reuse.
//!
//! [`MlKem768`] is `libcrux-ml-kem` (formally verified portable and AVX2 code; the NEON
//! backend is disabled, see `.cargo/config.toml`). The independent `ml-kem` crate is used only
//! in tests, as the differential oracle.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of a KEM key-generation seed (`d ‖ z` for ML-KEM, FIPS 203 §7.1).
pub const SEED_LEN: usize = 64;

/// Length of the encapsulation randomness (`m`, FIPS 203 §7.2).
pub const ENCAPSULATION_RANDOMNESS_LEN: usize = 32;

/// Length of a shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// Why a KEM operation refused its input. The variants carry no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KemError {
    /// The encapsulation key does not have the length of the algorithm.
    #[error("encapsulation key length")]
    EncapsulationKeyLength,
    /// The encapsulation key fails the FIPS 203 §7.2 input check (modulus check).
    #[error("invalid encapsulation key")]
    InvalidEncapsulationKey,
    /// The ciphertext does not have the length of the algorithm.
    #[error("ciphertext length")]
    CiphertextLength,
    /// The system random number generator is not available.
    #[error("system random generator unavailable")]
    Random,
}

/// A key-generation seed. Secret: no `Clone`, zeroized on drop, redacted `Debug`. It lives on
/// the heap, so moving a seed never leaves a copy of it on the stack.
pub struct KemSeed(Box<[u8; SEED_LEN]>);

impl KemSeed {
    /// A seed from bytes the caller drew from a CSPRNG (or a test vector). The caller's array
    /// is a copy: wipe it if it was secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    /// A seed drawn from the system CSPRNG directly into its final place.
    ///
    /// # Errors
    /// [`KemError::Random`] if the system random number generator is not available.
    pub fn random() -> Result<Self, KemError> {
        Self::filled_by(|bytes| getrandom::fill(bytes).map_err(|_| KemError::Random))
    }

    /// A seed written in place by `fill` (for example snow's random number generator). On
    /// error the partial seed is wiped.
    ///
    /// # Errors
    /// Whatever `fill` returns.
    pub fn filled_by<E>(fill: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, E> {
        let mut seed = Self(Box::new([0_u8; SEED_LEN]));
        fill(seed.0.as_mut_slice())?;
        Ok(seed)
    }

    /// The seed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl Drop for KemSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for KemSeed {}

impl core::fmt::Debug for KemSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemSeed(<redacted>)")
    }
}

/// A KEM shared secret. Secret: no `Clone`, zeroized on drop, constant-time comparison.
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);

impl SharedSecret {
    /// Wraps a shared secret computed by a provider.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl Eq for SharedSecret {}

impl ZeroizeOnDrop for SharedSecret {}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// A key encapsulation mechanism, **sans-IO**: randomness is always a parameter, never drawn
/// inside, so implementations are deterministic and testable against known-answer vectors and
/// against each other.
pub trait Kem {
    /// The algorithm name, as in FIPS 203 (for example `ML-KEM-768`).
    const ALGORITHM: &'static str;
    /// Length of an encapsulation key.
    const ENCAPSULATION_KEY_LEN: usize;
    /// Length of a ciphertext.
    const CIPHERTEXT_LEN: usize;
    /// The secret decapsulation key. It must wipe itself on drop (finding A8-12): in a
    /// handshake it is the ephemeral secret that forward secrecy depends on.
    type DecapsulationKey: ZeroizeOnDrop;

    /// Deterministic key generation from `seed`: the decapsulation key and the encoded
    /// encapsulation key.
    fn generate(seed: &KemSeed) -> (Self::DecapsulationKey, Vec<u8>);

    /// Encapsulation to `encapsulation_key` with the caller's `randomness`: the ciphertext and
    /// the shared secret.
    ///
    /// # Errors
    /// [`KemError::EncapsulationKeyLength`] or [`KemError::InvalidEncapsulationKey`]: the key
    /// is checked before it is used.
    fn encapsulate(
        encapsulation_key: &[u8],
        randomness: &[u8; ENCAPSULATION_RANDOMNESS_LEN],
    ) -> Result<(Vec<u8>, SharedSecret), KemError>;

    /// Decapsulation. A well-formed but wrong ciphertext gives a pseudo-random secret
    /// (implicit rejection), never an error.
    ///
    /// # Errors
    /// [`KemError::CiphertextLength`] only.
    fn decapsulate(
        key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, KemError>;
}

use core::ops::IndexMut;

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};

/// ML-KEM-768 (FIPS 203), provided by `libcrux-ml-kem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlKem768;

/// An ML-KEM-768 decapsulation key. Secret: no `Clone`, zeroized on drop, redacted `Debug`.
///
/// `libcrux-ml-kem` key types do not zeroize themselves, so the key is kept as **one**
/// heap-allocated `libcrux` value, used in place by every decapsulation (never rebuilt or
/// copied) and wiped in place when it is dropped (finding A8-12).
pub struct MlKem768DecapsulationKey(Box<MlKem768PrivateKey>);

impl Drop for MlKem768DecapsulationKey {
    fn drop(&mut self) {
        // `IndexMut` is the only mutable access libcrux offers to the key bytes.
        IndexMut::index_mut(&mut *self.0, 0..).zeroize();
    }
}

impl ZeroizeOnDrop for MlKem768DecapsulationKey {}

impl core::fmt::Debug for MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlKem768DecapsulationKey(<redacted>)")
    }
}

impl MlKem768 {
    /// `true` if `encapsulation_key` has the length of ML-KEM-768 and passes the FIPS 203
    /// §7.2 input check (type and modulus): the check of a static key at load time
    /// (PQ-AUTH), before it is ever used.
    #[must_use]
    pub fn is_valid_encapsulation_key(encapsulation_key: &[u8]) -> bool {
        MlKem768PublicKey::try_from(encapsulation_key)
            .is_ok_and(|ek| mlkem768::validate_public_key(&ek))
    }
}

impl Kem for MlKem768 {
    const ALGORITHM: &'static str = "ML-KEM-768";
    const ENCAPSULATION_KEY_LEN: usize = MlKem768PublicKey::len();
    const CIPHERTEXT_LEN: usize = MlKem768Ciphertext::len();
    type DecapsulationKey = MlKem768DecapsulationKey;

    fn generate(seed: &KemSeed) -> (Self::DecapsulationKey, Vec<u8>) {
        // FIPS 203 ML-KEM.KeyGen_internal(d, z), with seed = d ‖ z. libcrux takes the seed by
        // value: that copy belongs to libcrux and cannot be wiped from here.
        let (sk, pk) = mlkem768::generate_key_pair(*seed.as_bytes()).into_parts();
        (
            MlKem768DecapsulationKey(Box::new(sk)),
            pk.as_slice().to_vec(),
        )
    }

    fn encapsulate(
        encapsulation_key: &[u8],
        randomness: &[u8; ENCAPSULATION_RANDOMNESS_LEN],
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        let ek = MlKem768PublicKey::try_from(encapsulation_key)
            .map_err(|_| KemError::EncapsulationKeyLength)?;
        // FIPS 203 §7.2 input check (type and modulus) before the key is used.
        if !mlkem768::validate_public_key(&ek) {
            return Err(KemError::InvalidEncapsulationKey);
        }
        // The randomness is passed by value: a zeroizing local holds the copy this function
        // makes; the callee's own copy is out of reach.
        let m = Zeroizing::new(*randomness);
        let (ct, mut ss) = mlkem768::encapsulate(&ek, *m);
        let secret = SharedSecret::from_bytes(ss);
        ss.zeroize();
        Ok((ct.as_slice().to_vec(), secret))
    }

    fn decapsulate(
        key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, KemError> {
        // Length is the only check: a wrong ciphertext of the right length takes the implicit
        // rejection path inside ML-KEM.Decaps and yields a pseudo-random secret.
        let ct =
            MlKem768Ciphertext::try_from(ciphertext).map_err(|_| KemError::CiphertextLength)?;
        let mut ss = mlkem768::decapsulate(&key.0, &ct);
        let secret = SharedSecret::from_bytes(ss);
        ss.zeroize();
        Ok(secret)
    }
}
