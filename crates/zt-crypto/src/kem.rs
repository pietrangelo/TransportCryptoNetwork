//! Sans-IO key encapsulation (PQ-0): the provider trait and ML-KEM-768.
//!
//! The trait never draws randomness itself: seeds and encapsulation randomness are parameters,
//! so every provider is deterministic, checkable against the NIST ACVP and Wycheproof vectors
//! and against an independent implementation (`tests/kem.rs`). The handshake (PQ-1) draws
//! them from the system CSPRNG and passes them in.
//!
//! [`MlKem768`] is `libcrux-ml-kem` (formally verified portable and AVX2 code; the NEON
//! backend is disabled, see `.cargo/config.toml`). The independent `ml-kem` crate is used only
//! in tests, as the differential oracle.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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
}

/// A key-generation seed. Secret: no `Clone`, zeroized on drop, redacted `Debug`.
pub struct KemSeed(Zeroizing<[u8; SEED_LEN]>);

impl KemSeed {
    /// A seed from bytes the caller drew from a CSPRNG (or a test vector).
    #[must_use]
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The seed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

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
    /// The secret decapsulation key.
    type DecapsulationKey;

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

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use zeroize::Zeroize;

/// Length of an ML-KEM-768 decapsulation key in its expanded (FIPS 203) form.
const MLKEM768_DK_LEN: usize = MlKem768PrivateKey::len();

/// ML-KEM-768 (FIPS 203), provided by `libcrux-ml-kem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlKem768;

/// An ML-KEM-768 decapsulation key. Secret: no `Clone`, zeroized on drop, redacted `Debug`.
///
/// `libcrux-ml-kem` key types do not zeroize themselves, so the key lives here as zeroizing
/// bytes and is turned into a `libcrux` value only for the duration of a decapsulation (whose
/// temporary copy is wiped as well, as far as the compiler lets a copy be wiped).
pub struct MlKem768DecapsulationKey(Zeroizing<[u8; MLKEM768_DK_LEN]>);

impl core::fmt::Debug for MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlKem768DecapsulationKey(<redacted>)")
    }
}

impl Kem for MlKem768 {
    const ALGORITHM: &'static str = "ML-KEM-768";
    const ENCAPSULATION_KEY_LEN: usize = MlKem768PublicKey::len();
    const CIPHERTEXT_LEN: usize = MlKem768Ciphertext::len();
    type DecapsulationKey = MlKem768DecapsulationKey;

    fn generate(seed: &KemSeed) -> (Self::DecapsulationKey, Vec<u8>) {
        // FIPS 203 ML-KEM.KeyGen_internal(d, z), with seed = d ‖ z.
        let (sk, pk) = mlkem768::generate_key_pair(*seed.as_bytes()).into_parts();
        let mut raw: [u8; MLKEM768_DK_LEN] = sk.into();
        let key = MlKem768DecapsulationKey(Zeroizing::new(raw));
        raw.zeroize();
        (key, pk.as_slice().to_vec())
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
        let (ct, ss) = mlkem768::encapsulate(&ek, *randomness);
        Ok((ct.as_slice().to_vec(), SharedSecret::from_bytes(ss)))
    }

    fn decapsulate(
        key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, KemError> {
        // Length is the only check: a wrong ciphertext of the right length takes the implicit
        // rejection path inside ML-KEM.Decaps and yields a pseudo-random secret.
        let ct =
            MlKem768Ciphertext::try_from(ciphertext).map_err(|_| KemError::CiphertextLength)?;
        let sk = MlKem768PrivateKey::from(&*key.0);
        let ss = mlkem768::decapsulate(&sk, &ct);
        let mut wipe: [u8; MLKEM768_DK_LEN] = sk.into();
        wipe.zeroize();
        Ok(SharedSecret::from_bytes(ss))
    }
}
