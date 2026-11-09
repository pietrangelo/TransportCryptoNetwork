use core::fmt;
use core::str::FromStr;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zt_domain::Fingerprint;

use crate::error::CryptoError;
use crate::hybrid::{HybridPublicKey, StaticKem};
use crate::kem::{Kem, MlKem768};

/// Domain separation for fingerprints: a TCN hash never coincides with a hash of other
/// protocols over the same key.
const FINGERPRINT_DOMAIN: &[u8] = b"TCN fingerprint v1\0";

/// Fingerprint of the X25519 static key that Noise authenticates.
///
/// It is defined over the X25519 form because that is what the Noise responder receives: this
/// way the relay identifies the peer directly from what the handshake proved.
#[must_use]
pub fn fingerprint_of_x25519(x25519: &[u8; 32]) -> Fingerprint {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(x25519)
        .finalize()
        .into();
    Fingerprint::from_bytes(digest)
}

/// Long-term identity of a node (relay, agent or client): an Ed25519 secret key.
///
/// The inner key is zeroized on drop (`zeroize` feature of `ed25519-dalek`), it is not `Clone`
/// and its `Debug` is redacted.
pub struct Identity {
    key: SigningKey,
    /// The static ML-KEM-768 key pair derived from the seed (PQ-AUTH, D12).
    kem: StaticKem,
}

impl Identity {
    /// Generates a new identity from the operating system CSPRNG.
    ///
    /// # Errors
    /// [`CryptoError::Random`] if the system does not provide randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self::from_seed(&seed))
    }

    /// Loads an identity from its hex form (64 characters).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] if the string does not encode 32 bytes.
    pub fn from_secret_hex(text: &str) -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        hex::decode_to_slice(text.trim(), seed.as_mut()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
            kem: StaticKem::derive(seed),
        }
    }

    /// The v2 public key (PQ-AUTH): Ed25519 and the derived ML-KEM-768 encapsulation key.
    #[must_use]
    pub fn hybrid_public_key(&self) -> HybridPublicKey {
        HybridPublicKey::new(self.public_key(), std::sync::Arc::clone(&self.kem.ek))
    }

    /// The fingerprint v2 of the identity.
    #[must_use]
    pub fn hybrid_fingerprint(&self) -> zt_domain::HybridFingerprint {
        self.hybrid_public_key().hybrid_fingerprint()
    }

    /// The static ML-KEM key pair, for the hybrid IK responder.
    pub(crate) const fn static_kem(&self) -> &StaticKem {
        &self.kem
    }

    /// A fresh copy of the static decapsulation key, owned by a handshake in flight (the
    /// initiator decapsulates `ct2` after this borrow has ended). Re-derived from the seed:
    /// the key type has no `Clone`.
    pub(crate) fn static_decapsulation_key(&self) -> <MlKem768 as Kem>::DecapsulationKey {
        StaticKem::derive(self.key.as_bytes()).dk
    }

    /// `true` if `bytes` are the secret seed of this identity (comparison without early
    /// exits). Used to recognize a secret that ended up by mistake where a public key belongs,
    /// for example as the `subject_key` of a certificate (finding 0006-6).
    #[must_use]
    pub fn is_own_secret(&self, bytes: &[u8; 32]) -> bool {
        let diff = self
            .key
            .as_bytes()
            .iter()
            .zip(bytes)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        std::hint::black_box(diff) == 0
    }

    /// The hex form of the secret, to be written to a file with `0600` permissions.
    #[must_use]
    pub fn to_secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.key.as_bytes()))
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
        }
    }

    /// The fingerprint of the identity.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// The corresponding X25519 secret, for Noise.
    pub(crate) fn x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_scalar_bytes())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({}, secret: <redacted>)", self.fingerprint())
    }
}

/// Ed25519 public key of a peer, in the form used in configuration files (64 hex
/// characters).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl PublicKey {
    /// The X25519 form of the key, which Noise uses as the static key.
    #[must_use]
    pub fn x25519(&self) -> [u8; 32] {
        self.key.to_montgomery().to_bytes()
    }

    /// The fingerprint of the key.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of_x25519(&self.x25519())
    }

    /// A key from 32 Ed25519 bytes that MUST be the canonical encoding of a valid point not
    /// of small order (PROTOCOL §15.1 rule 8).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] for an invalid or non-canonical point,
    /// [`CryptoError::WeakKey`] for a small-order point.
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        // `from_bytes` also accepts `y >= p` and a sign bit on `x = 0`: re-encoding the
        // decompressed point must give back the same 32 bytes.
        if key.to_edwards().compress().to_bytes() != *bytes {
            return Err(CryptoError::InvalidKey);
        }
        if key.is_weak() {
            return Err(CryptoError::WeakKey);
        }
        Ok(Self { key })
    }

    /// The 32 Ed25519 bytes of the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub(crate) const fn from_verifying_key(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub(crate) const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

impl FromStr for PublicKey {
    type Err = CryptoError;

    fn from_str(text: &str) -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(text.trim(), &mut bytes).map_err(|_| CryptoError::InvalidKey)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidKey)?;
        if key.is_weak() {
            return Err(CryptoError::WeakKey);
        }
        Ok(Self { key })
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.key.as_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}
