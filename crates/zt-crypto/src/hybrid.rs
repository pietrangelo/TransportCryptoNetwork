//! Hybrid static identities (PQ-AUTH, PROTOCOL §7.5.3; decisions D12, D13; finding AP-6).
//!
//! Every node keeps its single secret, the Ed25519 seed. Its ML-KEM-768 static key is derived
//! from it: `d ‖ z = SHAKE256("TCN ML-KEM-768 seed v1\0" ‖ seed, 64)`, then FIPS 203
//! `ML-KEM.KeyGen_internal(d, z)`. No new secret file, and key files, permissions and rotation
//! are unchanged.
//!
//! The public form is `tcn-pub-v2:` + hex(Ed25519 (32) ‖ ek (1 184)), and the fingerprint v2 is
//! `SHA-256("TCN fingerprint v2\0" ‖ x25519 ‖ ek)`, shown as `SHA256v2:`. The X25519-level
//! fingerprint v1 stays the unit of roles and revocation (AP-6): a v2 key always yields it.

use core::fmt;
use core::str::FromStr;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zt_domain::{Fingerprint, HybridFingerprint};

use crate::error::CryptoError;
use crate::identity::PublicKey;
use crate::kem::{Kem, KemSeed, MlKem768};

/// Domain separation of the static ML-KEM key derivation (D12).
const KEM_SEED_DOMAIN: &[u8] = b"TCN ML-KEM-768 seed v1\0";

/// Domain separation of fingerprint v2.
const FINGERPRINT_V2_DOMAIN: &[u8] = b"TCN fingerprint v2\0";

/// Length of an ML-KEM-768 encapsulation key.
pub(crate) const EK_LEN: usize = 1_184;

/// The static ML-KEM-768 key pair of a seed. The decapsulation key wipes itself on drop.
pub(crate) struct StaticKem {
    pub(crate) dk: <MlKem768 as Kem>::DecapsulationKey,
    pub(crate) ek: Arc<[u8]>,
}

impl StaticKem {
    /// The key pair derived from the Ed25519 `seed` (D12).
    pub(crate) fn derive(seed: &[u8; 32]) -> Self {
        let mut xof = Shake256::default();
        xof.update(KEM_SEED_DOMAIN);
        xof.update(seed);
        // Written in place: no copy of `d ‖ z` is left on the stack (finding A12-8).
        let Ok(seed) = KemSeed::filled_by(|bytes| {
            xof.finalize_xof().read(bytes);
            Ok::<(), core::convert::Infallible>(())
        });
        let (dk, ek) = MlKem768::generate(&seed);
        Self {
            dk,
            ek: Arc::from(ek),
        }
    }
}

/// `SHA-256("TCN fingerprint v2\0" ‖ x25519 ‖ ek)`: the fingerprint v2 of a hybrid identity.
#[must_use]
pub fn hybrid_fingerprint_of(x25519: &[u8; 32], encapsulation_key: &[u8]) -> HybridFingerprint {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(FINGERPRINT_V2_DOMAIN)
        .chain_update(x25519)
        .chain_update(encapsulation_key)
        .finalize()
        .into();
    HybridFingerprint::from_bytes(digest)
}

/// A node's v2 public key: its Ed25519 key and its static ML-KEM-768 encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    classical: PublicKey,
    ek: Arc<[u8]>,
}

impl HybridPublicKey {
    /// The prefix of the text form.
    pub const PREFIX: &'static str = "tcn-pub-v2:";
    /// Hex characters after the prefix: (32 + 1 184) × 2.
    pub const HEX_LEN: usize = (32 + EK_LEN) * 2;

    pub(crate) const fn new(classical: PublicKey, ek: Arc<[u8]>) -> Self {
        Self { classical, ek }
    }

    /// The Ed25519 part: the v1 key of the same node.
    #[must_use]
    pub const fn classical(&self) -> &PublicKey {
        &self.classical
    }

    /// The ML-KEM-768 encapsulation key (1 184 bytes, valid per FIPS 203 §7.2).
    #[must_use]
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek
    }

    /// The X25519-level fingerprint (v1): the unit of roles and revocation.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.classical.fingerprint()
    }

    /// The fingerprint v2, over X25519 ‖ ek.
    #[must_use]
    pub fn hybrid_fingerprint(&self) -> HybridFingerprint {
        hybrid_fingerprint_of(&self.classical.x25519(), &self.ek)
    }
}

impl FromStr for HybridPublicKey {
    type Err = CryptoError;

    /// Exactly `tcn-pub-v2:` + 2 432 lowercase hex characters: a canonical, non-weak Ed25519
    /// key and an encapsulation key that passes the FIPS 203 §7.2 check. No trimming.
    fn from_str(text: &str) -> Result<Self, CryptoError> {
        let digits = text
            .strip_prefix(Self::PREFIX)
            .ok_or(CryptoError::InvalidKey)?;
        if digits.len() != Self::HEX_LEN
            || !digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CryptoError::InvalidKey);
        }
        let mut bytes = vec![0_u8; 32 + EK_LEN];
        hex::decode_to_slice(digits, &mut bytes).map_err(|_| CryptoError::InvalidKey)?;
        let (ed, ek) = bytes.split_at(32);
        let ed: [u8; 32] = ed.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let classical = PublicKey::from_canonical_bytes(&ed)?;
        if !MlKem768::is_valid_encapsulation_key(ek) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            classical,
            ek: Arc::from(ek),
        })
    }
}

impl fmt::Display for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::PREFIX)?;
        f.write_str(&hex::encode(self.classical.to_bytes()))?;
        f.write_str(&hex::encode(&self.ek))
    }
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridPublicKey({})", self.hybrid_fingerprint())
    }
}

/// The compact v2 pin of a **responder** (finding A12-2 of review 0012): the Ed25519 key and
/// the fingerprint v2, `tcn-pin-v2:<64 hex>:<64 hex>` (139 characters instead of 2 443). A
/// responder never needs the initiator's encapsulation key from its configuration: message 1
/// carries it, and the responder only compares its fingerprint v2 with the pin. An initiator
/// needs the full [`HybridPublicKey`], so this form is refused there.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HybridPin {
    classical: PublicKey,
    hybrid: HybridFingerprint,
}

impl HybridPin {
    /// The prefix of the text form.
    pub const PREFIX: &'static str = "tcn-pin-v2:";
    /// The length of the text form: the prefix, 64 hex, `:`, 64 hex.
    pub const TEXT_LEN: usize = Self::PREFIX.len() + 64 + 1 + 64;

    /// The Ed25519 part: the v1 key of the same node.
    #[must_use]
    pub const fn classical(&self) -> &PublicKey {
        &self.classical
    }

    /// The X25519-level fingerprint (v1): the unit of roles and revocation.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.classical.fingerprint()
    }

    /// The pinned fingerprint v2.
    #[must_use]
    pub const fn hybrid_fingerprint(&self) -> HybridFingerprint {
        self.hybrid
    }
}

impl From<&HybridPublicKey> for HybridPin {
    fn from(key: &HybridPublicKey) -> Self {
        Self {
            classical: key.classical,
            hybrid: key.hybrid_fingerprint(),
        }
    }
}

/// 64 lowercase hex characters, decoded.
fn lower_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0_u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

impl FromStr for HybridPin {
    type Err = CryptoError;

    /// Exactly `tcn-pin-v2:` + 64 lowercase hex (a canonical, non-weak Ed25519 key) + `:` + 64
    /// lowercase hex (the fingerprint v2). No trimming.
    fn from_str(text: &str) -> Result<Self, CryptoError> {
        let rest = text
            .strip_prefix(Self::PREFIX)
            .ok_or(CryptoError::InvalidKey)?;
        let (key, fingerprint) = rest.split_once(':').ok_or(CryptoError::InvalidKey)?;
        let (Some(key), Some(fingerprint)) = (lower_hex32(key), lower_hex32(fingerprint)) else {
            return Err(CryptoError::InvalidKey);
        };
        Ok(Self {
            classical: PublicKey::from_canonical_bytes(&key)?,
            hybrid: HybridFingerprint::from_bytes(fingerprint),
        })
    }
}

impl fmt::Display for HybridPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::PREFIX)?;
        f.write_str(&hex::encode(self.classical.to_bytes()))?;
        f.write_str(":")?;
        f.write_str(&hex::encode(self.hybrid.as_bytes()))
    }
}

impl fmt::Debug for HybridPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridPin({})", self.hybrid)
    }
}

/// The key an initiator pins for its responder: v1 (Ed25519) or v2 (with the static ML-KEM
/// key, needed by the hybrid IK suite).
#[derive(Clone, PartialEq, Eq)]
pub enum PeerKey {
    /// A v1 key.
    Classical(PublicKey),
    /// A v2 key.
    Hybrid(HybridPublicKey),
}

impl PeerKey {
    /// The Ed25519 key (the v1 key of a v2 key).
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        match self {
            Self::Classical(key) => key,
            Self::Hybrid(key) => key.classical(),
        }
    }

    /// The v2 key, if this pin has one.
    #[must_use]
    pub const fn hybrid(&self) -> Option<&HybridPublicKey> {
        match self {
            Self::Classical(_) => None,
            Self::Hybrid(key) => Some(key),
        }
    }

    /// The X25519-level fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }
}

impl From<PublicKey> for PeerKey {
    fn from(key: PublicKey) -> Self {
        Self::Classical(key)
    }
}

impl From<&PublicKey> for PeerKey {
    fn from(key: &PublicKey) -> Self {
        Self::Classical(*key)
    }
}

impl From<HybridPublicKey> for PeerKey {
    fn from(key: HybridPublicKey) -> Self {
        Self::Hybrid(key)
    }
}

impl From<&HybridPublicKey> for PeerKey {
    fn from(key: &HybridPublicKey) -> Self {
        Self::Hybrid(key.clone())
    }
}

impl From<&Self> for PeerKey {
    fn from(key: &Self) -> Self {
        key.clone()
    }
}

impl FromStr for PeerKey {
    type Err = CryptoError;

    /// A `tcn-pub-v2:` key, or a v1 key (64 hex characters).
    fn from_str(text: &str) -> Result<Self, CryptoError> {
        if text.starts_with(HybridPublicKey::PREFIX) {
            text.parse().map(Self::Hybrid)
        } else {
            text.parse().map(Self::Classical)
        }
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Classical(key) => key.fmt(f),
            Self::Hybrid(key) => key.fmt(f),
        }
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Classical(key) => key.fmt(f),
            Self::Hybrid(key) => key.fmt(f),
        }
    }
}
