use core::fmt;
use core::hash::{Hash, Hasher};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DomainError;

/// Cryptographic fingerprint (SHA-256, 32 bytes) of a peer's static public key.
///
/// It is the identity used in whitelists. Comparison is **constant-time** (`subtle`), so the
/// response time of a lookup does not reveal how many bytes of a guessed fingerprint match.
/// The hash is computed in the crypto adapter: the domain receives only the 32 bytes.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; Self::LEN]);

impl Fingerprint {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Builds a fingerprint from 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Fingerprint {
    type Error = DomainError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| DomainError::InvalidLength {
                what: "fingerprint",
                expected: Self::LEN,
                actual: bytes.len(),
            })
    }
}

impl ConstantTimeEq for Fingerprint {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fingerprint {}

impl Hash for Fingerprint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for Fingerprint {
    /// `SHA256:` + hex format, like OpenSSH fingerprints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SHA256:")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Fingerprint v2 (PQ-AUTH) of a hybrid static identity: `SHA-256("TCN fingerprint v2\0" ‖
/// x25519 ‖ mlkem768_ek)`, computed in the crypto adapter.
///
/// It is **not** an identity on its own (finding AP-6): the revocation, policy and audit unit
/// stays the X25519-level [`Fingerprint`], which every handshake version yields. A hybrid
/// fingerprint only *pins* the ML-KEM half of an identity. It has its own display prefix,
/// `SHA256v2:`, so that a v2 value is never mistaken for, or loaded as, a v1 fingerprint.
#[derive(Clone, Copy)]
pub struct HybridFingerprint([u8; Self::LEN]);

impl HybridFingerprint {
    /// Length in bytes.
    pub const LEN: usize = 32;
    /// Display prefix, distinct from the `SHA256:` of v1 fingerprints.
    pub const PREFIX: &'static str = "SHA256v2:";

    /// Builds a hybrid fingerprint from 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl ConstantTimeEq for HybridFingerprint {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for HybridFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for HybridFingerprint {}

impl Hash for HybridFingerprint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for HybridFingerprint {
    /// `SHA256v2:` + hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::PREFIX)?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HybridFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridFingerprint({self})")
    }
}

/// Which fingerprint a text names (finding AP-6): loaders that expect one kind reject the
/// other instead of silently matching nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintText {
    /// `SHA256:` + 64 lowercase hex characters.
    V1(Fingerprint),
    /// `SHA256v2:` + 64 lowercase hex characters.
    V2(HybridFingerprint),
}

impl FingerprintText {
    /// Parses exactly `SHA256:<64 hex>` or `SHA256v2:<64 hex>` (lowercase, no spaces).
    ///
    /// # Errors
    /// [`DomainError::InvalidLength`] for anything else (the text is never echoed).
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let bad = || DomainError::InvalidLength {
            what: "fingerprint",
            expected: Fingerprint::LEN,
            actual: 0,
        };
        let (v2, digits) = if let Some(rest) = text.strip_prefix(HybridFingerprint::PREFIX) {
            (true, rest)
        } else if let Some(rest) = text.strip_prefix("SHA256:") {
            (false, rest)
        } else {
            return Err(bad());
        };
        let raw = digits.as_bytes();
        if raw.len() != 64 {
            return Err(bad());
        }
        let mut bytes = [0_u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(raw.chunks_exact(2)) {
            let [hi, lo] = pair else { return Err(bad()) };
            let (Some(hi), Some(lo)) = (lower_hex(*hi), lower_hex(*lo)) else {
                return Err(bad());
            };
            *slot = hi.wrapping_mul(16) | lo;
        }
        Ok(if v2 {
            Self::V2(HybridFingerprint(bytes))
        } else {
            Self::V1(Fingerprint(bytes))
        })
    }
}

/// One lowercase hex digit.
const fn lower_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// 256-bit authentication secret (for example a single-use enrollment token).
///
/// Guarantees of the type:
/// - **no `Clone`/`Copy`**: the secret exists in only one place in memory;
/// - **`ZeroizeOnDrop`**: the bytes are zeroed when the value goes out of scope (RAII);
/// - **redacted `Debug`**: it cannot end up in logs, not even by accident (OWASP A09);
/// - **constant-time comparison** via [`AuthToken::verify`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthToken([u8; Self::LEN]);

impl AuthToken {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Takes ownership of 32 secret bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Read-only access to the bytes, to be used only inside the crypto adapters.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Compares the token with a candidate in time that is constant with respect to the content.
    ///
    /// A candidate of the wrong length returns `false` without comparing the bytes; the
    /// expected length is public, so this reveals nothing.
    #[must_use]
    pub fn verify(&self, candidate: &[u8]) -> bool {
        candidate.len() == Self::LEN && bool::from(self.0.ct_eq(candidate))
    }
}

impl TryFrom<&[u8]> for AuthToken {
    type Error = DomainError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array: [u8; Self::LEN] = bytes.try_into().map_err(|_| DomainError::InvalidLength {
            what: "auth token",
            expected: Self::LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthToken(<redacted>)")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_requires_exactly_32_bytes() {
        assert!(Fingerprint::try_from(&[0_u8; 32][..]).is_ok());
        assert_eq!(
            Fingerprint::try_from(&[0_u8; 31][..]),
            Err(DomainError::InvalidLength {
                what: "fingerprint",
                expected: 32,
                actual: 31
            })
        );
    }

    #[test]
    fn fingerprint_displays_like_openssh() {
        let fp = Fingerprint::from_bytes([0xab; 32]);
        assert_eq!(fp.to_string(), format!("SHA256:{}", "ab".repeat(32)));
    }

    #[test]
    fn auth_token_debug_never_leaks_the_secret() {
        let token = AuthToken::from_bytes([0x41; 32]);
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "AuthToken(<redacted>)");
        assert!(!rendered.contains("41"));
        assert!(!rendered.contains("AAAA"));
    }

    #[test]
    fn auth_token_verifies_only_the_exact_secret() {
        let token = AuthToken::from_bytes([7; 32]);
        assert!(token.verify(&[7; 32]));
        let mut almost = [7_u8; 32];
        almost[31] = 8;
        assert!(!token.verify(&almost));
        assert!(!token.verify(&[7; 31]));
        assert!(!token.verify(&[]));
    }

    #[test]
    fn auth_token_is_zeroized_explicitly() {
        let mut token = AuthToken::from_bytes([9; 32]);
        token.zeroize();
        assert_eq!(token.expose_secret(), &[0; 32]);
    }
}
