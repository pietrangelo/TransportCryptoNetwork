use core::fmt;
use core::hash::{Hash, Hasher};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DomainError;

/// Impronta crittografica (SHA-256, 32 byte) della chiave pubblica statica di un peer.
///
/// È l'identità usata nelle whitelist. Il confronto è **a tempo costante** (`subtle`), così il
/// tempo di risposta di un lookup non rivela quanti byte di un'impronta indovinata coincidono.
/// Il calcolo dell'hash avviene nell'adapter crittografico: il dominio riceve solo i 32 byte.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; Self::LEN]);

impl Fingerprint {
    /// Lunghezza in byte.
    pub const LEN: usize = 32;

    /// Costruisce un'impronta da 32 byte.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// I byte dell'impronta.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Fingerprint {
    type Error = DomainError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.try_into().map(Self).map_err(|_| DomainError::InvalidLength {
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
    /// Formato `SHA256:` + esadecimale, come le impronte di OpenSSH.
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

/// Segreto di autenticazione a 256 bit (per esempio un token di enrollment monouso).
///
/// Garanzie del tipo:
/// - **niente `Clone`/`Copy`**: il segreto esiste in un solo punto della memoria;
/// - **`ZeroizeOnDrop`**: i byte vengono azzerati quando il valore esce di scope (RAII);
/// - **`Debug` redatto**: non può finire nei log neppure per sbaglio (OWASP A09);
/// - **confronto a tempo costante** tramite [`AuthToken::verify`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthToken([u8; Self::LEN]);

impl AuthToken {
    /// Lunghezza in byte.
    pub const LEN: usize = 32;

    /// Prende possesso di 32 byte segreti.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Accesso in sola lettura ai byte, da usare solo all'interno degli adapter crittografici.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Confronta il token con un candidato in tempo costante rispetto al contenuto.
    ///
    /// Un candidato di lunghezza errata restituisce `false` senza confrontare i byte; la
    /// lunghezza attesa è pubblica, quindi questo non rivela nulla.
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
            Err(DomainError::InvalidLength { what: "fingerprint", expected: 32, actual: 31 })
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
