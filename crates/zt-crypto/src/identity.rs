use core::fmt;
use core::str::FromStr;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zt_domain::Fingerprint;

use crate::error::CryptoError;

/// Separazione di dominio per le fingerprint: un hash TCN non coincide mai con un hash di
/// altri protocolli sulla stessa chiave.
const FINGERPRINT_DOMAIN: &[u8] = b"TCN fingerprint v1\0";

/// Fingerprint della chiave statica X25519 che Noise autentica.
///
/// È definita sulla forma X25519 perché è quella che il responder Noise riceve: così il relay
/// identifica il peer direttamente da ciò che l'handshake ha provato.
#[must_use]
pub fn fingerprint_of_x25519(x25519: &[u8; 32]) -> Fingerprint {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(x25519)
        .finalize()
        .into();
    Fingerprint::from_bytes(digest)
}

/// Identità a lungo termine di un nodo (relay, agent o client): una chiave segreta Ed25519.
///
/// La chiave interna si azzera al drop (feature `zeroize` di `ed25519-dalek`), non è `Clone`
/// e il `Debug` è redatto.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    /// Genera una nuova identità dal CSPRNG del sistema operativo.
    ///
    /// # Errors
    /// [`CryptoError::Random`] se il sistema non fornisce casualità.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Carica un'identità dalla sua forma esadecimale (64 caratteri).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] se la stringa non codifica 32 byte.
    pub fn from_secret_hex(text: &str) -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        hex::decode_to_slice(text.trim(), seed.as_mut()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// `true` se `bytes` sono il seme segreto di questa identità (confronto senza uscite
    /// anticipate). Serve a riconoscere un segreto finito per errore dove va una chiave
    /// pubblica, per esempio come `subject_key` di un certificato (finding 0006-6).
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

    /// La forma esadecimale del segreto, da scrivere su un file con permessi `0600`.
    #[must_use]
    pub fn to_secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.key.as_bytes()))
    }

    /// La chiave pubblica.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
        }
    }

    /// La fingerprint dell'identità.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// Il segreto X25519 corrispondente, per Noise.
    pub(crate) fn x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_scalar_bytes())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({}, secret: <redacted>)", self.fingerprint())
    }
}

/// Chiave pubblica Ed25519 di un peer, nella forma usata nei file di configurazione
/// (64 caratteri esadecimali).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl PublicKey {
    /// La forma X25519 della chiave, che Noise usa come chiave statica.
    #[must_use]
    pub fn x25519(&self) -> [u8; 32] {
        self.key.to_montgomery().to_bytes()
    }

    /// La fingerprint della chiave.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of_x25519(&self.x25519())
    }

    /// Una chiave da 32 byte Ed25519 che DEVONO essere la codifica canonica di un punto valido
    /// e non di ordine piccolo (PROTOCOL §15.1 regola 8).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] per un punto non valido o non canonico,
    /// [`CryptoError::WeakKey`] per un punto di ordine piccolo.
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        // `from_bytes` accetta anche `y >= p` e un bit di segno su `x = 0`: la ricodifica del
        // punto decompresso deve restituire gli stessi 32 byte.
        if key.to_edwards().compress().to_bytes() != *bytes {
            return Err(CryptoError::InvalidKey);
        }
        if key.is_weak() {
            return Err(CryptoError::WeakKey);
        }
        Ok(Self { key })
    }

    /// I 32 byte Ed25519 della chiave.
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
