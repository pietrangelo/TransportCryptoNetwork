//! Firma e verifica dei certificati client (PROTOCOL §15.2, §15.4 passi 3–6).
//!
//! **Fase 6, RED**: stub che rifiutano sempre (fail closed).

use core::fmt;

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;
use zt_domain::trust::{CertTrust, TrustedCaKey};
use zt_domain::{CertBody, CertClaims, CertFormatError, CertKey, CertRejection, Fingerprint};

use crate::error::CryptoError;
use crate::identity::PublicKey;

/// Prefisso della riga di un file di certificato.
pub const CERT_FILE_PREFIX: &str = "tcn-client-cert-v1:";

/// Chiave segreta di una CA. Niente `Clone`, azzerata al drop, `Debug` redatto.
pub struct CaSigningKey {
    key: SigningKey,
}

impl CaSigningKey {
    /// Prefisso del file della chiave segreta della CA (diverso da quello delle chiavi di nodo).
    pub const FILE_PREFIX: &'static str = "tcn-ca-secret-v1:";

    /// Una nuova CA dal CSPRNG del sistema.
    ///
    /// # Errors
    /// [`CryptoError::Random`] senza casualità.
    pub fn generate() -> Result<Self, CryptoError> {
        // RED: stub.
        Err(CryptoError::Random)
    }

    /// Dal testo del file (`tcn-ca-secret-v1:<64 hex>`, a capo finale facoltativo).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] senza il prefisso o con un esadecimale non valido.
    pub fn from_secret_text(text: &str) -> Result<Self, CryptoError> {
        // RED: stub.
        let _ = text;
        Err(CryptoError::InvalidKey)
    }

    /// Il testo del file, da scrivere con permessi `0600`.
    #[must_use]
    pub fn to_secret_text(&self) -> Zeroizing<String> {
        // RED: stub.
        Zeroizing::new(String::new())
    }

    /// La chiave pubblica della CA.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_verifying_key(self.key.verifying_key())
    }
}

impl fmt::Debug for CaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CaSigningKey(<redacted>)")
    }
}

/// La chiave pinnata per una CA.
#[must_use]
pub fn trusted_ca_key(key: &PublicKey) -> TrustedCaKey {
    TrustedCaKey {
        key: cert_key(key),
        fingerprint: key.fingerprint(),
    }
}

/// I 32 byte Ed25519 di una chiave, come compaiono in un certificato.
#[must_use]
pub fn cert_key(key: &PublicKey) -> CertKey {
    CertKey::from_bytes(key.to_bytes())
}

/// Firma `body`.
///
/// # Errors
/// Se `body.ca_key()` non è la chiave pubblica di `ca`.
pub fn sign_certificate(ca: &CaSigningKey, body: &CertBody) -> Result<Vec<u8>, CryptoError> {
    // RED: stub.
    let _ = (ca, body);
    Err(CryptoError::InvalidKey)
}

/// Passi 3–6 di PROTOCOL §15.4, nell'ordine: formato, binding a `peer` (prima della firma),
/// CA pinnata byte per byte, firma stretta. Il resto lo decide il dominio.
///
/// # Errors
/// Il primo controllo che fallisce.
pub fn verify_certificate(
    bytes: &[u8],
    peer: &Fingerprint,
    trust: &CertTrust,
) -> Result<CertClaims, CertRejection> {
    // RED: stub.
    let _ = (bytes, peer, trust);
    Err(CertRejection::Malformed)
}

/// La riga di un file di certificato: [`CERT_FILE_PREFIX`] + esadecimale + a capo.
#[must_use]
pub fn encode_certificate_text(bytes: &[u8]) -> String {
    // RED: stub.
    let _ = bytes;
    String::new()
}

/// I byte di un file di certificato. Non controlla il formato del certificato.
///
/// # Errors
/// [`CertFormatError::Magic`] senza il prefisso, con spazi, più righe o esadecimale non valido.
pub fn decode_certificate_text(text: &str) -> Result<Vec<u8>, CertFormatError> {
    // RED: stub.
    let _ = text;
    Err(CertFormatError::Magic)
}
