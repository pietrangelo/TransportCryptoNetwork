//! Firma e verifica dei certificati client (PROTOCOL §15.2, §15.4 passi 3–6).

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey};
use zeroize::Zeroizing;
use zt_domain::cert::{CERT_SIGNATURE_CONTEXT, CERT_SIGNATURE_LEN};
use zt_domain::limits::MAX_CERT_LEN;
use zt_domain::trust::{CertTrust, TrustedCaKey};
use zt_domain::{
    CertBody, CertClaims, CertFormatError, CertKey, CertRejection, Fingerprint, decode_certificate,
};

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
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Dal testo del file (`tcn-ca-secret-v1:<64 hex>`, a capo finale facoltativo).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] senza il prefisso o con un esadecimale non valido.
    pub fn from_secret_text(text: &str) -> Result<Self, CryptoError> {
        let line = text.strip_suffix('\n').unwrap_or(text);
        let hex_part = line
            .strip_prefix(Self::FILE_PREFIX)
            .ok_or(CryptoError::InvalidKey)?;
        if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CryptoError::InvalidKey);
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        hex::decode_to_slice(hex_part, seed.as_mut()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Il testo del file, da scrivere con permessi `0600`.
    #[must_use]
    pub fn to_secret_text(&self) -> Zeroizing<String> {
        let hex_part = Zeroizing::new(hex::encode(self.key.as_bytes()));
        let mut text = Zeroizing::new(String::with_capacity(
            Self::FILE_PREFIX.len().saturating_add(65),
        ));
        text.push_str(Self::FILE_PREFIX);
        text.push_str(&hex_part);
        text.push('\n');
        text
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

/// Il messaggio firmato: `CTX || TBS` (PROTOCOL §15.2).
fn signed_message(tbs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CERT_SIGNATURE_CONTEXT.len().saturating_add(tbs.len()));
    message.extend_from_slice(CERT_SIGNATURE_CONTEXT);
    message.extend_from_slice(tbs);
    message
}

/// Firma `body`.
///
/// # Errors
/// Se `body.ca_key()` non è la chiave pubblica di `ca`.
pub fn sign_certificate(ca: &CaSigningKey, body: &CertBody) -> Result<Vec<u8>, CryptoError> {
    if body.ca_key() != &cert_key(&ca.public_key()) {
        return Err(CryptoError::InvalidKey);
    }
    let tbs = body.encode_tbs();
    let signature = ca
        .key
        .try_sign(&signed_message(&tbs))
        .map_err(|_| CryptoError::InvalidKey)?;
    let mut cert = tbs;
    cert.extend_from_slice(&signature.to_bytes());
    Ok(cert)
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
    // Passo 3: lunghezza (prima di tutto) e formato, regole 1–7.
    let parsed = decode_certificate(bytes).map_err(|_| CertRejection::Malformed)?;
    // Passo 4: `subject_key` canonica e non debole, e legata alla chiave che Noise ha
    // autenticato. Viene prima della firma: un certificato rubato non costa una verifica.
    let subject = PublicKey::from_canonical_bytes(parsed.body.subject_key().as_bytes())
        .map_err(|_| CertRejection::KeyMismatch)?;
    let subject_fp = subject.fingerprint();
    // `Fingerprint::eq` è a tempo costante (`subtle`).
    if subject_fp != *peer {
        return Err(CertRejection::KeyMismatch);
    }
    // Passo 5: `ca_key` uguale byte per byte a una chiave pinnata. Si verifica con il pin, mai
    // con la chiave scritta nel certificato.
    let authority = trust
        .authority_for_key(parsed.body.ca_key())
        .ok_or(CertRejection::UnknownAuthority)?;
    let pin = authority
        .keys()
        .iter()
        .find(|k| k.key == *parsed.body.ca_key())
        .ok_or(CertRejection::UnknownAuthority)?;
    let ca = PublicKey::from_canonical_bytes(pin.key.as_bytes())
        .map_err(|_| CertRejection::UnknownAuthority)?;
    // Passo 6: firma stretta (`S` canonico, `R` e chiave non di ordine piccolo).
    let signature_bytes: [u8; CERT_SIGNATURE_LEN] = *parsed.signature;
    let signature = Signature::from_bytes(&signature_bytes);
    ca.verifying_key()
        .verify_strict(&signed_message(parsed.tbs), &signature)
        .map_err(|_| CertRejection::BadSignature)?;
    Ok(CertClaims::from_verified(
        parsed.body,
        pin.fingerprint,
        subject_fp,
    ))
}

/// La riga di un file di certificato: [`CERT_FILE_PREFIX`] + esadecimale + a capo.
#[must_use]
pub fn encode_certificate_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(
        CERT_FILE_PREFIX
            .len()
            .saturating_add(bytes.len().saturating_mul(2))
            .saturating_add(1),
    );
    text.push_str(CERT_FILE_PREFIX);
    text.push_str(&hex::encode(bytes));
    text.push('\n');
    text
}

/// I byte di un file di certificato. Non controlla il formato del certificato.
///
/// Una sola forma è accettata: il prefisso, l'esadecimale minuscolo, al più un a capo finale.
///
/// # Errors
/// [`CertFormatError::Magic`] senza il prefisso, con spazi, più righe o esadecimale non valido;
/// [`CertFormatError::Length`] oltre `MAX_CERT_LEN` byte.
pub fn decode_certificate_text(text: &str) -> Result<Vec<u8>, CertFormatError> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let hex_part = line
        .strip_prefix(CERT_FILE_PREFIX)
        .ok_or(CertFormatError::Magic)?;
    if hex_part.is_empty()
        || !hex_part.len().is_multiple_of(2)
        || !hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CertFormatError::Magic);
    }
    let len = hex_part.len() / 2;
    if len > MAX_CERT_LEN {
        return Err(CertFormatError::Length { len });
    }
    hex::decode(hex_part).map_err(|_| CertFormatError::Magic)
}
