//! Signing and verification of client certificates (PROTOCOL §15.2, §15.4 steps 3–6).

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

/// Line prefix of a certificate file.
pub const CERT_FILE_PREFIX: &str = "tcn-client-cert-v1:";

/// Secret key of a CA. No `Clone`, zeroized on drop, redacted `Debug`.
pub struct CaSigningKey {
    key: SigningKey,
}

impl CaSigningKey {
    /// File prefix of the CA secret key (different from the one of node keys).
    pub const FILE_PREFIX: &'static str = "tcn-ca-secret-v1:";

    /// A new CA from the system CSPRNG.
    ///
    /// # Errors
    /// [`CryptoError::Random`] without randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// From the file text (`tcn-ca-secret-v1:<64 hex>`, optional trailing newline).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] without the prefix or with invalid hex.
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

    /// The file text, to be written with `0600` permissions.
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

    /// The public key of the CA.
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

/// The pinned key for a CA.
#[must_use]
pub fn trusted_ca_key(key: &PublicKey) -> TrustedCaKey {
    TrustedCaKey {
        key: cert_key(key),
        fingerprint: key.fingerprint(),
    }
}

/// The 32 Ed25519 bytes of a key, as they appear in a certificate.
#[must_use]
pub fn cert_key(key: &PublicKey) -> CertKey {
    CertKey::from_bytes(key.to_bytes())
}

/// The signed message: `CTX || TBS` (PROTOCOL §15.2).
fn signed_message(tbs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CERT_SIGNATURE_CONTEXT.len().saturating_add(tbs.len()));
    message.extend_from_slice(CERT_SIGNATURE_CONTEXT);
    message.extend_from_slice(tbs);
    message
}

/// Signs `body`.
///
/// # Errors
/// If `body.ca_key()` is not the public key of `ca`.
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

/// Steps 3–6 of PROTOCOL §15.4, in order: format, binding to `peer` (before the signature),
/// CA pinned byte for byte, strict signature. The rest is decided by the domain.
///
/// # Errors
/// The first check that fails.
pub fn verify_certificate(
    bytes: &[u8],
    peer: &Fingerprint,
    trust: &CertTrust,
) -> Result<CertClaims, CertRejection> {
    // Step 3: length (first of all) and format, rules 1–7.
    let parsed = decode_certificate(bytes).map_err(|_| CertRejection::Malformed)?;
    // Step 4: `subject_key` canonical and not weak, and bound to the key that Noise has
    // authenticated. It comes before the signature: a stolen certificate does not cost a
    // verification.
    let subject = PublicKey::from_canonical_bytes(parsed.body.subject_key().as_bytes())
        .map_err(|_| CertRejection::KeyMismatch)?;
    let subject_fp = subject.fingerprint();
    // `Fingerprint::eq` is constant-time (`subtle`).
    if subject_fp != *peer {
        return Err(CertRejection::KeyMismatch);
    }
    // Step 5: `ca_key` equal byte for byte to a pinned key. Verification uses the pin, never
    // the key written in the certificate.
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
    // Step 6: strict signature (canonical `S`, `R` and key not of small order).
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

/// The line of a certificate file: [`CERT_FILE_PREFIX`] + hex + newline.
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

/// The bytes of a certificate file. Does not check the certificate format.
///
/// Only one form is accepted: the prefix, lowercase hex, at most one trailing newline.
///
/// # Errors
/// [`CertFormatError::Magic`] without the prefix, with spaces, multiple lines or invalid hex;
/// [`CertFormatError::Length`] over `MAX_CERT_LEN` bytes.
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
