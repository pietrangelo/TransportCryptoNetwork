//! Signing and verification of client certificates (PROTOCOL §15.2, §15.4 steps 3–6), in both
//! versions: v1 signed with Ed25519, v2 (PQ-AUTH, §15.14) with the composite ML-DSA-65 **and**
//! Ed25519 signature.

use core::fmt;
use core::str::FromStr;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zt_domain::cert::{
    CERT_SIG_MLDSA65_ED25519, CERT_SIGNATURE_CONTEXT, CERT_SIGNATURE_LEN, CERT_V2_MLDSA_CONTEXT,
    CERT_V2_SIGNATURE_CONTEXT, CERT_VERSION, CERT_VERSION_2,
};
use zt_domain::limits::{MAX_CERT_LEN, MAX_CERT_V2_LEN};
use zt_domain::trust::{CertTrust, CompositeCaPin, TrustedCaKey};
use zt_domain::{
    AnyParsedCert, CaFingerprint, CaKeyRef, CertBody, CertBodyV2, CertClaims, CertFormatError,
    CertKey, CertRejection, Fingerprint, HybridFingerprint, ParsedCert, ParsedCertV2,
    decode_any_certificate,
};

use crate::error::CryptoError;
use crate::identity::PublicKey;
use crate::mldsa::{self, MlDsa65SigningKey};

/// Line prefix of a v1 certificate file.
pub const CERT_FILE_PREFIX: &str = "tcn-client-cert-v1:";

/// Line prefix of a v2 certificate file. The prefix must agree with the version byte inside.
pub const CERT_FILE_PREFIX_V2: &str = "tcn-client-cert-v2:";

/// Domain separation of the composite CA fingerprint (`ca_fp`, PROTOCOL §15.14).
const CA_FINGERPRINT_DOMAIN: &[u8] = b"TCN CA fingerprint v2\0";

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
        composite: None,
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

/// Steps 3–6 of PROTOCOL §15.4 for a handshake that authenticated only the X25519-level
/// identity `peer` (a classical or `IKhfs` suite): see [`verify_certificate_hybrid`].
///
/// # Errors
/// The first check that fails.
pub fn verify_certificate(
    bytes: &[u8],
    peer: &Fingerprint,
    trust: &CertTrust,
) -> Result<CertClaims, CertRejection> {
    verify_certificate_hybrid(bytes, peer, None, trust)
}

/// Steps 3–6 of PROTOCOL §15.4, in order: format, binding to the authenticated identity
/// (before any signature), CA pinned with its algorithm, signatures. `hybrid` is the hybrid
/// fingerprint the handshake authenticated (suite `IKhfs+psk0+psk2`, PROTOCOL §7.5.3), if any.
///
/// - v1: `subject_key` canonical and of `peer`, CA pinned byte for byte as an Ed25519 key,
///   strict Ed25519.
/// - v2: `subject_fp` equal to `peer` and, for `subject_kind = 0x02`, `subject_fp_v2` equal to
///   `hybrid` (a hybrid-bound certificate never passes a classical handshake); CA pinned as a
///   composite key by `ca_fp`; **Ed25519 first**, then ML-DSA-65, both mandatory (finding
///   AP-5: before a quantum computer exists, only a holder of a valid CA-signed TBS for its own
///   authenticated key reaches the ML-DSA decoder).
///
/// # Errors
/// The first check that fails.
pub fn verify_certificate_hybrid(
    bytes: &[u8],
    peer: &Fingerprint,
    hybrid: Option<&HybridFingerprint>,
    trust: &CertTrust,
) -> Result<CertClaims, CertRejection> {
    // Step 3: length (first of all, per version) and format.
    match decode_any_certificate(bytes).map_err(|_| CertRejection::Malformed)? {
        AnyParsedCert::V1(parsed) => verify_v1(parsed, peer, trust),
        AnyParsedCert::V2(parsed) => verify_v2(parsed, peer, hybrid, trust),
    }
}

fn verify_v1(
    parsed: ParsedCert<'_>,
    peer: &Fingerprint,
    trust: &CertTrust,
) -> Result<CertClaims, CertRejection> {
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
    // Step 5: `ca_key` equal byte for byte to a pinned **Ed25519** key. Verification uses the
    // pin, never the key written in the certificate.
    let reference = CaKeyRef::Ed25519(*parsed.body.ca_key());
    let pin = trust
        .authority_for(&reference)
        .and_then(|authority| authority.pin_for(&reference))
        .ok_or(CertRejection::UnknownAuthority)?;
    let ca = PublicKey::from_canonical_bytes(pin.key.as_bytes())
        .map_err(|_| CertRejection::UnknownAuthority)?;
    // Step 6: strict signature (canonical `S`, `R` and key not of small order).
    let signature = Signature::from_bytes(parsed.signature);
    ca.verifying_key()
        .verify_strict(&signed_message(parsed.tbs), &signature)
        .map_err(|_| CertRejection::BadSignature)?;
    Ok(CertClaims::from_verified(
        parsed.body,
        pin.fingerprint,
        subject_fp,
    ))
}

fn verify_v2(
    parsed: ParsedCertV2<'_>,
    peer: &Fingerprint,
    hybrid: Option<&HybridFingerprint>,
    trust: &CertTrust,
) -> Result<CertClaims, CertRejection> {
    let subject = parsed.body.subject();
    // Step 4, before any signature: both comparisons are constant-time (`subtle`). A hybrid
    // subject needs a hybrid handshake with this very ML-KEM key: no downgrade.
    if subject.classical() != peer {
        return Err(CertRejection::KeyMismatch);
    }
    if let Some(bound) = subject.hybrid()
        && hybrid != Some(bound)
    {
        return Err(CertRejection::KeyMismatch);
    }
    // Step 5: a pinned **composite** key with this `ca_fp`: the pin, not the certificate,
    // decides the algorithm (finding AP-13).
    let reference = CaKeyRef::Composite(*parsed.body.ca_fp());
    let pin = trust
        .authority_for(&reference)
        .and_then(|authority| authority.pin_for(&reference))
        .ok_or(CertRejection::UnknownAuthority)?;
    let composite = pin
        .composite
        .as_ref()
        .ok_or(CertRejection::UnknownAuthority)?;
    // A CA does not certify itself (rule 3 of v1, here against the pin).
    if pin.fingerprint == *peer {
        return Err(CertRejection::KeyMismatch);
    }
    let ca = PublicKey::from_canonical_bytes(pin.key.as_bytes())
        .map_err(|_| CertRejection::UnknownAuthority)?;
    // Step 6a then 6b.
    verify_composite(
        &ca,
        composite,
        &signed_message_v2(parsed.tbs),
        parsed.mldsa_signature,
        parsed.ed25519_signature,
    )?;
    Ok(CertClaims::from_verified_v2(parsed.body, pin.fingerprint))
}

/// The composite verification of PROTOCOL §15.14, shared by the fleet and by `zt-ca`'s
/// verify-after-sign: Ed25519 `verify_strict` first, then ML-DSA-65 with the `TCN-cert-v2`
/// context. Both must pass.
fn verify_composite(
    ed25519: &PublicKey,
    composite: &CompositeCaPin,
    message: &[u8],
    mldsa_signature: &[u8],
    ed25519_signature: &[u8; CERT_SIGNATURE_LEN],
) -> Result<(), CertRejection> {
    let signature = Signature::from_bytes(ed25519_signature);
    ed25519
        .verifying_key()
        .verify_strict(message, &signature)
        .map_err(|_| CertRejection::BadSignature)?;
    if !mldsa::verify(
        composite.mldsa_key(),
        message,
        CERT_V2_MLDSA_CONTEXT,
        mldsa_signature,
    ) {
        return Err(CertRejection::BadSignature);
    }
    Ok(())
}

/// The signed message of a certificate v2: `CTX2 ‖ TBS` (both components sign it).
fn signed_message_v2(tbs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CERT_V2_SIGNATURE_CONTEXT.len().saturating_add(tbs.len()));
    message.extend_from_slice(CERT_V2_SIGNATURE_CONTEXT);
    message.extend_from_slice(tbs);
    message
}

/// Secret key of a composite (v2) CA: an Ed25519 key and an ML-DSA-65 key, from two
/// independent 32-byte seeds (the components are never derived from each other, and the
/// Ed25519 seed is never the one of a v1 CA key: `zt-ca keygen --v2` draws both fresh). No
/// `Clone`, zeroized on drop, redacted `Debug`.
pub struct CompositeCaSigningKey {
    ed25519: SigningKey,
    mldsa_seed: Zeroizing<[u8; mldsa::SEED_LEN]>,
    mldsa: MlDsa65SigningKey,
}

impl CompositeCaSigningKey {
    /// File prefix of the composite CA secret key: v1 loaders refuse it, and this loader
    /// refuses a v1 key.
    pub const FILE_PREFIX: &'static str = "tcn-ca-secret-v2:";

    /// A new CA from the system CSPRNG.
    ///
    /// # Errors
    /// [`CryptoError::Random`] without randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seeds = Zeroizing::new([0_u8; 64]);
        getrandom::fill(seeds.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self::from_seeds(&seeds))
    }

    /// `ed25519_seed ‖ mldsa_seed`.
    fn from_seeds(seeds: &[u8; 64]) -> Self {
        let mut ed_seed = Zeroizing::new([0_u8; 32]);
        let mut mldsa_seed = Zeroizing::new([0_u8; mldsa::SEED_LEN]);
        let (ed, ml) = seeds.split_at(32);
        ed_seed.copy_from_slice(ed);
        mldsa_seed.copy_from_slice(ml);
        let mldsa = MlDsa65SigningKey::from_seed(&mldsa_seed);
        Self {
            ed25519: SigningKey::from_bytes(&ed_seed),
            mldsa_seed,
            mldsa,
        }
    }

    /// From the file text (`tcn-ca-secret-v2:<128 lowercase hex>`, optional trailing newline).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] without the prefix or with invalid hex.
    pub fn from_secret_text(text: &str) -> Result<Self, CryptoError> {
        let line = text.strip_suffix('\n').unwrap_or(text);
        let hex_part = line
            .strip_prefix(Self::FILE_PREFIX)
            .ok_or(CryptoError::InvalidKey)?;
        if hex_part.len() != 128
            || !hex_part
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(CryptoError::InvalidKey);
        }
        let mut seeds = Zeroizing::new([0_u8; 64]);
        hex::decode_to_slice(hex_part, seeds.as_mut()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::from_seeds(&seeds))
    }

    /// The file text, to be written with `0600` permissions.
    #[must_use]
    pub fn to_secret_text(&self) -> Zeroizing<String> {
        let mut seeds = Zeroizing::new([0_u8; 64]);
        let (ed, ml) = seeds.split_at_mut(32);
        ed.copy_from_slice(self.ed25519.as_bytes());
        ml.copy_from_slice(self.mldsa_seed.as_ref());
        let hex_part = Zeroizing::new(hex::encode(seeds.as_ref()));
        let mut text = Zeroizing::new(String::with_capacity(
            Self::FILE_PREFIX.len().saturating_add(129),
        ));
        text.push_str(Self::FILE_PREFIX);
        text.push_str(&hex_part);
        text.push('\n');
        text
    }

    /// The public key of the CA.
    #[must_use]
    pub fn public_key(&self) -> CompositeCaPublicKey {
        CompositeCaPublicKey {
            ed25519: PublicKey::from_verifying_key(self.ed25519.verifying_key()),
            mldsa: Arc::from(self.mldsa.public_key()),
        }
    }
}

impl fmt::Debug for CompositeCaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompositeCaSigningKey(<redacted>)")
    }
}

/// Public key of a composite (v2) CA: `tcn-ca-pub-v2:` + hex(ed25519 ‖ mldsa65), 3 968 hex
/// characters. It is what `[[authorities]]` pins.
#[derive(Clone, PartialEq, Eq)]
pub struct CompositeCaPublicKey {
    ed25519: PublicKey,
    mldsa: Arc<[u8]>,
}

impl CompositeCaPublicKey {
    /// Text prefix: never a valid v1 key (which is bare hex).
    pub const PREFIX: &'static str = "tcn-ca-pub-v2:";
    /// Hex characters after the prefix.
    pub const HEX_LEN: usize = (32 + mldsa::PUBLIC_KEY_LEN) * 2;

    /// The Ed25519 component.
    #[must_use]
    pub const fn ed25519(&self) -> &PublicKey {
        &self.ed25519
    }

    /// The ML-DSA-65 component (1 952 bytes).
    #[must_use]
    pub fn mldsa(&self) -> &[u8] {
        &self.mldsa
    }

    /// The X25519-form fingerprint of the Ed25519 component: the CA's name in the audit logs
    /// and the unit of the conflict checks with peer keys.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.ed25519.fingerprint()
    }

    /// `ca_fp = SHA-256("TCN CA fingerprint v2\0" ‖ sig_alg ‖ ed25519 ‖ mldsa65)`: it covers
    /// the algorithm (finding AP-13).
    #[must_use]
    pub fn ca_fp(&self) -> CaFingerprint {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(CA_FINGERPRINT_DOMAIN)
            .chain_update([CERT_SIG_MLDSA65_ED25519])
            .chain_update(self.ed25519.to_bytes())
            .chain_update(&self.mldsa)
            .finalize()
            .into();
        CaFingerprint::from_bytes(digest)
    }
}

impl FromStr for CompositeCaPublicKey {
    type Err = CryptoError;

    /// Exactly the prefix and 3 968 lowercase hex characters; the Ed25519 component must be a
    /// canonical point not of small order (PROTOCOL §15.1 rule 8).
    fn from_str(text: &str) -> Result<Self, CryptoError> {
        let hex_part = text
            .strip_prefix(Self::PREFIX)
            .ok_or(CryptoError::InvalidKey)?;
        if hex_part.len() != Self::HEX_LEN
            || !hex_part
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(CryptoError::InvalidKey);
        }
        let bytes = hex::decode(hex_part).map_err(|_| CryptoError::InvalidKey)?;
        let (ed, ml) = bytes.split_at(32);
        let ed: [u8; 32] = ed.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            ed25519: PublicKey::from_canonical_bytes(&ed)?,
            mldsa: Arc::from(ml),
        })
    }
}

impl fmt::Display for CompositeCaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::PREFIX)?;
        f.write_str(&hex::encode(self.ed25519.to_bytes()))?;
        f.write_str(&hex::encode(&self.mldsa))
    }
}

impl fmt::Debug for CompositeCaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompositeCaPublicKey({})", self.ca_fp())
    }
}

/// The pinned key for a composite (v2) CA.
///
/// # Errors
/// [`CryptoError::InvalidKey`] if the ML-DSA component has the wrong length (impossible for a
/// parsed key).
pub fn trusted_composite_ca_key(key: &CompositeCaPublicKey) -> Result<TrustedCaKey, CryptoError> {
    let composite =
        CompositeCaPin::new(key.ca_fp(), key.mldsa()).map_err(|_| CryptoError::InvalidKey)?;
    Ok(TrustedCaKey {
        key: cert_key(key.ed25519()),
        fingerprint: key.fingerprint(),
        composite: Some(composite),
    })
}

/// Signs a certificate v2 with both components (hedged ML-DSA: `rnd` from the system CSPRNG),
/// then **verifies it** with the fleet's verifier before returning it (finding AP-5): a
/// certificate this exact `ml-dsa` version would reject never leaves the CA.
///
/// # Errors
/// [`CryptoError::InvalidKey`] if `body.ca_fp()` is not this CA's, [`CryptoError::Random`]
/// without randomness, [`CryptoError::VerifyAfterSign`] if the fresh certificate does not
/// verify.
pub fn sign_certificate_v2(
    ca: &CompositeCaSigningKey,
    body: &CertBodyV2,
) -> Result<Vec<u8>, CryptoError> {
    let public = ca.public_key();
    if *body.ca_fp() != public.ca_fp() {
        return Err(CryptoError::InvalidKey);
    }
    let tbs = body.encode_tbs();
    let message = signed_message_v2(&tbs);
    let mut rnd = Zeroizing::new([0_u8; mldsa::RANDOMNESS_LEN]);
    getrandom::fill(rnd.as_mut()).map_err(|_| CryptoError::Random)?;
    let sig_m = ca.mldsa.sign(&message, CERT_V2_MLDSA_CONTEXT, &rnd)?;
    let sig_e = ca
        .ed25519
        .try_sign(&message)
        .map_err(|_| CryptoError::InvalidKey)?
        .to_bytes();
    // Verify-after-sign, with the same composite check as the fleet.
    let pin = trusted_composite_ca_key(&public)?;
    let composite = pin.composite.as_ref().ok_or(CryptoError::InvalidKey)?;
    verify_composite(public.ed25519(), composite, &message, &sig_m, &sig_e)
        .map_err(|_| CryptoError::VerifyAfterSign)?;
    let mut cert = tbs;
    cert.extend_from_slice(&sig_m);
    cert.extend_from_slice(&sig_e);
    // And the whole certificate through the fleet's decoder.
    match decode_any_certificate(&cert) {
        Ok(AnyParsedCert::V2(parsed)) if parsed.body == *body => Ok(cert),
        _ => Err(CryptoError::VerifyAfterSign),
    }
}

/// The line of a certificate file: the prefix of its version ([`CERT_FILE_PREFIX`] or
/// [`CERT_FILE_PREFIX_V2`]) + hex + newline.
#[must_use]
pub fn encode_certificate_text(bytes: &[u8]) -> String {
    let prefix = if bytes.get(4) == Some(&CERT_VERSION_2) {
        CERT_FILE_PREFIX_V2
    } else {
        CERT_FILE_PREFIX
    };
    let mut text = String::with_capacity(
        prefix
            .len()
            .saturating_add(bytes.len().saturating_mul(2))
            .saturating_add(1),
    );
    text.push_str(prefix);
    text.push_str(&hex::encode(bytes));
    text.push('\n');
    text
}

/// The bytes of a certificate file. Does not check the certificate format beyond the version
/// byte, which must be that of the prefix (a v2 certificate under the v1 prefix, or the
/// reverse, is refused).
///
/// Only one form is accepted: the prefix, lowercase hex, at most one trailing newline.
///
/// # Errors
/// [`CertFormatError::Magic`] without a known prefix, with spaces, multiple lines, invalid hex
/// or a version byte of the other prefix; [`CertFormatError::Length`] over the maximum of the
/// prefix's version.
pub fn decode_certificate_text(text: &str) -> Result<Vec<u8>, CertFormatError> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let (hex_part, version, max) = if let Some(rest) = line.strip_prefix(CERT_FILE_PREFIX) {
        (rest, CERT_VERSION, MAX_CERT_LEN)
    } else if let Some(rest) = line.strip_prefix(CERT_FILE_PREFIX_V2) {
        (rest, CERT_VERSION_2, MAX_CERT_V2_LEN)
    } else {
        return Err(CertFormatError::Magic);
    };
    if hex_part.is_empty()
        || !hex_part.len().is_multiple_of(2)
        || !hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CertFormatError::Magic);
    }
    let len = hex_part.len() / 2;
    if len > max {
        return Err(CertFormatError::Length { len });
    }
    let bytes = hex::decode(hex_part).map_err(|_| CertFormatError::Magic)?;
    // The version byte (offset 4) must be the prefix's, when present.
    if bytes.get(4).is_some_and(|v| *v != version) {
        return Err(CertFormatError::Magic);
    }
    Ok(bytes)
}
