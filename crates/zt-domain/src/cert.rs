//! Short-lived client certificates signed by an offline CA (PROTOCOL §15).
//!
//! The domain knows only the **syntax** of the format (rules 1–7 of §15.1) and the data of an
//! already-verified certificate ([`CertClaims`]). Signature, point canonicity and binding to the
//! Noise key live in `zt-crypto`.
//!

use core::fmt;
use std::collections::BTreeSet;

use thiserror::Error;

use crate::crypto::{Fingerprint, HybridFingerprint};
use crate::error::DomainError;
use crate::ids::NodeId;
use crate::limits::{
    MAX_CERT_LEN, MAX_CERT_LIFETIME_SECS, MAX_CERT_NODES, MAX_CERT_V2_LEN, MAX_NODE_ID_LEN,
    MIN_CERT_LEN, MIN_CERT_V2_LEN,
};

/// The first 4 bytes of every certificate.
pub const CERT_MAGIC: [u8; 4] = *b"TCNC";
/// The only version of the format.
pub const CERT_VERSION: u8 = 0x01;
/// The only signature algorithm: pure Ed25519 (RFC 8032).
pub const CERT_SIG_ED25519: u8 = 0x01;
/// Length of the signature at the end of the certificate.
pub const CERT_SIGNATURE_LEN: usize = 64;
/// Context string prepended to the TBS before signing (PROTOCOL §15.2).
pub const CERT_SIGNATURE_CONTEXT: &[u8] = b"TCN client certificate v1\0";

/// Version byte of certificate v2 (PQ-AUTH, PROTOCOL §15.14).
pub const CERT_VERSION_2: u8 = 0x02;
/// The composite signature of certificate v2: ML-DSA-65 **and** Ed25519, both must verify.
/// Codes 0x03 (ML-DSA-87 + Ed25519) and 0x04 (SLH-DSA-SHA2-128s + Ed25519) are reserved and
/// refused.
pub const CERT_SIG_MLDSA65_ED25519: u8 = 0x02;
/// Context prepended to the TBS of a certificate v2 for both signatures: `M' = CTX2 ‖ TBS`.
/// It differs from the v1 context, so neither component verifies as a v1 certificate.
pub const CERT_V2_SIGNATURE_CONTEXT: &[u8] = b"TCN client certificate v2\0";
/// The FIPS 204 `ctx` string of the ML-DSA component: separates TCN certificates from any
/// other use of the CA's ML-DSA key.
pub const CERT_V2_MLDSA_CONTEXT: &[u8] = b"TCN-cert-v2";
/// Length of an ML-DSA-65 public key (FIPS 204).
pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1_952;
/// Length of an ML-DSA-65 signature (FIPS 204).
pub const MLDSA65_SIGNATURE_LEN: usize = 3_309;
/// Length of the composite signature: `sig_M (3 309) ‖ sig_E (64)`.
pub const CERT_V2_SIGNATURE_LEN: usize = MLDSA65_SIGNATURE_LEN + CERT_SIGNATURE_LEN;
/// `subject_kind` of a classical subject: `subject_fp` only.
pub const SUBJECT_KIND_CLASSICAL: u8 = 0x01;
/// `subject_kind` of a hybrid subject: `subject_fp` and `subject_fp_v2`.
pub const SUBJECT_KIND_HYBRID: u8 = 0x02;

/// An instant in Unix seconds (UTC). The domain has no clock: time comes in as a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The instant `secs` seconds after 1970.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// The seconds since 1970.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// `self + secs`, or `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, secs: u64) -> Option<Self> {
        match self.0.checked_add(secs) {
            Some(t) => Some(Self(t)),
            None => None,
        }
    }

    /// `self - secs`, or `None` before 1970.
    #[must_use]
    pub const fn checked_sub(self, secs: u64) -> Option<Self> {
        match self.0.checked_sub(secs) {
            Some(t) => Some(Self(t)),
            None => None,
        }
    }

    /// `self + secs`, saturating at `u64::MAX`.
    #[must_use]
    pub const fn saturating_add(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// `self - secs`, saturating at 0.
    #[must_use]
    pub const fn saturating_sub(self, secs: u64) -> Self {
        Self(self.0.saturating_sub(secs))
    }
}

/// Serial number of a certificate: 128 random bits, never all zero. It is the identity of the
/// certificate (PROTOCOL §15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertSerial([u8; Self::LEN]);

impl CertSerial {
    /// Length in bytes.
    pub const LEN: usize = 16;

    /// The serial number bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<[u8; 16]> for CertSerial {
    type Error = CertFormatError;

    /// # Errors
    /// [`CertFormatError::SerialZero`] for the all-zero value.
    fn try_from(bytes: [u8; 16]) -> Result<Self, Self::Error> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(CertFormatError::SerialZero);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for CertSerial {
    /// 32 lowercase hex characters, as in the denylist.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// 32 bytes of an Ed25519 public key as they appear in the certificate, **not** yet
/// validated as a curve point (`zt-crypto` does that). Comparison is byte by byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertKey([u8; Self::LEN]);

impl CertKey {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Takes 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Scope of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertScope {
    /// `scope = 0x01`: all nodes granted to the CA (`allow`).
    All,
    /// `scope = 0x00`: these nodes, from 1 to [`crate::limits::MAX_CERT_NODES`].
    Only(BTreeSet<NodeId>),
}

/// The signed content of a certificate. An existing `CertBody` satisfies rules 1–7 of
/// PROTOCOL §15.1, so its encoding is infallible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertBody {
    ca_key: CertKey,
    subject_key: CertKey,
    serial: CertSerial,
    not_before: UnixTime,
    not_after: UnixTime,
    name: NodeId,
    scope: CertScope,
}

impl CertBody {
    /// Builds a valid body.
    ///
    /// # Errors
    /// One of rules 3–6 of PROTOCOL §15.1 is not satisfied.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ca_key: CertKey,
        subject_key: CertKey,
        serial: CertSerial,
        not_before: UnixTime,
        not_after: UnixTime,
        name: NodeId,
        scope: CertScope,
    ) -> Result<Self, CertFormatError> {
        if ca_key == subject_key {
            return Err(CertFormatError::SelfCertified);
        }
        check_validity(not_before, not_after)?;
        if let CertScope::Only(nodes) = &scope
            && (nodes.is_empty() || nodes.len() > MAX_CERT_NODES)
        {
            return Err(CertFormatError::NodeCount(
                u8::try_from(nodes.len()).unwrap_or(u8::MAX),
            ));
        }
        Ok(Self {
            ca_key,
            subject_key,
            serial,
            not_before,
            not_after,
            name,
            scope,
        })
    }

    /// Bytes `[0, L-64)` of the certificate (TBS, PROTOCOL §15.1).
    #[must_use]
    pub fn encode_tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_CERT_LEN);
        out.extend_from_slice(&CERT_MAGIC);
        out.push(CERT_VERSION);
        out.push(CERT_SIG_ED25519);
        out.extend_from_slice(self.ca_key.as_bytes());
        out.extend_from_slice(self.subject_key.as_bytes());
        out.extend_from_slice(self.serial.as_bytes());
        out.extend_from_slice(&self.not_before.as_secs().to_be_bytes());
        out.extend_from_slice(&self.not_after.as_secs().to_be_bytes());
        push_scope(&mut out, &self.name, &self.scope);
        out
    }

    /// Key of the signing CA (not yet compared against the pins).
    #[must_use]
    pub const fn ca_key(&self) -> &CertKey {
        &self.ca_key
    }

    /// Key of the client.
    #[must_use]
    pub const fn subject_key(&self) -> &CertKey {
        &self.subject_key
    }

    /// Serial number.
    #[must_use]
    pub const fn serial(&self) -> CertSerial {
        self.serial
    }

    /// Start of validity.
    #[must_use]
    pub const fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// End of validity (exclusive).
    #[must_use]
    pub const fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// Name of the client, for the audit logs only.
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// Scope.
    #[must_use]
    pub const fn scope(&self) -> &CertScope {
        &self.scope
    }

    /// `not_after - not_before` in seconds.
    #[must_use]
    pub const fn lifetime_secs(&self) -> u64 {
        self.not_after
            .as_secs()
            .saturating_sub(self.not_before.as_secs())
    }
}

/// A decoded certificate: body, signed bytes and signature (not yet verified).
#[derive(Debug)]
pub struct ParsedCert<'a> {
    /// The body.
    pub body: CertBody,
    /// Bytes `[0, L-64)`.
    pub tbs: &'a [u8],
    /// The last 64 bytes.
    pub signature: &'a [u8; CERT_SIGNATURE_LEN],
}

/// Decodes a certificate according to rules 1–7 of PROTOCOL §15.1. Does not verify the
/// signature.
///
/// # Errors
/// The first rule violated. Errors report only metadata, never certificate bytes.
pub fn decode_certificate(bytes: &[u8]) -> Result<ParsedCert<'_>, CertFormatError> {
    // Rule 1: the length before any field.
    let len = bytes.len();
    if !(MIN_CERT_LEN..=MAX_CERT_LEN).contains(&len) {
        return Err(CertFormatError::Length { len });
    }
    let mut r = Reader { bytes, pos: 0 };
    // Rule 2.
    if r.array::<4>()? != CERT_MAGIC {
        return Err(CertFormatError::Magic);
    }
    let version = r.byte()?;
    if version != CERT_VERSION {
        return Err(CertFormatError::Version(version));
    }
    let sig_alg = r.byte()?;
    if sig_alg != CERT_SIG_ED25519 {
        return Err(CertFormatError::Algorithm(sig_alg));
    }
    // Rule 3.
    let ca_key = CertKey::from_bytes(r.array::<32>()?);
    let subject_key = CertKey::from_bytes(r.array::<32>()?);
    let serial = CertSerial::try_from(r.array::<16>()?)?;
    if ca_key == subject_key {
        return Err(CertFormatError::SelfCertified);
    }
    let common = r.common_tail()?;
    // Rule 7: exactly 64 bytes of signature.
    let (tbs, sig) = r.split_signature(CERT_SIGNATURE_LEN)?;
    let signature: &[u8; CERT_SIGNATURE_LEN] = sig
        .try_into()
        .map_err(|_| CertFormatError::Truncated { at: tbs.len() })?;
    Ok(ParsedCert {
        body: CertBody {
            ca_key,
            subject_key,
            serial,
            not_before: common.not_before,
            not_after: common.not_after,
            name: common.name,
            scope: common.scope,
        },
        tbs,
        signature,
    })
}

/// The fields after the key fields, identical in v1 and v2 (rules 4–6 of PROTOCOL §15.1).
struct CommonTail {
    not_before: UnixTime,
    not_after: UnixTime,
    name: NodeId,
    scope: CertScope,
}

/// The fingerprint of a certificate v2's CA: `SHA-256("TCN CA fingerprint v2\0" ‖ sig_alg ‖
/// ed25519_pk ‖ mldsa65_pk)`, computed in the crypto adapter. It includes the algorithm
/// (finding AP-13), so the pinned key, never the certificate, decides which algorithm
/// verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaFingerprint([u8; Self::LEN]);

impl CaFingerprint {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Takes 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for CaFingerprint {
    /// `TCNCA2:` + hex: never confused with a node fingerprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TCNCA2:")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// The subject of a certificate v2 (`subject_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertSubject {
    /// `subject_kind = 0x01`: bound to the X25519-level fingerprint only.
    Classical(Fingerprint),
    /// `subject_kind = 0x02`: bound to the X25519-level fingerprint **and** to the hybrid
    /// fingerprint, so only a hybrid handshake with this very ML-KEM key can present it. The
    /// X25519-level fingerprint is carried too (finding AP-6): it is the revocation unit.
    Hybrid {
        /// The X25519-level fingerprint (`subject_fp`).
        classical: Fingerprint,
        /// The hybrid fingerprint (`subject_fp_v2`).
        hybrid: HybridFingerprint,
    },
}

impl CertSubject {
    /// The X25519-level fingerprint, present in both kinds.
    #[must_use]
    pub const fn classical(&self) -> &Fingerprint {
        match self {
            Self::Classical(fp) | Self::Hybrid { classical: fp, .. } => fp,
        }
    }

    /// The hybrid fingerprint of a `subject_kind = 0x02` certificate.
    #[must_use]
    pub const fn hybrid(&self) -> Option<&HybridFingerprint> {
        match self {
            Self::Classical(_) => None,
            Self::Hybrid { hybrid, .. } => Some(hybrid),
        }
    }

    const fn kind(&self) -> u8 {
        match self {
            Self::Classical(_) => SUBJECT_KIND_CLASSICAL,
            Self::Hybrid { .. } => SUBJECT_KIND_HYBRID,
        }
    }
}

/// The signed content of a certificate v2 (PROTOCOL §15.14). An existing `CertBodyV2` satisfies
/// the format rules, so its encoding is infallible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertBodyV2 {
    ca_fp: CaFingerprint,
    subject: CertSubject,
    serial: CertSerial,
    not_before: UnixTime,
    not_after: UnixTime,
    name: NodeId,
    scope: CertScope,
}

impl CertBodyV2 {
    /// Builds a valid body.
    ///
    /// # Errors
    /// Rules 4–6 of PROTOCOL §15.1 (validity, lifetime, node count).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ca_fp: CaFingerprint,
        subject: CertSubject,
        serial: CertSerial,
        not_before: UnixTime,
        not_after: UnixTime,
        name: NodeId,
        scope: CertScope,
    ) -> Result<Self, CertFormatError> {
        check_validity(not_before, not_after)?;
        if let CertScope::Only(nodes) = &scope
            && (nodes.is_empty() || nodes.len() > MAX_CERT_NODES)
        {
            return Err(CertFormatError::NodeCount(
                u8::try_from(nodes.len()).unwrap_or(u8::MAX),
            ));
        }
        Ok(Self {
            ca_fp,
            subject,
            serial,
            not_before,
            not_after,
            name,
            scope,
        })
    }

    /// Bytes `[0, L-3373)` of the certificate (TBS, PROTOCOL §15.14).
    #[must_use]
    pub fn encode_tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_CERT_V2_LEN);
        out.extend_from_slice(&CERT_MAGIC);
        out.push(CERT_VERSION_2);
        out.push(CERT_SIG_MLDSA65_ED25519);
        out.extend_from_slice(self.ca_fp.as_bytes());
        out.push(self.subject.kind());
        out.extend_from_slice(self.subject.classical().as_bytes());
        if let Some(hybrid) = self.subject.hybrid() {
            out.extend_from_slice(hybrid.as_bytes());
        }
        out.extend_from_slice(self.serial.as_bytes());
        out.extend_from_slice(&self.not_before.as_secs().to_be_bytes());
        out.extend_from_slice(&self.not_after.as_secs().to_be_bytes());
        push_scope(&mut out, &self.name, &self.scope);
        out
    }

    /// Fingerprint of the signing CA (not yet compared against the pins).
    #[must_use]
    pub const fn ca_fp(&self) -> &CaFingerprint {
        &self.ca_fp
    }

    /// The subject.
    #[must_use]
    pub const fn subject(&self) -> &CertSubject {
        &self.subject
    }

    /// Serial number.
    #[must_use]
    pub const fn serial(&self) -> CertSerial {
        self.serial
    }

    /// Start of validity.
    #[must_use]
    pub const fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// End of validity (exclusive).
    #[must_use]
    pub const fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// Name of the client, for the audit logs only.
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// Scope.
    #[must_use]
    pub const fn scope(&self) -> &CertScope {
        &self.scope
    }

    /// `not_after - not_before` in seconds.
    #[must_use]
    pub const fn lifetime_secs(&self) -> u64 {
        self.not_after
            .as_secs()
            .saturating_sub(self.not_before.as_secs())
    }
}

/// A decoded certificate v2: body, signed bytes and both signature components (not yet
/// verified).
#[derive(Debug)]
pub struct ParsedCertV2<'a> {
    /// The body.
    pub body: CertBodyV2,
    /// Bytes `[0, L-3373)`.
    pub tbs: &'a [u8],
    /// `sig_M`: the ML-DSA-65 component.
    pub mldsa_signature: &'a [u8; MLDSA65_SIGNATURE_LEN],
    /// `sig_E`: the Ed25519 component, the last 64 bytes.
    pub ed25519_signature: &'a [u8; CERT_SIGNATURE_LEN],
}

/// A decoded certificate of either version.
#[derive(Debug)]
pub enum AnyParsedCert<'a> {
    /// Version 1, Ed25519.
    V1(ParsedCert<'a>),
    /// Version 2, composite ML-DSA-65 + Ed25519.
    V2(ParsedCertV2<'a>),
}

impl AnyParsedCert<'_> {
    /// The version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        match self {
            Self::V1(_) => CERT_VERSION,
            Self::V2(_) => CERT_VERSION_2,
        }
    }
}

impl AnyParsedCert<'_> {
    /// The decoded body, whatever the version.
    #[must_use]
    pub fn into_body(self) -> AnyCertBody {
        match self {
            Self::V1(parsed) => AnyCertBody::V1(parsed.body),
            Self::V2(parsed) => AnyCertBody::V2(parsed.body),
        }
    }
}

/// The body of a certificate of either version, with the fields both have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyCertBody {
    /// Version 1.
    V1(CertBody),
    /// Version 2.
    V2(CertBodyV2),
}

impl AnyCertBody {
    /// The version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        match self {
            Self::V1(_) => CERT_VERSION,
            Self::V2(_) => CERT_VERSION_2,
        }
    }

    /// Serial number.
    #[must_use]
    pub const fn serial(&self) -> CertSerial {
        match self {
            Self::V1(b) => b.serial(),
            Self::V2(b) => b.serial(),
        }
    }

    /// Name of the client.
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        match self {
            Self::V1(b) => b.name(),
            Self::V2(b) => b.name(),
        }
    }

    /// Scope.
    #[must_use]
    pub const fn scope(&self) -> &CertScope {
        match self {
            Self::V1(b) => b.scope(),
            Self::V2(b) => b.scope(),
        }
    }

    /// Start of validity.
    #[must_use]
    pub const fn not_before(&self) -> UnixTime {
        match self {
            Self::V1(b) => b.not_before(),
            Self::V2(b) => b.not_before(),
        }
    }

    /// End of validity (exclusive).
    #[must_use]
    pub const fn not_after(&self) -> UnixTime {
        match self {
            Self::V1(b) => b.not_after(),
            Self::V2(b) => b.not_after(),
        }
    }

    /// `not_after - not_before` in seconds.
    #[must_use]
    pub const fn lifetime_secs(&self) -> u64 {
        match self {
            Self::V1(b) => b.lifetime_secs(),
            Self::V2(b) => b.lifetime_secs(),
        }
    }
}

/// Decodes a certificate v2 (PROTOCOL §15.14). Does not verify the signatures.
///
/// # Errors
/// The first rule violated. Errors report only metadata, never certificate bytes.
pub fn decode_certificate_v2(bytes: &[u8]) -> Result<ParsedCertV2<'_>, CertFormatError> {
    // Rule 1: the bounds of (version 2, sig_alg 0x02), before any field.
    let len = bytes.len();
    if !(MIN_CERT_V2_LEN..=MAX_CERT_V2_LEN).contains(&len) {
        return Err(CertFormatError::Length { len });
    }
    let mut r = Reader { bytes, pos: 0 };
    if r.array::<4>()? != CERT_MAGIC {
        return Err(CertFormatError::Magic);
    }
    let version = r.byte()?;
    if version != CERT_VERSION_2 {
        return Err(CertFormatError::Version(version));
    }
    // The reserved codes (0x03, 0x04) are refused like any unknown one.
    let sig_alg = r.byte()?;
    if sig_alg != CERT_SIG_MLDSA65_ED25519 {
        return Err(CertFormatError::Algorithm(sig_alg));
    }
    let ca_fp = CaFingerprint::from_bytes(r.array::<32>()?);
    let kind = r.byte()?;
    let classical = Fingerprint::from_bytes(r.array::<32>()?);
    let subject = match kind {
        SUBJECT_KIND_CLASSICAL => CertSubject::Classical(classical),
        SUBJECT_KIND_HYBRID => CertSubject::Hybrid {
            classical,
            hybrid: HybridFingerprint::from_bytes(r.array::<32>()?),
        },
        other => return Err(CertFormatError::SubjectKind(other)),
    };
    let serial = CertSerial::try_from(r.array::<16>()?)?;
    let common = r.common_tail()?;
    // Exactly the composite signature, `sig_M ‖ sig_E`.
    let (tbs, sig) = r.split_signature(CERT_V2_SIGNATURE_LEN)?;
    let (sig_m, sig_e) = sig.split_at(MLDSA65_SIGNATURE_LEN);
    let at = tbs.len();
    let mldsa_signature: &[u8; MLDSA65_SIGNATURE_LEN] = sig_m
        .try_into()
        .map_err(|_| CertFormatError::Truncated { at })?;
    let ed25519_signature: &[u8; CERT_SIGNATURE_LEN] = sig_e
        .try_into()
        .map_err(|_| CertFormatError::Truncated { at })?;
    Ok(ParsedCertV2 {
        body: CertBodyV2 {
            ca_fp,
            subject,
            serial,
            not_before: common.not_before,
            not_after: common.not_after,
            name: common.name,
            scope: common.scope,
        },
        tbs,
        mldsa_signature,
        ed25519_signature,
    })
}

/// Decodes a certificate of either version: the version byte selects the decoder, whose own
/// length bounds apply before any other field (rule 1).
///
/// # Errors
/// The first rule violated.
pub fn decode_any_certificate(bytes: &[u8]) -> Result<AnyParsedCert<'_>, CertFormatError> {
    // Only the header is read before the per-version bounds: the shortest legitimate
    // certificate is far longer than it.
    let len = bytes.len();
    let (Some(magic), Some(&version)) = (bytes.get(..4), bytes.get(4)) else {
        return Err(CertFormatError::Length { len });
    };
    if magic != CERT_MAGIC {
        // Within the bounds of some version, a wrong magic is a wrong magic; outside, a length.
        return if (MIN_CERT_LEN..=MAX_CERT_V2_LEN).contains(&len) {
            Err(CertFormatError::Magic)
        } else {
            Err(CertFormatError::Length { len })
        };
    }
    match version {
        CERT_VERSION => decode_certificate(bytes).map(AnyParsedCert::V1),
        CERT_VERSION_2 => decode_certificate_v2(bytes).map(AnyParsedCert::V2),
        other if (MIN_CERT_LEN..=MAX_CERT_V2_LEN).contains(&len) => {
            Err(CertFormatError::Version(other))
        }
        _ => Err(CertFormatError::Length { len }),
    }
}

const SCOPE_LIST: u8 = 0x00;
const SCOPE_ALL: u8 = 0x01;

/// Rule 4 of PROTOCOL §15.1, with checked arithmetic.
fn check_validity(not_before: UnixTime, not_after: UnixTime) -> Result<(), CertFormatError> {
    let Some(secs) = not_after.as_secs().checked_sub(not_before.as_secs()) else {
        return Err(CertFormatError::Validity);
    };
    if secs == 0 {
        return Err(CertFormatError::Validity);
    }
    if secs > MAX_CERT_LIFETIME_SECS {
        return Err(CertFormatError::Lifetime { secs });
    }
    Ok(())
}

/// Writes the name, the scope and the nodes (rules 5–6 of PROTOCOL §15.1).
fn push_scope(out: &mut Vec<u8>, name: &NodeId, scope: &CertScope) {
    push_label(out, name);
    match scope {
        CertScope::All => {
            out.push(SCOPE_ALL);
            out.push(0);
        }
        CertScope::Only(nodes) => {
            out.push(SCOPE_LIST);
            // 1..=MAX_CERT_NODES by construction.
            out.push(u8::try_from(nodes.len()).unwrap_or(u8::MAX));
            // `BTreeSet` of `NodeId` (ASCII strings): the order is byte order.
            for node in nodes {
                push_label(out, node);
            }
        }
    }
}

/// Writes `len (u8) + bytes` of a `NodeId` (1..=63 bytes by construction).
fn push_label(out: &mut Vec<u8>, id: &NodeId) {
    out.push(u8::try_from(id.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(id.as_bytes());
}

/// Sequential reader with bounds checking: never an index outside the buffer.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Rules 4–6: validity, name, scope and nodes.
    fn common_tail(&mut self) -> Result<CommonTail, CertFormatError> {
        // Rule 4.
        let not_before = UnixTime::from_secs(u64::from_be_bytes(self.array::<8>()?));
        let not_after = UnixTime::from_secs(u64::from_be_bytes(self.array::<8>()?));
        check_validity(not_before, not_after)?;
        // Rule 5.
        let name = self.label()?;
        // Rule 6.
        let scope_code = self.byte()?;
        let node_count = self.byte()?;
        let scope = match scope_code {
            SCOPE_LIST => {
                if node_count == 0 || usize::from(node_count) > MAX_CERT_NODES {
                    return Err(CertFormatError::NodeCount(node_count));
                }
                let mut nodes = BTreeSet::new();
                let mut previous: Option<NodeId> = None;
                for index in 0..usize::from(node_count) {
                    let node = self.label()?;
                    if let Some(prev) = &previous
                        && node.as_bytes() <= prev.as_bytes()
                    {
                        return Err(CertFormatError::NodeOrder { index });
                    }
                    nodes.insert(node.clone());
                    previous = Some(node);
                }
                CertScope::Only(nodes)
            }
            SCOPE_ALL => {
                if node_count != 0 {
                    return Err(CertFormatError::NodeCount(node_count));
                }
                CertScope::All
            }
            other => return Err(CertFormatError::Scope(other)),
        };
        Ok(CommonTail {
            not_before,
            not_after,
            name,
            scope,
        })
    }

    /// Exactly `len` bytes of signature after the TBS: `(tbs, signature)`.
    fn split_signature(&self, len: usize) -> Result<(&'a [u8], &'a [u8]), CertFormatError> {
        let tbs_len = self.pos;
        let remaining = self.bytes.len().saturating_sub(tbs_len);
        if remaining < len {
            return Err(CertFormatError::Truncated { at: tbs_len });
        }
        if remaining > len {
            return Err(CertFormatError::Trailing {
                extra: remaining.saturating_sub(len),
            });
        }
        Ok(self.bytes.split_at(tbs_len))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CertFormatError> {
        let at = self.pos;
        let end = at.checked_add(n).ok_or(CertFormatError::Truncated { at })?;
        let slice = self
            .bytes
            .get(at..end)
            .ok_or(CertFormatError::Truncated { at })?;
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CertFormatError> {
        let at = self.pos;
        self.take(1)?
            .first()
            .copied()
            .ok_or(CertFormatError::Truncated { at })
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CertFormatError> {
        let at = self.pos;
        self.take(N)?
            .try_into()
            .map_err(|_| CertFormatError::Truncated { at })
    }

    /// `len (u8, 1..=63) + NodeId`. The length is checked before reading the bytes.
    fn label(&mut self) -> Result<NodeId, CertFormatError> {
        let len = usize::from(self.byte()?);
        if len == 0 {
            return Err(CertFormatError::Name(DomainError::NodeIdEmpty));
        }
        if len > MAX_NODE_ID_LEN {
            return Err(CertFormatError::Name(DomainError::NodeIdTooLong {
                len,
                max: MAX_NODE_ID_LEN,
            }));
        }
        let raw = self.take(len)?;
        NodeId::try_from(raw).map_err(CertFormatError::Name)
    }
}

/// Why a certificate does not conform to the format. Only metadata (field, position,
/// length), never certificate bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertFormatError {
    /// Total length outside `MIN_CERT_LEN..=MAX_CERT_LEN`.
    #[error("certificate is {len} bytes, outside the bounds of its version (PROTOCOL §15.12)")]
    Length {
        /// The received length.
        len: usize,
    },
    /// The first 4 bytes are not `TCNC`.
    #[error("not a TCN client certificate")]
    Magic,
    /// Version other than 1.
    #[error("unsupported certificate version {0}")]
    Version(u8),
    /// Signature algorithm other than Ed25519.
    #[error("unsupported signature algorithm {0}")]
    Algorithm(u8),
    /// All-zero serial number.
    #[error("certificate serial must not be all zeros")]
    SerialZero,
    /// `ca_key` equal to `subject_key`: a CA does not certify itself (rule 3).
    #[error("certificate subject key must differ from the authority key")]
    SelfCertified,
    /// `not_before >= not_after`.
    #[error("certificate validity window is empty")]
    Validity,
    /// Lifetime beyond `MAX_CERT_LIFETIME_SECS`.
    #[error("certificate lifetime is {secs} s, maximum is 86400")]
    Lifetime {
        /// The declared lifetime.
        secs: u64,
    },
    /// Invalid name or node.
    #[error("invalid name in certificate: {0}")]
    Name(DomainError),
    /// Unknown `scope` code.
    #[error("unknown certificate scope {0:#04x}")]
    Scope(u8),
    /// `node_count` inconsistent with `scope` or beyond the maximum.
    #[error("invalid certificate node count {0}")]
    NodeCount(u8),
    /// Nodes not in strictly increasing order.
    #[error("certificate nodes out of order at index {index}")]
    NodeOrder {
        /// Index of the first out-of-order node.
        index: usize,
    },
    /// A field runs past the end of the certificate.
    #[error("certificate truncated at byte {at}")]
    Truncated {
        /// Position of the truncated field.
        at: usize,
    },
    /// Extra bytes after the signature.
    #[error("certificate has {extra} trailing bytes")]
    Trailing {
        /// How many.
        extra: usize,
    },
    /// Unknown `subject_kind` of a certificate v2.
    #[error("unknown certificate subject kind {0:#04x}")]
    SubjectKind(u8),
}

/// Why a presented certificate was rejected: the `cert_check` field of the audit
/// (PROTOCOL §15.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertRejection {
    /// Step 3: length or format.
    Malformed,
    /// Step 4: `subject_key` non-canonical or different from the Noise key.
    KeyMismatch,
    /// Step 5: `ca_key` not pinned.
    UnknownAuthority,
    /// Step 6: invalid signature.
    BadSignature,
    /// Step 7: serial number in the denylist.
    SerialRevoked,
    /// Step 8: before `not_before - SKEW`.
    NotYetValid,
    /// Step 9: from `not_after` onwards.
    Expired,
    /// Step 10: lifetime beyond the CA's `max_lifetime`.
    LifetimeExceedsAuthority,
    /// Step 11: the key belongs to an agent.
    RoleConflict,
    /// Step 12: the agent's node is not in the effective scope.
    NodeOutOfScope,
}

impl CertRejection {
    /// The value of `cert_check` in the audit log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::KeyMismatch => "key_mismatch",
            Self::UnknownAuthority => "unknown_authority",
            Self::BadSignature => "bad_signature",
            Self::SerialRevoked => "serial_revoked",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::LifetimeExceedsAuthority => "lifetime_exceeds_authority",
            Self::RoleConflict => "role_conflict",
            Self::NodeOutOfScope => "node_out_of_scope",
        }
    }

    /// `true` for the checks after signature verification (steps 7–12 of PROTOCOL
    /// §15.4): only for these does the audit report the CA and serial number (§15.11).
    #[must_use]
    pub const fn after_signature(self) -> bool {
        match self {
            Self::Malformed | Self::KeyMismatch | Self::UnknownAuthority | Self::BadSignature => {
                false
            }
            Self::SerialRevoked
            | Self::NotYetValid
            | Self::Expired
            | Self::LifetimeExceedsAuthority
            | Self::RoleConflict
            | Self::NodeOutOfScope => true,
        }
    }
}

/// How a certificate names its CA, with the algorithm: a v1 certificate by the Ed25519 key
/// itself, a v2 certificate by the composite key's [`CaFingerprint`]. A pin matches only a
/// reference of its own algorithm (finding AP-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaKeyRef {
    /// `ca_key` of a v1 certificate: an Ed25519 key.
    Ed25519(CertKey),
    /// `ca_fp` of a v2 certificate: a composite ML-DSA-65 + Ed25519 key.
    Composite(CaFingerprint),
}

/// The data of a certificate whose signature has already been verified by `zt-crypto` with a
/// pinned key. The relay core keeps only these, never the certificate bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertClaims {
    ca: Fingerprint,
    authority_key: CaKeyRef,
    subject: Fingerprint,
    subject_hybrid: Option<HybridFingerprint>,
    version: u8,
    serial: CertSerial,
    name: NodeId,
    scope: CertScope,
    not_before: UnixTime,
    not_after: UnixTime,
}

impl CertClaims {
    /// From a verified v1 body, with the fingerprints (X25519 form) of the CA and the subject.
    #[must_use]
    pub fn from_verified(body: CertBody, ca: Fingerprint, subject: Fingerprint) -> Self {
        Self {
            ca,
            authority_key: CaKeyRef::Ed25519(body.ca_key),
            subject,
            subject_hybrid: None,
            version: CERT_VERSION,
            serial: body.serial,
            name: body.name,
            scope: body.scope,
            not_before: body.not_before,
            not_after: body.not_after,
        }
    }

    /// From a verified v2 body, with the fingerprint (X25519 form) of the CA's Ed25519
    /// component.
    #[must_use]
    pub fn from_verified_v2(body: CertBodyV2, ca: Fingerprint) -> Self {
        Self {
            ca,
            authority_key: CaKeyRef::Composite(body.ca_fp),
            subject: *body.subject.classical(),
            subject_hybrid: body.subject.hybrid().copied(),
            version: CERT_VERSION_2,
            serial: body.serial,
            name: body.name,
            scope: body.scope,
            not_before: body.not_before,
            not_after: body.not_after,
        }
    }

    /// Reference for audit events.
    #[must_use]
    pub fn reference(&self) -> CertRef {
        CertRef {
            ca: self.ca,
            version: self.version,
            serial: self.serial,
            name: self.name.clone(),
            not_after: self.not_after,
        }
    }

    /// Fingerprint of the signing CA (X25519 form of its Ed25519 key or component).
    #[must_use]
    pub const fn ca(&self) -> &Fingerprint {
        &self.ca
    }

    /// The signing CA's key, as the certificate names it (with its algorithm).
    #[must_use]
    pub const fn authority_key(&self) -> &CaKeyRef {
        &self.authority_key
    }

    /// Fingerprint of the subject (X25519 level, equal to that of the Noise key).
    #[must_use]
    pub const fn subject(&self) -> &Fingerprint {
        &self.subject
    }

    /// Hybrid fingerprint of a `subject_kind = 0x02` certificate v2.
    #[must_use]
    pub const fn subject_hybrid(&self) -> Option<&HybridFingerprint> {
        self.subject_hybrid.as_ref()
    }

    /// The certificate version: 1 or 2 (the `cert_version` audit field).
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Serial number.
    #[must_use]
    pub const fn serial(&self) -> CertSerial {
        self.serial
    }

    /// Name of the client.
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// Declared scope.
    #[must_use]
    pub const fn scope(&self) -> &CertScope {
        &self.scope
    }

    /// Start of validity.
    #[must_use]
    pub const fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// End of validity (exclusive).
    #[must_use]
    pub const fn not_after(&self) -> UnixTime {
        self.not_after
    }
}

/// What an audit event says about a certificate: never its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRef {
    /// Fingerprint of the CA.
    pub ca: Fingerprint,
    /// Certificate version, 1 or 2 (the `cert_version` audit field).
    pub version: u8,
    /// Serial number.
    pub serial: CertSerial,
    /// Name of the client.
    pub name: NodeId,
    /// Expiry.
    pub not_after: UnixTime,
}
