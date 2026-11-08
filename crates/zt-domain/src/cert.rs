//! Certificati client brevi firmati da una CA offline (PROTOCOL §15).
//!
//! Il dominio conosce solo la **sintassi** del formato (regole 1–7 di §15.1) e i dati di un
//! certificato già verificato ([`CertClaims`]). Firma, canonicità dei punti e binding alla
//! chiave Noise stanno in `zt-crypto`.
//!

use core::fmt;
use std::collections::BTreeSet;

use thiserror::Error;

use crate::crypto::Fingerprint;
use crate::error::DomainError;
use crate::ids::NodeId;
use crate::limits::{
    MAX_CERT_LEN, MAX_CERT_LIFETIME_SECS, MAX_CERT_NODES, MAX_NODE_ID_LEN, MIN_CERT_LEN,
};

/// I primi 4 byte di ogni certificato.
pub const CERT_MAGIC: [u8; 4] = *b"TCNC";
/// L'unica versione del formato.
pub const CERT_VERSION: u8 = 0x01;
/// L'unico algoritmo di firma: Ed25519 puro (RFC 8032).
pub const CERT_SIG_ED25519: u8 = 0x01;
/// Lunghezza della firma in coda al certificato.
pub const CERT_SIGNATURE_LEN: usize = 64;
/// Stringa di contesto anteposta al TBS prima della firma (PROTOCOL §15.2).
pub const CERT_SIGNATURE_CONTEXT: &[u8] = b"TCN client certificate v1\0";

/// Un istante in secondi Unix (UTC). Il dominio non ha orologio: il tempo entra come parametro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// L'istante `secs` secondi dopo il 1970.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// I secondi dal 1970.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// `self + secs`, o `None` in overflow.
    #[must_use]
    pub const fn checked_add(self, secs: u64) -> Option<Self> {
        match self.0.checked_add(secs) {
            Some(t) => Some(Self(t)),
            None => None,
        }
    }

    /// `self - secs`, o `None` prima del 1970.
    #[must_use]
    pub const fn checked_sub(self, secs: u64) -> Option<Self> {
        match self.0.checked_sub(secs) {
            Some(t) => Some(Self(t)),
            None => None,
        }
    }

    /// `self + secs`, fermo a `u64::MAX`.
    #[must_use]
    pub const fn saturating_add(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// `self - secs`, fermo a 0.
    #[must_use]
    pub const fn saturating_sub(self, secs: u64) -> Self {
        Self(self.0.saturating_sub(secs))
    }
}

/// Numero di serie di un certificato: 128 bit casuali, mai tutti zero. È l'identità del
/// certificato (PROTOCOL §15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertSerial([u8; Self::LEN]);

impl CertSerial {
    /// Lunghezza in byte.
    pub const LEN: usize = 16;

    /// I byte del numero di serie.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<[u8; 16]> for CertSerial {
    type Error = CertFormatError;

    /// # Errors
    /// [`CertFormatError::SerialZero`] per il valore tutto a zero.
    fn try_from(bytes: [u8; 16]) -> Result<Self, Self::Error> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(CertFormatError::SerialZero);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for CertSerial {
    /// 32 caratteri esadecimali minuscoli, come nella denylist.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// 32 byte di una chiave pubblica Ed25519 come compaiono nel certificato, **non** ancora
/// validati come punto della curva (lo fa `zt-crypto`). Il confronto è byte per byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertKey([u8; Self::LEN]);

impl CertKey {
    /// Lunghezza in byte.
    pub const LEN: usize = 32;

    /// Prende 32 byte.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// I 32 byte.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Ambito di un certificato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertScope {
    /// `scope = 0x01`: tutti i nodi concessi alla CA (`allow`).
    All,
    /// `scope = 0x00`: questi nodi, da 1 a [`crate::limits::MAX_CERT_NODES`].
    Only(BTreeSet<NodeId>),
}

/// Il contenuto firmato di un certificato. Un `CertBody` esistente rispetta le regole 1–7 di
/// PROTOCOL §15.1, quindi la sua codifica è infallibile.
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
    /// Costruisce un corpo valido.
    ///
    /// # Errors
    /// Una delle regole 3–6 di PROTOCOL §15.1 non è rispettata.
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

    /// I byte `[0, L-64)` del certificato (TBS, PROTOCOL §15.1).
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
        push_label(&mut out, &self.name);
        match &self.scope {
            CertScope::All => {
                out.push(SCOPE_ALL);
                out.push(0);
            }
            CertScope::Only(nodes) => {
                out.push(SCOPE_LIST);
                // 1..=MAX_CERT_NODES per costruzione.
                out.push(u8::try_from(nodes.len()).unwrap_or(u8::MAX));
                // `BTreeSet` di `NodeId` (stringhe ASCII): l'ordine è quello dei byte.
                for node in nodes {
                    push_label(&mut out, node);
                }
            }
        }
        out
    }

    /// Chiave della CA firmataria (non ancora confrontata con i pin).
    #[must_use]
    pub const fn ca_key(&self) -> &CertKey {
        &self.ca_key
    }

    /// Chiave del client.
    #[must_use]
    pub const fn subject_key(&self) -> &CertKey {
        &self.subject_key
    }

    /// Numero di serie.
    #[must_use]
    pub const fn serial(&self) -> CertSerial {
        self.serial
    }

    /// Inizio della validità.
    #[must_use]
    pub const fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// Fine della validità (esclusa).
    #[must_use]
    pub const fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// Nome del client, solo per gli audit log.
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// Ambito.
    #[must_use]
    pub const fn scope(&self) -> &CertScope {
        &self.scope
    }

    /// `not_after - not_before` in secondi.
    #[must_use]
    pub const fn lifetime_secs(&self) -> u64 {
        self.not_after
            .as_secs()
            .saturating_sub(self.not_before.as_secs())
    }
}

/// Un certificato decodificato: corpo, byte firmati e firma (non ancora verificata).
#[derive(Debug)]
pub struct ParsedCert<'a> {
    /// Il corpo.
    pub body: CertBody,
    /// I byte `[0, L-64)`.
    pub tbs: &'a [u8],
    /// Gli ultimi 64 byte.
    pub signature: &'a [u8; CERT_SIGNATURE_LEN],
}

/// Decodifica un certificato secondo le regole 1–7 di PROTOCOL §15.1. Non verifica la firma.
///
/// # Errors
/// La prima regola violata. Gli errori riportano solo metadati, mai byte del certificato.
pub fn decode_certificate(bytes: &[u8]) -> Result<ParsedCert<'_>, CertFormatError> {
    // Regola 1: la lunghezza prima di qualsiasi campo.
    let len = bytes.len();
    if !(MIN_CERT_LEN..=MAX_CERT_LEN).contains(&len) {
        return Err(CertFormatError::Length { len });
    }
    let mut r = Reader { bytes, pos: 0 };
    // Regola 2.
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
    // Regola 3.
    let ca_key = CertKey::from_bytes(r.array::<32>()?);
    let subject_key = CertKey::from_bytes(r.array::<32>()?);
    let serial = CertSerial::try_from(r.array::<16>()?)?;
    if ca_key == subject_key {
        return Err(CertFormatError::SelfCertified);
    }
    // Regola 4.
    let not_before = UnixTime::from_secs(u64::from_be_bytes(r.array::<8>()?));
    let not_after = UnixTime::from_secs(u64::from_be_bytes(r.array::<8>()?));
    check_validity(not_before, not_after)?;
    // Regola 5.
    let name = r.label()?;
    // Regola 6.
    let scope_code = r.byte()?;
    let node_count = r.byte()?;
    let scope = match scope_code {
        SCOPE_LIST => {
            if node_count == 0 || usize::from(node_count) > MAX_CERT_NODES {
                return Err(CertFormatError::NodeCount(node_count));
            }
            let mut nodes = BTreeSet::new();
            let mut previous: Option<NodeId> = None;
            for index in 0..usize::from(node_count) {
                let node = r.label()?;
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
    // Regola 7: esattamente 64 byte di firma.
    let tbs_len = r.pos;
    let remaining = len.saturating_sub(tbs_len);
    if remaining < CERT_SIGNATURE_LEN {
        return Err(CertFormatError::Truncated { at: tbs_len });
    }
    if remaining > CERT_SIGNATURE_LEN {
        return Err(CertFormatError::Trailing {
            extra: remaining.saturating_sub(CERT_SIGNATURE_LEN),
        });
    }
    let (tbs, sig) = bytes.split_at(tbs_len);
    let signature: &[u8; CERT_SIGNATURE_LEN] = sig
        .try_into()
        .map_err(|_| CertFormatError::Truncated { at: tbs_len })?;
    Ok(ParsedCert {
        body: CertBody {
            ca_key,
            subject_key,
            serial,
            not_before,
            not_after,
            name,
            scope,
        },
        tbs,
        signature,
    })
}

const SCOPE_LIST: u8 = 0x00;
const SCOPE_ALL: u8 = 0x01;

/// Regola 4 di PROTOCOL §15.1, con aritmetica controllata.
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

/// Scrive `len (u8) + byte` di un `NodeId` (1..=63 byte per costruzione).
fn push_label(out: &mut Vec<u8>, id: &NodeId) {
    out.push(u8::try_from(id.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(id.as_bytes());
}

/// Lettore sequenziale con controllo dei limiti: mai un indice fuori dal buffer.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
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

    /// `len (u8, 1..=63) + NodeId`. La lunghezza si controlla prima di leggere i byte.
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

/// Perché un certificato non rispetta il formato. Solo metadati (campo, posizione,
/// lunghezza), mai byte del certificato.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertFormatError {
    /// Lunghezza totale fuori da `MIN_CERT_LEN..=MAX_CERT_LEN`.
    #[error("certificate is {len} bytes, must be between 170 and 4328")]
    Length {
        /// La lunghezza ricevuta.
        len: usize,
    },
    /// I primi 4 byte non sono `TCNC`.
    #[error("not a TCN client certificate")]
    Magic,
    /// Versione diversa da 1.
    #[error("unsupported certificate version {0}")]
    Version(u8),
    /// Algoritmo di firma diverso da Ed25519.
    #[error("unsupported signature algorithm {0}")]
    Algorithm(u8),
    /// Numero di serie tutto a zero.
    #[error("certificate serial must not be all zeros")]
    SerialZero,
    /// `ca_key` uguale a `subject_key`: una CA non certifica sé stessa (regola 3).
    #[error("certificate subject key must differ from the authority key")]
    SelfCertified,
    /// `not_before >= not_after`.
    #[error("certificate validity window is empty")]
    Validity,
    /// Durata oltre `MAX_CERT_LIFETIME_SECS`.
    #[error("certificate lifetime is {secs} s, maximum is 86400")]
    Lifetime {
        /// La durata dichiarata.
        secs: u64,
    },
    /// Nome o nodo non valido.
    #[error("invalid name in certificate: {0}")]
    Name(DomainError),
    /// Codice di `scope` sconosciuto.
    #[error("unknown certificate scope {0:#04x}")]
    Scope(u8),
    /// `node_count` incoerente con `scope` o oltre il massimo.
    #[error("invalid certificate node count {0}")]
    NodeCount(u8),
    /// Nodi non in ordine strettamente crescente.
    #[error("certificate nodes out of order at index {index}")]
    NodeOrder {
        /// Indice del primo nodo fuori posto.
        index: usize,
    },
    /// Un campo supera la fine del certificato.
    #[error("certificate truncated at byte {at}")]
    Truncated {
        /// Posizione del campo troncato.
        at: usize,
    },
    /// Byte in più dopo la firma.
    #[error("certificate has {extra} trailing bytes")]
    Trailing {
        /// Quanti.
        extra: usize,
    },
}

/// Perché un certificato presentato è stato rifiutato: il campo `cert_check` dell'audit
/// (PROTOCOL §15.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertRejection {
    /// Passo 3: lunghezza o formato.
    Malformed,
    /// Passo 4: `subject_key` non canonica o diversa dalla chiave Noise.
    KeyMismatch,
    /// Passo 5: `ca_key` non pinnata.
    UnknownAuthority,
    /// Passo 6: firma non valida.
    BadSignature,
    /// Passo 7: numero di serie nella denylist.
    SerialRevoked,
    /// Passo 8: prima di `not_before - SKEW`.
    NotYetValid,
    /// Passo 9: da `not_after` in poi.
    Expired,
    /// Passo 10: durata oltre `max_lifetime` della CA.
    LifetimeExceedsAuthority,
    /// Passo 11: la chiave è di un agent.
    RoleConflict,
    /// Passo 12: il nodo dell'agent non è nell'ambito effettivo.
    NodeOutOfScope,
}

impl CertRejection {
    /// Il valore di `cert_check` nell'audit log.
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
}

/// I dati di un certificato la cui firma è già stata verificata da `zt-crypto` con una chiave
/// pinnata. Il relay core tiene solo questi, mai i byte del certificato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertClaims {
    ca: Fingerprint,
    ca_key: CertKey,
    subject: Fingerprint,
    serial: CertSerial,
    name: NodeId,
    scope: CertScope,
    not_before: UnixTime,
    not_after: UnixTime,
}

impl CertClaims {
    /// Da un corpo verificato, con le fingerprint (forma X25519) della CA e del soggetto.
    #[must_use]
    pub fn from_verified(body: CertBody, ca: Fingerprint, subject: Fingerprint) -> Self {
        Self {
            ca,
            ca_key: body.ca_key,
            subject,
            serial: body.serial,
            name: body.name,
            scope: body.scope,
            not_before: body.not_before,
            not_after: body.not_after,
        }
    }

    /// Riferimento per gli eventi di audit.
    #[must_use]
    pub fn reference(&self) -> CertRef {
        CertRef {
            ca: self.ca,
            serial: self.serial,
            name: self.name.clone(),
            not_after: self.not_after,
        }
    }

    /// Fingerprint della CA che ha firmato.
    #[must_use]
    pub const fn ca(&self) -> &Fingerprint {
        &self.ca
    }

    /// Chiave della CA che ha firmato.
    #[must_use]
    pub const fn ca_key(&self) -> &CertKey {
        &self.ca_key
    }

    /// Fingerprint del soggetto (uguale a quella della chiave Noise).
    #[must_use]
    pub const fn subject(&self) -> &Fingerprint {
        &self.subject
    }

    /// Numero di serie.
    #[must_use]
    pub const fn serial(&self) -> CertSerial {
        self.serial
    }

    /// Nome del client.
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// Ambito dichiarato.
    #[must_use]
    pub const fn scope(&self) -> &CertScope {
        &self.scope
    }

    /// Inizio della validità.
    #[must_use]
    pub const fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// Fine della validità (esclusa).
    #[must_use]
    pub const fn not_after(&self) -> UnixTime {
        self.not_after
    }
}

/// Ciò che un evento di audit dice di un certificato: mai i suoi byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRef {
    /// Fingerprint della CA.
    pub ca: Fingerprint,
    /// Numero di serie.
    pub serial: CertSerial,
    /// Nome del client.
    pub name: NodeId,
    /// Scadenza.
    pub not_after: UnixTime,
}
