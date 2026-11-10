//! PQ-AUTH, certificate v2 (PROTOCOL §15.14): binary format of the composite-signed
//! certificate, its length bounds per (version, `sig_alg`), the typed subject, and the binding of
//! the CA algorithm to the pinned key (findings AP-6, AP-13 of review 0007).
//!
//! RED tests: specification ("S") and attack ("A"). The bytes are written by hand, independent
//! of the encoder under test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::panic
)]

use std::collections::BTreeSet;

use zt_domain::cert::{
    CERT_SIG_MLDSA65_ED25519, CERT_V2_MLDSA_CONTEXT, CERT_V2_SIGNATURE_CONTEXT,
    CERT_V2_SIGNATURE_LEN, CERT_VERSION_2, MLDSA65_SIGNATURE_LEN,
};
use zt_domain::limits::{
    MAX_ANY_CERT_LEN, MAX_CERT_V2_LEN, MAX_PAYLOAD_LEN, MIN_CERT_LEN, MIN_CERT_V2_LEN,
    NOISE_MAX_MESSAGE_LEN,
};
use zt_domain::trust::{CertTrust, CompositeCaPin, TrustedCaKey};
use zt_domain::{
    AllowedNodes, AnyParsedCert, CaFingerprint, CaKeyRef, CertBodyV2, CertClaims, CertFormatError,
    CertKey, CertRejection, CertScope, CertSerial, CertSubject, DomainError, Fingerprint,
    FingerprintText, HandshakeSuite, HybridFingerprint, NodeId, UnixTime, decode_any_certificate,
    decode_certificate, decode_certificate_v2,
};

const NB: u64 = 1_800_000_000;
const NA: u64 = 1_800_003_600;

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

/// A v2 certificate written by hand: header, subject, common fields, a signature of `sig_len`
/// bytes (the format does not look inside it).
struct Raw {
    version: u8,
    sig_alg: u8,
    ca_fp: [u8; 32],
    kind: u8,
    subject: [u8; 32],
    hybrid: Option<[u8; 32]>,
    serial: [u8; 16],
    nb: u64,
    na: u64,
    name: Vec<u8>,
    scope: u8,
    nodes: Vec<Vec<u8>>,
    count: Option<u8>,
    sig_len: usize,
    trailing: usize,
}

impl Raw {
    fn classical() -> Self {
        Self {
            version: 0x02,
            sig_alg: 0x02,
            ca_fp: [0xca; 32],
            kind: 0x01,
            subject: [0x5b; 32],
            hybrid: None,
            serial: [7; 16],
            nb: NB,
            na: NA,
            name: b"alice".to_vec(),
            scope: 0x00,
            nodes: vec![b"db-01".to_vec(), b"web-01".to_vec()],
            count: None,
            sig_len: 3_373,
            trailing: 0,
        }
    }
    fn hybrid() -> Self {
        Self {
            kind: 0x02,
            hybrid: Some([0x4b; 32]),
            ..Self::classical()
        }
    }
    fn tbs(&self) -> Vec<u8> {
        let mut b = b"TCNC".to_vec();
        b.push(self.version);
        b.push(self.sig_alg);
        b.extend_from_slice(&self.ca_fp);
        b.push(self.kind);
        b.extend_from_slice(&self.subject);
        if let Some(h) = self.hybrid {
            b.extend_from_slice(&h);
        }
        b.extend_from_slice(&self.serial);
        b.extend_from_slice(&self.nb.to_be_bytes());
        b.extend_from_slice(&self.na.to_be_bytes());
        b.push(self.name.len() as u8);
        b.extend_from_slice(&self.name);
        b.push(self.scope);
        b.push(self.count.unwrap_or(self.nodes.len() as u8));
        for n in &self.nodes {
            b.push(n.len() as u8);
            b.extend_from_slice(n);
        }
        b
    }
    fn bytes(&self) -> Vec<u8> {
        let mut b = self.tbs();
        b.extend((0..self.sig_len).map(|i| i as u8));
        b.extend(std::iter::repeat_n(0xee, self.trailing));
        b
    }
}

fn subject_of(raw: &Raw) -> CertSubject {
    match raw.hybrid {
        None => CertSubject::Classical(Fingerprint::from_bytes(raw.subject)),
        Some(h) => CertSubject::Hybrid {
            classical: Fingerprint::from_bytes(raw.subject),
            hybrid: HybridFingerprint::from_bytes(h),
        },
    }
}

fn body_of(raw: &Raw) -> CertBodyV2 {
    let scope = if raw.scope == 0x01 {
        CertScope::All
    } else {
        CertScope::Only(
            raw.nodes
                .iter()
                .map(|n| NodeId::try_from(std::str::from_utf8(n).unwrap()).unwrap())
                .collect(),
        )
    };
    CertBodyV2::new(
        CaFingerprint::from_bytes(raw.ca_fp),
        subject_of(raw),
        CertSerial::try_from(raw.serial).unwrap(),
        UnixTime::from_secs(raw.nb),
        UnixTime::from_secs(raw.na),
        NodeId::try_from(std::str::from_utf8(&raw.name).unwrap()).unwrap(),
        scope,
    )
    .unwrap()
}

fn decode(raw: &Raw) -> Result<CertBodyV2, CertFormatError> {
    decode_certificate_v2(&raw.bytes()).map(|p| p.body)
}

// ======================= specification =======================

/// S: constants of PROTOCOL §15.14.
#[test]
fn v2_constants_are_those_of_the_specification() {
    assert_eq!(CERT_VERSION_2, 0x02);
    assert_eq!(CERT_SIG_MLDSA65_ED25519, 0x02);
    assert_eq!(CERT_V2_SIGNATURE_CONTEXT, b"TCN client certificate v2\0");
    assert_eq!(CERT_V2_MLDSA_CONTEXT, b"TCN-cert-v2");
    assert_eq!(MLDSA65_SIGNATURE_LEN, 3_309);
    assert_eq!(CERT_V2_SIGNATURE_LEN, 3_373);
    assert_eq!(MIN_CERT_V2_LEN, 3_480);
    assert_eq!(MAX_CERT_V2_LEN, 7_670);
    assert_eq!(MAX_ANY_CERT_LEN, MAX_CERT_V2_LEN);
    // Every handshake still carries the largest certificate of any version.
    for suite in HandshakeSuite::ALL {
        assert!(suite.max_msg1_len() >= suite.msg1_overhead() + MAX_ANY_CERT_LEN);
        assert!(suite.max_msg1_len() <= MAX_PAYLOAD_LEN);
        assert!(suite.max_msg1_len() <= NOISE_MAX_MESSAGE_LEN);
    }
}

/// S: a classical and a hybrid subject decode to their fields; the TBS is everything but the
/// last 3 373 bytes, `sig_M` then `sig_E`.
#[test]
fn a_v2_certificate_decodes_with_its_typed_subject() {
    for raw in [Raw::classical(), Raw::hybrid()] {
        let bytes = raw.bytes();
        let parsed = decode_certificate_v2(&bytes).unwrap();
        assert_eq!(parsed.body, body_of(&raw));
        assert_eq!(parsed.tbs, &raw.tbs()[..]);
        assert_eq!(parsed.mldsa_signature.len(), 3_309);
        assert_eq!(
            parsed.mldsa_signature.as_slice(),
            &bytes[bytes.len() - 3_373..bytes.len() - 64]
        );
        assert_eq!(
            parsed.ed25519_signature.as_slice(),
            &bytes[bytes.len() - 64..]
        );
        // The encoder writes exactly the hand-written TBS.
        assert_eq!(parsed.body.encode_tbs(), raw.tbs());
        assert_eq!(parsed.body.subject().classical().as_bytes(), &raw.subject);
        assert_eq!(
            parsed.body.subject().hybrid().map(|h| *h.as_bytes()),
            raw.hybrid
        );
        // Through the version-agnostic decoder too.
        match decode_any_certificate(&bytes).unwrap() {
            AnyParsedCert::V2(p) => assert_eq!(p.body, body_of(&raw)),
            AnyParsedCert::V1(_) => panic!("a v2 certificate decoded as v1"),
        }
    }
}

/// S: the smallest and largest v2 certificates are accepted, at exactly the bounds.
#[test]
fn smallest_and_largest_v2_certificates_are_accepted() {
    let smallest = Raw {
        name: b"a".to_vec(),
        scope: 0x01,
        nodes: vec![],
        ..Raw::classical()
    };
    assert_eq!(smallest.bytes().len(), MIN_CERT_V2_LEN);
    assert!(decode(&smallest).is_ok());
    let mut names: Vec<Vec<u8>> = (0..64)
        .map(|i| format!("{i:02}{}", "n".repeat(61)).into_bytes())
        .collect();
    names.sort();
    let largest = Raw {
        name: vec![b'a'; 63],
        nodes: names,
        ..Raw::hybrid()
    };
    assert_eq!(largest.bytes().len(), MAX_CERT_V2_LEN);
    assert!(decode(&largest).is_ok());
}

/// S: v1 decoding is unchanged; the version byte chooses the decoder.
#[test]
fn the_version_byte_selects_the_decoder() {
    let v2 = Raw::classical().bytes();
    assert!(matches!(
        decode_certificate(&v2),
        Err(CertFormatError::Length { .. } | CertFormatError::Version(2))
    ));
    let mut v1_header = v2.clone();
    v1_header[4] = 0x01;
    // A v1 version byte on a v2-sized certificate: the v1 bounds apply first.
    assert!(decode_any_certificate(&v1_header).is_err());
}

// ======================= attacks =======================

/// A (Parsing): lengths min-1, max+1, `u16::MAX`, and the v1 range for a v2 header are all
/// refused before any field is read.
#[test]
fn lengths_outside_the_v2_bounds_are_rejected_first() {
    for len in [0, 5, MIN_CERT_LEN, MIN_CERT_V2_LEN - 1] {
        let mut bytes = Raw::classical().bytes();
        bytes.resize(len, 0);
        assert!(
            matches!(
                decode_certificate_v2(&bytes),
                Err(CertFormatError::Length { .. })
            ),
            "{len}"
        );
    }
    for len in [MAX_CERT_V2_LEN + 1, usize::from(u16::MAX)] {
        let mut bytes = Raw::classical().bytes();
        bytes.resize(len, 0);
        assert!(matches!(
            decode_certificate_v2(&bytes),
            Err(CertFormatError::Length { .. })
        ));
        assert!(decode_any_certificate(&bytes).is_err());
    }
}

/// A (Parsing, alg confusion): the reserved `sig_alg` codes (0x03 ML-DSA-87, 0x04 SLH-DSA),
/// the v1 code and any other are refused; so are other versions.
#[test]
fn reserved_and_unknown_algorithms_and_versions_are_rejected() {
    for alg in [0x00, 0x01, 0x03, 0x04, 0xff] {
        let raw = Raw {
            sig_alg: alg,
            ..Raw::classical()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Algorithm(alg)), "{alg}");
    }
    for version in [0x00, 0x03, 0xff] {
        let raw = Raw {
            version,
            ..Raw::classical()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Version(version)));
        assert!(decode_any_certificate(&raw.bytes()).is_err());
    }
}

/// A (Parsing): an unknown `subject_kind` is refused; a kind that disagrees with the layout
/// (hybrid kind without the 32 bytes, classical kind with them) fails the strict layout.
#[test]
fn subject_kinds_are_strict() {
    for kind in [0x00, 0x03, 0xff] {
        let raw = Raw {
            kind,
            ..Raw::classical()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::SubjectKind(kind)));
    }
    // Kind 0x02 without its hybrid fingerprint: the following fields shift and the parse
    // fails somewhere, never yields a certificate.
    let missing = Raw {
        kind: 0x02,
        hybrid: None,
        ..Raw::classical()
    };
    assert!(decode(&missing).is_err());
    let extra = Raw {
        kind: 0x01,
        hybrid: Some([0x4b; 32]),
        ..Raw::classical()
    };
    assert!(decode(&extra).is_err());
}

/// A (Malleability): exactly one encoding. A missing or extra signature byte, trailing bytes,
/// a zero serial, unsorted or duplicate nodes, scope/count mismatches are all refused.
#[test]
fn every_non_canonical_v2_encoding_is_rejected() {
    let short = Raw {
        sig_len: 3_372,
        ..Raw::classical()
    };
    assert!(matches!(
        decode(&short),
        Err(CertFormatError::Truncated { .. })
    ));
    let long = Raw {
        trailing: 1,
        ..Raw::classical()
    };
    assert_eq!(decode(&long), Err(CertFormatError::Trailing { extra: 1 }));
    let zero = Raw {
        serial: [0; 16],
        ..Raw::classical()
    };
    assert_eq!(decode(&zero), Err(CertFormatError::SerialZero));
    let unsorted = Raw {
        nodes: vec![b"web-01".to_vec(), b"db-01".to_vec()],
        ..Raw::classical()
    };
    assert!(matches!(
        decode(&unsorted),
        Err(CertFormatError::NodeOrder { .. })
    ));
    let dup = Raw {
        nodes: vec![b"db-01".to_vec(), b"db-01".to_vec()],
        ..Raw::classical()
    };
    assert!(matches!(dup.bytes().len(), _));
    assert!(matches!(
        decode(&dup),
        Err(CertFormatError::NodeOrder { .. })
    ));
    let all_with_nodes = Raw {
        scope: 0x01,
        ..Raw::classical()
    };
    assert!(decode(&all_with_nodes).is_err());
    let count_lies = Raw {
        count: Some(3),
        ..Raw::classical()
    };
    assert!(decode(&count_lies).is_err());
    let inverted = Raw {
        nb: NA,
        na: NB,
        ..Raw::classical()
    };
    assert_eq!(decode(&inverted), Err(CertFormatError::Validity));
    let too_long = Raw {
        na: NB + 86_401,
        ..Raw::classical()
    };
    assert!(matches!(
        decode(&too_long),
        Err(CertFormatError::Lifetime { .. })
    ));
}

/// A (Side channels): errors never echo certificate bytes.
#[test]
fn v2_errors_never_echo_certificate_bytes() {
    let raw = Raw {
        kind: 0x7e,
        ..Raw::classical()
    };
    let text = decode(&raw).unwrap_err().to_string();
    assert!(!text.contains("caca"), "{text}");
    assert!(!text.contains("5b5b"), "{text}");
}

// ---------- fingerprints (AP-6) ----------

/// S: v1 and v2 fingerprints have distinct display prefixes, and a loader that parses one
/// kind sees which kind it got.
#[test]
fn fingerprint_kinds_have_distinct_prefixes() {
    let v1 = Fingerprint::from_bytes([0xab; 32]);
    let v2 = HybridFingerprint::from_bytes([0xab; 32]);
    assert_eq!(v1.to_string(), format!("SHA256:{}", "ab".repeat(32)));
    assert_eq!(v2.to_string(), format!("SHA256v2:{}", "ab".repeat(32)));
    assert_eq!(
        FingerprintText::parse(&v1.to_string()).unwrap(),
        FingerprintText::V1(v1)
    );
    assert_eq!(
        FingerprintText::parse(&v2.to_string()).unwrap(),
        FingerprintText::V2(v2)
    );
    for bad in [
        String::new(),
        "ab".repeat(32),
        format!("SHA256:{}", "AB".repeat(32)),
        format!("SHA256:{}", "ab".repeat(31)),
        format!("SHA256: {}", "ab".repeat(32)),
        format!("sha256v2:{}", "ab".repeat(32)),
        format!("SHA256v3:{}", "ab".repeat(32)),
    ] {
        assert!(FingerprintText::parse(&bad).is_err(), "{bad}");
    }
}

// ---------- trust: the algorithm is bound to the pinned key (AP-13) ----------

fn v1_pin(byte: u8) -> TrustedCaKey {
    TrustedCaKey {
        key: CertKey::from_bytes([byte; 32]),
        fingerprint: Fingerprint::from_bytes([byte ^ 0xff; 32]),
        composite: None,
    }
}

fn v2_pin(ed: u8, fp: u8) -> TrustedCaKey {
    TrustedCaKey {
        key: CertKey::from_bytes([ed; 32]),
        fingerprint: Fingerprint::from_bytes([ed ^ 0xff; 32]),
        composite: Some(
            CompositeCaPin::new(CaFingerprint::from_bytes([fp; 32]), &[fp; 1_952]).unwrap(),
        ),
    }
}

/// A (alg confusion): a v1 reference never matches a composite pin with the same Ed25519
/// bytes, and a composite reference never matches a v1 pin.
#[test]
fn a_reference_matches_only_a_pin_of_its_own_algorithm() {
    let mut trust = CertTrust::new();
    trust
        .add_authority(node("ca-new"), &[v2_pin(1, 9)], AllowedNodes::All, 3_600)
        .unwrap();
    assert!(
        trust
            .authority_for(&CaKeyRef::Composite(CaFingerprint::from_bytes([9; 32])))
            .is_some()
    );
    // The composite's Ed25519 component, presented as a v1 CA key.
    assert!(
        trust
            .authority_for_key(&CertKey::from_bytes([1; 32]))
            .is_none()
    );
    assert!(
        trust
            .authority_for(&CaKeyRef::Ed25519(CertKey::from_bytes([1; 32])))
            .is_none()
    );
    let mut trust = CertTrust::new();
    trust
        .add_authority(node("ca-old"), &[v1_pin(2)], AllowedNodes::All, 3_600)
        .unwrap();
    assert!(
        trust
            .authority_for(&CaKeyRef::Composite(CaFingerprint::from_bytes([2; 32])))
            .is_none()
    );
}

/// A (AP-13): a composite key's Ed25519 component equal to a v1 key, in the same entry
/// (rotation `[v2, v1]`) or in another entry, is a load error.
#[test]
fn component_key_reuse_is_rejected_at_load() {
    let mut trust = CertTrust::new();
    assert!(matches!(
        trust.add_authority(
            node("ca"),
            &[v2_pin(3, 8), v1_pin(3)],
            AllowedNodes::All,
            3_600
        ),
        Err(DomainError::AuthorityKeys(_))
    ));
    let mut trust = CertTrust::new();
    trust
        .add_authority(node("ca-a"), &[v1_pin(4)], AllowedNodes::All, 3_600)
        .unwrap();
    assert!(matches!(
        trust.add_authority(node("ca-b"), &[v2_pin(4, 8)], AllowedNodes::All, 3_600),
        Err(DomainError::DuplicatePeer(_))
    ));
    // Distinct components: a rotation [v2, v1] loads.
    let mut trust = CertTrust::new();
    trust
        .add_authority(
            node("ca"),
            &[v2_pin(5, 8), v1_pin(6)],
            AllowedNodes::All,
            3_600,
        )
        .unwrap();
    assert_eq!(trust.rotations_pending().count(), 1);
}

/// S (rotation, State): with `[v2, v1]` both versions pass step 5; once the v1 key is removed,
/// a v1 certificate is `unknown_authority` (no implicit acceptance of v1).
#[test]
fn v1_certificates_pass_only_while_a_v1_key_is_pinned() {
    let v2_claims = CertClaims::from_verified_v2(
        CertBodyV2::new(
            CaFingerprint::from_bytes([8; 32]),
            CertSubject::Classical(Fingerprint::from_bytes([0x11; 32])),
            CertSerial::try_from([1; 16]).unwrap(),
            UnixTime::from_secs(NB),
            UnixTime::from_secs(NA),
            node("alice"),
            CertScope::Only(BTreeSet::from([node("web-01")])),
        )
        .unwrap(),
        Fingerprint::from_bytes([5 ^ 0xff; 32]),
    );
    assert_eq!(v2_claims.version(), 2);
    assert_eq!(
        v2_claims.authority_key(),
        &CaKeyRef::Composite(CaFingerprint::from_bytes([8; 32]))
    );
    let v1_claims = CertClaims::from_verified(
        zt_domain::CertBody::new(
            CertKey::from_bytes([6; 32]),
            CertKey::from_bytes([0x22; 32]),
            CertSerial::try_from([2; 16]).unwrap(),
            UnixTime::from_secs(NB),
            UnixTime::from_secs(NA),
            node("bob"),
            CertScope::All,
        )
        .unwrap(),
        Fingerprint::from_bytes([6 ^ 0xff; 32]),
        Fingerprint::from_bytes([0x33; 32]),
    );
    assert_eq!(v1_claims.version(), 1);
    let now = UnixTime::from_secs(NB + 10);
    let empty = zt_domain::Revocations::new([], []).unwrap();
    let mut rotating = CertTrust::new();
    rotating
        .add_authority(
            node("ca"),
            &[v2_pin(5, 8), v1_pin(6)],
            AllowedNodes::All,
            3_600,
        )
        .unwrap();
    rotating.set_revocations(empty.clone());
    assert!(rotating.check(&v2_claims, now).is_ok());
    assert!(rotating.check(&v1_claims, now).is_ok());
    let mut done = CertTrust::new();
    done.add_authority(node("ca"), &[v2_pin(5, 8)], AllowedNodes::All, 3_600)
        .unwrap();
    done.set_revocations(empty);
    assert!(done.check(&v2_claims, now).is_ok());
    assert_eq!(
        done.check(&v1_claims, now).err(),
        Some(CertRejection::UnknownAuthority)
    );
}

/// A (Parsing): a composite pin with an ML-DSA key of the wrong length is refused.
#[test]
fn a_composite_pin_needs_a_full_ml_dsa_key() {
    for len in [0, 1_951, 1_953] {
        assert!(
            CompositeCaPin::new(CaFingerprint::from_bytes([1; 32]), &vec![0; len]).is_err(),
            "{len}"
        );
    }
}
