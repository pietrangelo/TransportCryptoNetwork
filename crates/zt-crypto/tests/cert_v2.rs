//! PQ-AUTH: certificate v2 signed with the composite ML-DSA-65 + Ed25519 CA key (PROTOCOL
//! §15.14; findings AP-5, AP-6, AP-13 of review 0007).
//!
//! Specification ("S") and attack ("A") tests. Attack certificates are signed **by hand** with
//! `ed25519-dalek` and the ML-DSA primitive, so they do not depend on the certificate code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey};
use zt_crypto::mldsa::MlDsa65SigningKey;
use zt_crypto::{
    CERT_FILE_PREFIX, CERT_FILE_PREFIX_V2, CaSigningKey, CompositeCaPublicKey,
    CompositeCaSigningKey, CryptoError, Identity, cert_key, decode_certificate_text,
    encode_certificate_text, sign_certificate, sign_certificate_v2, trusted_ca_key,
    trusted_composite_ca_key, verify_certificate, verify_certificate_hybrid,
};
use zt_domain::trust::{CertTrust, TrustedCaKey};
use zt_domain::{
    AllowedNodes, CaFingerprint, CaKeyRef, CertBody, CertBodyV2, CertFormatError, CertRejection,
    CertScope, CertSerial, CertSubject, Fingerprint, HybridFingerprint, NodeId, Revocations,
    UnixTime,
};

const CTX2: &[u8] = b"TCN client certificate v2\0";
const NB: u64 = 1_800_000_000;
const NA: u64 = 1_800_003_600;
const ED_SEED: [u8; 32] = [0x11; 32];
const ML_SEED: [u8; 32] = [0x22; 32];

fn secret_text(ed: [u8; 32], ml: [u8; 32]) -> String {
    format!(
        "{}{}{}\n",
        CompositeCaSigningKey::FILE_PREFIX,
        hex::encode(ed),
        hex::encode(ml)
    )
}
fn ca() -> CompositeCaSigningKey {
    CompositeCaSigningKey::from_secret_text(&secret_text(ED_SEED, ML_SEED)).unwrap()
}
fn other_ca() -> CompositeCaSigningKey {
    CompositeCaSigningKey::from_secret_text(&secret_text([0x33; 32], [0x44; 32])).unwrap()
}
fn client() -> Identity {
    Identity::from_secret_hex(&"02".repeat(32)).unwrap()
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn trust_of(keys: &[TrustedCaKey]) -> CertTrust {
    let mut t = CertTrust::new();
    t.add_authority(node("ca"), keys, AllowedNodes::All, 28_800)
        .unwrap();
    t.set_revocations(Revocations::new([], []).unwrap());
    t
}
fn pinned(ca: &CompositeCaSigningKey) -> CertTrust {
    trust_of(&[trusted_composite_ca_key(&ca.public_key()).unwrap()])
}
fn body(ca: &CompositeCaSigningKey, subject: CertSubject) -> CertBodyV2 {
    CertBodyV2::new(
        ca.public_key().ca_fp(),
        subject,
        CertSerial::try_from([9; 16]).unwrap(),
        UnixTime::from_secs(NB),
        UnixTime::from_secs(NA),
        node("alice"),
        CertScope::Only(BTreeSet::from([node("web-01")])),
    )
    .unwrap()
}
fn classical(id: &Identity) -> CertSubject {
    CertSubject::Classical(id.fingerprint())
}
fn hybrid_fp() -> HybridFingerprint {
    HybridFingerprint::from_bytes([0x4b; 32])
}

/// A certificate v2 signed by hand: `tbs ‖ sig_M ‖ sig_E`, with the chosen components.
fn by_hand(tbs: &[u8], sig_m: &[u8], sig_e: &[u8]) -> Vec<u8> {
    let mut cert = tbs.to_vec();
    cert.extend_from_slice(sig_m);
    cert.extend_from_slice(sig_e);
    cert
}
fn message(tbs: &[u8]) -> Vec<u8> {
    [CTX2, tbs].concat()
}
fn sig_m(tbs: &[u8], ctx: &[u8]) -> Vec<u8> {
    MlDsa65SigningKey::from_seed(&ML_SEED)
        .sign(&message(tbs), ctx, &[5; 32])
        .unwrap()
}
fn sig_e(tbs: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&ED_SEED)
        .sign(&message(tbs))
        .to_bytes()
}

// ======================= specification =======================

/// S: `sign_certificate_v2` produces a certificate of `MIN..=MAX` length that the fleet's
/// verifier accepts, with version 2 claims and the CA named by its Ed25519 component.
#[test]
fn a_signed_v2_certificate_verifies() {
    let ca = ca();
    let id = client();
    let cert = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    assert_eq!(cert[4], 0x02);
    assert_eq!(cert[5], 0x02);
    let claims = verify_certificate(&cert, &id.fingerprint(), &pinned(&ca)).unwrap();
    assert_eq!(claims.version(), 2);
    assert_eq!(claims.subject(), &id.fingerprint());
    assert_eq!(claims.subject_hybrid(), None);
    assert_eq!(claims.ca(), &ca.public_key().fingerprint());
    assert_eq!(
        claims.authority_key(),
        &CaKeyRef::Composite(ca.public_key().ca_fp())
    );
    assert_eq!(claims.name(), &node("alice"));
    // Hedged: two signatures of the same body differ, and both verify.
    let again = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    assert_ne!(cert, again);
    assert!(verify_certificate(&again, &id.fingerprint(), &pinned(&ca)).is_ok());
}

/// S: the composite public key text round-trips, and `ca_fp` covers the algorithm and both
/// components.
#[test]
fn the_composite_key_text_round_trips() {
    let public = ca().public_key();
    let text = public.to_string();
    assert!(text.starts_with("tcn-ca-pub-v2:"));
    assert_eq!(text.len(), "tcn-ca-pub-v2:".len() + 3_968);
    let parsed = CompositeCaPublicKey::from_str(&text).unwrap();
    assert_eq!(parsed, public);
    assert_eq!(parsed.ca_fp(), public.ca_fp());
    assert_ne!(public.ca_fp(), other_ca().public_key().ca_fp());
    assert_eq!(
        public.fingerprint(),
        Identity::from_secret_hex(&hex::encode(ED_SEED))
            .unwrap()
            .fingerprint()
    );
    // The secret text round-trips and is redacted.
    let secret = ca().to_secret_text();
    assert_eq!(&*secret, &secret_text(ED_SEED, ML_SEED));
    assert_eq!(format!("{:?}", ca()), "CompositeCaSigningKey(<redacted>)");
}

/// S (AP-9/AP-6): a hybrid-bound certificate carries both fingerprints and verifies only in a
/// handshake that authenticated this very hybrid identity.
#[test]
fn a_hybrid_subject_needs_the_hybrid_handshake() {
    let ca = ca();
    let id = client();
    let subject = CertSubject::Hybrid {
        classical: id.fingerprint(),
        hybrid: hybrid_fp(),
    };
    let cert = sign_certificate_v2(&ca, &body(&ca, subject)).unwrap();
    let trust = pinned(&ca);
    let claims =
        verify_certificate_hybrid(&cert, &id.fingerprint(), Some(&hybrid_fp()), &trust).unwrap();
    assert_eq!(claims.subject_hybrid(), Some(&hybrid_fp()));
    assert_eq!(claims.subject(), &id.fingerprint());
    // Classical handshake (downgrade): refused before any signature.
    assert_eq!(
        verify_certificate(&cert, &id.fingerprint(), &trust).err(),
        Some(CertRejection::KeyMismatch)
    );
    // Same X25519, another ML-KEM key (a CRQC pairing the victim's X25519 with its own KEM).
    let other = HybridFingerprint::from_bytes([0x4c; 32]);
    assert_eq!(
        verify_certificate_hybrid(&cert, &id.fingerprint(), Some(&other), &trust).err(),
        Some(CertRejection::KeyMismatch)
    );
    // A classical certificate in a hybrid handshake is accepted (classical identity match).
    let plain = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    assert!(
        verify_certificate_hybrid(&plain, &id.fingerprint(), Some(&hybrid_fp()), &trust).is_ok()
    );
}

/// S: certificate files carry the prefix of their version.
#[test]
fn certificate_files_carry_their_version_prefix() {
    let ca = ca();
    let id = client();
    let cert = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    let text = encode_certificate_text(&cert);
    assert!(text.starts_with(CERT_FILE_PREFIX_V2));
    assert_eq!(decode_certificate_text(&text).unwrap(), cert);
    // A v2 certificate under the v1 prefix, and a v1 under the v2 prefix: refused.
    let swapped = text.replacen(CERT_FILE_PREFIX_V2, CERT_FILE_PREFIX, 1);
    assert!(decode_certificate_text(&swapped).is_err());
    let v1_ca = CaSigningKey::from_secret_text(&format!(
        "{}{}\n",
        CaSigningKey::FILE_PREFIX,
        "01".repeat(32)
    ))
    .unwrap();
    let v1 = sign_certificate(
        &v1_ca,
        &CertBody::new(
            cert_key(&v1_ca.public_key()),
            cert_key(&id.public_key()),
            CertSerial::try_from([1; 16]).unwrap(),
            UnixTime::from_secs(NB),
            UnixTime::from_secs(NA),
            node("alice"),
            CertScope::All,
        )
        .unwrap(),
    )
    .unwrap();
    let v1_text = encode_certificate_text(&v1);
    assert!(v1_text.starts_with(CERT_FILE_PREFIX));
    let lying = v1_text.replacen(CERT_FILE_PREFIX, CERT_FILE_PREFIX_V2, 1);
    assert!(decode_certificate_text(&lying).is_err());
    // Over the v2 maximum: a length error before decoding.
    let huge = format!("{CERT_FILE_PREFIX_V2}{}", "00".repeat(7_671));
    assert!(matches!(
        decode_certificate_text(&huge),
        Err(CertFormatError::Length { .. })
    ));
}

/// S (verify-after-sign): a body that names another CA is refused before signing.
#[test]
fn signing_refuses_a_body_of_another_ca() {
    let id = client();
    let body = body(&other_ca(), classical(&id));
    assert_eq!(
        sign_certificate_v2(&ca(), &body).err(),
        Some(CryptoError::InvalidKey)
    );
}

// ======================= attacks =======================

/// A (stripping): either component replaced by zeros, or by the other certificate's, fails.
#[test]
fn stripping_or_replacing_one_component_fails() {
    let ca = ca();
    let id = client();
    let trust = pinned(&ca);
    let tbs = body(&ca, classical(&id)).encode_tbs();
    let (m, e) = (sig_m(&tbs, b"TCN-cert-v2"), sig_e(&tbs));
    assert!(verify_certificate(&by_hand(&tbs, &m, &e), &id.fingerprint(), &trust).is_ok());
    for (sm, se) in [
        (vec![0; 3_309], e.to_vec()),
        (m.clone(), vec![0; 64]),
        (vec![0; 3_309], vec![0; 64]),
    ] {
        assert_eq!(
            verify_certificate(&by_hand(&tbs, &sm, &se), &id.fingerprint(), &trust).err(),
            Some(CertRejection::BadSignature)
        );
    }
    // Components of a certificate with another serial (both valid there).
    let other_body = CertBodyV2::new(
        ca.public_key().ca_fp(),
        classical(&id),
        CertSerial::try_from([8; 16]).unwrap(),
        UnixTime::from_secs(NB),
        UnixTime::from_secs(NA),
        node("alice"),
        CertScope::Only(BTreeSet::from([node("web-01")])),
    )
    .unwrap()
    .encode_tbs();
    let (m2, e2) = (sig_m(&other_body, b"TCN-cert-v2"), sig_e(&other_body));
    for (sm, se) in [(&m2, &e), (&m, &e2)] {
        assert_eq!(
            verify_certificate(&by_hand(&tbs, sm, se), &id.fingerprint(), &trust).err(),
            Some(CertRejection::BadSignature)
        );
    }
}

/// A (swap): `sig_E ‖ sig_M` instead of `sig_M ‖ sig_E` has the same length and fails.
#[test]
fn swapped_components_fail() {
    let ca = ca();
    let id = client();
    let tbs = body(&ca, classical(&id)).encode_tbs();
    let (m, e) = (sig_m(&tbs, b"TCN-cert-v2"), sig_e(&tbs));
    let swapped = by_hand(&tbs, &e, &m);
    assert_eq!(
        verify_certificate(&swapped, &id.fingerprint(), &pinned(&ca)).err(),
        Some(CertRejection::BadSignature)
    );
}

/// A (AP-5): with a bad Ed25519 component the ML-DSA component is never needed; with a good
/// Ed25519 component, a garbage ML-DSA component (non-canonical hints, `z` out of range) is
/// refused without a panic. Both are `bad_signature`.
#[test]
fn ed25519_is_checked_first_and_garbage_ml_dsa_never_panics() {
    let ca = ca();
    let id = client();
    let trust = pinned(&ca);
    let tbs = body(&ca, classical(&id)).encode_tbs();
    let (m, e) = (sig_m(&tbs, b"TCN-cert-v2"), sig_e(&tbs));
    let mut bad_e = e;
    bad_e[0] ^= 1;
    assert_eq!(
        verify_certificate(&by_hand(&tbs, &m, &bad_e), &id.fingerprint(), &trust).err(),
        Some(CertRejection::BadSignature)
    );
    for fill in [0x00_u8, 0xff, 0x80] {
        let garbage = vec![fill; 3_309];
        assert_eq!(
            verify_certificate(&by_hand(&tbs, &garbage, &e), &id.fingerprint(), &trust).err(),
            Some(CertRejection::BadSignature)
        );
    }
    // Repeated hint indices (CVE-2026-24850 class) inside an otherwise valid certificate. The
    // first polynomial needs at least two hints for the repetition: the signing randomness is
    // varied until it has them, so the check never silently checks nothing (A12-9).
    let base = 3_309 - 61;
    let (mut hints, count) = (0_u8..=255)
        .map(|r| {
            let m = MlDsa65SigningKey::from_seed(&ML_SEED)
                .sign(&message(&tbs), b"TCN-cert-v2", &[r; 32])
                .unwrap();
            let count = usize::from(m[base + 55]);
            (m, count)
        })
        .find(|(_, count)| *count >= 2)
        .expect("a signature whose first polynomial has two hints");
    assert!(
        verify_certificate(&by_hand(&tbs, &hints, &e), &id.fingerprint(), &trust).is_ok(),
        "the unmodified signature verifies"
    );
    hints[base + count - 1] = hints[base + count - 2];
    assert_eq!(
        verify_certificate(&by_hand(&tbs, &hints, &e), &id.fingerprint(), &trust).err(),
        Some(CertRejection::BadSignature)
    );
}

/// A (Malleability): a non-canonical Ed25519 `S` (S + ℓ) is refused (`verify_strict`).
#[test]
fn a_non_canonical_ed25519_component_is_refused() {
    // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let ca = ca();
    let id = client();
    let tbs = body(&ca, classical(&id)).encode_tbs();
    let (m, e) = (sig_m(&tbs, b"TCN-cert-v2"), sig_e(&tbs));
    let mut s_plus_l = e;
    let mut carry = 0_u16;
    for i in 0..32 {
        let sum = u16::from(s_plus_l[32 + i]) + u16::from(L[i]) + carry;
        s_plus_l[32 + i] = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(
        verify_certificate(
            &by_hand(&tbs, &m, &s_plus_l),
            &id.fingerprint(),
            &pinned(&ca)
        )
        .err(),
        Some(CertRejection::BadSignature)
    );
}

/// A (context): an ML-DSA component made with another FIPS 204 context, or without
/// `CTX2`, fails.
#[test]
fn the_ml_dsa_context_and_ctx2_are_enforced() {
    let ca = ca();
    let id = client();
    let tbs = body(&ca, classical(&id)).encode_tbs();
    let e = sig_e(&tbs);
    for ctx in [&b""[..], b"TCN-cert-v1", b"TCN-cert-v2\0"] {
        let m = sig_m(&tbs, ctx);
        assert_eq!(
            verify_certificate(&by_hand(&tbs, &m, &e), &id.fingerprint(), &pinned(&ca)).err(),
            Some(CertRejection::BadSignature)
        );
    }
    // Both components over the bare TBS (no CTX2).
    let m = MlDsa65SigningKey::from_seed(&ML_SEED)
        .sign(&tbs, b"TCN-cert-v2", &[1; 32])
        .unwrap();
    let e = SigningKey::from_bytes(&ED_SEED).sign(&tbs).to_bytes();
    assert_eq!(
        verify_certificate(&by_hand(&tbs, &m, &e), &id.fingerprint(), &pinned(&ca)).err(),
        Some(CertRejection::BadSignature)
    );
}

/// A (alg confusion, AP-13): a v1 certificate signed by the composite's Ed25519 key is
/// `unknown_authority` under the composite pin; a v2 certificate is `unknown_authority` under
/// a v1 pin of the same Ed25519 key.
#[test]
fn the_algorithm_comes_from_the_pinned_key() {
    let ca = ca();
    let id = client();
    // v1 under the composite pin.
    let ed_as_v1 = CaSigningKey::from_secret_text(&format!(
        "{}{}\n",
        CaSigningKey::FILE_PREFIX,
        hex::encode(ED_SEED)
    ))
    .unwrap();
    let v1 = sign_certificate(
        &ed_as_v1,
        &CertBody::new(
            cert_key(&ed_as_v1.public_key()),
            cert_key(&id.public_key()),
            CertSerial::try_from([1; 16]).unwrap(),
            UnixTime::from_secs(NB),
            UnixTime::from_secs(NA),
            node("alice"),
            CertScope::All,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_certificate(&v1, &id.fingerprint(), &pinned(&ca)).err(),
        Some(CertRejection::UnknownAuthority)
    );
    // v2 under a v1 pin of the composite's Ed25519 component.
    let v2 = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    let v1_trust = trust_of(&[trusted_ca_key(ca.public_key().ed25519())]);
    assert_eq!(
        verify_certificate(&v2, &id.fingerprint(), &v1_trust).err(),
        Some(CertRejection::UnknownAuthority)
    );
}

/// A (Identity): a `ca_fp` that matches no pin, or another composite CA's, is
/// `unknown_authority`, even with valid signatures of the named CA.
#[test]
fn an_unpinned_ca_fp_is_unknown() {
    let id = client();
    let other = other_ca();
    let cert = sign_certificate_v2(&other, &body(&other, classical(&id))).unwrap();
    assert_eq!(
        verify_certificate(&cert, &id.fingerprint(), &pinned(&ca())).err(),
        Some(CertRejection::UnknownAuthority)
    );
    // A certificate whose `ca_fp` names the pinned CA but is signed by another: bad signature.
    let ca = ca();
    let tbs = body(&ca, classical(&id)).encode_tbs();
    let forged_m = MlDsa65SigningKey::from_seed(&[0x44; 32])
        .sign(&message(&tbs), b"TCN-cert-v2", &[1; 32])
        .unwrap();
    let forged_e = SigningKey::from_bytes(&[0x33; 32])
        .sign(&message(&tbs))
        .to_bytes();
    assert_eq!(
        verify_certificate(
            &by_hand(&tbs, &forged_m, &forged_e),
            &id.fingerprint(),
            &pinned(&ca)
        )
        .err(),
        Some(CertRejection::BadSignature)
    );
}

/// A (binding first): a certificate for another key costs no signature check; a CA that
/// certifies its own Ed25519 component is refused.
#[test]
fn binding_and_self_certification() {
    let ca = ca();
    let id = client();
    let cert = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    let stranger = Fingerprint::from_bytes([0x77; 32]);
    assert_eq!(
        verify_certificate(&cert, &stranger, &pinned(&ca)).err(),
        Some(CertRejection::KeyMismatch)
    );
    let ca_fp = ca.public_key().fingerprint();
    let own = sign_certificate_v2(&ca, &body(&ca, CertSubject::Classical(ca_fp))).unwrap();
    assert_eq!(
        verify_certificate(&own, &ca_fp, &pinned(&ca)).err(),
        Some(CertRejection::KeyMismatch)
    );
}

/// A (Parsing): truncated, extended and oversized certificates are `malformed`.
#[test]
fn truncated_or_extended_v2_certificates_are_malformed() {
    let ca = ca();
    let id = client();
    let cert = sign_certificate_v2(&ca, &body(&ca, classical(&id))).unwrap();
    for cut in [1, 64, 3_309, 3_373] {
        assert_eq!(
            verify_certificate(&cert[..cert.len() - cut], &id.fingerprint(), &pinned(&ca)).err(),
            Some(CertRejection::Malformed)
        );
    }
    let mut longer = cert.clone();
    longer.push(0);
    assert_eq!(
        verify_certificate(&longer, &id.fingerprint(), &pinned(&ca)).err(),
        Some(CertRejection::Malformed)
    );
    let mut huge = cert;
    huge.resize(7_671, 0);
    assert_eq!(
        verify_certificate(&huge, &id.fingerprint(), &pinned(&ca)).err(),
        Some(CertRejection::Malformed)
    );
}

/// A (key text): composite keys are parsed strictly; a v1 key, uppercase hex, wrong lengths
/// and a non-canonical Ed25519 component are refused. CA secret files of one version are
/// refused by the other's loader.
#[test]
fn key_texts_are_strict_and_versions_do_not_mix() {
    let text = ca().public_key().to_string();
    let hex_part = text.strip_prefix("tcn-ca-pub-v2:").unwrap();
    for bad in [
        hex_part.to_owned(),
        format!("tcn-ca-pub-v2:{}", hex_part.to_uppercase()),
        format!("tcn-ca-pub-v2:{}", &hex_part[2..]),
        format!("tcn-ca-pub-v2:{hex_part}00"),
        format!("tcn-ca-pub-v2: {hex_part}"),
        format!("{text}\n"),
        // y = p (non-canonical encoding of a valid point) as the Ed25519 component.
        format!(
            "tcn-ca-pub-v2:edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f{}",
            &hex_part[64..]
        ),
        "01".repeat(32),
    ] {
        assert!(
            CompositeCaPublicKey::from_str(&bad).is_err(),
            "{}",
            &bad[..20.min(bad.len())]
        );
    }
    let v2_secret = secret_text(ED_SEED, ML_SEED);
    assert!(CaSigningKey::from_secret_text(&v2_secret).is_err());
    let v1_secret = format!("{}{}\n", CaSigningKey::FILE_PREFIX, "01".repeat(32));
    assert!(CompositeCaSigningKey::from_secret_text(&v1_secret).is_err());
    let lettered = secret_text([0xab; 32], [0xcd; 32]);
    assert!(CompositeCaSigningKey::from_secret_text(&lettered).is_ok());
    let upper = lettered.replace("ab", "AB");
    assert!(CompositeCaSigningKey::from_secret_text(&upper).is_err());
}

/// S (rotation, AP-13): a composite pin whose Ed25519 component equals the v1 key it rotates
/// away from is a load error, so a v2 CA always has fresh components.
#[test]
fn a_composite_key_never_reuses_the_v1_key() {
    let ca = ca();
    let v1_same = trusted_ca_key(ca.public_key().ed25519());
    let v2 = trusted_composite_ca_key(&ca.public_key()).unwrap();
    let mut t = CertTrust::new();
    assert!(
        t.add_authority(node("ca"), &[v2, v1_same], AllowedNodes::All, 28_800)
            .is_err()
    );
    // And the composite fingerprint is not the v1 fingerprint.
    assert_ne!(
        CaFingerprint::from_bytes(*ca.public_key().fingerprint().as_bytes()),
        ca.public_key().ca_fp()
    );
}
