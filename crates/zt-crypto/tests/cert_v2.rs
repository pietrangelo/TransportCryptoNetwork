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
