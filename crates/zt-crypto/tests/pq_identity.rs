//! PQ-AUTH, hybrid static identities (PROTOCOL §7.5.3; decision D12; findings AP-6 of review
//! 0007): every node's ML-KEM-768 static key is derived from its existing seed, its public
//! form is `tcn-pub-v2:` (Ed25519 ‖ ML-KEM ek) and its fingerprint v2 covers X25519 ‖ ek.
//!
//! The derivation and the fingerprint are recomputed here from their definitions (SHAKE256,
//! SHA-256, the KEM primitive), not through the identity code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use sha2::{Digest, Sha256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zt_crypto::kem::{Kem, KemSeed, MlKem768};
use zt_crypto::{CryptoError, HybridPublicKey, Identity, PeerKey, PublicKey};
use zt_domain::{FingerprintText, HybridFingerprint};

fn seeded(b: u8) -> ([u8; 32], Identity) {
    let seed = [b; 32];
    (seed, Identity::from_secret_hex(&hex::encode(seed)).unwrap())
}

/// D12: `d ‖ z = SHAKE256("TCN ML-KEM-768 seed v1\0" ‖ seed, 64)`, then FIPS 203 `KeyGen`.
fn derived_ek(seed: &[u8; 32]) -> Vec<u8> {
    let mut xof = Shake256::default();
    xof.update(b"TCN ML-KEM-768 seed v1\0");
    xof.update(seed);
    let mut dz = [0_u8; 64];
    xof.finalize_xof().read(&mut dz);
    MlKem768::generate(&KemSeed::from_bytes(dz)).1
}

fn v2_fingerprint(x25519: &[u8; 32], ek: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"TCN fingerprint v2\0")
        .chain_update(x25519)
        .chain_update(ek)
        .finalize()
        .into()
}

/// Spec (D12): the ML-KEM-768 static key is a function of the seed only, domain-separated.
#[test]
fn the_kem_key_is_derived_from_the_seed() {
    let (seed, id) = seeded(0x31);
    let hybrid = id.hybrid_public_key();
    assert_eq!(hybrid.encapsulation_key(), derived_ek(&seed).as_slice());
    assert_eq!(hybrid.encapsulation_key().len(), 1_184);
    // Deterministic, and different for another seed.
    let (_, again) = seeded(0x31);
    assert_eq!(again.hybrid_public_key(), hybrid);
    let (_, other) = seeded(0x32);
    assert_ne!(
        other.hybrid_public_key().encapsulation_key(),
        hybrid.encapsulation_key()
    );
    // Not the ML-KEM key of `KeyGen(seed ‖ seed)` (no domain separation would give it).
    let mut naive = [0_u8; 64];
    naive[..32].copy_from_slice(&seed);
    naive[32..].copy_from_slice(&seed);
    assert_ne!(
        MlKem768::generate(&KemSeed::from_bytes(naive)).1,
        hybrid.encapsulation_key()
    );
}

/// Spec: fingerprint v2 = SHA-256("TCN fingerprint v2\0" ‖ x25519 ‖ ek), shown as
/// `SHA256v2:`; the v1 fingerprint of the hybrid key is that of its Ed25519 part.
#[test]
fn fingerprint_v2_covers_x25519_and_the_kem_key() {
    let (_, id) = seeded(0x33);
    let hybrid = id.hybrid_public_key();
    let expected = HybridFingerprint::from_bytes(v2_fingerprint(
        &id.public_key().x25519(),
        hybrid.encapsulation_key(),
    ));
    assert_eq!(hybrid.hybrid_fingerprint(), expected);
    assert_eq!(id.hybrid_fingerprint(), expected);
    assert_eq!(hybrid.fingerprint(), id.fingerprint());
    assert_eq!(hybrid.classical(), &id.public_key());
    assert!(expected.to_string().starts_with("SHA256v2:"));
    assert_eq!(
        zt_crypto::hybrid_fingerprint_of(&id.public_key().x25519(), hybrid.encapsulation_key()),
        expected
    );
    assert!(matches!(
        FingerprintText::parse(&expected.to_string()),
        Ok(FingerprintText::V2(_))
    ));
}

/// Spec (D13): the public key text is `tcn-pub-v2:` + 2 432 lowercase hex (Ed25519 ‖ ek), and
/// it round-trips.
#[test]
fn the_v2_public_key_text_round_trips() {
    let (_, id) = seeded(0x34);
    let hybrid = id.hybrid_public_key();
    let text = hybrid.to_string();
    assert!(text.starts_with("tcn-pub-v2:"));
    assert_eq!(text.len(), "tcn-pub-v2:".len() + 2_432);
    assert_eq!(HybridPublicKey::HEX_LEN, 2_432);
    assert_eq!(
        &text["tcn-pub-v2:".len()..][..64],
        hex::encode(id.public_key().to_bytes())
    );
    assert_eq!(text.parse::<HybridPublicKey>().unwrap(), hybrid);
    // A peer key is either kind.
    let peer: PeerKey = (&hybrid).into();
    assert_eq!(peer.public_key(), &id.public_key());
    assert_eq!(peer.hybrid(), Some(&hybrid));
    assert_eq!(peer.fingerprint(), id.fingerprint());
    let classical: PeerKey = (&id.public_key()).into();
    assert_eq!(classical.hybrid(), None);
}

/// Attack (Parsing, AP-6): wrong lengths, uppercase, a v1 key, another prefix, an `ek` that
/// fails the FIPS 203 modulus check, and a non-canonical or weak Ed25519 part are refused.
#[test]
fn malformed_v2_public_keys_are_refused() {
    let (_, id) = seeded(0x35);
    let text = id.hybrid_public_key().to_string();
    let body = &text["tcn-pub-v2:".len()..];
    // An ek of all 0xff fails the modulus check (coefficients ≥ q).
    let bad_ek = format!("tcn-pub-v2:{}{}", &body[..64], "ff".repeat(1_184));
    // The identity point is a small-order (weak) Ed25519 key.
    let mut weak = [0_u8; 32];
    weak[0] = 1;
    let weak_ed = format!("tcn-pub-v2:{}{}", hex::encode(weak), &body[64..]);
    for bad in [
        String::new(),
        "tcn-pub-v2:".to_owned(),
        text[..text.len() - 2].to_owned(),
        format!("{text}00"),
        text.to_uppercase(),
        format!("tcn-pub-v2:{}", body.to_uppercase()),
        text.replacen("tcn-pub-v2:", "tcn-pub-v3:", 1),
        text.replacen("tcn-pub-v2:", "", 1),
        format!(" {text}"),
        id.public_key().to_string(),
        bad_ek,
        weak_ed,
    ] {
        assert!(
            bad.parse::<HybridPublicKey>().is_err(),
            "{}",
            &bad[..bad.len().min(40)]
        );
    }
    // The v1 parser does not take a v2 text either.
    assert!(text.parse::<PublicKey>().is_err());
    // Errors never carry the key.
    let err = text[..text.len() - 2]
        .parse::<HybridPublicKey>()
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidKey));
}

/// The secret never shows: `Debug` of an identity names only its fingerprint.
#[test]
fn identity_debug_shows_no_kem_secret() {
    let (seed, id) = seeded(0x36);
    let debug = format!("{id:?}");
    assert!(!debug.contains(&hex::encode(seed)));
    assert!(
        debug.len() < 200,
        "Debug of an identity is {} bytes long",
        debug.len()
    );
}
