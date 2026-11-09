//! PQ-0 specification: the sans-IO KEM provider trait and ML-KEM-768 (FIPS 203).
//!
//! One harness, generic over [`Kem`], runs the NIST ACVP and Wycheproof known-answer vectors
//! (`tests/vectors/mlkem768.txt`) against every provider: `libcrux-ml-kem` (the production
//! provider) and the `ml-kem` crate (a test-only, independent oracle). A differential test then
//! checks that the two agree on inputs no vector covers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use sha2::{Digest, Sha256};
use zt_crypto::kem::{
    ENCAPSULATION_RANDOMNESS_LEN, Kem, KemError, KemSeed, MlKem768, SEED_LEN, SharedSecret,
};

// --- the oracle: RustCrypto ml-kem behind the same trait ---------------------------------

/// The `ml-kem` crate, adapted to TCN's trait. Test-only: it never enters a binary.
struct Oracle;

impl Kem for Oracle {
    const ALGORITHM: &'static str = "ML-KEM-768";
    const ENCAPSULATION_KEY_LEN: usize = 1184;
    const CIPHERTEXT_LEN: usize = 1088;
    type DecapsulationKey = ml_kem::DecapsulationKey768;

    fn generate(seed: &KemSeed) -> (Self::DecapsulationKey, Vec<u8>) {
        use ml_kem::kem::KeyExport;
        let seed = ml_kem::Seed::try_from(seed.as_bytes().as_slice()).unwrap();
        let dk = ml_kem::DecapsulationKey768::from_seed(seed);
        let ek = dk.encapsulation_key().to_bytes().to_vec();
        (dk, ek)
    }

    fn encapsulate(
        encapsulation_key: &[u8],
        randomness: &[u8; ENCAPSULATION_RANDOMNESS_LEN],
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        let key = ml_kem::array::Array::try_from(encapsulation_key)
            .map_err(|_| KemError::EncapsulationKeyLength)?;
        let ek = ml_kem::EncapsulationKey768::new(&key)
            .map_err(|_| KemError::InvalidEncapsulationKey)?;
        let m = ml_kem::B32::try_from(randomness.as_slice()).unwrap();
        let (c, k) = ek.encapsulate_deterministic(&m);
        Ok((c.to_vec(), SharedSecret::from_bytes(k.into())))
    }

    fn decapsulate(
        key: &Self::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, KemError> {
        use ml_kem::kem::Decapsulate;
        let c = ml_kem::ml_kem_768::Ciphertext::try_from(ciphertext)
            .map_err(|_| KemError::CiphertextLength)?;
        Ok(SharedSecret::from_bytes(key.decapsulate(&c).into()))
    }
}

// --- vectors -------------------------------------------------------------------------------

const VECTORS: &str = include_str!("vectors/mlkem768.txt");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex in vectors: {e}"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn records(kind: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    VECTORS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.split(' ').collect::<Vec<_>>())
        .filter(move |f| f[0] == kind)
}

fn seed(d: &[u8], z: &[u8]) -> KemSeed {
    let mut s = [0_u8; SEED_LEN];
    s[..32].copy_from_slice(d);
    s[32..].copy_from_slice(z);
    KemSeed::from_bytes(s)
}

/// ACVP keyGen: `(d, z)` gives exactly the expected encapsulation key.
fn keygen_vectors<K: Kem>() -> usize {
    let mut n = 0;
    for f in records("keygen") {
        let (_, ek) = K::generate(&seed(&unhex(f[2]), &unhex(f[3])));
        assert_eq!(sha256(&ek), f[4], "{} keygen tcId {}", K::ALGORITHM, f[1]);
        n += 1;
    }
    n
}

/// ACVP encapsulation: `(ek, m)` gives exactly the expected ciphertext and key.
fn encap_vectors<K: Kem>() -> usize {
    let mut n = 0;
    for f in records("encap") {
        let m: [u8; 32] = unhex(f[3]).try_into().unwrap();
        let (c, k) = K::encapsulate(&unhex(f[2]), &m).unwrap();
        assert_eq!(sha256(&c), f[4], "encap tcId {}", f[1]);
        assert_eq!(k.as_bytes().as_slice(), unhex(f[5]), "encap tcId {}", f[1]);
        n += 1;
    }
    n
}

/// ACVP encapsulation key check (FIPS 203 §7.2): invalid keys are refused, never used.
fn ek_check_vectors<K: Kem>() -> usize {
    let mut n = 0;
    for f in records("ekcheck") {
        let result = K::encapsulate(&unhex(f[2]), &[7; 32]);
        if f[3] == "1" {
            assert!(result.is_ok(), "ekcheck tcId {} must be valid", f[1]);
        } else {
            assert_eq!(
                result.err(),
                Some(KemError::InvalidEncapsulationKey),
                "ekcheck tcId {} must be refused",
                f[1]
            );
        }
        n += 1;
    }
    n
}

/// Wycheproof decapsulation, implicit rejection included: a valid-length ciphertext always
/// gives the expected key (real or pseudo-random), a wrong length is an error.
fn decap_vectors<K: Kem>() -> usize {
    let mut n = 0;
    for f in records("decap") {
        let s = unhex(f[2]);
        let (dk, ek) = K::generate(&seed(&s[..32], &s[32..]));
        assert_eq!(sha256(&ek), f[3], "decap tcId {}: ek", f[1]);
        let c = if f[4] == "-" { Vec::new() } else { unhex(f[4]) };
        let result = K::decapsulate(&dk, &c);
        match f[6] {
            "valid" => assert_eq!(
                result.unwrap().as_bytes().as_slice(),
                unhex(f[5]),
                "decap tcId {}",
                f[1]
            ),
            "invalid" => assert_eq!(
                result.err(),
                Some(KemError::CiphertextLength),
                "decap tcId {}",
                f[1]
            ),
            other => panic!("unknown result {other}"),
        }
        n += 1;
    }
    n
}

fn all_vectors<K: Kem>() {
    assert_eq!(keygen_vectors::<K>(), 25);
    assert_eq!(encap_vectors::<K>(), 25);
    assert_eq!(ek_check_vectors::<K>(), 10);
    assert_eq!(decap_vectors::<K>(), 91);
}

#[test]
fn libcrux_ml_kem_768_passes_the_nist_and_wycheproof_vectors() {
    all_vectors::<MlKem768>();
}

#[test]
fn the_oracle_passes_the_same_vectors() {
    // If the oracle failed, a disagreement in the differential test would mean nothing.
    all_vectors::<Oracle>();
}

#[test]
fn ml_kem_768_sizes_are_those_of_fips_203() {
    assert_eq!(MlKem768::ALGORITHM, "ML-KEM-768");
    assert_eq!(MlKem768::ENCAPSULATION_KEY_LEN, 1184);
    assert_eq!(MlKem768::CIPHERTEXT_LEN, 1088);
    let (_, ek) = MlKem768::generate(&KemSeed::from_bytes([1; SEED_LEN]));
    assert_eq!(ek.len(), 1184);
    let (c, _) = MlKem768::encapsulate(&ek, &[2; 32]).unwrap();
    assert_eq!(c.len(), 1088);
}

#[test]
fn encapsulation_and_decapsulation_agree() {
    let (dk, ek) = MlKem768::generate(&KemSeed::from_bytes([3; SEED_LEN]));
    let (c, k1) = MlKem768::encapsulate(&ek, &[4; 32]).unwrap();
    let k2 = MlKem768::decapsulate(&dk, &c).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn key_generation_is_deterministic_in_the_seed() {
    let (_, a) = MlKem768::generate(&KemSeed::from_bytes([5; SEED_LEN]));
    let (_, b) = MlKem768::generate(&KemSeed::from_bytes([5; SEED_LEN]));
    let (_, c) = MlKem768::generate(&KemSeed::from_bytes([6; SEED_LEN]));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

/// Seeds and randomness that no vector covers: both implementations must produce the same
/// bytes, and each must decapsulate what the other encapsulated.
#[test]
fn libcrux_agrees_with_the_independent_oracle() {
    for i in 0_u32..48 {
        let mut s = [0_u8; SEED_LEN];
        s[..32].copy_from_slice(&Sha256::digest(format!("seed d {i}")));
        s[32..].copy_from_slice(&Sha256::digest(format!("seed z {i}")));
        let m: [u8; 32] = Sha256::digest(format!("m {i}")).into();
        let (dk_a, ek_a) = MlKem768::generate(&KemSeed::from_bytes(s));
        let (dk_b, ek_b) = Oracle::generate(&KemSeed::from_bytes(s));
        assert_eq!(ek_a, ek_b, "ek {i}");
        let (c_a, k_a) = MlKem768::encapsulate(&ek_a, &m).unwrap();
        let (c_b, k_b) = Oracle::encapsulate(&ek_b, &m).unwrap();
        assert_eq!(c_a, c_b, "ct {i}");
        assert_eq!(k_a, k_b, "ss {i}");
        assert_eq!(Oracle::decapsulate(&dk_b, &c_a).unwrap(), k_a);
        assert_eq!(MlKem768::decapsulate(&dk_a, &c_b).unwrap(), k_b);
        // A tampered ciphertext: both take the same implicit-rejection path.
        let mut bad = c_a.clone();
        let at = (i as usize * 37) % bad.len();
        bad[at] ^= 1 << (i % 8);
        let r_a = MlKem768::decapsulate(&dk_a, &bad).unwrap();
        let r_b = Oracle::decapsulate(&dk_b, &bad).unwrap();
        assert_eq!(r_a, r_b, "implicit rejection {i}");
        assert_ne!(r_a, k_a);
    }
}

#[test]
fn secrets_are_redacted_in_debug() {
    let (dk, _) = MlKem768::generate(&KemSeed::from_bytes([9; SEED_LEN]));
    let seed = KemSeed::from_bytes([0xab; SEED_LEN]);
    let ss = SharedSecret::from_bytes([0xcd; 32]);
    for text in [format!("{dk:?}"), format!("{seed:?}"), format!("{ss:?}")] {
        assert!(text.contains("redacted"), "{text}");
        assert!(!text.contains("ab") || text.contains("redacted"));
        assert!(!text.to_lowercase().contains("abab"), "{text}");
        assert!(!text.to_lowercase().contains("cdcd"), "{text}");
    }
}

// --- PQ-1: secret hygiene (review 0008, finding A8-12) -------------------------------------

/// Every KEM secret wipes itself on drop: the trait requires it of every provider's
/// decapsulation key, so the ephemeral key of a hybrid handshake (the secret IKhfs's forward
/// secrecy depends on) cannot outlive the handshake in memory.
#[test]
fn kem_secrets_are_wiped_on_drop() {
    fn wiped<T: zeroize::ZeroizeOnDrop>() {}
    wiped::<<MlKem768 as Kem>::DecapsulationKey>();
    wiped::<<Oracle as Kem>::DecapsulationKey>();
    wiped::<KemSeed>();
    wiped::<SharedSecret>();
}

/// A seed drawn by the provider's helper is never all zeros (it comes from the system CSPRNG)
/// and two draws differ.
#[test]
fn random_seeds_come_from_the_system_csprng() {
    let a = KemSeed::random().unwrap();
    let b = KemSeed::random().unwrap();
    assert_ne!(a.as_bytes(), &[0_u8; SEED_LEN]);
    assert_ne!(a.as_bytes(), b.as_bytes());
}
