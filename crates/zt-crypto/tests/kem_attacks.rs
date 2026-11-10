//! PQ-0 attack catalogue for the KEM provider (pq.md §7 PQ-1 rows that PQ-0 already owns:
//! encapsulation-key modulus check, ciphertext lengths, implicit rejection, no secrets in
//! errors).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use zt_crypto::kem::{Kem, KemError, KemSeed, MlKem768, SEED_LEN};

fn keys(b: u8) -> (<MlKem768 as Kem>::DecapsulationKey, Vec<u8>) {
    MlKem768::generate(&KemSeed::from_bytes([b; SEED_LEN]))
}

/// Parsing: an encapsulation key of any other length is refused before use.
#[test]
fn encapsulation_keys_of_the_wrong_length_are_refused() {
    let (_, ek) = keys(1);
    let mut longer = ek.clone();
    longer.push(0);
    for bad in [
        Vec::new(),
        vec![0],
        ek[..1_183].to_vec(),
        longer,
        vec![0; 65_535],
    ] {
        assert_eq!(
            MlKem768::encapsulate(&bad, &[1; 32]).err(),
            Some(KemError::EncapsulationKeyLength),
            "len {}",
            bad.len()
        );
    }
}

/// Parsing: the FIPS 203 §7.2 modulus check. A coefficient ≥ q = 3329 in `t` makes the key
/// invalid; encapsulating to it would hand an attacker a non-canonical key.
#[test]
fn an_encapsulation_key_with_a_coefficient_above_the_modulus_is_refused() {
    let (_, ek) = keys(2);
    // The first 12-bit coefficient of the first polynomial of t: set it to 0xFFF (4095).
    for poly in [0_usize, 1, 2] {
        let mut bad = ek.clone();
        let at = poly * 384;
        bad[at] = 0xff;
        bad[at + 1] |= 0x0f;
        assert_eq!(
            MlKem768::encapsulate(&bad, &[1; 32]).err(),
            Some(KemError::InvalidEncapsulationKey),
            "polynomial {poly}"
        );
    }
    // The seed rho (last 32 bytes) is not range checked: any value is a valid key.
    let mut rho = ek.clone();
    let last = rho.len() - 1;
    rho[last] ^= 0xff;
    assert!(MlKem768::encapsulate(&rho, &[1; 32]).is_ok());
}

/// Parsing: a ciphertext of any other length is an error, not a rejection secret.
#[test]
fn ciphertexts_of_the_wrong_length_are_refused() {
    let (dk, ek) = keys(3);
    let (ct, _) = MlKem768::encapsulate(&ek, &[3; 32]).unwrap();
    let mut longer = ct.clone();
    longer.push(0);
    for bad in [Vec::new(), vec![0], ct[..1_087].to_vec(), longer] {
        assert_eq!(
            MlKem768::decapsulate(&dk, &bad).err(),
            Some(KemError::CiphertextLength),
            "len {}",
            bad.len()
        );
    }
}

/// Malleability / side channels: a modified ciphertext gives a different, deterministic
/// secret (implicit rejection), never an error that would act as an oracle.
#[test]
fn a_modified_ciphertext_gets_implicit_rejection() {
    let (dk, ek) = keys(4);
    let (ct, ss) = MlKem768::encapsulate(&ek, &[4; 32]).unwrap();
    for at in [0, 1, 500, 959, 960, 1_087] {
        let mut bad = ct.clone();
        bad[at] ^= 0x80;
        let r1 = MlKem768::decapsulate(&dk, &bad).expect("no error on a valid length");
        let r2 = MlKem768::decapsulate(&dk, &bad).unwrap();
        assert_ne!(r1, ss, "byte {at}");
        assert_eq!(r1, r2, "byte {at}: rejection is deterministic");
    }
}

/// The rejection secret depends on the key: another recipient learns nothing from it.
#[test]
fn the_rejection_secret_is_bound_to_the_decapsulation_key() {
    let (dk_a, ek_a) = keys(5);
    let (dk_b, _) = keys(6);
    let (ct, _) = MlKem768::encapsulate(&ek_a, &[5; 32]).unwrap();
    let mut bad = ct.clone();
    bad[10] ^= 1;
    assert_ne!(
        MlKem768::decapsulate(&dk_a, &bad).unwrap(),
        MlKem768::decapsulate(&dk_b, &bad).unwrap()
    );
}

/// Side channels: errors describe the input class, never the bytes.
#[test]
fn kem_errors_carry_no_input() {
    for e in [
        KemError::EncapsulationKeyLength,
        KemError::InvalidEncapsulationKey,
        KemError::CiphertextLength,
    ] {
        let text = format!("{e} {e:?}");
        assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text}");
    }
}
