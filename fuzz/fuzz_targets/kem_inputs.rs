//! The ML-KEM-768 parsers on **chosen** input (finding A9-7 of review 0009).
//!
//! In a handshake, `e1` and `ekem1` travel under AEAD, so the byte-level Noise targets never
//! get a mutated key or ciphertext past the tag. The responder hands the decrypted `e1` to
//! `encapsulate` and the initiator the decrypted ciphertext to `decapsulate` unchanged: this
//! target feeds both directly, as an authorized but malicious peer would.
//!
//! Properties: no panic; an encapsulation key is accepted only at its exact length; the
//! genuine key round-trips; a ciphertext of the right length always decapsulates (implicit
//! rejection), to the encapsulated secret only when it is the genuine one; any other length is
//! an error.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::kem::{Kem, KemSeed, MlKem768};

struct Fixture {
    dk: <MlKem768 as Kem>::DecapsulationKey,
    ek: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let (dk, ek) = MlKem768::generate(&KemSeed::from_bytes([0x5a; 64]));
        Fixture { dk, ek }
    })
}

/// `(position, xor)` pairs on `genuine`; an odd trailing byte truncates.
fn mutate(genuine: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut msg = genuine.to_vec();
    for pair in rest.chunks(2) {
        match *pair {
            [pos, x] => {
                let len = msg.len().max(1);
                let at = (usize::from(pos) * 5 + usize::from(x)) % len;
                if let Some(b) = msg.get_mut(at) {
                    *b ^= x | 1;
                }
            }
            [cut] => msg.truncate(usize::from(cut) * 5),
            _ => {}
        }
    }
    msg
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let randomness = [mode; 32];
    let (ct, secret) = MlKem768::encapsulate(&f.ek, &randomness).expect("genuine key");
    match mode % 4 {
        // An encapsulation key from the peer: arbitrary bytes or a mutated genuine one.
        0 | 1 => {
            let ek = if mode % 4 == 0 {
                rest.to_vec()
            } else {
                mutate(&f.ek, rest)
            };
            if let Ok((ct2, _)) = MlKem768::encapsulate(&ek, &randomness) {
                assert_eq!(ek.len(), MlKem768::ENCAPSULATION_KEY_LEN, "wrong length accepted");
                assert_eq!(ct2.len(), MlKem768::CIPHERTEXT_LEN);
            }
        }
        // A ciphertext from the peer: arbitrary bytes or a mutated genuine one.
        _ => {
            let c = if mode % 4 == 2 {
                rest.to_vec()
            } else {
                mutate(&ct, rest)
            };
            match MlKem768::decapsulate(&f.dk, &c) {
                Ok(got) => {
                    assert_eq!(c.len(), MlKem768::CIPHERTEXT_LEN, "wrong length accepted");
                    if c == ct {
                        assert!(got == secret, "the genuine ciphertext gave another secret");
                    }
                }
                Err(_) => assert_ne!(c.len(), MlKem768::CIPHERTEXT_LEN, "implicit rejection broken"),
            }
        }
    }
});
