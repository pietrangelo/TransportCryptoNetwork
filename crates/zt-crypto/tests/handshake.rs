//! Specifica e attacchi dell'adapter crittografico (Adversarial TDD, Fase 2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use zt_crypto::noise::{self, Channel, MAX_PLAINTEXT_LEN};
use zt_crypto::{CryptoError, Identity, PublicKey};

fn pair(initiator: &Identity, responder: &Identity, ch: Channel) -> (noise::Transport, noise::Transport) {
    let (msg1, waiting) = noise::initiate(initiator, &responder.public_key(), ch).unwrap();
    let pending = noise::respond(responder, &msg1, ch).unwrap();
    assert_eq!(pending.peer(), initiator.fingerprint(), "responder learns initiator identity");
    let (msg2, resp) = pending.accept().unwrap();
    let init = waiting.complete(&msg2).unwrap();
    (init, resp)
}

// ---------- specifica ----------

#[test]
fn generated_identities_are_distinct_and_round_trip_through_hex() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
    let restored = Identity::from_secret_hex(&a.to_secret_hex()).unwrap();
    assert_eq!(restored.public_key(), a.public_key());
    let pk: PublicKey = a.public_key().to_string().parse().unwrap();
    assert_eq!(pk, a.public_key());
    assert_eq!(pk.fingerprint(), a.fingerprint());
}

#[test]
fn ik_handshake_establishes_a_bidirectional_channel() {
    let client = Identity::generate().unwrap();
    let relay = Identity::generate().unwrap();
    let (mut c, mut r) = pair(&client, &relay, Channel::Outer);
    assert_eq!(c.peer(), relay.fingerprint());
    assert_eq!(r.peer(), client.fingerprint());
    let ct = c.encrypt(b"hello relay").unwrap();
    assert_eq!(r.decrypt(&ct).unwrap(), b"hello relay");
    let ct = r.encrypt(b"hello client").unwrap();
    assert_eq!(c.decrypt(&ct).unwrap(), b"hello client");
}

#[test]
fn maximum_plaintext_fits_one_noise_message() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let (mut x, mut y) = pair(&a, &b, Channel::EndToEnd);
    let big = vec![0x42; MAX_PLAINTEXT_LEN];
    let ct = x.encrypt(&big).unwrap();
    assert_eq!(ct.len(), 65_535);
    assert_eq!(y.decrypt(&ct).unwrap(), big);
    assert!(matches!(x.encrypt(&[0; MAX_PLAINTEXT_LEN + 1]), Err(CryptoError::MessageTooLarge)));
}

// ---------- attacchi ----------

#[test]
fn initiator_rejects_an_impostor_responder() {
    // Il client pinna la chiave del relay: un MITM con un'altra chiave non completa l'handshake.
    let client = Identity::generate().unwrap();
    let relay = Identity::generate().unwrap();
    let mitm = Identity::generate().unwrap();
    let (msg1, waiting) = noise::initiate(&client, &relay.public_key(), Channel::Outer).unwrap();
    // Il MITM non riesce nemmeno a leggere msg1: è cifrato verso la chiave statica del relay.
    assert!(noise::respond(&mitm, &msg1, Channel::Outer).is_err());
    // Né può forgiare una risposta che il client accetti.
    let (fake1, _) = noise::initiate(&mitm, &mitm.public_key(), Channel::Outer).unwrap();
    let (fake2, _) = noise::respond(&mitm, &fake1, Channel::Outer).unwrap().accept().unwrap();
    assert!(waiting.complete(&fake2).is_err());
}

#[test]
fn channels_are_domain_separated() {
    // Un msg1 del canale end-to-end non vale sul canale esterno (prologue diverso).
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let (msg1, _) = noise::initiate(&a, &b.public_key(), Channel::EndToEnd).unwrap();
    assert!(noise::respond(&b, &msg1, Channel::Outer).is_err());
}

#[test]
fn tampered_handshake_and_transport_messages_are_rejected() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let (mut msg1, _) = noise::initiate(&a, &b.public_key(), Channel::Outer).unwrap();
    let last = msg1.len() - 1;
    msg1[last] ^= 1;
    assert!(noise::respond(&b, &msg1, Channel::Outer).is_err());

    let (mut x, mut y) = pair(&a, &b, Channel::Outer);
    let mut ct = x.encrypt(b"payload").unwrap();
    ct[0] ^= 0x80;
    assert!(matches!(y.decrypt(&ct), Err(CryptoError::Decrypt)));
}

#[test]
fn replayed_and_reordered_transport_messages_are_rejected() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let (mut x, mut y) = pair(&a, &b, Channel::Outer);
    let first = x.encrypt(b"one").unwrap();
    let second = x.encrypt(b"two").unwrap();
    assert!(y.decrypt(&second).is_err(), "out of order");
    let (mut x, mut y) = pair(&a, &b, Channel::Outer);
    let first_again = x.encrypt(b"one").unwrap();
    y.decrypt(&first_again).unwrap();
    assert!(y.decrypt(&first_again).is_err(), "replay");
    let _ = first;
}

#[test]
fn garbage_handshake_inputs_never_panic() {
    let b = Identity::generate().unwrap();
    for len in [0, 1, 31, 32, 95, 96, 97, 1000, 65_535, 70_000] {
        assert!(noise::respond(&b, &vec![0xff; len], Channel::Outer).is_err(), "len {len}");
    }
}

#[test]
fn weak_and_malformed_public_keys_are_rejected() {
    // Il punto identità (y = 1) è di ordine piccolo: un DH con esso dà un segreto noto.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert!(matches!(hex::encode(identity).parse::<PublicKey>(), Err(CryptoError::WeakKey)));
    for bad in ["", "zz", &"0".repeat(63), &"0".repeat(65), &"g".repeat(64)] {
        assert!(bad.parse::<PublicKey>().is_err(), "{bad:?}");
    }
    assert!(Identity::from_secret_hex("00").is_err());
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let id = Identity::generate().unwrap();
    let secret = id.to_secret_hex();
    let rendered = format!("{id:?}");
    assert!(!rendered.contains(secret.as_str()), "{rendered}");
    assert!(rendered.contains("redacted"));
}
