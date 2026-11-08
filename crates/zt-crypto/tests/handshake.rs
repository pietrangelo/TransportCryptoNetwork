//! Specifica e attacchi dell'adapter crittografico (Adversarial TDD, Fase 2).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use zt_crypto::noise::{self, Channel, MAX_PLAINTEXT_LEN};
use zt_crypto::{CryptoError, Identity, PublicKey};

fn pair(
    initiator: &Identity,
    responder: &Identity,
    ch: Channel,
) -> (noise::Transport, noise::Transport) {
    let (msg1, waiting) = noise::initiate(initiator, &responder.public_key(), ch).unwrap();
    let pending = noise::respond(responder, &msg1, ch).unwrap();
    assert_eq!(
        pending.peer(),
        initiator.fingerprint(),
        "responder learns initiator identity"
    );
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
    assert!(matches!(
        x.encrypt(&vec![0; MAX_PLAINTEXT_LEN + 1]),
        Err(CryptoError::MessageTooLarge)
    ));
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
    let (fake2, _) = noise::respond(&mitm, &fake1, Channel::Outer)
        .unwrap()
        .accept()
        .unwrap();
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
        assert!(
            noise::respond(&b, &vec![0xff; len], Channel::Outer).is_err(),
            "len {len}"
        );
    }
}

#[test]
fn weak_and_malformed_public_keys_are_rejected() {
    // Il punto identità (y = 1) è di ordine piccolo: un DH con esso dà un segreto noto.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert!(matches!(
        hex::encode(identity).parse::<PublicKey>(),
        Err(CryptoError::WeakKey)
    ));
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

// ======================= Fase 6: payload del messaggio 1 (PROTOCOL §15.3) =======================

use zt_crypto::Keyring;
use zt_crypto::noise::MAX_HANDSHAKE_PAYLOAD_LEN;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn prologue(ch: Channel) -> &'static [u8] {
    match ch {
        Channel::Outer => b"TCN/1 outer",
        Channel::EndToEnd => b"TCN/1 end-to-end",
    }
}

/// Un'identità con il seme noto, per costruire a mano stati Noise equivalenti.
fn seeded(b: u8) -> ([u8; 32], Identity) {
    let seed = [b; 32];
    (seed, Identity::from_secret_hex(&hex::encode(seed)).unwrap())
}

/// Il segreto X25519 che Noise usa per un seme Ed25519 (come `Identity`).
fn x25519_secret(seed: [u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&seed).to_scalar_bytes()
}

/// Un initiator scritto con `snow`, senza i controlli di `zt-crypto`: msg1 con `payload`.
fn raw_msg1(
    initiator_seed: [u8; 32],
    responder: &PublicKey,
    ch: Channel,
    payload: &[u8],
) -> Vec<u8> {
    let secret = x25519_secret(initiator_seed);
    let remote = responder.x25519();
    let mut state = snow::Builder::new(PATTERN.parse().unwrap())
        .prologue(prologue(ch))
        .unwrap()
        .local_private_key(&secret)
        .unwrap()
        .remote_public_key(&remote)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut out = vec![0_u8; 65_535];
    let len = state.write_message(payload, &mut out).unwrap();
    out.truncate(len);
    out
}

#[test]
fn msg1_payload_reaches_the_responder_intact() {
    let relay = Identity::generate().unwrap();
    let client = Identity::generate().unwrap();
    for ch in [Channel::Outer, Channel::EndToEnd] {
        for len in [1, 187, 4_328] {
            let payload: Vec<u8> = (0..len)
                .map(|i: usize| u8::try_from(i % 251).unwrap())
                .collect();
            let (msg1, waiting) =
                noise::initiate_with_payload(&client, &relay.public_key(), ch, &payload).unwrap();
            let pending = noise::respond(&relay, &msg1, ch).unwrap();
            assert_eq!(pending.peer(), client.fingerprint());
            assert_eq!(pending.payload(), payload.as_slice(), "{ch:?} {len}");
            // L'handshake si completa normalmente.
            let (msg2, mut resp) = pending.accept().unwrap();
            let mut init = waiting.complete(&msg2).unwrap();
            let ct = init.encrypt(b"after").unwrap();
            assert_eq!(resp.decrypt(&ct).unwrap(), b"after");
        }
    }
    // Anche con `respond_any` sulla chiave precedente (rotazione, PROTOCOL §14).
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let old_pin = old.public_key();
    let keys = Keyring::rotating(new, old).unwrap();
    for ch in [Channel::Outer, Channel::EndToEnd] {
        let (msg1, _) =
            noise::initiate_with_payload(&client, &old_pin, ch, b"certificate").unwrap();
        let pending = noise::respond_any(&keys, &msg1, ch).unwrap();
        assert_eq!(pending.payload(), b"certificate");
    }
}

#[test]
fn initiate_without_payload_is_unchanged() {
    let relay = Identity::generate().unwrap();
    let client = Identity::generate().unwrap();
    for ch in [Channel::Outer, Channel::EndToEnd] {
        let (msg1, _) = noise::initiate(&client, &relay.public_key(), ch).unwrap();
        // e (32) + s cifrata (48) + tag del payload vuoto (16).
        assert_eq!(msg1.len(), 96);
        let pending = noise::respond(&relay, &msg1, ch).unwrap();
        assert!(pending.payload().is_empty());
        let (msg1, _) =
            noise::initiate_with_payload(&client, &relay.public_key(), ch, &[]).unwrap();
        assert_eq!(msg1.len(), 96);
        assert!(
            noise::respond(&relay, &msg1, ch)
                .unwrap()
                .payload()
                .is_empty()
        );
    }
}

#[test]
fn an_oversized_msg1_payload_is_refused_on_both_sides() {
    let relay = Identity::generate().unwrap();
    let (seed, client) = seeded(0x21);
    let max = vec![0x42; MAX_HANDSHAKE_PAYLOAD_LEN];
    let over = vec![0x42; MAX_HANDSHAKE_PAYLOAD_LEN + 1];
    assert_eq!(MAX_HANDSHAKE_PAYLOAD_LEN, 4_328);
    for ch in [Channel::Outer, Channel::EndToEnd] {
        // Initiator: il massimo passa, uno in più no.
        assert!(noise::initiate_with_payload(&client, &relay.public_key(), ch, &max).is_ok());
        assert!(matches!(
            noise::initiate_with_payload(&client, &relay.public_key(), ch, &over),
            Err(CryptoError::MessageTooLarge)
        ));
        // Responder, con un initiator che non rispetta il limite.
        let ok = raw_msg1(seed, &relay.public_key(), ch, &max);
        assert_eq!(
            noise::respond(&relay, &ok, ch).unwrap().payload(),
            max.as_slice()
        );
        for len in [MAX_HANDSHAKE_PAYLOAD_LEN + 1, 10_000, 65_535 - 96] {
            let msg1 = raw_msg1(seed, &relay.public_key(), ch, &vec![0x42; len]);
            assert!(
                matches!(
                    noise::respond(&relay, &msg1, ch),
                    Err(CryptoError::Handshake)
                ),
                "{ch:?}: payload of {len} bytes accepted"
            );
        }
    }
}

#[test]
fn a_non_empty_msg2_payload_is_refused_by_the_initiator() {
    let (relay_seed, relay) = seeded(0x31);
    let client = Identity::generate().unwrap();
    // Un responder modificato, scritto con `snow`, che mette un payload nel messaggio 2.
    let reply = |msg1: &[u8], ch: Channel, payload: &[u8]| {
        let secret = x25519_secret(relay_seed);
        let mut state = snow::Builder::new(PATTERN.parse().unwrap())
            .prologue(prologue(ch))
            .unwrap()
            .local_private_key(&secret)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = vec![0_u8; 65_535];
        state.read_message(msg1, &mut buf).unwrap();
        let len = state.write_message(payload, &mut buf).unwrap();
        buf.truncate(len);
        buf
    };
    for ch in [Channel::Outer, Channel::EndToEnd] {
        // Controllo: lo stesso responder con payload vuoto è accettato.
        let (msg1, waiting) = noise::initiate(&client, &relay.public_key(), ch).unwrap();
        assert!(waiting.complete(&reply(&msg1, ch, &[])).is_ok());
        for payload in [&b"x"[..], &[0; 64][..], &[0xff; 4_328][..]] {
            let (msg1, waiting) = noise::initiate(&client, &relay.public_key(), ch).unwrap();
            assert!(
                matches!(
                    waiting.complete(&reply(&msg1, ch, payload)),
                    Err(CryptoError::Handshake)
                ),
                "{ch:?}: msg2 with a {}-byte payload accepted",
                payload.len()
            );
        }
    }
}
