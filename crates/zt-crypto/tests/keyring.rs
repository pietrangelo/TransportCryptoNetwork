//! Rotazione delle chiavi (Fase 5, PROTOCOL §14): un responder con chiave corrente e
//! precedente accetta i `msg1` verso entrambe, e nessun altro.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use zt_crypto::noise::{self, Channel};
use zt_crypto::{CryptoError, Identity, Keyring};

fn handshake_with(pinned: &Identity, keys: &Keyring, ch: Channel) -> Result<(), CryptoError> {
    let initiator = Identity::generate().unwrap();
    let (msg1, waiting) = noise::initiate(&initiator, &pinned.public_key(), ch)?;
    let pending = noise::respond_any(keys, &msg1, ch)?;
    assert_eq!(pending.peer(), initiator.fingerprint());
    let (msg2, mut resp) = pending.accept()?;
    let mut init = waiting.complete(&msg2)?;
    // Il canale funziona in entrambe le direzioni.
    let ct = init.encrypt(b"ping")?;
    assert_eq!(resp.decrypt(&ct)?, b"ping");
    let ct = resp.encrypt(b"pong")?;
    assert_eq!(init.decrypt(&ct)?, b"pong");
    Ok(())
}

fn rotating() -> (Identity, Identity, Keyring) {
    let new = Identity::generate().unwrap();
    let old = Identity::generate().unwrap();
    let keys = Keyring::rotating(
        Identity::from_secret_hex(&new.to_secret_hex()).unwrap(),
        Identity::from_secret_hex(&old.to_secret_hex()).unwrap(),
    )
    .unwrap();
    (new, old, keys)
}

// ---------- specifica ----------

#[test]
fn a_peer_pinning_the_current_key_completes_the_handshake() {
    let (new, _, keys) = rotating();
    for ch in [Channel::Outer, Channel::EndToEnd] {
        handshake_with(&new, &keys, ch).unwrap();
    }
}

#[test]
fn a_peer_still_pinning_the_previous_key_completes_the_handshake() {
    let (_, old, keys) = rotating();
    for ch in [Channel::Outer, Channel::EndToEnd] {
        handshake_with(&old, &keys, ch).unwrap();
    }
}

#[test]
fn a_single_key_keyring_behaves_like_respond() {
    let only = Identity::generate().unwrap();
    let keys = Keyring::single(Identity::from_secret_hex(&only.to_secret_hex()).unwrap());
    handshake_with(&only, &keys, Channel::Outer).unwrap();
    assert!(keys.previous().is_none());
}

// ---------- attacchi ----------

#[test]
fn a_key_that_is_neither_current_nor_previous_is_refused() {
    let (_, _, keys) = rotating();
    let stranger = Identity::generate().unwrap();
    assert_eq!(
        handshake_with(&stranger, &keys, Channel::Outer),
        Err(CryptoError::Handshake)
    );
}

#[test]
fn once_the_previous_key_is_dropped_its_pin_stops_working() {
    let (new, old, _) = rotating();
    let keys = Keyring::single(Identity::from_secret_hex(&new.to_secret_hex()).unwrap());
    assert_eq!(
        handshake_with(&old, &keys, Channel::EndToEnd),
        Err(CryptoError::Handshake)
    );
}

#[test]
fn rotating_to_the_same_key_is_a_configuration_error() {
    let k = Identity::generate().unwrap();
    let same = || Identity::from_secret_hex(&k.to_secret_hex()).unwrap();
    assert!(Keyring::rotating(same(), same()).is_err());
}

#[test]
fn a_message_for_the_previous_key_on_the_other_channel_is_refused() {
    // La separazione di dominio dei canali vale anche per la chiave precedente.
    let (_, old, keys) = rotating();
    let initiator = Identity::generate().unwrap();
    let (msg1, _) = noise::initiate(&initiator, &old.public_key(), Channel::Outer).unwrap();
    assert!(noise::respond_any(&keys, &msg1, Channel::EndToEnd).is_err());
}
