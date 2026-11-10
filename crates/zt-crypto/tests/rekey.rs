//! Periodic rekey of Noise channels (Phase 4).
//!
//! Every [`REKEY_INTERVAL`] messages per direction both parties call Noise's `rekey()`: the
//! transport key advances one-way, so compromising the memory of a process does not reveal
//! the traffic of previous periods. The rekey is implicit (deterministic on the counter), so
//! it does not change the wire format.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel, REKEY_INTERVAL, Transport};

fn pair() -> (Transport, Transport) {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let (msg1, waiting) = noise::initiate(&a, b.public_key(), Channel::Outer).unwrap();
    let (msg2, resp) = noise::respond(&b, &msg1, Channel::Outer)
        .unwrap()
        .accept()
        .unwrap();
    (waiting.complete(&msg2).unwrap(), resp)
}

#[test]
fn rekey_interval_is_a_sane_constant() {
    assert!((256..=1 << 20).contains(&REKEY_INTERVAL));
}

#[test]
fn both_directions_keep_working_across_many_rekeys() {
    let (mut a, mut b) = pair();
    let n = REKEY_INTERVAL * 3 + 7;
    for i in 0..n {
        let msg = (i as u32).to_be_bytes();
        let ct = a.encrypt(&msg).unwrap();
        assert_eq!(b.decrypt(&ct).unwrap(), msg, "a→b message {i}");
        if i % 3 == 0 {
            let ct = b.encrypt(&msg).unwrap();
            assert_eq!(a.decrypt(&ct).unwrap(), msg, "b→a message {i}");
        }
    }
    assert_eq!(a.send_epoch(), n / REKEY_INTERVAL);
    assert_eq!(b.recv_epoch(), n / REKEY_INTERVAL);
    assert_eq!(b.send_epoch(), n.div_ceil(3) / REKEY_INTERVAL);
}

#[test]
fn ciphertext_from_an_old_epoch_is_rejected() {
    let (mut a, mut b) = pair();
    let old = a.encrypt(b"old epoch").unwrap();
    assert_eq!(b.decrypt(&old).unwrap(), b"old epoch");
    for _ in 1..=REKEY_INTERVAL {
        let ct = a.encrypt(b"x").unwrap();
        b.decrypt(&ct).unwrap();
    }
    assert!(b.decrypt(&old).is_err());
}

/// Attack: forged or corrupted messages (a relay or an on-path attacker) must not advance the
/// counter, otherwise they would desynchronize the rekey and kill the channel.
#[test]
fn garbage_before_any_message_does_not_shift_the_receiver() {
    let (mut a, mut b) = pair();
    for _ in 0..REKEY_INTERVAL + 10 {
        assert!(b.decrypt(&[7_u8; 64]).is_err());
    }
    for i in 0..REKEY_INTERVAL * 2 {
        let ct = a.encrypt(b"m").unwrap();
        assert!(b.decrypt(&ct).is_ok(), "desynchronised at {i}");
    }
}
