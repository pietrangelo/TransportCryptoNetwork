//! Arbitrary transport messages after a real handshake, interleaved with genuine messages.
//! Properties: no panic; a forged message is never accepted and does not desynchronize the
//! channel (subsequent genuine messages, even past a rekey, still decrypt).
//!
//! The identities are fixed: per input only one handshake remains, the minimum to get a fresh
//! transport state (finding 0004-6). The jump past the rekey happens only if the input asks
//! for it.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel, REKEY_INTERVAL};

fn pair() -> &'static (Identity, Identity) {
    static P: OnceLock<(Identity, Identity)> = OnceLock::new();
    P.get_or_init(|| {
        (
            Identity::generate().expect("rng"),
            Identity::generate().expect("rng"),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let (a, b) = pair();
    let (msg1, waiting) = noise::initiate(a, &b.public_key(), Channel::EndToEnd).expect("init");
    let (msg2, mut rx) = noise::respond(b, &msg1, Channel::EndToEnd)
        .expect("respond")
        .accept()
        .expect("accept");
    let mut tx = waiting.complete(&msg2).expect("complete");
    for (i, forged) in data.split(|b| *b == 0xff).take(64).enumerate() {
        assert!(rx.decrypt(forged).is_err(), "forged message accepted");
        // A genuine message after each forged one; with an odd `mode`, at the fourth forged one
        // a rekey is crossed.
        let n = if i == 3 && mode & 1 == 1 { REKEY_INTERVAL } else { 1 };
        for _ in 0..n {
            let ct = tx.encrypt(forged).expect("encrypt");
            assert_eq!(rx.decrypt(&ct).expect("genuine message rejected"), forged);
        }
    }
});
