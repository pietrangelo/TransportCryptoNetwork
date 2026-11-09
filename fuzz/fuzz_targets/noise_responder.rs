//! The first message of the IK handshake, as it arrives from an unauthenticated network, on
//! the outer channel and on the end-to-end one.
//!
//! Half of the inputs are arbitrary bytes; the other half is a **genuine** msg1 with modified
//! bytes, so the fuzzer also reaches the accepting branch (finding 0004-6).
//! Properties: no panic; an accepted msg1 reveals the true identity of the initiator, never
//! another one (Noise authenticates the static key); the intact genuine msg1 is accepted.
//!
//! Phase 6 (PROTOCOL §15.3): with bit 1 of the mode the genuine msg1 carries a payload (a
//! certificate); with bit 2 the remaining bytes are the payload of a new msg1. The payload
//! returned by the responder is the one sent; a payload over the maximum is never accepted
//! nor sent.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel, MAX_HANDSHAKE_PAYLOAD_LEN};

/// The payload of genuine msg1s with payload: as long as the vector of §15.13.
const PAYLOAD: [u8; 187] = [0x54; 187];

struct Fixture {
    responder: Identity,
    initiator: Identity,
    /// One genuine msg1 per channel: `[Outer, EndToEnd]`.
    msg1: [Vec<u8>; 2],
    /// One genuine msg1 with [`PAYLOAD`] per channel.
    with_payload: [Vec<u8>; 2],
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let responder = Identity::generate().expect("rng");
        let initiator = Identity::generate().expect("rng");
        let msg1 = [Channel::Outer, Channel::EndToEnd].map(|ch| {
            noise::initiate(&initiator, &responder.public_key(), ch)
                .expect("initiate")
                .0
        });
        let with_payload = [Channel::Outer, Channel::EndToEnd].map(|ch| {
            noise::initiate_with_payload(&initiator, &responder.public_key(), ch, &PAYLOAD)
                .expect("initiate with payload")
                .0
        });
        Fixture {
            responder,
            initiator,
            msg1,
            with_payload,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 4 != 0 {
        // The remaining bytes as the payload of a new msg1.
        for channel in [Channel::Outer, Channel::EndToEnd] {
            match noise::initiate_with_payload(
                &f.initiator,
                &f.responder.public_key(),
                channel,
                rest,
            ) {
                Ok((msg, _)) => {
                    assert!(
                        rest.len() <= MAX_HANDSHAKE_PAYLOAD_LEN,
                        "oversized payload sent"
                    );
                    let pending = noise::respond(&f.responder, &msg, channel).expect("genuine");
                    assert_eq!(pending.payload(), rest, "payload changed in transit");
                }
                Err(_) => assert!(rest.len() > MAX_HANDSHAKE_PAYLOAD_LEN, "payload refused"),
            }
        }
        return;
    }
    let genuine = if mode & 2 == 0 {
        &f.msg1
    } else {
        &f.with_payload
    };
    let sent: &[u8] = if mode & 2 == 0 { &[] } else { &PAYLOAD };
    for (i, channel) in [Channel::Outer, Channel::EndToEnd].into_iter().enumerate() {
        let msg = if mode & 1 == 0 {
            rest.to_vec()
        } else {
            // (position, xor) pairs on the genuine msg1; an odd trailing byte truncates.
            let mut msg = genuine[i].clone();
            for pair in rest.chunks(2) {
                match *pair {
                    [pos, x] => {
                        let len = msg.len().max(1);
                        if let Some(b) = msg.get_mut(usize::from(pos) % len) {
                            *b ^= x;
                        }
                    }
                    [cut] => msg.truncate(usize::from(cut)),
                    _ => {}
                }
            }
            msg
        };
        if let Ok(pending) = noise::respond(&f.responder, &msg, channel) {
            assert_eq!(
                pending.peer(),
                f.initiator.fingerprint(),
                "a modified msg1 was accepted with another identity"
            );
            assert!(pending.payload().len() <= MAX_HANDSHAKE_PAYLOAD_LEN);
            if msg == genuine[i] {
                assert_eq!(pending.payload(), sent, "the genuine payload changed");
            }
            let _ = pending.accept();
        } else {
            assert!(msg != genuine[i], "the genuine msg1 was rejected");
        }
    }
});
