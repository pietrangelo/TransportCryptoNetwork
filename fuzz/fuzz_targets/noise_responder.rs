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
//!
//! PQ-1 (PROTOCOL §7.5): with bit 3 of the mode the same runs with the hybrid suite
//! `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` on the end-to-end channel, through the
//! vendored snow's HFS paths (`e1` read, then `ekem1` written by `accept`). The responder
//! accepts both suites, as an upgraded agent does; the reported suite is the one sent; the
//! outer channel never accepts a hybrid msg1.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::noise::{self, Channel, MAX_HANDSHAKE_PAYLOAD_LEN};
use zt_crypto::{Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

/// The payload of genuine msg1s with payload: as long as the vector of §15.13.
const PAYLOAD: [u8; 187] = [0x54; 187];

struct Fixture {
    responder: Identity,
    /// The responder's key as an agent holds it.
    keys: Keyring,
    initiator: Identity,
    /// One genuine msg1 per channel: `[Outer, EndToEnd]`.
    msg1: [Vec<u8>; 2],
    /// One genuine msg1 with [`PAYLOAD`] per channel.
    with_payload: [Vec<u8>; 2],
    /// Genuine hybrid msg1s (end to end): without and with [`PAYLOAD`].
    hybrid: [Vec<u8>; 2],
}

fn both() -> AcceptedSuites {
    AcceptedSuites::new([HandshakeSuite::NoiseIk25519, HFS]).expect("set")
}

/// `(position, xor)` pairs on `genuine`; an odd trailing byte truncates.
fn mutate(genuine: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut msg = genuine.to_vec();
    for pair in rest.chunks(2) {
        match *pair {
            [pos, x] => {
                let len = msg.len().max(1);
                // Spread the positions over the whole message (a hybrid msg1 is over 1 KiB).
                let at = (usize::from(pos) * 7 + usize::from(x)) % len;
                if let Some(b) = msg.get_mut(at) {
                    *b ^= x | 1;
                }
            }
            [cut] => msg.truncate(usize::from(cut) * 8),
            _ => {}
        }
    }
    msg
}

fn hybrid(f: &Fixture, mode: u8, rest: &[u8]) {
    if mode & 4 != 0 {
        match noise::initiate_suite(
            &f.initiator,
            &f.responder.public_key(),
            Channel::EndToEnd,
            HFS,
            rest,
        ) {
            Ok((msg, _)) => {
                assert!(rest.len() <= MAX_HANDSHAKE_PAYLOAD_LEN, "oversized payload sent");
                let pending = noise::respond_suites(&f.keys, &msg, Channel::EndToEnd, both())
                    .expect("genuine hybrid msg1");
                assert_eq!(pending.suite(), HFS);
                assert_eq!(pending.payload(), rest, "payload changed in transit");
            }
            Err(_) => assert!(rest.len() > MAX_HANDSHAKE_PAYLOAD_LEN, "payload refused"),
        }
        return;
    }
    let (genuine, sent): (&[u8], &[u8]) = if mode & 2 == 0 {
        (&f.hybrid[0], &[])
    } else {
        (&f.hybrid[1], &PAYLOAD)
    };
    let msg = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        mutate(genuine, rest)
    };
    assert!(
        noise::respond_suites(&f.keys, &msg, Channel::Outer, AcceptedSuites::only(HFS)).is_err(),
        "the outer channel accepted a hybrid msg1"
    );
    if let Ok(pending) = noise::respond_suites(&f.keys, &msg, Channel::EndToEnd, both()) {
        assert_eq!(
            pending.peer(),
            f.initiator.fingerprint(),
            "a modified msg1 was accepted with another identity"
        );
        assert!(pending.payload().len() <= MAX_HANDSHAKE_PAYLOAD_LEN);
        if msg == genuine {
            assert_eq!(pending.suite(), HFS);
            assert_eq!(pending.payload(), sent, "the genuine payload changed");
        }
        // Runs the responder's KEM path (encapsulation to `e1`).
        let _ = pending.accept();
    } else {
        assert!(msg != genuine, "the genuine hybrid msg1 was rejected");
    }
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let responder = Identity::generate().expect("rng");
        let keys = Keyring::single(
            Identity::from_secret_hex(&responder.to_secret_hex()).expect("copy"),
        );
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
        let hybrid = [&[][..], &PAYLOAD[..]].map(|payload| {
            noise::initiate_suite(
                &initiator,
                &responder.public_key(),
                Channel::EndToEnd,
                HFS,
                payload,
            )
            .expect("initiate hybrid")
            .0
        });
        Fixture {
            responder,
            keys,
            initiator,
            msg1,
            with_payload,
            hybrid,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 8 != 0 {
        hybrid(f, mode, rest);
        return;
    }
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
