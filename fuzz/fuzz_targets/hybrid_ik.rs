//! The hybrid IK handshake, suite 0x02 (PQ-AUTH, PROTOCOL §7.5.3), as it arrives from an
//! unauthenticated network: message 1 on both channels for the responder, message 2 for the
//! initiator.
//!
//! Inputs: arbitrary bytes (mode bit 0 clear), or a genuine message with modified bytes (bit 0
//! set). Bit 1 selects the end-to-end channel, bit 2 the initiator side (message 2), bit 3 a
//! responder that also accepts the classical and IKhfs suites.
//! Properties: no panic; a message 1 is accepted only intact, with the true initiator and both
//! of its fingerprints, never as another suite; a message 2 completes only intact; the genuine
//! messages are accepted.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::noise::{self, Channel};
use zt_crypto::{HybridPublicKey, Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;

struct Fixture {
    keys: Keyring,
    responder: HybridPublicKey,
    initiator: Identity,
    /// Genuine message 1 per channel: `[Outer, EndToEnd]`, with a small payload.
    msg1: [Vec<u8>; 2],
}

const PAYLOAD: [u8; 64] = [0x54; 64];

fn channel(i: usize) -> Channel {
    if i == 0 { Channel::Outer } else { Channel::EndToEnd }
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let responder = Identity::generate().expect("rng");
        let initiator = Identity::generate().expect("rng");
        let key = responder.hybrid_public_key();
        let msg1 = [0, 1].map(|i| {
            noise::initiate_suite(&initiator, &key, channel(i), HYBRID, &PAYLOAD)
                .expect("msg1")
                .0
        });
        Fixture {
            keys: Keyring::single(responder),
            responder: key,
            initiator,
            msg1,
        }
    })
}

/// `(hi, lo, xor)` triples on `genuine`; a shorter tail truncates.
fn mutate(genuine: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut msg = genuine.to_vec();
    for t in rest.chunks(3) {
        match *t {
            [hi, lo, x] => {
                let len = msg.len().max(1);
                let at = usize::from(u16::from_be_bytes([hi, lo])) % len;
                if let Some(b) = msg.get_mut(at) {
                    *b ^= x;
                }
            }
            [cut, ..] => msg.truncate(msg.len().saturating_sub(usize::from(cut))),
            [] => {}
        }
    }
    msg
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let ch = usize::from(mode & 2 != 0);
    if mode & 4 != 0 {
        // Initiator side: a fresh message 1, then the fuzzed message 2.
        let Ok((msg1, waiting)) =
            noise::initiate_suite(&f.initiator, &f.responder, channel(ch), HYBRID, &[])
        else {
            return;
        };
        let genuine = noise::respond_suites(&f.keys, &msg1, channel(ch), AcceptedSuites::only(HYBRID))
            .expect("genuine msg1")
            .accept()
            .expect("accept")
            .0;
        let msg2 = if mode & 1 == 0 { rest.to_vec() } else { mutate(&genuine, rest) };
        match waiting.complete(&msg2) {
            Ok(_) => assert_eq!(msg2, genuine, "a modified message 2 completed"),
            Err(_) => assert_ne!(msg2, genuine, "the genuine message 2 failed"),
        }
        return;
    }
    let genuine = &f.msg1[ch];
    let msg1 = if mode & 1 == 0 { rest.to_vec() } else { mutate(genuine, rest) };
    let accepted = if mode & 8 != 0 {
        AcceptedSuites::new(HandshakeSuite::ALL).expect("set")
    } else {
        AcceptedSuites::only(HYBRID)
    };
    match noise::respond_suites(&f.keys, &msg1, channel(ch), accepted) {
        Ok(pending) => {
            assert_eq!(&msg1, genuine, "a modified message 1 was accepted");
            assert_eq!(pending.suite(), HYBRID);
            assert_eq!(pending.peer(), f.initiator.fingerprint());
            assert_eq!(pending.hybrid_peer(), Some(f.initiator.hybrid_fingerprint()));
            assert_eq!(pending.payload(), PAYLOAD);
        }
        Err(_) => assert_ne!(&msg1, genuine, "the genuine message 1 was refused"),
    }
    // Never valid on the other channel.
    assert!(noise::respond_suites(&f.keys, &msg1, channel(1 - ch), accepted).is_err());
});
