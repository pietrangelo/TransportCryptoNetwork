//! Message 2 as the initiator receives it (PQ-1): the hybrid suite reads `ekem1` and
//! decapsulates it with the ephemeral ML-KEM-768 key of message 1, the classical suite reads
//! `e`. A compromised relay, or anyone on the path, controls these bytes.
//!
//! Each input starts a fresh handshake (mode bit 0: hybrid end to end, else classical), lets
//! the genuine responder answer, and then feeds either arbitrary bytes (mode bit 1 clear) or
//! the genuine message 2 modified by `(position, xor)` pairs (bit 1 set; an odd trailing byte
//! truncates).
//! Properties: no panic; a message 2 that differs from the genuine one is never accepted;
//! the genuine one always is, and its keys match the responder's.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};

struct Fixture {
    initiator: Identity,
    agent: zt_crypto::PublicKey,
    keys: Keyring,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let agent = Identity::generate().expect("rng");
        Fixture {
            initiator: Identity::generate().expect("rng"),
            agent: agent.public_key(),
            keys: Keyring::single(agent),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let suite = if mode & 1 != 0 {
        HandshakeSuite::NoiseIkhfs25519MlKem768
    } else {
        HandshakeSuite::NoiseIk25519
    };
    let (msg1, waiting) =
        noise::initiate_suite(&f.initiator, &f.agent, Channel::EndToEnd, suite, &[])
            .expect("initiate");
    let (genuine, mut responder) = noise::respond_suites(
        &f.keys,
        &msg1,
        Channel::EndToEnd,
        AcceptedSuites::only(suite),
    )
    .expect("genuine msg1")
    .accept()
    .expect("accept");
    let msg2 = if mode & 2 == 0 {
        rest.to_vec()
    } else {
        let mut msg = genuine.clone();
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
    };
    match waiting.complete(&msg2) {
        Ok(mut transport) => {
            assert_eq!(msg2, genuine, "a modified message 2 was accepted");
            let ct = transport.encrypt(suite.confirmation()).expect("encrypt");
            assert_eq!(
                responder.decrypt(&ct).expect("same keys"),
                suite.confirmation()
            );
        }
        Err(_) => assert!(msg2 != genuine, "the genuine message 2 was rejected"),
    }
});
