//! Il primo messaggio dell'handshake IK, così come arriva da una rete non autenticata, sul
//! canale esterno e su quello end-to-end.
//!
//! Metà degli input sono byte arbitrari; l'altra metà è un msg1 **autentico** con byte
//! modificati, così il fuzzer raggiunge anche il ramo che accetta (finding 0004-6).
//! Proprietà: nessun panic; un msg1 accettato rivela l'identità vera dell'iniziatore, mai
//! un'altra (Noise autentica la chiave statica); il msg1 autentico intatto è accettato.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel};

struct Fixture {
    responder: Identity,
    initiator: Identity,
    /// Un msg1 autentico per canale: `[Outer, EndToEnd]`.
    msg1: [Vec<u8>; 2],
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
        Fixture {
            responder,
            initiator,
            msg1,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    for (i, channel) in [Channel::Outer, Channel::EndToEnd].into_iter().enumerate() {
        let msg = if mode & 1 == 0 {
            rest.to_vec()
        } else {
            // Coppie (posizione, xor) sul msg1 autentico; un byte finale dispari tronca.
            let mut msg = f.msg1[i].clone();
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
            let _ = pending.accept();
        } else {
            assert!(
                msg != f.msg1[i],
                "the genuine msg1 was rejected"
            );
        }
    }
});
