//! Il primo messaggio dell'handshake IK, così come arriva da una rete non autenticata, sul
//! canale esterno e su quello end-to-end.
//!
//! Metà degli input sono byte arbitrari; l'altra metà è un msg1 **autentico** con byte
//! modificati, così il fuzzer raggiunge anche il ramo che accetta (finding 0004-6).
//! Proprietà: nessun panic; un msg1 accettato rivela l'identità vera dell'iniziatore, mai
//! un'altra (Noise autentica la chiave statica); il msg1 autentico intatto è accettato.
//!
//! Fase 6 (PROTOCOL §15.3): con il bit 1 del modo il msg1 autentico porta un payload (un
//! certificato); con il bit 2 i byte restanti sono il payload di un msg1 nuovo. Il payload
//! restituito dal responder è quello inviato; un payload oltre il massimo non è mai accettato
//! né inviato.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel, MAX_HANDSHAKE_PAYLOAD_LEN};

/// Il payload dei msg1 autentici con payload: lungo quanto il vettore di §15.13.
const PAYLOAD: [u8; 187] = [0x54; 187];

struct Fixture {
    responder: Identity,
    initiator: Identity,
    /// Un msg1 autentico per canale: `[Outer, EndToEnd]`.
    msg1: [Vec<u8>; 2],
    /// Un msg1 autentico con [`PAYLOAD`] per canale.
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
        // I byte restanti come payload di un msg1 nuovo.
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
            // Coppie (posizione, xor) sul msg1 autentico; un byte finale dispari tronca.
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
