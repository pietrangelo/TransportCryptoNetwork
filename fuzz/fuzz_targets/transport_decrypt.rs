//! Messaggi di trasporto arbitrari dopo un handshake vero, intercalati a messaggi autentici.
//! Proprietà: nessun panic; un messaggio falso non viene mai accettato e non desincronizza il
//! canale (i messaggi autentici successivi, anche oltre un rekey, si decifrano ancora).
//!
//! Le identità sono fisse: per input resta un solo handshake, il minimo per avere uno stato di
//! trasporto nuovo (finding 0004-6). Il salto oltre il rekey si fa solo se l'input lo chiede.
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
        // Un messaggio autentico dopo ogni falso; con `mode` dispari, al quarto falso si
        // attraversa un rekey.
        let n = if i == 3 && mode & 1 == 1 { REKEY_INTERVAL } else { 1 };
        for _ in 0..n {
            let ct = tx.encrypt(forged).expect("encrypt");
            assert_eq!(rx.decrypt(&ct).expect("genuine message rejected"), forged);
        }
    }
});
