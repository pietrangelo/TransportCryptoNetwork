//! Messaggi di trasporto arbitrari dopo un handshake vero, intercalati a messaggi autentici.
//! Proprietà: nessun panic; un messaggio falso non viene mai accettato e non desincronizza il
//! canale (i messaggi autentici successivi, anche oltre un rekey, si decifrano ancora).
#![no_main]

use libfuzzer_sys::fuzz_target;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel, REKEY_INTERVAL};

fuzz_target!(|data: &[u8]| {
    let a = Identity::generate().expect("rng");
    let b = Identity::generate().expect("rng");
    let (msg1, waiting) = noise::initiate(&a, &b.public_key(), Channel::EndToEnd).expect("init");
    let (msg2, mut rx) = noise::respond(&b, &msg1, Channel::EndToEnd)
        .expect("respond")
        .accept()
        .expect("accept");
    let mut tx = waiting.complete(&msg2).expect("complete");
    for (i, forged) in data.split(|b| *b == 0xff).take(64).enumerate() {
        assert!(rx.decrypt(forged).is_err(), "forged message accepted");
        // Un messaggio autentico dopo ogni falso, con un salto oltre il rekey a metà.
        let n = if i == 8 { REKEY_INTERVAL } else { 1 };
        for _ in 0..n {
            let ct = tx.encrypt(forged).expect("encrypt");
            assert_eq!(rx.decrypt(&ct).expect("genuine message rejected"), forged);
        }
    }
});
