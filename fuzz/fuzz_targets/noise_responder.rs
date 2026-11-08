//! Il primo messaggio dell'handshake IK, così come arriva da una rete non autenticata, sul
//! canale esterno e su quello end-to-end. Proprietà: nessun panic, nessuna allocazione
//! sproporzionata; un messaggio accettato rivela solo una fingerprint.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel};

fn responder() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(|| Identity::generate().expect("rng"))
}

fuzz_target!(|data: &[u8]| {
    for channel in [Channel::Outer, Channel::EndToEnd] {
        if let Ok(pending) = noise::respond(responder(), data, channel) {
            let _ = pending.peer();
        }
    }
});
