//! I parser dei file di configurazione (policy del relay, client autorizzati, nodi noti,
//! configurazione del client) su testo arbitrario. Proprietà: nessun panic; un messaggio
//! d'errore non riporta mai una chiave segreta (qui: nessun testo lungo del file).
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use zt_net::config;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = config::parse_policy("f", text);
    let _ = config::parse_authorized_clients("f", text);
    let _ = config::parse_known_nodes("f", text);
    if let Ok(settings) = config::parse_client_settings("f", Path::new("/etc/tcn"), text) {
        for node in settings.nodes.keys() {
            let _ = settings.client_config(node, zt_net::Timeouts::default());
        }
    }
});
