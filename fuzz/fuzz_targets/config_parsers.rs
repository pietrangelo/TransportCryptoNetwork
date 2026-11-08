//! I parser dei file di configurazione (policy del relay, client autorizzati, nodi noti,
//! configurazione del client) su testo arbitrario.
//!
//! Proprietà: nessun panic; un messaggio d'errore non riporta mai una sequenza esadecimale
//! lunga presa dal file, dove starebbe una chiave segreta incollata per sbaglio. (Un controllo
//! sulle righe intere darebbe falsi positivi: il fuzzer impara a scrivere il testo degli errori.)
//!
//! Fase 6: i blocchi `[[authorities]]` di policy e client autorizzati (arrivano dagli stessi
//! parser), la denylist `revoked.toml` e il file del certificato del client.
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use zt_net::config;

/// Le sequenze esadecimali di almeno 32 caratteri presenti nel testo.
fn hex_runs(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_ascii_hexdigit())
        .filter(|run| run.len() >= 32)
        .collect()
}

fn check(text: &str, error: impl std::fmt::Display) {
    let message = error.to_string();
    for run in hex_runs(text) {
        assert!(
            !message.contains(run),
            "error echoes key material: {message}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Err(e) = config::parse_policy("f", text) {
        check(text, e);
    }
    if let Err(e) = config::parse_authorized_clients("f", text) {
        check(text, e);
    }
    if let Err(e) = config::parse_known_nodes("f", text) {
        check(text, e);
    }
    if let Err(e) = config::parse_revocations("f", text) {
        check(text, e);
    }
    match config::parse_certificate_file("f", text) {
        // Un file accettato contiene un certificato che rispetta il formato.
        Ok(file) => assert!(zt_domain::decode_certificate(&file.bytes).is_ok()),
        Err(e) => check(text, e),
    }
    match config::parse_client_settings("f", Path::new("/etc/tcn"), text) {
        Ok(settings) => {
            for node in settings.nodes.keys() {
                if let Err(e) = settings.client_config(node, zt_net::Timeouts::default()) {
                    check(text, e);
                }
            }
        }
        Err(e) => check(text, e),
    }
});
