//! The configuration file parsers (relay policy, authorized clients, known nodes, client
//! configuration) on arbitrary text.
//!
//! Properties: no panic; an error message never reports a long hex sequence taken from the
//! file, where a secret key pasted by mistake would be. (A check on whole lines would give
//! false positives: the fuzzer learns to write the text of the errors.)
//!
//! Phase 6: the `[[authorities]]` blocks of the policy and of the authorized clients (they come
//! from the same parsers), the `revoked.toml` denylist and the client certificate file.
//!
//! Review 0008 (finding A8-7): `relay.toml` (handshake suites and admission limits). An
//! accepted file always gives limits that validate.
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use zt_net::config;

/// The hex sequences of at least 32 characters present in the text.
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
    match config::parse_relay_settings("f", text) {
        Ok(settings) => assert_eq!(settings.admission.validate(), Ok(())),
        Err(e) => check(text, e),
    }
    match config::parse_certificate_file("f", text) {
        // An accepted file contains a certificate that conforms to the format.
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
