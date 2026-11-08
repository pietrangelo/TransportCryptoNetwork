//! Il decoder dei certificati client (PROTOCOL §15.1) su byte arbitrari: è il primo codice che
//! legge il payload del messaggio 1, prima di qualsiasi firma.
//!
//! Proprietà: nessun panic; un certificato accettato si ricodifica identico (`encode_tbs` più
//! la firma: una sola codifica per contenuto); un errore riporta solo metadati, mai byte
//! dell'input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zt_domain::decode_certificate;
use zt_domain::limits::{MAX_CERT_LEN, MIN_CERT_LEN};

/// Le sequenze esadecimali di almeno 16 caratteri.
fn hex_runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_hexdigit())
        .filter(|run| run.len() >= 16)
}

fuzz_target!(|data: &[u8]| {
    match decode_certificate(data) {
        Ok(parsed) => {
            assert!((MIN_CERT_LEN..=MAX_CERT_LEN).contains(&data.len()));
            let tbs = parsed.body.encode_tbs();
            assert_eq!(
                tbs.as_slice(),
                parsed.tbs,
                "tbs is not the canonical encoding"
            );
            let mut again = tbs;
            again.extend_from_slice(parsed.signature);
            assert_eq!(
                again.as_slice(),
                data,
                "an accepted certificate does not re-encode"
            );
            assert!(parsed.body.not_before() < parsed.body.not_after());
            assert_ne!(parsed.body.ca_key(), parsed.body.subject_key());
        }
        Err(e) => {
            let message = format!("{e} {e:?}");
            assert!(
                hex_runs(&message).next().is_none(),
                "error carries input bytes: {message}"
            );
        }
    }
});
