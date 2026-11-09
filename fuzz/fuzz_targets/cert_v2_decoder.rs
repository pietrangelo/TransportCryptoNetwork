//! The certificate decoder for every version (PROTOCOL §15.1, §15.14) on arbitrary bytes: it
//! is the first code that reads the payload of message 1, before any signature.
//!
//! Properties: no panic; an accepted v2 certificate is within the v2 bounds and re-encodes
//! identically (`encode_tbs` ‖ sig_M ‖ sig_E: a single encoding per content); an accepted v1
//! certificate likewise; an error reports only metadata, never bytes of the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zt_domain::limits::{MAX_CERT_LEN, MAX_CERT_V2_LEN, MIN_CERT_LEN, MIN_CERT_V2_LEN};
use zt_domain::{AnyParsedCert, CertFormatError, decode_any_certificate};

/// Hex sequences of at least 16 characters.
fn hex_runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_hexdigit())
        .filter(|run| run.len() >= 16)
}

fuzz_target!(|data: &[u8]| {
    match decode_any_certificate(data) {
        Ok(AnyParsedCert::V2(parsed)) => {
            assert!((MIN_CERT_V2_LEN..=MAX_CERT_V2_LEN).contains(&data.len()));
            let tbs = parsed.body.encode_tbs();
            assert_eq!(
                tbs.as_slice(),
                parsed.tbs,
                "tbs is not the canonical encoding"
            );
            let mut again = tbs;
            again.extend_from_slice(parsed.mldsa_signature);
            again.extend_from_slice(parsed.ed25519_signature);
            assert_eq!(
                again.as_slice(),
                data,
                "an accepted certificate does not re-encode"
            );
            assert!(parsed.body.not_before() < parsed.body.not_after());
        }
        Ok(AnyParsedCert::V1(parsed)) => {
            assert!((MIN_CERT_LEN..=MAX_CERT_LEN).contains(&data.len()));
            let mut again = parsed.body.encode_tbs();
            again.extend_from_slice(parsed.signature);
            assert_eq!(
                again.as_slice(),
                data,
                "an accepted certificate does not re-encode"
            );
        }
        Err(e) => {
            let mut message = format!("{e} {e:?}");
            if let CertFormatError::Lifetime { secs } = e {
                message = message.replace(&secs.to_string(), "<secs>");
            }
            assert!(
                hex_runs(&message).next().is_none(),
                "error carries input bytes: {message}"
            );
        }
    }
});
