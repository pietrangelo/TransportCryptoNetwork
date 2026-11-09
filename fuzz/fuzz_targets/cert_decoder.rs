//! The client certificate decoder (PROTOCOL §15.1) on arbitrary bytes: it is the first code
//! that reads the payload of message 1, before any signature.
//!
//! Properties: no panic; an accepted certificate re-encodes identically (`encode_tbs` plus the
//! signature: a single encoding per content); an error reports only metadata, never bytes of
//! the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zt_domain::{CertFormatError, decode_certificate};
use zt_domain::limits::{MAX_CERT_LEN, MIN_CERT_LEN};

/// Hex sequences of at least 16 characters.
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
            let mut message = format!("{e} {e:?}");
            // The lifetime is allowed metadata (plan §2, `Lifetime{secs}`) and can have 20 decimal
            // digits: only that number is removed, the rest of the message stays checked.
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
