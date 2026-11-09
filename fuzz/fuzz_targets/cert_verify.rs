//! Certificate verification (PROTOCOL §15.4 steps 3–6) with fixed trust and peer key.
//!
//! Half of the inputs are arbitrary bytes; the other half is a **genuine** certificate (signed
//! by the CA pinned for the peer) with modified bytes, so the fuzzer also reaches the signature
//! and acceptance branches.
//! Properties: no panic; an accepted input is, byte for byte, the genuine certificate, and the
//! claims are its own (no malleability of the encoding or of the signature); the intact
//! certificate is accepted; the same certificate for another peer is rejected.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::{
    CaSigningKey, Identity, cert_key, sign_certificate, trusted_ca_key, verify_certificate,
};
use zt_domain::limits::DEFAULT_AUTHORITY_LIFETIME_SECS;
use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{AllowedNodes, CertBody, CertScope, CertSerial, Fingerprint, NodeId, UnixTime};

struct Fixture {
    trust: CertTrust,
    peer: Fingerprint,
    other: Fingerprint,
    genuine: Vec<u8>,
    body: CertBody,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let ca = CaSigningKey::generate().expect("rng");
        let peer = Identity::generate().expect("rng");
        let other = Identity::generate().expect("rng");
        let node = |n: &str| NodeId::try_from(n).expect("valid");
        let body = CertBody::new(
            cert_key(&ca.public_key()),
            cert_key(&peer.public_key()),
            CertSerial::try_from([0x42; 16]).expect("non-zero"),
            UnixTime::from_secs(1_800_000_000),
            UnixTime::from_secs(1_800_003_600),
            node("alice"),
            CertScope::Only([node("db-01"), node("web-01")].into_iter().collect()),
        )
        .expect("valid body");
        let genuine = sign_certificate(&ca, &body).expect("sign");
        let mut trust = CertTrust::new();
        trust
            .add_authority(
                node("ops-ca"),
                &[trusted_ca_key(&ca.public_key())],
                AllowedNodes::All,
                DEFAULT_AUTHORITY_LIFETIME_SECS,
            )
            .expect("authority");
        trust.set_revocations(Revocations::new([], []).expect("empty"));
        Fixture {
            trust,
            peer: peer.fingerprint(),
            other: other.fingerprint(),
            genuine,
            body,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let input = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        // (position, xor) pairs on the genuine certificate; an odd trailing byte truncates or,
        // with bit 1 of the mode, extends.
        let mut cert = f.genuine.clone();
        for pair in rest.chunks(2) {
            match *pair {
                [pos, x] => {
                    let len = cert.len().max(1);
                    if let Some(b) = cert.get_mut(usize::from(pos) % len) {
                        *b ^= x;
                    }
                }
                [n] if mode & 2 != 0 => cert.extend(std::iter::repeat_n(n, usize::from(n))),
                [cut] => cert.truncate(usize::from(cut)),
                _ => {}
            }
        }
        cert
    };
    match verify_certificate(&input, &f.peer, &f.trust) {
        Ok(claims) => {
            assert_eq!(input, f.genuine, "a modified certificate was accepted");
            assert_eq!(claims.subject(), &f.peer);
            assert_eq!(claims.serial(), f.body.serial());
            assert_eq!(claims.not_after(), f.body.not_after());
            assert_eq!(claims.scope(), f.body.scope());
        }
        Err(_) => assert_ne!(input, f.genuine, "the genuine certificate was rejected"),
    }
    assert!(
        verify_certificate(&input, &f.other, &f.trust).is_err(),
        "a certificate was accepted for another peer"
    );
});
