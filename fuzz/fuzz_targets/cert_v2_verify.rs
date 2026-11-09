//! Certificate v2 verification (PROTOCOL §15.14) with a fixed composite CA, trust and peer.
//!
//! Inputs: arbitrary bytes (mode bit 0 clear); or a **genuine** v2 certificate with modified
//! bytes anywhere (bit 0 set, bit 2 clear); or with modified bytes in the ML-DSA component only
//! (bits 0 and 2 set), which keeps the Ed25519 component valid (finding AP-5: the ML-DSA
//! verifier must be the one that refuses).
//! Properties: no panic; an accepted input is, byte for byte, the genuine certificate, with
//! its own claims; the intact certificate is accepted; the same certificate for another peer,
//! or with another hybrid fingerprint, is rejected.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zt_crypto::{
    CompositeCaSigningKey, Identity, sign_certificate_v2, trusted_composite_ca_key,
    verify_certificate,
};
use zt_domain::cert::{CERT_V2_SIGNATURE_LEN, MLDSA65_SIGNATURE_LEN};
use zt_domain::limits::DEFAULT_AUTHORITY_LIFETIME_SECS;
use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{
    AllowedNodes, CertBodyV2, CertScope, CertSerial, CertSubject, Fingerprint, NodeId, UnixTime,
};

struct Fixture {
    trust: CertTrust,
    peer: Fingerprint,
    other: Fingerprint,
    genuine: Vec<u8>,
    body: CertBodyV2,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let ca = CompositeCaSigningKey::generate().expect("rng");
        let peer = Identity::generate().expect("rng");
        let other = Identity::generate().expect("rng");
        let node = |n: &str| NodeId::try_from(n).expect("valid");
        let body = CertBodyV2::new(
            ca.public_key().ca_fp(),
            CertSubject::Classical(peer.fingerprint()),
            CertSerial::try_from([0x42; 16]).expect("non-zero"),
            UnixTime::from_secs(1_800_000_000),
            UnixTime::from_secs(1_800_003_600),
            node("alice"),
            CertScope::Only([node("db-01"), node("web-01")].into_iter().collect()),
        )
        .expect("valid body");
        let genuine = sign_certificate_v2(&ca, &body).expect("sign");
        let mut trust = CertTrust::new();
        trust
            .add_authority(
                node("ops-ca"),
                &[trusted_composite_ca_key(&ca.public_key()).expect("pin")],
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
        let mut cert = f.genuine.clone();
        // The ML-DSA component is [L-3373, L-64); the whole certificate otherwise.
        let (base, span) = if mode & 4 != 0 {
            (
                cert.len().saturating_sub(CERT_V2_SIGNATURE_LEN),
                MLDSA65_SIGNATURE_LEN,
            )
        } else {
            (0, cert.len())
        };
        let mut chunks = rest.chunks(3);
        for chunk in chunks.by_ref() {
            match *chunk {
                [hi, lo, x] => {
                    let pos = usize::from(u16::from_be_bytes([hi, lo])) % span.max(1);
                    if let Some(b) = cert.get_mut(base.saturating_add(pos)) {
                        *b ^= x;
                    }
                }
                [n, ..] if mode & 2 != 0 => cert.extend(std::iter::repeat_n(n, usize::from(n))),
                [cut, ..] => cert.truncate(cert.len().saturating_sub(usize::from(cut))),
                [] => {}
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
            assert_eq!(claims.version(), 2);
        }
        Err(_) => assert_ne!(input, f.genuine, "the genuine certificate was rejected"),
    }
    assert!(
        verify_certificate(&input, &f.other, &f.trust).is_err(),
        "a certificate was accepted for another peer"
    );
});
