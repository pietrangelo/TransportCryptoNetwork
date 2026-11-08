//! La verifica dei certificati (PROTOCOL §15.4 passi 3–6) con trust e chiave del peer fissi.
//!
//! Metà degli input sono byte arbitrari; l'altra metà è un certificato **autentico** (firmato
//! dalla CA pinnata per il peer) con byte modificati, così il fuzzer raggiunge anche i rami
//! della firma e dell'accettazione.
//! Proprietà: nessun panic; un input accettato è, byte per byte, il certificato autentico, e i
//! claims sono i suoi (nessuna malleabilità della codifica o della firma); il certificato
//! intatto è accettato; lo stesso certificato per un altro peer è rifiutato.
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
        // Coppie (posizione, xor) sul certificato autentico; un byte finale dispari tronca o,
        // con il bit 1 del modo, allunga.
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
