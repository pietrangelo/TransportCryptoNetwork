//! Fase 6, passo 3: firma e verifica dei certificati client (PROTOCOL §15.1 regola 8, §15.2,
//! §15.4 passi 3–6, §15.13).
//!
//! I certificati di prova si scrivono e si firmano anche **a mano** (`tbs()` e `ed25519-dalek`
//! con `hazmat`), così i test d'attacco non dipendono dal codice che verificano.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

use std::collections::BTreeSet;

use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::{Sha512, Signer, SigningKey, VerifyingKey};
use zt_crypto::{
    CERT_FILE_PREFIX, CaSigningKey, CryptoError, Identity, PublicKey, cert_key,
    decode_certificate_text, encode_certificate_text, fingerprint_of_x25519, sign_certificate,
    trusted_ca_key, verify_certificate,
};
use zt_domain::trust::CertTrust;
use zt_domain::{
    AllowedNodes, CertBody, CertRejection, CertScope, CertSerial, Fingerprint, NodeId, UnixTime,
};

// ---------- vettore di riferimento (PROTOCOL §15.13) ----------

const CTX: &[u8] = b"TCN client certificate v1\0";
const REF_CERT_HEX: &str = concat!(
    "54434e4301018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf374",
    "8801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df6",
    "0f5b8fc9b3940102030405060708090a0b0c0d0e0f10000000006b49d2000000",
    "00006b49e01005616c69636500020564622d3031067765622d3031659fa00c94",
    "7c7c513c256db9673ba40a895ee8adba9e4da97e578f6743f976ac5301b6aad1",
    "203e4a03a87dd2cffca22d964126ae7d5b26a9d16067697e5b530f",
);
const REF_CA_KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const REF_SUBJECT_KEY: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
const REF_FINGERPRINT: &str =
    "SHA256:2f5eeec4374d5bc20b0db3d79cf1ebaee1b6834b48e41fe65e8d24f5b653228b";
const REF_SERIAL: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const NB: u64 = 1_800_000_000;
const NA: u64 = 1_800_003_600;

fn reference_cert() -> Vec<u8> {
    hex::decode(REF_CERT_HEX).unwrap()
}
fn ca_seed() -> [u8; 32] {
    [1; 32]
}
fn client() -> Identity {
    Identity::from_secret_hex(&"02".repeat(32)).unwrap()
}
fn ca_secret_text(seed: [u8; 32]) -> String {
    format!("{}{}\n", CaSigningKey::FILE_PREFIX, hex::encode(seed))
}
fn reference_ca() -> CaSigningKey {
    CaSigningKey::from_secret_text(&ca_secret_text(ca_seed())).unwrap()
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn nodes(list: &[&str]) -> BTreeSet<NodeId> {
    list.iter().map(|n| node(n)).collect()
}
fn ed_public(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}
/// Fingerprint (forma X25519) di 32 byte Ed25519 qualsiasi che si decomprimono.
fn fingerprint_of_ed(bytes: &[u8; 32]) -> Fingerprint {
    let vk = VerifyingKey::from_bytes(bytes).unwrap();
    fingerprint_of_x25519(&vk.to_montgomery().to_bytes())
}

/// Il TBS scritto a mano (PROTOCOL §15.1).
fn tbs(
    ca: [u8; 32],
    subject: [u8; 32],
    serial: [u8; 16],
    nb: u64,
    na: u64,
    name: &str,
    list: Option<&[&str]>,
) -> Vec<u8> {
    let mut b = b"TCNC\x01\x01".to_vec();
    b.extend_from_slice(&ca);
    b.extend_from_slice(&subject);
    b.extend_from_slice(&serial);
    b.extend_from_slice(&nb.to_be_bytes());
    b.extend_from_slice(&na.to_be_bytes());
    b.push(name.len() as u8);
    b.extend_from_slice(name.as_bytes());
    match list {
        None => b.extend_from_slice(&[0x01, 0x00]),
        Some(list) => {
            b.push(0x00);
            b.push(list.len() as u8);
            for n in list {
                b.push(n.len() as u8);
                b.extend_from_slice(n.as_bytes());
            }
        }
    }
    b
}

/// Firma Ed25519 pura di `CTX || tbs` con il seme `seed`, fatta a mano.
fn sign_raw(seed: [u8; 32], tbs: &[u8]) -> Vec<u8> {
    let mut message = CTX.to_vec();
    message.extend_from_slice(tbs);
    let mut cert = tbs.to_vec();
    cert.extend_from_slice(&SigningKey::from_bytes(&seed).sign(&message).to_bytes());
    cert
}

/// Le CA pinnate: la CA di riferimento, `allow = ["*"]`, 24 h, denylist vuota.
fn trust() -> CertTrust {
    trust_for(&[ed_public(ca_seed())])
}

fn trust_for(keys: &[[u8; 32]]) -> CertTrust {
    let mut t = CertTrust::new();
    for (i, key) in keys.iter().enumerate() {
        let pk = PublicKey::from_canonical_bytes(key).unwrap();
        t.add_authority(
            node(&format!("ca-{i}")),
            &[trusted_ca_key(&pk)],
            AllowedNodes::All,
            86_400,
        )
        .unwrap();
    }
    t.set_revocations(zt_domain::trust::Revocations::new([], []).unwrap());
    t
}

fn reference_body(ca: &CaSigningKey) -> CertBody {
    CertBody::new(
        cert_key(&ca.public_key()),
        cert_key(&client().public_key()),
        CertSerial::try_from(REF_SERIAL).unwrap(),
        UnixTime::from_secs(NB),
        UnixTime::from_secs(NA),
        node("alice"),
        CertScope::Only(nodes(&["db-01", "web-01"])),
    )
    .unwrap()
}

/// 32 byte non canonici: `y + p` per un `y` piccolo che è un punto valido e non debole.
fn non_canonical_valid_points() -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for y in 0_u8..19 {
        // p = 2^255 - 19: little-endian ed ff..ff 7f. y + p non va in overflow per y < 19.
        let mut bytes = [0xff_u8; 32];
        bytes[0] = 0xed + y;
        bytes[31] = 0x7f;
        for sign in [0_u8, 0x80] {
            let mut b = bytes;
            b[31] |= sign;
            if let Ok(vk) = VerifyingKey::from_bytes(&b)
                && !vk.is_weak()
                && vk.to_edwards().compress().to_bytes() != b
            {
                out.push(b);
            }
        }
    }
    out
}

/// Codifiche (canoniche e no) di punti di ordine piccolo.
const SMALL_ORDER: [&str; 11] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    // Non canoniche: y = p + 1 (identità), y = p (ordine 4), identità con il bit di segno.
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0100000000000000000000000000000000000000000000000000000000000080",
];

fn small_order() -> Vec<[u8; 32]> {
    SMALL_ORDER
        .iter()
        .map(|h| hex::decode(h).unwrap().try_into().unwrap())
        .collect()
}

// ======================= specifica =======================

#[test]
fn reference_vector_matches_the_protocol() {
    // Verifiche indipendenti dal codice sotto test: il documento è coerente con Ed25519.
    let cert = reference_cert();
    assert_eq!(cert.len(), 187);
    assert_eq!(hex::encode(ed_public(ca_seed())), REF_CA_KEY);
    assert_eq!(client().public_key().to_string(), REF_SUBJECT_KEY);
    assert_eq!(client().fingerprint().to_string(), REF_FINGERPRINT);
    let manual = tbs(
        ed_public(ca_seed()),
        client().public_key().to_bytes(),
        REF_SERIAL,
        NB,
        NA,
        "alice",
        Some(&["db-01", "web-01"]),
    );
    assert_eq!(manual, cert[..123]);
    assert_eq!(sign_raw(ca_seed(), &manual), cert, "the document signature");

    // Il codice sotto test produce e accetta gli stessi byte.
    let ca = reference_ca();
    assert_eq!(ca.public_key().to_string(), REF_CA_KEY);
    let body = reference_body(&ca);
    assert_eq!(sign_certificate(&ca, &body).unwrap(), cert);
    let claims = verify_certificate(&cert, &client().fingerprint(), &trust()).unwrap();
    assert_eq!(claims.subject().to_string(), REF_FINGERPRINT);
    assert_eq!(claims.ca(), &ca.public_key().fingerprint());
    assert_eq!(
        claims.serial().to_string(),
        "0102030405060708090a0b0c0d0e0f10"
    );
    assert_eq!(claims.name(), &node("alice"));
    assert_eq!(claims.not_before(), UnixTime::from_secs(NB));
    assert_eq!(claims.not_after(), UnixTime::from_secs(NA));
    assert_eq!(
        claims.scope(),
        &CertScope::Only(nodes(&["db-01", "web-01"]))
    );
}

#[test]
fn sign_then_verify_yields_the_claims() {
    let ca = CaSigningKey::generate().unwrap();
    let subject = Identity::generate().unwrap();
    let body = CertBody::new(
        cert_key(&ca.public_key()),
        cert_key(&subject.public_key()),
        CertSerial::try_from([0x42; 16]).unwrap(),
        UnixTime::from_secs(1_000),
        UnixTime::from_secs(2_000),
        node("bob"),
        CertScope::All,
    )
    .unwrap();
    let cert = sign_certificate(&ca, &body).unwrap();
    let decoded = zt_domain::decode_certificate(&cert).unwrap();
    assert_eq!(decoded.body, body);
    let trust = trust_for(&[ca.public_key().to_bytes()]);
    let claims = verify_certificate(&cert, &subject.fingerprint(), &trust).unwrap();
    assert_eq!(claims.ca(), &ca.public_key().fingerprint());
    assert_eq!(claims.ca_key(), body.ca_key());
    assert_eq!(claims.subject(), &subject.fingerprint());
    assert_eq!(claims.serial(), body.serial());
    assert_eq!(claims.name(), body.name());
    assert_eq!(claims.scope(), body.scope());
    assert_eq!(claims.not_before(), body.not_before());
    assert_eq!(claims.not_after(), body.not_after());
    // La verifica non decide il tempo: un certificato scaduto da anni passa i passi 3–6.
    assert!(verify_certificate(&cert, &subject.fingerprint(), &trust).is_ok());
}

#[test]
fn ca_secret_files_have_their_own_format() {
    let ca = CaSigningKey::generate().unwrap();
    let text = ca.to_secret_text();
    assert!(text.starts_with("tcn-ca-secret-v1:"), "{}", text.len());
    let hex_part = text.trim_end().strip_prefix("tcn-ca-secret-v1:").unwrap();
    assert_eq!(hex_part.len(), 64);
    assert!(hex_part.bytes().all(|b| b.is_ascii_hexdigit()));
    let restored = CaSigningKey::from_secret_text(&text).unwrap();
    assert_eq!(restored.public_key(), ca.public_key());
    // A capo finale facoltativo.
    let trimmed = CaSigningKey::from_secret_text(text.trim_end()).unwrap();
    assert_eq!(trimmed.public_key(), ca.public_key());
    // Il prefisso è obbligatorio ed esatto.
    for bad in [
        hex_part.to_owned(),
        format!("tcn-ca-secret-v2:{hex_part}"),
        format!("TCN-CA-SECRET-V1:{hex_part}"),
        format!(" tcn-ca-secret-v1:{hex_part}"),
        format!("tcn-ca-secret-v1: {hex_part}"),
        format!("tcn-ca-secret-v1:{}", &hex_part[..62]),
        format!("tcn-ca-secret-v1:{hex_part}00"),
        format!("tcn-ca-secret-v1:{}zz", &hex_part[..62]),
        String::new(),
    ] {
        assert!(
            matches!(
                CaSigningKey::from_secret_text(&bad),
                Err(CryptoError::InvalidKey)
            ),
            "accepted {:?}",
            bad.len()
        );
    }
}

#[test]
fn certificate_text_round_trips() {
    let cert = reference_cert();
    let text = encode_certificate_text(&cert);
    assert_eq!(text.trim_end(), format!("{CERT_FILE_PREFIX}{REF_CERT_HEX}"));
    assert!(!text.trim_end().contains('\n'), "one line");
    assert_eq!(decode_certificate_text(&text).unwrap(), cert);
    let line = format!("tcn-client-cert-v1:{REF_CERT_HEX}");
    assert_eq!(decode_certificate_text(&line).unwrap(), cert);
    assert_eq!(decode_certificate_text(&format!("{line}\n")).unwrap(), cert);
}

// ======================= attacchi =======================

#[test]
fn a_certificate_with_another_static_key_fails_before_the_signature() {
    let cert = reference_cert();
    let thief = Identity::generate().unwrap();
    let trust = trust();
    // Controllo: il proprietario della chiave passa.
    assert!(verify_certificate(&cert, &client().fingerprint(), &trust).is_ok());
    assert_eq!(
        verify_certificate(&cert, &thief.fingerprint(), &trust).err(),
        Some(CertRejection::KeyMismatch)
    );
    // Con la firma rotta: chi non è il soggetto riceve ancora `KeyMismatch` (la firma non è
    // valutata), il soggetto riceve `BadSignature`.
    let mut broken = cert.clone();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;
    assert_eq!(
        verify_certificate(&broken, &thief.fingerprint(), &trust).err(),
        Some(CertRejection::KeyMismatch)
    );
    assert_eq!(
        verify_certificate(&broken, &client().fingerprint(), &trust).err(),
        Some(CertRejection::BadSignature)
    );
    // Anche con una CA non pinnata: il binding viene prima del passo 5.
    assert_eq!(
        verify_certificate(
            &cert,
            &thief.fingerprint(),
            &trust_for(&[ed_public([9; 32])])
        )
        .err(),
        Some(CertRejection::KeyMismatch)
    );
}

#[test]
fn any_single_bit_flip_invalidates_the_certificate() {
    let cert = reference_cert();
    let trust = trust();
    let peer = client().fingerprint();
    assert!(verify_certificate(&cert, &peer, &trust).is_ok());
    for i in 0..cert.len() {
        for bit in 0..8 {
            let mut flipped = cert.clone();
            flipped[i] ^= 1 << bit;
            assert!(
                verify_certificate(&flipped, &peer, &trust).is_err(),
                "flip of bit {bit} in byte {i} accepted"
            );
        }
    }
}

#[test]
fn a_signature_without_the_context_string_is_rejected() {
    let cert = reference_cert();
    let trust = trust();
    let peer = client().fingerprint();
    assert!(verify_certificate(&cert, &peer, &trust).is_ok());
    let key = SigningKey::from_bytes(&ca_seed());
    let body = &cert[..123];
    let mut other_ctx = b"TCN client certificate v2\0".to_vec();
    other_ctx.extend_from_slice(body);
    let mut no_nul = b"TCN client certificate v1".to_vec();
    no_nul.extend_from_slice(body);
    for message in [body.to_vec(), other_ctx, no_nul] {
        let mut forged = body.to_vec();
        forged.extend_from_slice(&key.sign(&message).to_bytes());
        assert_eq!(
            verify_certificate(&forged, &peer, &trust).err(),
            Some(CertRejection::BadSignature)
        );
    }
}

#[test]
fn non_canonical_or_small_order_keys_are_rejected() {
    let non_canonical = non_canonical_valid_points();
    assert!(
        !non_canonical.is_empty(),
        "fixture: no non-canonical valid point found"
    );
    // Controllo: una chiave canonica e valida è accettata e ricodificata identica.
    let good = ed_public([7; 32]);
    assert_eq!(
        PublicKey::from_canonical_bytes(&good).unwrap().to_bytes(),
        good
    );
    let weak = small_order();
    for bytes in non_canonical.iter().chain(&weak) {
        assert!(
            PublicKey::from_canonical_bytes(bytes).is_err(),
            "from_canonical_bytes accepted {}",
            hex::encode(bytes)
        );
    }
    for bytes in &weak {
        assert!(matches!(
            PublicKey::from_canonical_bytes(bytes),
            Err(CryptoError::WeakKey | CryptoError::InvalidKey)
        ));
    }
    // y >= p che non si decomprime: chiave non valida.
    assert!(PublicKey::from_canonical_bytes(&[0xff; 32]).is_err());

    let trust = trust();
    // `subject_key` non canonica o debole, firmata dalla CA vera, presentata dalla chiave
    // Noise «corrispondente» (stessa forma X25519): `KeyMismatch`.
    for subject in non_canonical.iter().chain(&weak) {
        let t = tbs(
            ed_public(ca_seed()),
            *subject,
            REF_SERIAL,
            NB,
            NA,
            "alice",
            None,
        );
        let cert = sign_raw(ca_seed(), &t);
        let peer = VerifyingKey::from_bytes(subject)
            .map_or(Fingerprint::from_bytes([0; 32]), |vk| {
                fingerprint_of_x25519(&vk.to_montgomery().to_bytes())
            });
        assert_eq!(
            verify_certificate(&cert, &peer, &trust).err(),
            Some(CertRejection::KeyMismatch),
            "subject {}",
            hex::encode(subject)
        );
    }
    // `ca_key` non canonica o debole: mai uguale a un pin (i pin sono canonici).
    for ca in non_canonical.iter().chain(&weak) {
        let t = tbs(
            *ca,
            client().public_key().to_bytes(),
            REF_SERIAL,
            NB,
            NA,
            "alice",
            None,
        );
        let mut cert = t.clone();
        cert.extend_from_slice(&[0x11; 64]);
        assert_eq!(
            verify_certificate(&cert, &client().fingerprint(), &trust).err(),
            Some(CertRejection::UnknownAuthority),
            "ca {}",
            hex::encode(ca)
        );
    }
}

#[test]
fn a_malleated_signature_is_rejected() {
    let cert = reference_cert();
    let trust = trust();
    let peer = client().fingerprint();
    assert!(verify_certificate(&cert, &peer, &trust).is_ok());
    // S + ℓ: stesso valore modulo ℓ, codifica non canonica di S.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut malleated = cert.clone();
    let mut carry = 0_u16;
    for i in 0..32 {
        let sum = u16::from(malleated[123 + 32 + i]) + u16::from(L[i]) + carry;
        malleated[123 + 32 + i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        verify_certificate(&malleated, &peer, &trust).err(),
        Some(CertRejection::BadSignature)
    );
    // R di ordine piccolo.
    for r in small_order() {
        let mut forged = cert.clone();
        forged[123..123 + 32].copy_from_slice(&r);
        assert_eq!(
            verify_certificate(&forged, &peer, &trust).err(),
            Some(CertRejection::BadSignature)
        );
    }
    // Firma tutta a zero.
    let mut zero = cert.clone();
    zero[123..].copy_from_slice(&[0; 64]);
    assert_eq!(
        verify_certificate(&zero, &peer, &trust).err(),
        Some(CertRejection::BadSignature)
    );
}

#[test]
fn the_ca_key_must_match_a_pin_byte_for_byte() {
    // Pin P; certificato con ca_key = -P firmato con -s. -P ha la stessa forma X25519 di P
    // (quindi la stessa fingerprint), ed è una firma valida per -P: solo il confronto byte per
    // byte con il pin lo ferma.
    let seed = ca_seed();
    let p = VerifyingKey::from_bytes(&ed_public(seed)).unwrap();
    let minus_p = VerifyingKey::from_bytes(&(-p.to_edwards()).compress().to_bytes()).unwrap();
    assert_ne!(minus_p.to_bytes(), p.to_bytes());
    assert_eq!(
        fingerprint_of_ed(&minus_p.to_bytes()),
        fingerprint_of_ed(&p.to_bytes()),
        "P and -P share the X25519 form"
    );
    let esk = ExpandedSecretKey::from(&seed);
    let negated = ExpandedSecretKey {
        scalar: -esk.scalar,
        hash_prefix: esk.hash_prefix,
    };
    let t = tbs(
        minus_p.to_bytes(),
        client().public_key().to_bytes(),
        REF_SERIAL,
        NB,
        NA,
        "alice",
        None,
    );
    let mut message = CTX.to_vec();
    message.extend_from_slice(&t);
    let signature = raw_sign::<Sha512>(&negated, &message, &minus_p);
    minus_p.verify_strict(&message, &signature).unwrap();
    let mut cert = t;
    cert.extend_from_slice(&signature.to_bytes());

    // Controllo: lo stesso contenuto con ca_key = P, firmato con s, passa.
    let honest = sign_raw(
        seed,
        &tbs(
            p.to_bytes(),
            client().public_key().to_bytes(),
            REF_SERIAL,
            NB,
            NA,
            "alice",
            None,
        ),
    );
    let trust = trust();
    assert!(verify_certificate(&honest, &client().fingerprint(), &trust).is_ok());
    assert_eq!(
        verify_certificate(&cert, &client().fingerprint(), &trust).err(),
        Some(CertRejection::UnknownAuthority)
    );
}

#[test]
fn a_ca_key_equal_to_the_subject_is_rejected() {
    // La CA certifica la propria chiave come client (PROTOCOL §15.1 regola 3): è un errore di
    // formato (passo 3, `malformed`), anche se la firma è valida e il peer è quella chiave.
    let seed = ca_seed();
    let ca_pub = ed_public(seed);
    let cert = sign_raw(seed, &tbs(ca_pub, ca_pub, REF_SERIAL, NB, NA, "ca", None));
    let peer = fingerprint_of_ed(&ca_pub);
    assert_eq!(
        verify_certificate(&cert, &peer, &trust()).err(),
        Some(CertRejection::Malformed)
    );
    // Controllo: un soggetto diverso passa.
    assert!(verify_certificate(&reference_cert(), &client().fingerprint(), &trust()).is_ok());
}

#[test]
fn sign_refuses_a_body_naming_another_ca() {
    let ca = reference_ca();
    let other = CaSigningKey::generate().unwrap();
    let body = reference_body(&ca);
    assert!(sign_certificate(&ca, &body).is_ok());
    assert!(sign_certificate(&other, &body).is_err());
}

#[test]
fn node_and_ca_key_files_are_not_interchangeable() {
    let ca = CaSigningKey::generate().unwrap();
    let ca_text = ca.to_secret_text();
    assert!(CaSigningKey::from_secret_text(&ca_text).is_ok());
    // Una chiave di nodo non carica il file della CA, e viceversa.
    assert!(Identity::from_secret_hex(&ca_text).is_err());
    let node_key = Identity::generate().unwrap();
    assert!(CaSigningKey::from_secret_text(&node_key.to_secret_hex()).is_err());
    assert!(
        CaSigningKey::from_secret_text(&format!("{}\n", node_key.to_secret_hex().as_str()))
            .is_err()
    );
    // Un certificato non è una chiave.
    let cert_text = format!("{CERT_FILE_PREFIX}{REF_CERT_HEX}\n");
    assert!(Identity::from_secret_hex(&cert_text).is_err());
    assert!(cert_text.parse::<PublicKey>().is_err());
    assert!(CaSigningKey::from_secret_text(&cert_text).is_err());
    // E una chiave della CA non è un certificato.
    assert!(decode_certificate_text(&ca_text).is_err());
    assert!(decode_certificate_text(&node_key.to_secret_hex()).is_err());
}

#[test]
fn ca_signing_key_debug_is_redacted() {
    let ca = CaSigningKey::from_secret_text(&ca_secret_text([0xab; 32])).unwrap();
    let rendered = format!("{ca:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    let secret = ca.to_secret_text();
    let hex_part = secret.trim_end().strip_prefix("tcn-ca-secret-v1:").unwrap();
    assert_eq!(hex_part, "ab".repeat(32));
    assert!(!rendered.contains(hex_part));
    assert!(!rendered.to_lowercase().contains("abab"));
    assert!(!rendered.contains("171"));
}

#[test]
fn certificate_text_rejects_other_shapes() {
    // Aggiunto: il formato del file (PROTOCOL §15.1, ultimo paragrafo). I casi del caricatore
    // sono in `zt-net/tests/cert_config.rs`.
    let line = format!("{CERT_FILE_PREFIX}{REF_CERT_HEX}");
    assert!(decode_certificate_text(&line).is_ok());
    for bad in [
        REF_CERT_HEX.to_owned(),
        format!("tcn-client-cert-v2:{REF_CERT_HEX}"),
        format!(" {line}"),
        format!("{line} "),
        format!("{line}\n\n"),
        format!("{line}\n{line}"),
        format!("{CERT_FILE_PREFIX} {REF_CERT_HEX}"),
        format!("{CERT_FILE_PREFIX}{}", &REF_CERT_HEX[1..]),
        CERT_FILE_PREFIX.to_owned(),
    ] {
        assert!(decode_certificate_text(&bad).is_err(), "accepted {bad:?}");
    }
}
