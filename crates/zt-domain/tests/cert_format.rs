//! Phase 6, step 1: binary format of client certificates (PROTOCOL §15.1, §15.12, §15.13).
//!
//! RED tests (Adversarial TDD): specification ("S") and attack ("A") of the decoder and of the
//! TBS encoder. The bytes are written by hand with `common::Raw`, independent of the code under
//! test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::assertions_on_constants
)]

mod common;

use common::{Raw, largest_nodes, node, reference_cert, short_nodes};
use zt_domain::cert::{
    CERT_MAGIC, CERT_SIG_ED25519, CERT_SIGNATURE_CONTEXT, CERT_SIGNATURE_LEN, CERT_VERSION,
};
use zt_domain::limits::{
    CERT_CLOCK_SKEW_SECS, DEFAULT_AUTHORITY_LIFETIME_SECS, MAX_AUTHORITIES, MAX_AUTHORITY_KEYS,
    MAX_CERT_LEN, MAX_CERT_LIFETIME_SECS, MAX_CERT_NODES, MAX_PAYLOAD_LEN, MAX_REVOKED_KEYS,
    MAX_REVOKED_SERIALS, MIN_AUTHORITY_LIFETIME_SECS, MIN_CERT_LEN, NOISE_MAX_MESSAGE_LEN,
    NOISE_MSG1_OVERHEAD, NOISE_TAG_LEN,
};
use zt_domain::{
    CertBody, CertFormatError, CertKey, CertScope, CertSerial, NodeId, UnixTime, decode_certificate,
};

fn decode(raw: &Raw) -> Result<CertBody, CertFormatError> {
    let bytes = raw.bytes();
    decode_certificate(&bytes).map(|p| p.body)
}

fn assert_accepted(raw: &Raw) {
    let bytes = raw.bytes();
    let parsed = decode_certificate(&bytes)
        .unwrap_or_else(|e| panic!("valid certificate ({} bytes) refused: {e}", bytes.len()));
    assert_eq!(parsed.body, raw.body());
}

// ======================= specification =======================

#[test]
fn reference_vector_layout_decodes() {
    let cert = reference_cert();
    assert_eq!(cert.len(), 187);
    // The test encoder reproduces the document: the transcription is consistent.
    assert_eq!(Raw::reference().bytes(), cert);

    let parsed = decode_certificate(&cert).unwrap();
    assert_eq!(parsed.tbs.len(), 123);
    assert_eq!(parsed.tbs, &cert[..123]);
    assert_eq!(parsed.signature.as_slice(), &cert[123..]);
    let body = &parsed.body;
    assert_eq!(body.ca_key().as_bytes(), &common::key32(common::REF_CA_KEY));
    assert_eq!(
        body.subject_key().as_bytes(),
        &common::key32(common::REF_SUBJECT_KEY)
    );
    assert_eq!(body.serial().as_bytes(), &common::REF_SERIAL);
    assert_eq!(
        body.serial().to_string(),
        "0102030405060708090a0b0c0d0e0f10"
    );
    assert_eq!(body.not_before(), UnixTime::from_secs(1_800_000_000));
    assert_eq!(body.not_after(), UnixTime::from_secs(1_800_003_600));
    assert_eq!(body.lifetime_secs(), 3_600);
    assert_eq!(body.name(), &node("alice"));
    assert_eq!(
        body.scope(),
        &CertScope::Only([node("db-01"), node("web-01")].into_iter().collect())
    );
    // The domain encoder produces exactly the same 123 bytes.
    assert_eq!(body.encode_tbs(), &cert[..123]);
}

#[test]
fn a_certificate_body_round_trips_canonically() {
    for raw in [Raw::valid(), Raw::smallest(), Raw::largest()] {
        let body = raw.body();
        let mut bytes = body.encode_tbs();
        assert_eq!(bytes, raw.tbs(), "encode_tbs differs from the layout");
        bytes.extend_from_slice(&[0x77; CERT_SIGNATURE_LEN]);
        let parsed = decode_certificate(&bytes).unwrap();
        assert_eq!(parsed.body, body);
        assert_eq!(parsed.tbs, body.encode_tbs().as_slice());
        assert_eq!(parsed.signature, &[0x77; CERT_SIGNATURE_LEN]);
        // Same bytes after a second round trip.
        let mut again = parsed.body.encode_tbs();
        again.extend_from_slice(parsed.signature);
        assert_eq!(again, bytes);
    }
}

#[test]
fn smallest_and_largest_certificates_are_accepted() {
    let small = Raw::smallest();
    assert_eq!(small.bytes().len(), MIN_CERT_LEN);
    assert_accepted(&small);
    let large = Raw::largest();
    assert_eq!(large.bytes().len(), MAX_CERT_LEN);
    assert_accepted(&large);
    let body = decode(&large).unwrap();
    match body.scope() {
        CertScope::Only(nodes) => assert_eq!(nodes.len(), MAX_CERT_NODES),
        CertScope::All => panic!("expected a node list"),
    }
}

#[test]
fn scope_all_carries_no_nodes() {
    let raw = Raw {
        scope: 0x01,
        nodes: Vec::new(),
        ..Raw::valid()
    };
    assert_eq!(decode(&raw).unwrap().scope(), &CertScope::All);
    // And the encoder writes `0x01` followed by `node_count = 0`.
    let tbs = raw.body().encode_tbs();
    assert_eq!(&tbs[tbs.len() - 2..], &[0x01, 0x00]);
}

#[test]
fn limits_are_consistent() {
    // Normative values of PROTOCOL §15.12.
    assert_eq!(MAX_CERT_LEN, 4_328);
    assert_eq!(MIN_CERT_LEN, 170);
    assert_eq!(MAX_CERT_NODES, 64);
    assert_eq!(MAX_CERT_LIFETIME_SECS, 86_400);
    assert_eq!(CERT_CLOCK_SKEW_SECS, 120);
    assert_eq!(MIN_AUTHORITY_LIFETIME_SECS, 60);
    assert_eq!(DEFAULT_AUTHORITY_LIFETIME_SECS, 28_800);
    assert_eq!(MAX_AUTHORITIES, 16);
    assert_eq!(MAX_AUTHORITY_KEYS, 2);
    assert_eq!(MAX_REVOKED_SERIALS, 16_384);
    assert_eq!(MAX_REVOKED_KEYS, 4_096);
    assert_eq!(NOISE_MSG1_OVERHEAD, 32 + 32 + 16 + 16);
    // The limits derive from the layout: fixed 102-byte header + name_len + scope + node_count
    // + signature.
    let fixed = 4 + 1 + 1 + 32 + 32 + 16 + 8 + 8;
    assert_eq!(fixed, 102);
    assert_eq!(MIN_CERT_LEN, fixed + 1 + 1 + 1 + 1 + CERT_SIGNATURE_LEN);
    assert_eq!(
        MAX_CERT_LEN,
        fixed + 1 + 63 + 1 + 1 + MAX_CERT_NODES * (1 + 63) + CERT_SIGNATURE_LEN
    );
    // Message 1 carrying the largest certificate fits in a `Data` frame and in a Noise message.
    assert!(NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN <= MAX_PAYLOAD_LEN);
    assert!(NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN <= NOISE_MAX_MESSAGE_LEN);
    assert!(DEFAULT_AUTHORITY_LIFETIME_SECS <= MAX_CERT_LIFETIME_SECS);
    assert!(MIN_AUTHORITY_LIFETIME_SECS <= DEFAULT_AUTHORITY_LIFETIME_SECS);
    // Format constants.
    assert_eq!(&CERT_MAGIC, b"TCNC");
    assert_eq!(CERT_VERSION, 1);
    assert_eq!(CERT_SIG_ED25519, 1);
    assert_eq!(CERT_SIGNATURE_CONTEXT, b"TCN client certificate v1\0");
    assert_eq!(CERT_SIGNATURE_CONTEXT.len(), 26);
}

// ======================= attacks =======================

#[test]
fn lengths_outside_the_bounds_are_rejected_before_parsing() {
    // Positive control: both extremes are accepted.
    assert_accepted(&Raw::smallest());
    assert_accepted(&Raw::largest());
    // Outside the limits the error is `Length` even with wrong magic and version: the length is
    // checked before reading any field.
    for len in [0, 1, MIN_CERT_LEN - 1, MAX_CERT_LEN + 1, 65_535] {
        let bytes = vec![0xff_u8; len];
        assert_eq!(
            decode_certificate(&bytes).map(|p| p.body),
            Err(CertFormatError::Length { len }),
            "len {len}"
        );
    }
    // A valid prefix does not change the outcome.
    let mut long = Raw::largest().bytes();
    long.push(0);
    assert_eq!(
        decode_certificate(&long).map(|p| p.body),
        Err(CertFormatError::Length {
            len: MAX_CERT_LEN + 1
        })
    );
}

#[test]
fn every_other_magic_version_and_algorithm_is_rejected() {
    assert_accepted(&Raw::valid());
    for v in (0..=u8::MAX).filter(|v| *v != CERT_VERSION) {
        let raw = Raw {
            version: v,
            ..Raw::valid()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Version(v)));
    }
    for a in (0..=u8::MAX).filter(|a| *a != CERT_SIG_ED25519) {
        let raw = Raw {
            sig_alg: a,
            ..Raw::valid()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Algorithm(a)));
    }
    for magic in [*b"TCND", *b"tcnc", *b"CNCT", [0; 4], [0xff; 4], *b"TCN\0"] {
        let raw = Raw {
            magic,
            ..Raw::valid()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Magic), "{magic:?}");
    }
    // Every single bit of the magic.
    for i in 0..4 {
        for bit in 0..8 {
            let mut magic = *b"TCNC";
            magic[i] ^= 1 << bit;
            let raw = Raw {
                magic,
                ..Raw::valid()
            };
            assert_eq!(decode(&raw), Err(CertFormatError::Magic));
        }
    }
}

#[test]
fn a_zero_serial_is_rejected() {
    assert_accepted(&Raw::valid());
    let raw = Raw {
        serial: [0; 16],
        ..Raw::valid()
    };
    assert_eq!(decode(&raw), Err(CertFormatError::SerialZero));
    assert_eq!(
        CertSerial::try_from([0_u8; 16]),
        Err(CertFormatError::SerialZero)
    );
    // A single set bit is enough.
    let mut one = [0_u8; 16];
    one[15] = 1;
    assert!(CertSerial::try_from(one).is_ok());
    assert_accepted(&Raw {
        serial: one,
        ..Raw::valid()
    });
}

#[test]
fn a_self_certified_body_is_rejected() {
    // PROTOCOL §15.1 rule 3: `ca_key` and `subject_key` do not coincide. (Added test: the
    // rule has no row of its own in the plan, which covers it only in `zt-crypto`.)
    assert_accepted(&Raw::valid());
    let raw = Raw {
        subject_key: [0xca; 32],
        ..Raw::valid()
    };
    assert_eq!(decode(&raw), Err(CertFormatError::SelfCertified));
    assert_eq!(
        CertBody::new(
            CertKey::from_bytes([0xca; 32]),
            CertKey::from_bytes([0xca; 32]),
            CertSerial::try_from(common::REF_SERIAL).unwrap(),
            UnixTime::from_secs(1_000),
            UnixTime::from_secs(2_000),
            node("alice"),
            CertScope::All,
        ),
        Err(CertFormatError::SelfCertified)
    );
}

#[test]
fn empty_or_inverted_validity_is_rejected() {
    assert_accepted(&Raw::valid());
    for (nb, na) in [(1_000, 1_000), (1_001, 1_000), (u64::MAX, 0), (5, 4)] {
        let raw = Raw {
            not_before: nb,
            not_after: na,
            ..Raw::valid()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Validity), "{nb}..{na}");
        assert_eq!(
            CertBody::new(
                CertKey::from_bytes([0xca; 32]),
                CertKey::from_bytes([0x5b; 32]),
                CertSerial::try_from(common::REF_SERIAL).unwrap(),
                UnixTime::from_secs(nb),
                UnixTime::from_secs(na),
                node("alice"),
                CertScope::All,
            ),
            Err(CertFormatError::Validity)
        );
    }
    // One second of validity is allowed.
    assert_accepted(&Raw {
        not_before: 1_000,
        not_after: 1_001,
        ..Raw::valid()
    });
}

#[test]
fn a_lifetime_over_24_hours_is_rejected() {
    let at = |secs: u64| Raw {
        not_before: 1_800_000_000,
        not_after: 1_800_000_000 + secs,
        ..Raw::valid()
    };
    assert_accepted(&at(86_400));
    assert_eq!(decode(&at(86_400)).unwrap().lifetime_secs(), 86_400);
    assert_eq!(
        decode(&at(86_401)),
        Err(CertFormatError::Lifetime { secs: 86_401 })
    );
    assert_eq!(
        CertBody::new(
            CertKey::from_bytes([0xca; 32]),
            CertKey::from_bytes([0x5b; 32]),
            CertSerial::try_from(common::REF_SERIAL).unwrap(),
            UnixTime::from_secs(0),
            UnixTime::from_secs(86_401),
            node("alice"),
            CertScope::All,
        ),
        Err(CertFormatError::Lifetime { secs: 86_401 })
    );
}

#[test]
fn extreme_times_never_overflow() {
    // At the edges of u64: an error, never a panic or a result that wraps around.
    let cases = [
        (
            0,
            u64::MAX,
            Err(CertFormatError::Lifetime { secs: u64::MAX }),
        ),
        (u64::MAX, 0, Err(CertFormatError::Validity)),
        (u64::MAX, u64::MAX, Err(CertFormatError::Validity)),
        (u64::MAX - 1, u64::MAX, Ok(1)),
        (0, 1, Ok(1)),
        (0, 86_400, Ok(86_400)),
        (
            1,
            u64::MAX,
            Err(CertFormatError::Lifetime { secs: u64::MAX - 1 }),
        ),
    ];
    for (nb, na, expected) in cases {
        let raw = Raw {
            not_before: nb,
            not_after: na,
            ..Raw::valid()
        };
        let got = decode(&raw).map(|b| b.lifetime_secs());
        assert_eq!(got, expected, "{nb}..{na}");
    }
    // `UnixTime` arithmetic is checked.
    assert_eq!(UnixTime::from_secs(u64::MAX).checked_add(1), None);
    assert_eq!(UnixTime::from_secs(0).checked_sub(1), None);
    assert_eq!(
        UnixTime::from_secs(u64::MAX).saturating_add(5),
        UnixTime::from_secs(u64::MAX)
    );
    assert_eq!(
        UnixTime::from_secs(3).saturating_sub(5),
        UnixTime::from_secs(0)
    );
}

#[test]
fn invalid_names_and_node_ids_are_rejected() {
    assert_accepted(&Raw::valid());
    let bad: Vec<Vec<u8>> = vec![
        b"Alice".to_vec(),
        b"al\0ce".to_vec(),
        b"al\nce".to_vec(),
        b"-alice".to_vec(),
        b"alice-".to_vec(),
        "alicé".as_bytes().to_vec(),
        b"al ce".to_vec(),
        b"al.ce".to_vec(),
        b"al_ce".to_vec(),
        vec![b'a'; 64],
    ];
    for name in &bad {
        let raw = Raw {
            name: name.clone(),
            ..Raw::valid()
        };
        assert!(
            matches!(decode(&raw), Err(CertFormatError::Name(_))),
            "name {name:?} accepted or wrong error: {:?}",
            decode(&raw)
        );
        let raw = Raw {
            nodes: vec![b"db-01".to_vec(), name.clone()],
            ..Raw::valid()
        };
        // Order matters little here: an invalid node is a name or order error, never Ok.
        assert!(
            matches!(
                decode(&raw),
                Err(CertFormatError::Name(_) | CertFormatError::NodeOrder { .. })
            ),
            "node {name:?}: {:?}",
            decode(&raw)
        );
        let raw = Raw {
            nodes: vec![name.clone()],
            ..Raw::valid()
        };
        assert!(
            matches!(decode(&raw), Err(CertFormatError::Name(_))),
            "single node {name:?}: {:?}",
            decode(&raw)
        );
    }
    // Zero length: `name_len = 0`, and a node with `len = 0`.
    let empty_name = Raw {
        name: Vec::new(),
        ..Raw::valid()
    };
    assert!(matches!(decode(&empty_name), Err(CertFormatError::Name(_))));
    let empty_node = Raw {
        nodes: vec![Vec::new()],
        ..Raw::valid()
    };
    assert!(matches!(decode(&empty_node), Err(CertFormatError::Name(_))));
    // 63 bytes is the maximum, and it is allowed.
    assert_accepted(&Raw {
        name: vec![b'z'; 63],
        nodes: vec![vec![b'y'; 63]],
        ..Raw::valid()
    });
}

#[test]
fn unsorted_or_duplicate_nodes_are_rejected() {
    assert_accepted(&Raw::valid());
    let cases: Vec<(Vec<&[u8]>, usize)> = vec![
        (vec![b"web-01", b"db-01"], 1),
        (vec![b"db-01", b"db-01"], 1),
        (vec![b"a", b"b", b"c", b"b"], 3),
        (vec![b"a", b"c", b"b"], 2),
        // Byte order, not length order: "ab" < "b".
        (vec![b"b", b"ab"], 1),
    ];
    for (nodes, index) in cases {
        let raw = Raw {
            nodes: nodes.iter().map(|n| n.to_vec()).collect(),
            ..Raw::valid()
        };
        assert_eq!(
            decode(&raw),
            Err(CertFormatError::NodeOrder { index }),
            "{nodes:?}"
        );
    }
    // A single encoding for each set: the one in increasing order.
    assert_accepted(&Raw {
        nodes: vec![b"ab".to_vec(), b"b".to_vec()],
        ..Raw::valid()
    });
}

#[test]
fn an_empty_list_or_nodes_with_scope_all_are_rejected() {
    assert_accepted(&Raw::smallest());
    let empty = Raw {
        scope: 0x00,
        nodes: Vec::new(),
        ..Raw::valid()
    };
    assert_eq!(decode(&empty), Err(CertFormatError::NodeCount(0)));
    let all_with_nodes = Raw {
        scope: 0x01,
        nodes: vec![b"web-01".to_vec()],
        ..Raw::valid()
    };
    assert_eq!(decode(&all_with_nodes), Err(CertFormatError::NodeCount(1)));
    // The constructor also rejects an empty list.
    assert!(
        CertBody::new(
            CertKey::from_bytes([0xca; 32]),
            CertKey::from_bytes([0x5b; 32]),
            CertSerial::try_from(common::REF_SERIAL).unwrap(),
            UnixTime::from_secs(1_000),
            UnixTime::from_secs(2_000),
            node("alice"),
            CertScope::Only(std::collections::BTreeSet::new()),
        )
        .is_err()
    );
}

#[test]
fn unknown_scope_codes_are_rejected() {
    assert_accepted(&Raw::valid());
    assert_accepted(&Raw::smallest());
    for code in 0x02..=u8::MAX {
        let raw = Raw {
            scope: code,
            nodes: Vec::new(),
            ..Raw::smallest()
        };
        assert_eq!(decode(&raw), Err(CertFormatError::Scope(code)));
    }
}

#[test]
fn more_than_64_nodes_are_rejected() {
    assert_accepted(&Raw {
        nodes: short_nodes(64),
        ..Raw::valid()
    });
    let raw = Raw {
        nodes: short_nodes(65),
        ..Raw::valid()
    };
    assert_eq!(decode(&raw), Err(CertFormatError::NodeCount(65)));
    // `node_count` 255 with few nodes: rejected on the count, before reading the nodes.
    let raw = Raw {
        node_count: Some(255),
        ..Raw::valid()
    };
    assert_eq!(decode(&raw), Err(CertFormatError::NodeCount(255)));
    // The constructor rejects 65 nodes.
    let nodes: std::collections::BTreeSet<NodeId> = short_nodes(65)
        .iter()
        .map(|n| NodeId::try_from(n.as_slice()).unwrap())
        .collect();
    assert!(
        CertBody::new(
            CertKey::from_bytes([0xca; 32]),
            CertKey::from_bytes([0x5b; 32]),
            CertSerial::try_from(common::REF_SERIAL).unwrap(),
            UnixTime::from_secs(1_000),
            UnixTime::from_secs(2_000),
            node("alice"),
            CertScope::Only(nodes),
        )
        .is_err()
    );
}

#[test]
fn length_fields_past_the_end_are_rejected() {
    assert_accepted(&Raw::valid());
    // The last node declares 63 bytes but the certificate ends after 10: `Truncated`.
    let mut raw = Raw {
        name: vec![b'n'; 63],
        signature: Vec::new(),
        ..Raw::valid()
    };
    raw.nodes = vec![b"a".to_vec()];
    raw.node_count = Some(2);
    let mut bytes = raw.tbs();
    bytes.push(63);
    bytes.extend_from_slice(&[b'b'; 10]);
    assert!(bytes.len() >= MIN_CERT_LEN);
    assert!(
        matches!(
            decode_certificate(&bytes).map(|p| p.body),
            Err(CertFormatError::Truncated { .. })
        ),
        "{:?}",
        decode_certificate(&bytes).map(|p| p.body)
    );
    // `name_len` past the end (255 on a minimal certificate). The plan says `Truncated`;
    // a decoder that checks the `1..=63` range first answers `Name`: both
    // reject without reading past the buffer.
    let raw = Raw {
        name_len: Some(255),
        ..Raw::smallest()
    };
    assert!(
        matches!(
            decode(&raw),
            Err(CertFormatError::Truncated { .. } | CertFormatError::Name(_))
        ),
        "{:?}",
        decode(&raw)
    );
    // `node_count` that makes the nodes be read inside the signature and past the end.
    let raw = Raw {
        node_count: Some(64),
        nodes: largest_nodes(2),
        ..Raw::valid()
    };
    assert!(decode(&raw).is_err());
}

#[test]
fn missing_or_extra_signature_bytes_are_rejected() {
    assert_accepted(&Raw::valid());
    let short = Raw {
        signature: vec![0x5a; 63],
        ..Raw::valid()
    };
    assert!(
        matches!(decode(&short), Err(CertFormatError::Truncated { .. })),
        "{:?}",
        decode(&short)
    );
    let long = Raw {
        signature: vec![0x5a; 65],
        ..Raw::valid()
    };
    assert_eq!(decode(&long), Err(CertFormatError::Trailing { extra: 1 }));
}

#[test]
fn errors_never_echo_certificate_bytes() {
    let secretish = "zebra-secret-name";
    let base = Raw {
        name: secretish.as_bytes().to_vec(),
        nodes: vec![b"vault-node".to_vec()],
        ca_key: [0xab; 32],
        subject_key: [0xcd; 32],
        ..Raw::valid()
    };
    assert_accepted(&base);
    let broken = [
        Raw {
            version: 9,
            ..base.clone()
        },
        Raw {
            serial: [0; 16],
            ..base.clone()
        },
        Raw {
            not_after: base.not_before,
            ..base.clone()
        },
        Raw {
            name: b"Zebra-Secret-Name".to_vec(),
            ..base.clone()
        },
        Raw {
            nodes: vec![b"vault-node".to_vec(), b"Vault-Node".to_vec()],
            ..base.clone()
        },
        Raw {
            nodes: vec![b"vault-node".to_vec(), b"vault-node".to_vec()],
            ..base.clone()
        },
        Raw {
            scope: 7,
            ..base.clone()
        },
        Raw {
            signature: vec![0; 70],
            ..base.clone()
        },
    ];
    for raw in &broken {
        let err = decode(raw).expect_err("malformed certificate accepted");
        for rendered in [err.to_string(), format!("{err:?}")] {
            for needle in [
                "zebra", "Zebra", "vault", "Vault", "abababab", "cdcdcdcd", "ABABABAB", "171, 171",
                "205, 205",
            ] {
                assert!(
                    !rendered.contains(needle),
                    "error echoes certificate bytes ({needle}): {rendered}"
                );
            }
        }
    }
}
