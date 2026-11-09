//! Phase 6, step 1: properties of the certificate decoder on arbitrary and structured inputs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod common;

use common::Raw;
use proptest::collection::{btree_set, vec};
use proptest::prelude::*;
use zt_domain::decode_certificate;
use zt_domain::limits::{MAX_CERT_LEN, MIN_CERT_LEN};

/// Any valid `NodeId`.
fn node_id() -> impl Strategy<Value = Vec<u8>> {
    "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?".prop_map(String::into_bytes)
}

/// A certificate valid for the format.
fn valid_raw() -> impl Strategy<Value = Raw> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 16]>(),
        any::<u64>(),
        1_u64..=86_400,
        node_id(),
        prop_oneof![Just(None), btree_set(node_id(), 1..=20).prop_map(Some),],
        vec(any::<u8>(), 64),
    )
        .prop_filter_map(
            "keys must differ, serial non-zero, no overflow",
            |(ca, subject, serial, nb, life, name, nodes, signature)| {
                if ca == subject || serial == [0; 16] {
                    return None;
                }
                let na = nb.checked_add(life)?;
                let (scope, nodes) = match nodes {
                    None => (1, Vec::new()),
                    Some(set) => (0, set.into_iter().collect()),
                };
                Some(Raw {
                    ca_key: ca,
                    subject_key: subject,
                    serial,
                    not_before: nb,
                    not_after: na,
                    name,
                    scope,
                    nodes,
                    signature,
                    ..Raw::valid()
                })
            },
        )
}

/// Targeted modifications to a valid certificate, to get past the first filters.
fn mutated() -> impl Strategy<Value = Vec<u8>> {
    (
        valid_raw(),
        vec((any::<usize>(), any::<u8>()), 1..4),
        any::<Option<usize>>(),
    )
        .prop_map(|(raw, flips, cut)| {
            let mut bytes = raw.bytes();
            for (pos, x) in flips {
                let len = bytes.len();
                bytes[pos % len] ^= x;
            }
            if let Some(cut) = cut {
                let len = bytes.len();
                bytes.truncate(cut % (len + 1));
            }
            bytes
        })
}

fn check_canonical(bytes: &[u8]) -> Result<(), TestCaseError> {
    if let Ok(parsed) = decode_certificate(bytes) {
        prop_assert!((MIN_CERT_LEN..=MAX_CERT_LEN).contains(&bytes.len()));
        let mut again = parsed.body.encode_tbs();
        prop_assert_eq!(again.as_slice(), parsed.tbs);
        again.extend_from_slice(parsed.signature);
        prop_assert_eq!(
            again.as_slice(),
            bytes,
            "accepted certificate is not canonical"
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic_and_accepted_certificates_are_canonical(
        valid in valid_raw(),
        noise in vec(any::<u8>(), 0..5000),
        near in mutated(),
    ) {
        // Structured: every valid certificate is accepted, with the same body, and is canonical.
        let bytes = valid.bytes();
        let parsed = decode_certificate(&bytes);
        prop_assert!(parsed.is_ok(), "valid certificate refused: {:?}", parsed.err());
        prop_assert_eq!(parsed.unwrap().body, valid.body());
        check_canonical(&bytes)?;
        // Arbitrary and near-valid: no panic; if accepted, canonical.
        check_canonical(&noise)?;
        check_canonical(&near)?;
    }
}
