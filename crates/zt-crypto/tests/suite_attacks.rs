//! PQ-0 attack catalogue for the suite-aware handshake: suites outside the accepted set are not
//! even tried, channels stay separated, lengths outside the suite bounds are refused.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use zt_crypto::noise::{self, Channel};
use zt_crypto::{CryptoError, Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn setup() -> (Identity, Keyring, zt_crypto::PublicKey) {
    let relay = Identity::generate().unwrap();
    let pk = relay.public_key();
    (Identity::generate().unwrap(), Keyring::single(relay), pk)
}

/// Downgrade: a responder that does not accept the classical suite does not run it, even on
/// a perfectly valid classical message 1.
#[test]
fn a_suite_outside_the_accepted_set_is_not_tried() {
    let (client, keys, pk) = setup();
    let (msg1, _) = noise::initiate_suite(&client, pk, Channel::Outer, CLASSIC, &[]).unwrap();
    assert_eq!(
        noise::respond_suites(&keys, &msg1, Channel::Outer, AcceptedSuites::only(HFS)).err(),
        Some(CryptoError::Handshake)
    );
}

/// Identity / domain separation: the suite API keeps the per-channel prologues.
#[test]
fn an_outer_message_1_is_not_valid_end_to_end() {
    let (client, keys, pk) = setup();
    let (msg1, _) = noise::initiate_suite(&client, pk, Channel::Outer, CLASSIC, &[]).unwrap();
    assert!(
        noise::respond_suites(
            &keys,
            &msg1,
            Channel::EndToEnd,
            AcceptedSuites::only(CLASSIC)
        )
        .is_err()
    );
}

/// Parsing: lengths outside the suite's bounds never reach Noise, and fail like any other
/// invalid message (no oracle).
#[test]
fn message_1_lengths_outside_the_suite_bounds_are_refused() {
    let (client, keys, pk) = setup();
    let (msg1, _) = noise::initiate_suite(&client, pk, Channel::Outer, CLASSIC, &[]).unwrap();
    let accepted = AcceptedSuites::only(CLASSIC);
    let mut too_long = msg1.clone();
    too_long.resize(CLASSIC.max_msg1_len() + 1, 0);
    for bad in [
        Vec::new(),
        vec![0; 1],
        msg1[..msg1.len() - 1].to_vec(),
        too_long,
        vec![0; 65_536],
    ] {
        assert_eq!(
            noise::respond_suites(&keys, &bad, Channel::Outer, accepted).err(),
            Some(CryptoError::Handshake),
            "len {}",
            bad.len()
        );
    }
}

/// Resources: a message 1 at exactly the largest legitimate size is still parsed (a valid
/// maximum-size certificate payload must fit).
#[test]
fn a_message_1_at_the_largest_legitimate_size_is_accepted() {
    let (client, keys, pk) = setup();
    let payload = vec![0x5a; zt_domain::limits::MAX_ANY_CERT_LEN];
    let (msg1, _) = noise::initiate_suite(&client, pk, Channel::Outer, CLASSIC, &payload).unwrap();
    assert_eq!(msg1.len(), CLASSIC.max_msg1_len());
    let pending =
        noise::respond_suites(&keys, &msg1, Channel::Outer, AcceptedSuites::only(CLASSIC)).unwrap();
    assert_eq!(pending.payload().len(), payload.len());
}
