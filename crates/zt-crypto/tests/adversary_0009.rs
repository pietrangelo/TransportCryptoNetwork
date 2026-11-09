//! Regression tests for adversary review 0009 (docs/adversary/0009-phase2-pq1-e2e.md).
//!
//! A9-3: a message 1 whose suite the responder does not accept is only **identified** (who,
//! which suite, which payload), as a value that has no `accept`: it can never produce a
//! message 2, whatever the caller does with it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use zt_crypto::noise::{self, Channel, Responded};
use zt_crypto::{Identity, Keyring};
use zt_domain::limits::MAX_ANY_CERT_LEN;
use zt_domain::{AcceptedSuites, HandshakeSuite};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn both() -> AcceptedSuites {
    AcceptedSuites::new([CLASSIC, HFS]).unwrap()
}

fn agent() -> (Identity, Keyring) {
    let id = Identity::generate().unwrap();
    let keys = Keyring::single(Identity::from_secret_hex(&id.to_secret_hex()).unwrap());
    (id, keys)
}

/// A9-3: in either direction, a known initiator with a suite outside the set is identified,
/// not pending.
#[test]
fn a_suite_outside_the_accepted_set_is_identified_but_never_pending() {
    let (agent, keys) = agent();
    let alice = Identity::generate().unwrap();
    for (sent, accepted) in [
        (CLASSIC, AcceptedSuites::only(HFS)),
        (HFS, AcceptedSuites::only(CLASSIC)),
    ] {
        let (msg1, _) =
            noise::initiate_suite(&alice, agent.public_key(), Channel::EndToEnd, sent, b"cert")
                .unwrap();
        match noise::respond_or_identify(&keys, &msg1, Channel::EndToEnd, accepted).unwrap() {
            Responded::Unaccepted(found) => {
                assert_eq!(found.peer(), alice.fingerprint());
                assert_eq!(found.suite(), sent);
                assert_eq!(found.payload(), b"cert");
            }
            Responded::Pending(_) => panic!("{sent:?} is outside {accepted:?}"),
        }
    }
}

/// A9-3: a suite inside the set is pending, and only that one.
#[test]
fn a_suite_inside_the_accepted_set_is_pending() {
    let (agent, keys) = agent();
    let alice = Identity::generate().unwrap();
    for (sent, accepted) in [
        (CLASSIC, AcceptedSuites::only(CLASSIC)),
        (HFS, AcceptedSuites::only(HFS)),
        (CLASSIC, both()),
        (HFS, both()),
    ] {
        let (msg1, _) =
            noise::initiate_suite(&alice, agent.public_key(), Channel::EndToEnd, sent, &[])
                .unwrap();
        match noise::respond_or_identify(&keys, &msg1, Channel::EndToEnd, accepted).unwrap() {
            Responded::Pending(pending) => {
                assert_eq!(pending.suite(), sent);
                assert!(accepted.contains(pending.suite()));
                assert!(pending.accept().is_ok());
            }
            Responded::Unaccepted(_) => panic!("{sent:?} is inside {accepted:?}"),
        }
    }
}

/// A9-3: an invalid message is an error for every set; the fallback adds no oracle.
#[test]
fn an_invalid_message_1_is_an_error_for_every_set() {
    let (_, keys) = agent();
    for len in [0, 95, 96, 500, 1_296, 4_424, 5_624] {
        for accepted in [
            AcceptedSuites::only(CLASSIC),
            AcceptedSuites::only(HFS),
            both(),
        ] {
            assert!(
                noise::respond_or_identify(&keys, &vec![0x42; len], Channel::EndToEnd, accepted)
                    .is_err()
            );
        }
    }
}

/// A9-5: a hybrid message 1 with the largest certificate is identified by a classical-only
/// responder (it is longer than any classical message 1).
#[test]
fn a_hybrid_message_1_with_the_largest_certificate_is_identified_by_a_classical_responder() {
    let (agent, keys) = agent();
    let alice = Identity::generate().unwrap();
    let payload = vec![0x54; MAX_ANY_CERT_LEN];
    let (msg1, _) =
        noise::initiate_suite(&alice, agent.public_key(), Channel::EndToEnd, HFS, &payload)
            .unwrap();
    assert!(msg1.len() > CLASSIC.max_msg1_len());
    match noise::respond_or_identify(
        &keys,
        &msg1,
        Channel::EndToEnd,
        AcceptedSuites::only(CLASSIC),
    )
    .unwrap()
    {
        Responded::Unaccepted(found) => {
            assert_eq!(found.suite(), HFS);
            assert_eq!(found.payload(), &payload[..]);
        }
        Responded::Pending(_) => panic!("the hybrid suite is not accepted"),
    }
}

/// A9-3: on the outer channel there is nothing to fall back to: only the classical suite runs
/// there, so a message 1 of another channel is an error, never identified.
#[test]
fn the_outer_channel_has_no_fallback() {
    let (agent, keys) = agent();
    let alice = Identity::generate().unwrap();
    let (e2e, _) =
        noise::initiate_suite(&alice, agent.public_key(), Channel::EndToEnd, HFS, &[]).unwrap();
    assert!(
        noise::respond_or_identify(&keys, &e2e, Channel::Outer, AcceptedSuites::only(CLASSIC))
            .is_err()
    );
}
