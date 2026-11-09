//! PQ-0 specification: the handshake API takes an explicit suite (PROTOCOL §7.5).
//!
//! The classical suite is byte-for-byte today's handshake: no envelope, no magic, the same
//! prologues (finding AP-11), so v1 peers interoperate with the new API in both directions.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn ids() -> (Identity, Identity) {
    (Identity::generate().unwrap(), Identity::generate().unwrap())
}

#[test]
fn a_pinned_classical_handshake_completes_and_reports_its_suite() {
    let (client, relay) = ids();
    let keys = Keyring::single(Identity::from_secret_hex(&relay.to_secret_hex()).unwrap());
    let (msg1, waiting) = noise::initiate_suite(
        &client,
        &relay.public_key(),
        Channel::Outer,
        CLASSIC,
        b"cert",
    )
    .unwrap();
    assert_eq!(waiting.suite(), CLASSIC);
    let pending =
        noise::respond_suites(&keys, &msg1, Channel::Outer, AcceptedSuites::only(CLASSIC)).unwrap();
    assert_eq!(pending.suite(), CLASSIC);
    assert_eq!(pending.peer(), client.fingerprint());
    assert_eq!(pending.payload(), b"cert");
    let (msg2, mut r) = pending.accept().unwrap();
    let mut c = waiting.complete(&msg2).unwrap();
    let ct = c.encrypt(b"TCN/1 ready").unwrap();
    assert_eq!(r.decrypt(&ct).unwrap(), b"TCN/1 ready");
}

#[test]
fn the_classical_suite_has_the_sizes_its_constants_say() {
    let (client, relay) = ids();
    let keys = Keyring::single(Identity::from_secret_hex(&relay.to_secret_hex()).unwrap());
    let payload = vec![0x42; 300];
    let (msg1, waiting) = noise::initiate_suite(
        &client,
        &relay.public_key(),
        Channel::EndToEnd,
        CLASSIC,
        &payload,
    )
    .unwrap();
    assert_eq!(msg1.len(), CLASSIC.msg1_overhead() + payload.len());
    let pending = noise::respond_suites(
        &keys,
        &msg1,
        Channel::EndToEnd,
        AcceptedSuites::only(CLASSIC),
    )
    .unwrap();
    let (msg2, _) = pending.accept().unwrap();
    assert_eq!(msg2.len(), CLASSIC.msg2_len());
    waiting.complete(&msg2).unwrap();
}

#[test]
fn the_new_api_is_wire_compatible_with_the_v1_one() {
    let (client, relay) = ids();
    let keys = Keyring::single(Identity::from_secret_hex(&relay.to_secret_hex()).unwrap());
    // New initiator, v1 responder.
    let (msg1, waiting) =
        noise::initiate_suite(&client, &relay.public_key(), Channel::Outer, CLASSIC, &[]).unwrap();
    let (msg2, _) = noise::respond_any(&keys, &msg1, Channel::Outer)
        .unwrap()
        .accept()
        .unwrap();
    waiting.complete(&msg2).unwrap();
    // v1 initiator, new responder.
    let (msg1, waiting) = noise::initiate(&client, &relay.public_key(), Channel::Outer).unwrap();
    let pending =
        noise::respond_suites(&keys, &msg1, Channel::Outer, AcceptedSuites::only(CLASSIC)).unwrap();
    assert_eq!(pending.suite(), CLASSIC);
    let (msg2, _) = pending.accept().unwrap();
    waiting.complete(&msg2).unwrap();
}

#[test]
fn the_previous_key_is_still_tried_for_every_accepted_suite() {
    let (client, old) = ids();
    let new = Identity::generate().unwrap();
    let keys = Keyring::rotating(
        new,
        Identity::from_secret_hex(&old.to_secret_hex()).unwrap(),
    )
    .unwrap();
    let (msg1, _) =
        noise::initiate_suite(&client, &old.public_key(), Channel::Outer, CLASSIC, &[]).unwrap();
    let pending =
        noise::respond_suites(&keys, &msg1, Channel::Outer, AcceptedSuites::only(CLASSIC)).unwrap();
    assert_eq!(pending.peer(), client.fingerprint());
}

#[test]
fn an_initiator_pins_the_hybrid_suite_on_either_channel() {
    // Every suite of this build runs on both channels since PQ-1 on the outer channel;
    // `UnsupportedSuite` stays for a future suite that does not.
    let (client, relay) = ids();
    for channel in [Channel::Outer, Channel::EndToEnd] {
        let (msg1, waiting) =
            noise::initiate_suite(&client, &relay.public_key(), channel, HFS, &[]).unwrap();
        assert_eq!(msg1.len(), HFS.msg1_overhead());
        assert_eq!(waiting.suite(), HFS);
    }
}
