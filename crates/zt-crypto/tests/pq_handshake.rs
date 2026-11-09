//! PQ-1 specification: the hybrid suite `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` on the
//! end-to-end channel (PROTOCOL §7.5).
//!
//! ```text
//! -> e, es, e1, s, ss       e1: ephemeral ML-KEM-768 encapsulation key (encrypted under es)
//! <- e, ee, ekem1, se       ekem1: its ciphertext (encrypted), then MixKey(shared secret)
//! ```
//!
//! The KEM is `zt_crypto::kem::MlKem768` (libcrux), handed to snow through a resolver. The
//! prologue is `TCN/2 end-to-end` followed by the suite id, and the protocol name is hashed
//! into the transcript, so a message of one suite is never valid as another.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use zt_crypto::noise::{self, Channel};
use zt_crypto::{CryptoError, Identity, Keyring};
use zt_domain::limits::MAX_ANY_CERT_LEN;
use zt_domain::{AcceptedSuites, HandshakeSuite};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn setup() -> (Identity, Keyring, zt_crypto::PublicKey) {
    let agent = Identity::generate().unwrap();
    let pk = agent.public_key();
    (Identity::generate().unwrap(), Keyring::single(agent), pk)
}

fn both() -> AcceptedSuites {
    AcceptedSuites::new([CLASSIC, HFS]).unwrap()
}

#[test]
fn a_pinned_hybrid_handshake_completes_end_to_end() {
    let (client, keys, pk) = setup();
    let (msg1, waiting) =
        noise::initiate_suite(&client, pk, Channel::EndToEnd, HFS, b"certificate").unwrap();
    assert_eq!(waiting.suite(), HFS);
    let pending =
        noise::respond_suites(&keys, &msg1, Channel::EndToEnd, AcceptedSuites::only(HFS)).unwrap();
    assert_eq!(pending.suite(), HFS);
    assert_eq!(pending.peer(), client.fingerprint());
    assert_eq!(pending.payload(), b"certificate");
    let (msg2, mut agent) = pending.accept().unwrap();
    let mut client_t = waiting.complete(&msg2).unwrap();
    assert_eq!(client_t.peer(), pk.fingerprint());
    assert_eq!(agent.peer(), client.fingerprint());
    // Both sides derived the same keys, in both directions.
    let ct = client_t.encrypt(HFS.confirmation()).unwrap();
    assert_eq!(agent.decrypt(&ct).unwrap(), b"TCN/2 ready");
    let ct = agent.encrypt(b"SSH-2.0-OpenSSH").unwrap();
    assert_eq!(client_t.decrypt(&ct).unwrap(), b"SSH-2.0-OpenSSH");
}

/// The sizes of PROTOCOL §7.5, measured: message 1 is 1 296 bytes plus the payload, message 2
/// 1 152 bytes.
#[test]
fn the_hybrid_suite_has_the_sizes_its_constants_say() {
    let (client, keys, pk) = setup();
    for payload in [Vec::new(), vec![0x42; 300], vec![0x5a; MAX_ANY_CERT_LEN]] {
        let (msg1, waiting) =
            noise::initiate_suite(&client, pk, Channel::EndToEnd, HFS, &payload).unwrap();
        assert_eq!(msg1.len(), 1_296 + payload.len());
        assert_eq!(msg1.len(), HFS.msg1_overhead() + payload.len());
        let pending =
            noise::respond_suites(&keys, &msg1, Channel::EndToEnd, AcceptedSuites::only(HFS))
                .unwrap();
        assert_eq!(pending.payload(), payload.as_slice());
        let (msg2, _) = pending.accept().unwrap();
        assert_eq!(msg2.len(), 1_152);
        assert_eq!(msg2.len(), HFS.msg2_len());
        waiting.complete(&msg2).unwrap();
    }
}

#[test]
fn a_responder_that_accepts_both_suites_finds_each_one() {
    let (client, keys, pk) = setup();
    for suite in [CLASSIC, HFS] {
        let (msg1, waiting) =
            noise::initiate_suite(&client, pk, Channel::EndToEnd, suite, &[]).unwrap();
        let pending = noise::respond_suites(&keys, &msg1, Channel::EndToEnd, both()).unwrap();
        assert_eq!(pending.suite(), suite);
        let (msg2, _) = pending.accept().unwrap();
        assert_eq!(waiting.complete(&msg2).unwrap().peer(), pk.fingerprint());
    }
}

/// Phase 5 rotation is unaffected: the previous key is tried for the hybrid suite too.
#[test]
fn the_previous_key_is_tried_for_the_hybrid_suite() {
    let client = Identity::generate().unwrap();
    let old = Identity::generate().unwrap();
    let old_pk = old.public_key();
    let keys = Keyring::rotating(Identity::generate().unwrap(), old).unwrap();
    let (msg1, waiting) =
        noise::initiate_suite(&client, old_pk, Channel::EndToEnd, HFS, &[]).unwrap();
    let pending = noise::respond_suites(&keys, &msg1, Channel::EndToEnd, both()).unwrap();
    assert_eq!(pending.suite(), HFS);
    let (msg2, _) = pending.accept().unwrap();
    waiting.complete(&msg2).unwrap();
}

/// PQ-1 on the outer channel: the hybrid suite completes there too, with the outer prologue
/// (`TCN/2 outer` ‖ `0x01`), and an end-to-end hybrid message 1 is not valid on it.
#[test]
fn the_hybrid_suite_runs_on_the_outer_channel_with_its_own_prologue() {
    let (client, keys, pk) = setup();
    let (msg1, waiting) = noise::initiate_suite(&client, pk, Channel::Outer, HFS, &[]).unwrap();
    assert_eq!(msg1.len(), HFS.msg1_overhead());
    let pending =
        noise::respond_suites(&keys, &msg1, Channel::Outer, AcceptedSuites::only(HFS)).unwrap();
    assert_eq!(pending.suite(), HFS);
    let (msg2, mut responder) = pending.accept().unwrap();
    assert_eq!(msg2.len(), HFS.msg2_len());
    let mut initiator = waiting.complete(&msg2).unwrap();
    let sealed = initiator.encrypt(b"first frame").unwrap();
    assert_eq!(responder.decrypt(&sealed).unwrap(), b"first frame");
    let (e2e, _) = noise::initiate_suite(&client, pk, Channel::EndToEnd, HFS, &[]).unwrap();
    assert_eq!(
        noise::respond_suites(&keys, &e2e, Channel::Outer, AcceptedSuites::only(HFS)).err(),
        Some(CryptoError::Handshake)
    );
}

/// Every hybrid handshake draws fresh ephemeral keys (X25519 and ML-KEM): two handshakes
/// between the same parties never produce the same messages or keys.
#[test]
fn every_hybrid_handshake_is_fresh() {
    let (client, keys, pk) = setup();
    let run = || {
        let (msg1, waiting) =
            noise::initiate_suite(&client, pk, Channel::EndToEnd, HFS, &[]).unwrap();
        let pending =
            noise::respond_suites(&keys, &msg1, Channel::EndToEnd, AcceptedSuites::only(HFS))
                .unwrap();
        let (msg2, _) = pending.accept().unwrap();
        let mut t = waiting.complete(&msg2).unwrap();
        (msg1, msg2, t.encrypt(b"same plaintext").unwrap())
    };
    let (a, b) = (run(), run());
    assert_ne!(a.0, b.0);
    assert_ne!(a.1, b.1);
    assert_ne!(a.2, b.2);
}
