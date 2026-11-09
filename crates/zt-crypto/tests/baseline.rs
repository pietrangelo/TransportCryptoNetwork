//! PQ-0 / PQ-1 baseline: handshake and ML-KEM CPU cost on this machine (docs/analysis/pq.md
//! §3.5), for the classical suite and, end to end, the hybrid one.
//!
//! Ignored by default; run it in release mode, on an otherwise idle machine:
//!
//! ```sh
//! cargo test --release -p zt-crypto --test baseline -- --ignored --nocapture
//! ```
//!
//! It prints the median and the 99th percentile per operation. The perf gate of PQ-1 (pq.md §7:
//! ≤ +200 µs p99 per side on `x86_64`) compares the hybrid rows with the classical ones. The
//! figures recorded so far are in docs/pq-snow.md §5.
#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::time::{Duration, Instant};

use zt_crypto::kem::{Kem, KemSeed, MlKem768, SEED_LEN};
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, Keyring, PeerKey};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const ROUNDS: usize = 2_000;

fn report(name: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    // Nearest-rank percentile, in integers: `per_mille` of the sorted samples.
    let at = |per_mille: usize| samples[(samples.len() - 1) * per_mille / 1_000];
    println!(
        "{name:<40} median {:>8.1} µs   p99 {:>8.1} µs   (n = {})",
        at(500).as_secs_f64() * 1e6,
        at(990).as_secs_f64() * 1e6,
        samples.len()
    );
}

fn time(mut op: impl FnMut()) -> Vec<Duration> {
    // Warm-up, then one sample per call.
    for _ in 0..ROUNDS / 10 {
        op();
    }
    (0..ROUNDS)
        .map(|_| {
            let t = Instant::now();
            op();
            t.elapsed()
        })
        .collect()
}

/// Every step of one handshake of `suite` on `channel`, with a 400-byte certificate.
fn handshake_baseline(suite: HandshakeSuite, channel: Channel) {
    let client = Identity::generate().unwrap();
    let responder = Identity::generate().unwrap();
    // The hybrid IK suite pins the responder's v2 key (PROTOCOL §7.5.3).
    let responder_pk: PeerKey = if suite.requires_hybrid_identity() {
        responder.hybrid_public_key().into()
    } else {
        responder.public_key().into()
    };
    let keys = Keyring::single(responder);
    let accepted = AcceptedSuites::only(suite);
    let cert = vec![0x5a; 400];
    println!("{suite} ({channel:?})");

    report(
        "initiator: write msg1",
        time(|| {
            let _ = noise::initiate_suite(&client, &responder_pk, channel, suite, &cert).unwrap();
        }),
    );
    let (msg1, _) = noise::initiate_suite(&client, &responder_pk, channel, suite, &cert).unwrap();
    report(
        "responder: read msg1 (unauthenticated cost)",
        time(|| {
            let _ = noise::respond_suites(&keys, &msg1, channel, accepted).unwrap();
        }),
    );
    let mut garbage = msg1.clone();
    garbage[40] ^= 1;
    report(
        "responder: reject an invalid msg1",
        time(|| {
            assert!(noise::respond_suites(&keys, &garbage, channel, accepted).is_err());
        }),
    );
    report(
        "responder: read msg1 + write msg2",
        time(|| {
            let pending = noise::respond_suites(&keys, &msg1, channel, accepted).unwrap();
            let _ = pending.accept().unwrap();
        }),
    );
    report(
        "initiator: read msg2",
        time_with(
            || {
                let (msg1, waiting) =
                    noise::initiate_suite(&client, &responder_pk, channel, suite, &cert).unwrap();
                let pending = noise::respond_suites(&keys, &msg1, channel, accepted).unwrap();
                let (msg2, _) = pending.accept().unwrap();
                (waiting, msg2)
            },
            |(waiting, msg2)| {
                let _ = waiting.complete(&msg2).unwrap();
            },
        ),
    );
    report(
        "full handshake, both sides",
        time(|| {
            let (msg1, waiting) =
                noise::initiate_suite(&client, &responder_pk, channel, suite, &cert).unwrap();
            let pending = noise::respond_suites(&keys, &msg1, channel, accepted).unwrap();
            let (msg2, _) = pending.accept().unwrap();
            let _ = waiting.complete(&msg2).unwrap();
        }),
    );
}

/// Like [`time`], with an untimed `setup` before each sample.
fn time_with<T>(mut setup: impl FnMut() -> T, mut op: impl FnMut(T)) -> Vec<Duration> {
    for _ in 0..ROUNDS / 10 {
        op(setup());
    }
    (0..ROUNDS)
        .map(|_| {
            let input = setup();
            let t = Instant::now();
            op(input);
            t.elapsed()
        })
        .collect()
}

#[test]
#[ignore = "timing baseline: run explicitly in release mode"]
fn classical_handshake_cpu_baseline() {
    handshake_baseline(HandshakeSuite::NoiseIk25519, Channel::Outer);
    handshake_baseline(HandshakeSuite::NoiseIk25519, Channel::EndToEnd);
}

#[test]
#[ignore = "timing baseline: run explicitly in release mode"]
fn hybrid_handshake_cpu_baseline() {
    handshake_baseline(HandshakeSuite::NoiseIkhfs25519MlKem768, Channel::EndToEnd);
    // An agent that accepts both suites tries both on an invalid message 1 of a length both
    // can have (the unauthenticated cost an end-to-end msg1 can cause, PROTOCOL §7.5).
    let client = Identity::generate().unwrap();
    let agent = Identity::generate().unwrap();
    let agent_pk = agent.public_key();
    let keys = Keyring::single(agent);
    let both = AcceptedSuites::new([
        HandshakeSuite::NoiseIk25519,
        HandshakeSuite::NoiseIkhfs25519MlKem768,
    ])
    .unwrap();
    let (mut msg1, _) = noise::initiate_suite(
        &client,
        agent_pk,
        Channel::EndToEnd,
        HandshakeSuite::NoiseIkhfs25519MlKem768,
        &[0x5a; 400],
    )
    .unwrap();
    msg1[40] ^= 1;
    report(
        "both suites: reject an invalid msg1",
        time(|| {
            assert!(noise::respond_suites(&keys, &msg1, Channel::EndToEnd, both).is_err());
        }),
    );
}

/// PQ-AUTH: the hybrid IK suite on both channels. Its responder decapsulates `ct1` with its
/// static key before Noise runs: that is the new unauthenticated cost of an invalid message 1.
#[test]
#[ignore = "timing baseline: run explicitly in release mode"]
fn hybrid_ik_handshake_cpu_baseline() {
    handshake_baseline(HandshakeSuite::NoiseIkHybrid25519MlKem768, Channel::Outer);
    handshake_baseline(
        HandshakeSuite::NoiseIkHybrid25519MlKem768,
        Channel::EndToEnd,
    );
    report(
        "identity: derive the static ML-KEM key",
        time(|| {
            let _ = Identity::from_secret_hex(&"11".repeat(32)).unwrap();
        }),
    );
}

#[test]
#[ignore = "timing baseline: run explicitly in release mode"]
fn ml_kem_768_cpu_baseline() {
    let mut i = 0_u8;
    report(
        "ML-KEM-768 keygen (libcrux)",
        time(|| {
            i = i.wrapping_add(1);
            let _ = MlKem768::generate(&KemSeed::from_bytes([i; SEED_LEN]));
        }),
    );
    let (dk, ek) = MlKem768::generate(&KemSeed::from_bytes([1; SEED_LEN]));
    report(
        "ML-KEM-768 encapsulate (libcrux)",
        time(|| {
            i = i.wrapping_add(1);
            let _ = MlKem768::encapsulate(&ek, &[i; 32]).unwrap();
        }),
    );
    let (ct, _) = MlKem768::encapsulate(&ek, &[2; 32]).unwrap();
    report(
        "ML-KEM-768 decapsulate (libcrux)",
        time(|| {
            let _ = MlKem768::decapsulate(&dk, &ct).unwrap();
        }),
    );
}
