//! PQ-0 baseline: handshake and ML-KEM CPU cost on this machine (docs/analysis/pq.md §3.5).
//!
//! Ignored by default; run it in release mode, on an otherwise idle machine:
//!
//! ```sh
//! cargo test --release -p zt-crypto --test baseline -- --ignored --nocapture
//! ```
//!
//! It prints the median and the 99th percentile per operation. PQ-1 compares its own numbers
//! against these (the perf gate in pq.md §7: ≤ +200 µs p99 per side on x86_64). The figures
//! recorded so far are in docs/pq-snow.md §5.
#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    missing_docs
)]

use std::time::{Duration, Instant};

use zt_crypto::kem::{Kem, KemSeed, MlKem768, SEED_LEN};
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const ROUNDS: usize = 2_000;

fn report(name: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q) as usize];
    println!(
        "{name:<40} median {:>8.1} µs   p99 {:>8.1} µs   (n = {})",
        at(0.5).as_secs_f64() * 1e6,
        at(0.99).as_secs_f64() * 1e6,
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

#[test]
#[ignore = "timing baseline: run explicitly in release mode"]
fn classical_handshake_cpu_baseline() {
    let client = Identity::generate().unwrap();
    let relay = Identity::generate().unwrap();
    let relay_pk = relay.public_key();
    let keys = Keyring::single(relay);
    let accepted = AcceptedSuites::only(HandshakeSuite::NoiseIk25519);
    let cert = vec![0x5a; 400];
    let classic = HandshakeSuite::NoiseIk25519;

    report(
        "initiator: write msg1",
        time(|| {
            let _ =
                noise::initiate_suite(&client, &relay_pk, Channel::Outer, classic, &cert).unwrap();
        }),
    );
    let (msg1, _) =
        noise::initiate_suite(&client, &relay_pk, Channel::Outer, classic, &cert).unwrap();
    report(
        "responder: read msg1 (unauthenticated cost)",
        time(|| {
            let _ = noise::respond_suites(&keys, &msg1, Channel::Outer, accepted).unwrap();
        }),
    );
    let mut garbage = msg1.clone();
    garbage[40] ^= 1;
    report(
        "responder: reject an invalid msg1",
        time(|| {
            assert!(noise::respond_suites(&keys, &garbage, Channel::Outer, accepted).is_err());
        }),
    );
    report(
        "responder: read msg1 + write msg2",
        time(|| {
            let pending = noise::respond_suites(&keys, &msg1, Channel::Outer, accepted).unwrap();
            let _ = pending.accept().unwrap();
        }),
    );
    report(
        "full handshake, both sides",
        time(|| {
            let (msg1, waiting) =
                noise::initiate_suite(&client, &relay_pk, Channel::Outer, classic, &cert).unwrap();
            let pending = noise::respond_suites(&keys, &msg1, Channel::Outer, accepted).unwrap();
            let (msg2, _) = pending.accept().unwrap();
            let _ = waiting.complete(&msg2).unwrap();
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
