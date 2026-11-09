//! PQ-1 specification of `zt-client`: a node pinned to the hybrid suite in `client.toml`
//! (`suite` in its `[[nodes]]` entry) is reached through an unchanged relay.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

mod common;

use std::time::Duration;

use common::{Counting, Fleet, echo_through, finish};
use zt_domain::{AcceptedSuites, HandshakeSuite};

const HFS: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";

fn both() -> AcceptedSuites {
    AcceptedSuites::new([
        HandshakeSuite::NoiseIk25519,
        HandshakeSuite::NoiseIkhfs25519MlKem768,
    ])
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_pinned_to_the_hybrid_suite_is_reached() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent_with(ssh.addr, both()).await;
    let dir = fleet.client_dir(&fleet.ansible);
    dir.pin_last_node_suite(HFS);

    let mut child = dir.spawn("web-01");
    let data: Vec<u8> = (0..256 * 1024_usize).map(|i| (i % 251) as u8).collect();
    assert_eq!(echo_through(&mut child, &data).await, data);
    let out = finish(child, Duration::from_secs(10)).await;
    assert!(out.success, "stderr: {}", out.stderr);
    assert_eq!(ssh.count(), 1);
}

/// No fallback: a client pinned to the hybrid suite towards an agent that accepts only the
/// classical one fails, and never retries with the classical suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hybrid_pin_towards_a_classical_agent_fails_closed() {
    let fleet = Fleet::start().await;
    let ssh = Counting::start(true).await;
    fleet.start_agent(ssh.addr).await;
    let dir = fleet.client_dir(&fleet.ansible);
    dir.pin_last_node_suite(HFS);

    let child = dir.spawn("web-01");
    let out = finish(child, Duration::from_secs(15)).await;
    assert!(!out.success, "a classical agent accepted a hybrid pin");
    assert_eq!(ssh.count(), 0);
}

/// The relay pin is the outer channel: the hybrid suite is refused there in this release,
/// before any connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hybrid_relay_pin_is_a_configuration_error() {
    let fleet = Fleet::start().await;
    let dir = fleet.client_dir(&fleet.ansible);
    let path = dir.config();
    let toml = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("relay_suite = \"{HFS}\"\n{toml}")).unwrap();
    let out = finish(dir.spawn("web-01"), Duration::from_secs(10)).await;
    assert!(!out.success);
    assert!(out.stderr.contains("suite"), "{}", out.stderr);
}
