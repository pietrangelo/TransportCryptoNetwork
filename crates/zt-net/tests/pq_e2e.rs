//! PQ-1 specification, on the wire: the hybrid suite on the end-to-end channel (client ↔
//! agent) through real relays that are **not** changed, configured or restarted for it
//! (PROTOCOL §7.5, docs/analysis/pq.md §6.3).
//!
//! The relays of these tests run with the configuration every earlier release had: the
//! classical suite on the outer channel and no suite option at all. They forward the hybrid
//! end-to-end handshake as the opaque `Data` payloads it is.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::{
    Ca, Captured, Lab, agent_clients, assert_alive, field, relay_config, relay_policy, scope,
    trust,
};
use zt_crypto::Identity;
use zt_domain::{AcceptedSuites, AllowedNodes, HandshakeSuite};
use zt_net::relay::RelayConfig;

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

fn both() -> AcceptedSuites {
    AcceptedSuites::new([CLASSIC, HFS]).unwrap()
}

/// The relay exactly as earlier releases configure it: no suite options.
fn unchanged_relay() -> RelayConfig {
    let config = relay_config();
    assert_eq!(config.suites, zt_domain::SuitePolicy::classical());
    config
}

async fn lab(whitelist: &[&Arc<Identity>], accepted: AcceptedSuites) -> Lab {
    let agent = id();
    let keys: Vec<_> = whitelist.iter().map(|c| c.fingerprint()).collect();
    let policy = relay_policy(&agent.fingerprint(), &keys, zt_domain::trust::CertTrust::new());
    Lab::start_suites(
        agent,
        vec![(policy, unchanged_relay())],
        agent_clients(&keys, zt_domain::trust::CertTrust::new()),
        accepted,
    )
    .await
}

#[tokio::test]
async fn a_hybrid_session_crosses_an_unchanged_relay() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let lab = lab(&[&alice], both()).await;
    let (mut app, _task) = lab
        .session_with(&alice, lab.config_suite(None, HFS))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 1);
    // The agent names the suite of the session; the relay knows nothing about it.
    let started = log.events("e2e_session_started");
    assert_eq!(started.len(), 1, "{}", log.text());
    assert_eq!(
        field(&started[0], "suite").as_deref(),
        Some(HFS.protocol_name())
    );
    let established = log.events("session_established");
    assert_eq!(established.len(), 1, "{}", log.text());
    assert!(field(&established[0], "suite").is_none(), "{}", established[0]);
}

/// A certificate travels in message 1 of both channels (PROTOCOL §15.3): on the outer one
/// under the classical suite, end to end under the hybrid one. Both verify it.
#[tokio::test]
async fn a_certified_client_reaches_its_node_with_the_hybrid_suite() {
    let ca = Ca::new();
    let alice = id();
    let agent = id();
    let lab = Lab::start_suites(
        Arc::clone(&agent),
        vec![(
            relay_policy(
                &agent.fingerprint(),
                &[],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            ),
            unchanged_relay(),
        )],
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
        both(),
    )
    .await;
    let (cert, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (mut app, _task) = lab
        .session_with(&alice, lab.config_suite(Some(&cert), HFS))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 1);
}

/// Rollout step 1 (OPERATIONS §12): an upgraded agent accepts both suites, so clients that
/// still pin the classical suite keep working while others flip.
#[tokio::test]
async fn classical_and_hybrid_clients_share_an_agent_that_accepts_both() {
    let (alice, bob) = (id(), id());
    let lab = lab(&[&alice, &bob], both()).await;
    let (mut a, _ta) = lab
        .session_with(&alice, lab.config_suite(None, CLASSIC))
        .await
        .unwrap();
    let (mut b, _tb) = lab
        .session_with(&bob, lab.config_suite(None, HFS))
        .await
        .unwrap();
    assert_alive(&mut a).await;
    assert_alive(&mut b).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 2);
}

/// An agent that accepts only the hybrid suite (the end state, PQ-SUNSET) serves hybrid clients.
#[tokio::test]
async fn an_agent_that_accepts_only_the_hybrid_suite_serves_hybrid_clients() {
    let alice = id();
    let lab = lab(&[&alice], AcceptedSuites::only(HFS)).await;
    let (mut app, _task) = lab
        .session_with(&alice, lab.config_suite(None, HFS))
        .await
        .unwrap();
    assert_alive(&mut app).await;
}

/// AP-7: the agent logs the suites it accepts from clients at startup.
#[tokio::test]
async fn the_agent_logs_the_accepted_suites_at_startup() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let _lab = lab(&[&alice], both()).await;
    let lines = log.events("handshake_suites_in_use");
    let agent_line = lines
        .iter()
        .find(|l| field(l, "role").as_deref() == Some("agent"))
        .unwrap_or_else(|| panic!("{}", log.text()));
    let names = field(agent_line, "client_suites").unwrap();
    assert!(names.contains(CLASSIC.protocol_name()), "{agent_line}");
    assert!(names.contains(HFS.protocol_name()), "{agent_line}");
    assert_eq!(
        field(agent_line, "relay_suites").as_deref(),
        Some(CLASSIC.protocol_name()),
        "{agent_line}"
    );
}
