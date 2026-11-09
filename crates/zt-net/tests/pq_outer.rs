//! PQ-1 specification, on the wire: the hybrid suite on the **outer** channel (client ↔ relay
//! and agent ↔ relay), with accepted sets per role on the relay, one pinned suite per relay on
//! the initiators and a mixed fleet during the rollout (PROTOCOL §7.5, §7.5.2,
//! docs/analysis/pq.md §6.3).
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
use std::time::Duration;

use common::{
    Captured, Lab, agent_clients, assert_alive, field, number, relay_config, relay_policy,
};
use zt_crypto::Identity;
use zt_domain::{AcceptedSuites, HandshakeChannel, HandshakeSuite, SuitePolicy};
use zt_net::relay::RelayConfig;

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

fn both() -> AcceptedSuites {
    AcceptedSuites::new([CLASSIC, HFS]).unwrap()
}

fn relay_with(suites: SuitePolicy) -> RelayConfig {
    let mut config = RelayConfig {
        suites,
        ..relay_config()
    };
    config.admission.summary_interval = Duration::from_secs(1);
    config
}

/// One relay with `suites`, the `web-01` agent pinning `agent_suite` towards it, and
/// `alice` whitelisted on both sides (both end-to-end suites accepted by the agent).
async fn lab(alice: &Arc<Identity>, suites: SuitePolicy, agent_suite: HandshakeSuite) -> Lab {
    let agent = id();
    let keys = [alice.fingerprint()];
    let policy = relay_policy(
        &agent.fingerprint(),
        &keys,
        zt_domain::trust::CertTrust::new(),
    );
    Lab::start_outer(
        agent,
        vec![(policy, relay_with(suites))],
        agent_clients(&keys, zt_domain::trust::CertTrust::new()),
        both(),
        agent_suite,
    )
    .await
}

#[test]
fn the_hybrid_suite_runs_on_both_channels() {
    assert!(HFS.is_supported(HandshakeChannel::Outer));
    assert!(HFS.is_supported(HandshakeChannel::EndToEnd));
    // PQ-AUTH adds the hybrid IK suite (PROTOCOL §7.5.3) on both channels.
    assert_eq!(
        AcceptedSuites::supported(HandshakeChannel::Outer),
        AcceptedSuites::new([CLASSIC, HFS, HandshakeSuite::NoiseIkHybrid25519MlKem768]).unwrap()
    );
}

/// The full upgrade (pq.md §6.3, last row): every hop and the end-to-end channel hybrid.
#[tokio::test]
async fn hybrid_agent_and_client_reach_each_other_through_a_hybrid_relay() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let suites = SuitePolicy {
        agents: AcceptedSuites::only(HFS),
        clients: AcceptedSuites::only(HFS),
    };
    let lab = lab(&alice, suites, HFS).await;
    let (mut app, _task) = lab
        .session_with(&alice, lab.config_outer(None, HFS, HFS))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", log.text()));
    assert_alive(&mut app).await;
    // The agent names the suite it registered with (audit, not only a debug line).
    let registered = log.events("relay_registered");
    assert_eq!(registered.len(), 1, "{}", log.text());
    assert_eq!(
        field(&registered[0], "suite").as_deref(),
        Some(HFS.protocol_name())
    );
    let started = log.events("e2e_session_started");
    assert_eq!(
        field(&started[0], "suite").as_deref(),
        Some(HFS.protocol_name())
    );
}

/// Rollout step 3 (OPERATIONS §13): a relay that accepts both suites serves the peers that
/// still pin the classical one, and those that already pin the hybrid one, at the same time.
#[tokio::test]
async fn a_relay_accepting_both_suites_serves_a_mixed_fleet() {
    let alice = id();
    let suites = SuitePolicy {
        agents: both(),
        clients: both(),
    };
    for (agent_suite, client_suite) in [(CLASSIC, HFS), (HFS, CLASSIC), (CLASSIC, CLASSIC)] {
        let lab = lab(&alice, suites, agent_suite).await;
        let (mut app, _task) = lab
            .session_with(&alice, lab.config_outer(None, client_suite, CLASSIC))
            .await
            .unwrap_or_else(|e| panic!("{agent_suite} / {client_suite}: {e}"));
        assert_alive(&mut app).await;
    }
}

/// The relay counts the confirmed outer handshakes per role and suite, without identities,
/// once per summary interval: the sunset signal of OPERATIONS §13 (which suite is still in
/// use), that a replayed message 1 cannot inflate (it never confirms).
#[tokio::test]
async fn the_relay_reports_confirmed_handshakes_per_role_and_suite() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let suites = SuitePolicy {
        agents: both(),
        clients: both(),
    };
    let lab = lab(&alice, suites, HFS).await;
    let (mut app, _task) = lab
        .session_with(&alice, lab.config_outer(None, CLASSIC, CLASSIC))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    let lines = log.events("outer_suites_confirmed");
    assert!(!lines.is_empty(), "{}", log.text());
    let sum = |key: &str| lines.iter().filter_map(|l| number(l, key)).sum::<u64>();
    assert_eq!(sum("agents_hybrid"), 1, "{lines:?}");
    assert_eq!(sum("clients_classical"), 1, "{lines:?}");
    assert_eq!(sum("agents_classical"), 0, "{lines:?}");
    assert_eq!(sum("clients_hybrid"), 0, "{lines:?}");
    for line in &lines {
        assert!(field(line, "peer").is_none(), "{line}");
    }
}

/// The relay announces its per-role sets at startup, hybrid included.
#[tokio::test]
async fn the_relay_announces_hybrid_sets_at_startup() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let suites = SuitePolicy {
        agents: both(),
        clients: AcceptedSuites::only(CLASSIC),
    };
    let _lab = lab(&alice, suites, CLASSIC).await;
    let lines = log.events("handshake_suites_in_use");
    let relay = lines
        .iter()
        .find(|l| field(l, "agent_suites").is_some())
        .unwrap_or_else(|| panic!("{}", log.text()));
    assert_eq!(field(relay, "agent_suites"), Some(both().names()));
    assert_eq!(
        field(relay, "client_suites").as_deref(),
        Some(CLASSIC.protocol_name())
    );
}
