//! PQ-1 attack catalogue on the wire: the agent's per-role suite check (review 0008, A8-11,
//! end-to-end), no fallback, replay, the confirmation of each suite, oversized and truncated
//! hybrid message 1s, and the relay's outer channel that still refuses the hybrid suite.
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
use std::time::Duration;

use common::{
    AgentAnswer, Captured, FakeRelay, Lab, agent_clients, field, relay_config, relay_policy,
};
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel};
use zt_domain::trust::CertTrust;
use zt_domain::{AcceptedSuites, CloseReason, HandshakeSuite, SuiteError, SuitePolicy};
use zt_net::NetError;
use zt_net::relay::{RelayConfig, RelayServer};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

fn both() -> AcceptedSuites {
    AcceptedSuites::new([CLASSIC, HFS]).unwrap()
}

async fn lab(relays: usize, client: &Arc<Identity>, accepted: AcceptedSuites) -> Lab {
    let agent = id();
    let keys = [client.fingerprint()];
    let configs = (0..relays)
        .map(|_| {
            (
                relay_policy(&agent.fingerprint(), &keys, CertTrust::new()),
                relay_config(),
            )
        })
        .collect();
    Lab::start_suites(
        agent,
        configs,
        agent_clients(&keys, CertTrust::new()),
        accepted,
    )
    .await
}

/// A8-11 (end to end): a known client whose suite the agent does not accept gets no message 2
/// and no session, and the agent names it once in `handshake_suite_rejected`. Both
/// directions: hybrid client to a classical-only agent, classical client to a hybrid-only one.
#[tokio::test]
async fn a_suite_the_agent_does_not_accept_is_rejected_and_audited() {
    for (accepted, pinned) in [
        (AcceptedSuites::only(CLASSIC), HFS),
        (AcceptedSuites::only(HFS), CLASSIC),
    ] {
        let log = Captured::default();
        let _guard = log.install();
        let alice = id();
        let lab = lab(1, &alice, accepted).await;
        let outcome = lab
            .refused_with(&alice, &lab.config_suite(None, pinned))
            .await;
        assert!(
            matches!(
                outcome,
                Err(NetError::StreamClosed(CloseReason::Unauthorized))
            ),
            "{pinned}: {outcome:?}"
        );
        assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
        let rejected = log.events("handshake_suite_rejected");
        assert_eq!(rejected.len(), 1, "{}", log.text());
        assert_eq!(
            field(&rejected[0], "peer"),
            Some(alice.fingerprint().to_string())
        );
        assert_eq!(
            field(&rejected[0], "suite").as_deref(),
            Some(pinned.protocol_name())
        );
        assert!(log.events("e2e_session_started").is_empty());
    }
}

/// An unknown key never produces a per-suite line, whatever its suite (anyone can make up
/// keys, PROTOCOL §10.1): it fails as an unknown client.
#[tokio::test]
async fn an_unknown_client_with_a_rejected_suite_is_not_named_as_a_suite_rejection() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let mallory = id();
    let lab = lab(1, &alice, AcceptedSuites::only(CLASSIC)).await;
    // Mallory is not in the policy either, so the relay refuses her before the agent: the
    // agent is reached through a fake relay below. Here: no suite line about anyone.
    let _ = lab
        .refused_with(&mallory, &lab.config_suite(None, HFS))
        .await;
    assert!(log.events("handshake_suite_rejected").is_empty());

    let mut relay = FakeRelay::start_suites(
        [alice.fingerprint()].into_iter().collect(),
        AcceptedSuites::only(CLASSIC),
    )
    .await;
    let (msg1, _) = noise::initiate_suite(
        &mallory,
        &relay.agent.public_key(),
        Channel::EndToEnd,
        HFS,
        &[],
    )
    .unwrap();
    assert_eq!(
        relay.offer(1, msg1).await,
        AgentAnswer::Closed(CloseReason::Unauthorized)
    );
    assert!(log.events("handshake_suite_rejected").is_empty());
}

/// Downgrade: a client pinned to the hybrid suite never retries with the classical one, on
/// the same relay or on the next (an error after `OpenAck` is final, PROTOCOL §13).
#[tokio::test]
async fn a_hybrid_pin_never_falls_back() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let lab = lab(2, &alice, AcceptedSuites::only(CLASSIC)).await;
    let outcome = lab
        .refused_with(&alice, &lab.config_suite(None, HFS))
        .await;
    assert!(outcome.is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(log.events("handshake_suite_rejected").len(), 1);
    assert_eq!(log.events("session_established").len(), 1, "{}", log.text());
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
}

/// Replay (finding 0002-3, hybrid suite): a compromised relay that replays a recorded hybrid
/// message 1 gets message 2 each time, but sshd is never contacted without the confirmation
/// that only the real client can produce.
#[tokio::test]
async fn a_replayed_hybrid_message_1_never_reaches_sshd() {
    let alice = id();
    let mut relay =
        FakeRelay::start_suites([alice.fingerprint()].into_iter().collect(), both()).await;
    let (msg1, _) = noise::initiate_suite(
        &alice,
        &relay.agent.public_key(),
        Channel::EndToEnd,
        HFS,
        &[],
    )
    .unwrap();
    for n in 1..=3 {
        let msg2 = relay.msg2(n, msg1.clone()).await.unwrap();
        assert_eq!(msg2.len(), HFS.msg2_len());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(relay.sshd_connections(), 0);
}

/// Each suite has its own confirmation: `TCN/1 ready` on a hybrid session, or `TCN/2 ready`
/// on a classical one, closes the stream without contacting sshd. The right one opens sshd.
#[tokio::test]
async fn the_confirmation_must_match_the_suite() {
    let alice = id();
    let mut relay =
        FakeRelay::start_suites([alice.fingerprint()].into_iter().collect(), both()).await;
    let agent_key = relay.agent.public_key();
    let mut stream = 0;
    for (suite, confirm) in [
        (HFS, &b"TCN/1 ready"[..]),
        (CLASSIC, &b"TCN/2 ready"[..]),
        (HFS, &b"TCN/2 ready\0"[..]),
    ] {
        stream += 1;
        let (msg1, waiting) =
            noise::initiate_suite(&alice, &agent_key, Channel::EndToEnd, suite, &[]).unwrap();
        let msg2 = relay.msg2(stream, msg1).await.unwrap();
        let mut t = waiting.complete(&msg2).unwrap();
        relay.data(stream, t.encrypt(confirm).unwrap()).await;
        assert_eq!(
            relay.next_on(stream).await,
            Err(AgentAnswer::Closed(CloseReason::ProtocolViolation)),
            "{suite}"
        );
    }
    assert_eq!(relay.sshd_connections(), 0);
    for suite in [HFS, CLASSIC] {
        stream += 1;
        let (msg1, waiting) =
            noise::initiate_suite(&alice, &agent_key, Channel::EndToEnd, suite, &[]).unwrap();
        let msg2 = relay.msg2(stream, msg1).await.unwrap();
        let mut t = waiting.complete(&msg2).unwrap();
        relay
            .data(stream, t.encrypt(suite.confirmation()).unwrap())
            .await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(relay.sshd_connections(), 2);
}

/// Resources: a message 1 over the largest legitimate one of the accepted set is refused
/// before it is parsed. For a classical-only agent that includes a hybrid message 1 with a
/// large certificate.
#[tokio::test]
async fn an_oversized_message_1_is_refused_before_parsing() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    for (accepted, len) in [
        (both(), HFS.max_msg1_len() + 1),
        (AcceptedSuites::only(CLASSIC), CLASSIC.max_msg1_len() + 1),
    ] {
        let mut relay =
            FakeRelay::start_suites([alice.fingerprint()].into_iter().collect(), accepted).await;
        let (mut msg1, _) = noise::initiate_suite(
            &alice,
            &relay.agent.public_key(),
            Channel::EndToEnd,
            HFS,
            &vec![0x5a; zt_domain::limits::MAX_CERT_LEN],
        )
        .unwrap();
        msg1.resize(len, 0);
        assert_eq!(
            relay.offer(1, msg1).await,
            AgentAnswer::Closed(CloseReason::Unauthorized)
        );
        assert_eq!(relay.sshd_connections(), 0);
    }
    let failed = log.events("authentication_failed");
    assert_eq!(failed.len(), 2, "{}", log.text());
    assert!(
        failed
            .iter()
            .all(|l| field(l, "cert_check").as_deref() == Some("malformed"))
    );
}

/// Parsing: a hybrid message 1 cut inside `e1` is an invalid handshake (no oracle about where
/// it was cut).
#[tokio::test]
async fn a_truncated_hybrid_message_1_is_an_invalid_handshake() {
    let alice = id();
    let mut relay =
        FakeRelay::start_suites([alice.fingerprint()].into_iter().collect(), both()).await;
    let (msg1, _) = noise::initiate_suite(
        &alice,
        &relay.agent.public_key(),
        Channel::EndToEnd,
        HFS,
        &[],
    )
    .unwrap();
    for (n, cut) in [32 + 600, 32 + 1_200, 1_295].into_iter().enumerate() {
        assert_eq!(
            relay
                .offer(u32::try_from(n).unwrap() + 1, msg1[..cut].to_vec())
                .await,
            AgentAnswer::Closed(CloseReason::ProtocolViolation),
            "cut at {cut}"
        );
    }
    assert_eq!(relay.sshd_connections(), 0);
}

/// A8-11 stays dead code on the relay in this release: the outer channel refuses the hybrid
/// suite for either role, so the relay cannot be configured into the per-role branch.
#[tokio::test]
async fn the_relay_refuses_the_hybrid_suite_on_the_outer_channel() {
    for suites in [
        SuitePolicy {
            agents: both(),
            clients: AcceptedSuites::only(CLASSIC),
        },
        SuitePolicy {
            agents: AcceptedSuites::only(CLASSIC),
            clients: AcceptedSuites::only(HFS),
        },
    ] {
        let config = RelayConfig {
            suites,
            ..relay_config()
        };
        let bound = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::generate().unwrap(),
            zt_domain::AccessPolicy::new(),
            config,
        )
        .await;
        assert!(
            matches!(bound, Err(NetError::Suite(SuiteError::Unsupported))),
            "{suites:?}"
        );
    }
}
