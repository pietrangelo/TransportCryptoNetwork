//! PQ-1 attack tests on the outer channel (docs/analysis/pq.md §7, PQ-1 catalogue; review
//! 0008, A8-11): the relay's per-role accepted sets on the wire, initiators that never fall
//! back, the pre-authentication cap with hybrid message 1s, and domain separation between the
//! two channels.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    Captured, agent_clients, field, number, probe_relay, relay_config, relay_policy,
    start_relay_with, summed,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel};
use zt_domain::{AcceptedSuites, HandshakeSuite, SuitePolicy};
use zt_net::client::{self, ClientConfig};
use zt_net::relay::RelayConfig;

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn relay_with(suites: SuitePolicy) -> RelayConfig {
    let mut config = RelayConfig {
        suites,
        ..relay_config()
    };
    config.admission.summary_interval = Duration::from_secs(1);
    config
}

/// A8-11: the role is known only after message 1. An agent whose suite is accepted only for
/// clients gets no message 2, no registration, and one `handshake_suite_rejected` per interval
/// however often its message 1 is replayed; the repeats are counted.
#[tokio::test]
async fn an_agent_with_a_client_only_suite_gets_no_message_2() {
    let log = Captured::default();
    let _guard = log.install();
    let agent = Identity::generate().unwrap();
    let policy = relay_policy(
        &agent.fingerprint(),
        &[],
        zt_domain::trust::CertTrust::new(),
    );
    let relay = start_relay_with(
        policy,
        relay_with(SuitePolicy {
            agents: AcceptedSuites::only(CLASSIC),
            clients: AcceptedSuites::only(HFS),
        }),
    )
    .await;
    let (msg1, _) = noise::initiate_suite(&agent, relay.key, Channel::Outer, HFS, &[]).unwrap();
    for _ in 0..5 {
        assert_eq!(probe_relay(relay.addr, &msg1).await, None);
    }
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let rejected = log.events("handshake_suite_rejected");
    assert_eq!(rejected.len(), 1, "{}", log.text());
    assert_eq!(
        field(&rejected[0], "peer"),
        Some(agent.fingerprint().to_string())
    );
    assert_eq!(
        field(&rejected[0], "suite").as_deref(),
        Some(HFS.protocol_name())
    );
    let repeated = log.events("handshake_suite_rejected_repeated");
    assert_eq!(summed(&repeated, "count"), 4, "{}", log.text());
    assert!(log.events("agent_registered").is_empty());
}

/// A8-11, the other way round: a client whose suite is accepted only for agents.
#[tokio::test]
async fn a_client_with_an_agent_only_suite_gets_no_message_2() {
    let log = Captured::default();
    let _guard = log.install();
    let agent = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let policy = relay_policy(
        &agent.fingerprint(),
        &[alice.fingerprint()],
        zt_domain::trust::CertTrust::new(),
    );
    let relay = start_relay_with(
        policy,
        relay_with(SuitePolicy {
            agents: AcceptedSuites::only(HFS),
            clients: AcceptedSuites::only(CLASSIC),
        }),
    )
    .await;
    let (msg1, _) = noise::initiate_suite(&alice, relay.key, Channel::Outer, HFS, &[]).unwrap();
    for _ in 0..3 {
        assert_eq!(probe_relay(relay.addr, &msg1).await, None);
    }
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let rejected = log.events("handshake_suite_rejected");
    assert_eq!(rejected.len(), 1, "{}", log.text());
    assert_eq!(
        field(&rejected[0], "peer"),
        Some(alice.fingerprint().to_string())
    );
    assert_eq!(
        summed(&log.events("handshake_suite_rejected_repeated"), "count"),
        2
    );
    // And the agent's own suite still works for the agent.
    let (msg1, _) = noise::initiate_suite(&agent, relay.key, Channel::Outer, HFS, &[]).unwrap();
    assert_eq!(
        probe_relay(relay.addr, &msg1).await.map(|m| m.len()),
        Some(HFS.msg2_len())
    );
}

/// A relay stand-in that records the length of every message 1 it receives and never answers.
async fn silent_relay() -> (SocketAddr, Arc<Mutex<Vec<usize>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            let record = Arc::clone(&record);
            tokio::spawn(async move {
                let mut head = [0_u8; 2];
                if tcp.read_exact(&mut head).await.is_ok() {
                    let mut body = vec![0_u8; usize::from(u16::from_be_bytes(head))];
                    if tcp.read_exact(&mut body).await.is_ok() {
                        record.lock().unwrap().push(body.len());
                    }
                }
                // Then close without message 2, as a relay that does not accept the suite.
                let _ = tcp.shutdown().await;
            });
        }
    });
    (addr, seen)
}

/// A client pinned to the hybrid suite never retries the classical one: not on the same relay
/// and not on the next one, whose own pin is hybrid too (PROTOCOL §7.5).
#[tokio::test]
async fn a_hybrid_pinned_client_never_falls_back() {
    let alice = Arc::new(Identity::generate().unwrap());
    let agent = Identity::generate().unwrap();
    let (first, seen_first) = silent_relay().await;
    let (second, seen_second) = silent_relay().await;
    let relay_key = Identity::generate().unwrap().public_key();
    let config = ClientConfig {
        relays: [first, second]
            .iter()
            .map(|a| zt_net::RelayEndpoint {
                address: a.to_string(),
                public_key: relay_key.into(),
                suite: HFS,
            })
            .collect(),
        node: common::node("web-01"),
        node_key: agent.public_key().into(),
        node_suite: CLASSIC,
        certificate: None,
        timeouts: common::timeouts(),
        failover: zt_net::client::FailoverConfig::default(),
        require_outer_suite: None,
    };
    let (_app, local) = tokio::io::duplex(1024);
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect(&alice, &config, local),
    )
    .await
    .expect("client hung");
    assert!(outcome.is_err());
    for seen in [seen_first, seen_second] {
        assert_eq!(
            *seen.lock().unwrap(),
            vec![HFS.msg1_overhead()],
            "one hybrid message 1 per relay, nothing else"
        );
    }
}

/// An agent pinned to the hybrid suite keeps reconnecting with that suite only.
#[tokio::test]
async fn a_hybrid_pinned_agent_never_falls_back() {
    let (addr, seen) = silent_relay().await;
    let agent = Arc::new(zt_crypto::Keyring::single(Identity::generate().unwrap()));
    let (clients, _updater) =
        zt_net::Revocable::new(agent_clients(&[], zt_domain::trust::CertTrust::new()));
    let task = tokio::spawn(zt_net::agent::run(
        agent,
        zt_net::agent::AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: addr.to_string(),
                public_key: Identity::generate().unwrap().public_key().into(),
                suite: HFS,
            }],
            node: common::node("web-01"),
            ssh_target: "127.0.0.1:9".into(),
            authorized_clients: clients,
            timeouts: common::timeouts(),
            max_streams: 4,
            client_suites: AcceptedSuites::only(CLASSIC),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
            reconnect: zt_application::reconnect::ReconnectConfig::default(),
        },
    ));
    tokio::time::sleep(Duration::from_secs(5)).await;
    task.abort();
    let seen = seen.lock().unwrap().clone();
    assert!(seen.len() >= 2, "the agent did not retry: {seen:?}");
    assert!(
        seen.iter().all(|len| *len == HFS.msg1_overhead()),
        "{seen:?}"
    );
}

/// The relay's pre-authentication cap follows the accepted sets: a hybrid message 1 with the
/// largest payload is read in full (and refused as a certificate), one byte more is
/// `oversized` on sight.
#[tokio::test]
async fn the_preauth_cap_admits_the_largest_hybrid_message_1_and_nothing_more() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = Identity::generate().unwrap();
    // A key the relay does not know: its failures are only counted (PROTOCOL §10.1).
    let policy = relay_policy(
        &Identity::generate().unwrap().fingerprint(),
        &[],
        zt_domain::trust::CertTrust::new(),
    );
    let relay = start_relay_with(
        policy,
        relay_with(SuitePolicy {
            agents: AcceptedSuites::only(CLASSIC),
            clients: AcceptedSuites::only(HFS),
        }),
    )
    .await;
    let payload = vec![0x5a; zt_domain::limits::MAX_ANY_CERT_LEN];
    let (largest, _) =
        noise::initiate_suite(&alice, relay.key, Channel::Outer, HFS, &payload).unwrap();
    assert_eq!(largest.len(), HFS.max_msg1_len());
    assert_eq!(probe_relay(relay.addr, &largest).await, None);
    let mut over = largest.clone();
    over.push(0);
    assert_eq!(probe_relay(relay.addr, &over).await, None);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let summaries = log.events("preauth_summary");
    assert_eq!(summed(&summaries, "oversized"), 1, "{}", log.text());
    assert_eq!(
        summed(&summaries, "unverified_certificate"),
        1,
        "{}",
        log.text()
    );
    for line in &summaries {
        assert!(number(line, "handshake_failed").is_none(), "{line}");
    }
}

/// Domain separation (PROTOCOL §7.5): a hybrid message 1 of one channel is never valid on the
/// other, so a relay cannot replay a client's end-to-end message 1 to another relay as an
/// outer one, nor the reverse. A classical message 1 is never valid as a hybrid one.
#[test]
fn hybrid_message_1s_are_bound_to_their_channel() {
    let alice = Identity::generate().unwrap();
    let responder = Identity::generate().unwrap();
    let keys = zt_crypto::Keyring::single(common::copy_of(&responder));
    let both = AcceptedSuites::new([CLASSIC, HFS]).unwrap();
    for (sent, other) in [
        (Channel::Outer, Channel::EndToEnd),
        (Channel::EndToEnd, Channel::Outer),
    ] {
        let (msg1, _) =
            noise::initiate_suite(&alice, responder.public_key(), sent, HFS, &[]).unwrap();
        assert_eq!(
            noise::respond_suites(&keys, &msg1, sent, both)
                .unwrap()
                .suite(),
            HFS
        );
        assert!(noise::respond_suites(&keys, &msg1, other, both).is_err());
        assert!(noise::respond_or_identify(&keys, &msg1, other, both).is_err());
    }
    let (classic, _) =
        noise::initiate_suite(&alice, responder.public_key(), Channel::Outer, CLASSIC, &[])
            .unwrap();
    assert!(
        noise::respond_suites(&keys, &classic, Channel::Outer, AcceptedSuites::only(HFS)).is_err()
    );
}

/// The outer channel's key confirmation is its first authentic frame, not a confirmation
/// string: the end-to-end confirmations are never a valid outer first frame.
#[test]
fn end_to_end_confirmations_are_not_outer_frames() {
    for suite in HandshakeSuite::ALL {
        let mut buf = bytes::BytesMut::from(suite.confirmation());
        let decoded = zt_proto::FrameDecoder::new().decode(&mut buf);
        assert!(
            !matches!(decoded, Ok(Some(_))),
            "{suite}: a confirmation decodes as a frame"
        );
    }
}
