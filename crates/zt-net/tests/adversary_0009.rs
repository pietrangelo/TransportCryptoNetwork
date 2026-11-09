//! Adversary review 0009 (Phase 2, PQ-1) on the wire: an agent behind a compromised relay
//! (`FakeRelay`). The reviewer's reproducers asserted the attackable behaviour; these assert
//! the safe one (docs/adversary/0009-phase2-pq1-e2e.md).
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
    AgentAnswer, Ca, Captured, FakeRelay, agent_clients, field, node, number, seeded, trust,
};
use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel};
use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{AcceptedSuites, AllowedNodes, CertScope, CloseReason, HandshakeSuite, NodeId};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
/// The interval of the agent's per-identity lines in these tests.
const INTERVAL: Duration = Duration::from_secs(1);

/// The full lines of `kind` naming `peer`, and the sum of the `count` of its `_repeated` lines.
fn full_and_repeated(log: &Captured, kind: &str, peer: &str) -> (usize, u64) {
    let full = log
        .events(kind)
        .iter()
        .filter(|l| field(l, "peer").as_deref() == Some(peer))
        .count();
    let repeated = log
        .events(&format!("{kind}_repeated"))
        .iter()
        .filter(|l| field(l, "peer").as_deref() == Some(peer))
        .filter_map(|l| number(l, "count"))
        .sum();
    (full, repeated)
}

/// A9-2: after PQ-SUNSET (the agent accepts only the hybrid suite), a compromised relay
/// replays a classical message 1 it recorded before. The agent names the victim in full once
/// per interval and counts the rest; every line says that the attempt was not confirmed (it
/// cannot be: there is no message 2), so it is not evidence of a live classical client.
#[tokio::test]
async fn replayed_suite_rejections_on_the_agent_are_rate_limited_per_identity() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = Arc::new(Identity::generate().unwrap());
    let mut relay = FakeRelay::start_logging(
        agent_clients(&[alice.fingerprint()], CertTrust::new()),
        AcceptedSuites::only(HFS),
        INTERVAL,
    )
    .await;
    let (recorded, _) = noise::initiate_suite(
        &alice,
        &relay.agent.public_key(),
        Channel::EndToEnd,
        CLASSIC,
        &[],
    )
    .unwrap();
    for i in 1..=40 {
        assert_eq!(
            relay.offer(i, recorded.clone()).await,
            AgentAnswer::Closed(CloseReason::Unauthorized)
        );
    }
    tokio::time::sleep(INTERVAL * 5 / 2).await;
    let peer = alice.fingerprint().to_string();
    let (full, repeated) = full_and_repeated(&log, "handshake_suite_rejected", &peer);
    assert!((1..=2).contains(&full), "{full} full lines\n{}", log.text());
    assert_eq!(full as u64 + repeated, 40, "every replay is accounted for");
    for line in log
        .events("handshake_suite_rejected")
        .iter()
        .chain(log.events("handshake_suite_rejected_repeated").iter())
    {
        assert!(line.contains("\"confirmed\":false"), "{line}");
        assert_eq!(field(line, "suite").as_deref(), Some(CLASSIC.protocol_name()));
    }
    assert_eq!(relay.sshd_connections(), 0);
}

/// A9-2: the same for the `authentication_failed` lines that name a peer: a recorded message 1
/// of a key revoked since, replayed at the agent.
#[tokio::test]
async fn replayed_authentication_failures_on_the_agent_are_rate_limited_per_identity() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = Arc::new(Identity::generate().unwrap());
    let mut revoked = CertTrust::new();
    revoked.set_revocations(Revocations::new([], [alice.fingerprint()]).unwrap());
    let mut relay = FakeRelay::start_logging(
        agent_clients(&[alice.fingerprint()], revoked),
        AcceptedSuites::only(CLASSIC),
        INTERVAL,
    )
    .await;
    let (recorded, _) = noise::initiate_suite(
        &alice,
        &relay.agent.public_key(),
        Channel::EndToEnd,
        CLASSIC,
        &[],
    )
    .unwrap();
    for i in 1..=30 {
        assert_eq!(
            relay.offer(i, recorded.clone()).await,
            AgentAnswer::Closed(CloseReason::Unauthorized)
        );
    }
    tokio::time::sleep(INTERVAL * 5 / 2).await;
    let (full, repeated) =
        full_and_repeated(&log, "authentication_failed", &alice.fingerprint().to_string());
    assert!((1..=2).contains(&full), "{full} full lines\n{}", log.text());
    assert_eq!(full as u64 + repeated, 30);
    let line = &log.events("authentication_failed_repeated")[0];
    assert_eq!(field(line, "reason").as_deref(), Some("key_revoked"));
}

/// A9-2: made-up keys do not grow the agent's table: beyond 256 identities per interval the
/// events are only counted (in `identity_events_suppressed` at the end of the interval).
#[tokio::test]
async fn made_up_keys_cannot_grow_the_agents_line_table() {
    let log = Captured::default();
    let _guard = log.install();
    let mut relay = FakeRelay::start_logging(
        agent_clients(&[], CertTrust::new()),
        AcceptedSuites::only(CLASSIC),
        Duration::from_secs(30),
    )
    .await;
    // Message 1s are cheap to make; one stream at a time keeps the agent's quota free.
    for i in 1..=300 {
        let mallory = Identity::generate().unwrap();
        let (msg1, _) =
            noise::initiate_suite(&mallory, &relay.agent.public_key(), Channel::EndToEnd, CLASSIC, &[])
                .unwrap();
        assert_eq!(
            relay.offer(i, msg1).await,
            AgentAnswer::Closed(CloseReason::Unauthorized)
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let full = log.events("authentication_failed").len();
    assert_eq!(full, zt_application::identity_lines::MAX_LOGGED_IDENTITIES);
}

/// A KEM for the initiator only: its `e1` is 1 184 bytes that fail the FIPS 203 §7.2 modulus
/// check (finding A9-4).
struct InvalidKeyKem;

impl snow::types::Kem for InvalidKeyKem {
    fn name(&self) -> &'static str {
        "MLKEM768"
    }
    fn pub_len(&self) -> usize {
        1_184
    }
    fn ciphertext_len(&self) -> usize {
        1_088
    }
    fn shared_secret_len(&self) -> usize {
        32
    }
    fn generate(&mut self, _rng: &mut dyn Random) {}
    fn pubkey(&self) -> &[u8] {
        &[0xff; 1_184]
    }
    fn encapsulate(&self, _: &[u8], _: &mut [u8], _: &mut [u8]) -> Result<(usize, usize), snow::Error> {
        Err(snow::Error::Kem)
    }
    fn decapsulate(&self, _: &[u8], _: &mut [u8]) -> Result<usize, snow::Error> {
        Err(snow::Error::Kem)
    }
}

struct InvalidKeyResolver;

impl CryptoResolver for InvalidKeyResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        DefaultResolver.resolve_rng()
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
    fn resolve_kem(&self, _: &KemChoice) -> Option<Box<dyn snow::types::Kem>> {
        Some(Box::new(InvalidKeyKem))
    }
}

/// A valid, authenticated hybrid message 1 from `seed` whose `e1` is invalid.
fn msg1_with_invalid_e1(seed: [u8; 32], agent: &zt_crypto::PublicKey) -> Vec<u8> {
    let secret = ed25519_dalek::SigningKey::from_bytes(&seed).to_scalar_bytes();
    let mut state = snow::Builder::with_resolver(
        HFS.protocol_name().parse().unwrap(),
        Box::new(InvalidKeyResolver),
    )
    .prologue(b"TCN/2 end-to-end\x01")
    .unwrap()
    .local_private_key(&secret)
    .unwrap()
    .remote_public_key(&agent.x25519())
    .unwrap()
    .build_initiator()
    .unwrap();
    let mut out = vec![0_u8; 65_535];
    let len = state.write_message(&[], &mut out).unwrap();
    out.truncate(len);
    out
}

/// A9-4: an authorized client (or whoever holds its key) whose `e1` fails the modulus check is
/// closed and **audited**, with its identity.
#[tokio::test]
async fn an_invalid_e1_from_a_known_client_is_audited() {
    let log = Captured::default();
    let _guard = log.install();
    let (seed, alice) = seeded(0x91);
    let mut relay = FakeRelay::start_logging(
        agent_clients(&[alice.fingerprint()], CertTrust::new()),
        AcceptedSuites::only(HFS),
        INTERVAL,
    )
    .await;
    let msg1 = msg1_with_invalid_e1(seed, &relay.agent.public_key());
    assert_eq!(
        relay.offer(1, msg1).await,
        AgentAnswer::Closed(CloseReason::ProtocolViolation)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let failed: Vec<String> = log
        .events("authentication_failed")
        .into_iter()
        .filter(|l| field(l, "peer") == Some(alice.fingerprint().to_string()))
        .collect();
    assert_eq!(failed.len(), 1, "{}", log.text());
    assert_eq!(field(&failed[0], "reason").as_deref(), Some("handshake_failed"));
    assert_eq!(relay.sshd_connections(), 0);
}

/// A certificate for `subject` with 64 node names of 55 bytes (one of them `web-01`): over
/// 3 128 bytes, so that its hybrid message 1 is longer than any classical one.
fn large_certificate(ca: &Ca, subject: &zt_crypto::PublicKey) -> Arc<[u8]> {
    let mut nodes: Vec<NodeId> = vec![node("web-01")];
    for i in 1..64 {
        nodes.push(node(&format!("node-{i:02}-{}", "x".repeat(46))));
    }
    let (cert, _) = ca.issue(subject, CertScope::Only(nodes.into_iter().collect()));
    assert!(cert.len() > CLASSIC.max_msg1_len() - HFS.msg1_overhead());
    cert
}

/// A9-5: a client pinned to the hybrid suite with a large (legitimate) certificate, towards
/// an agent that accepts only the classical suite: the agent reports a suite rejection with
/// the client's identity, as OPERATIONS §12 says, not an anonymous malformed certificate.
#[tokio::test]
async fn a_large_certificate_hybrid_msg1_to_a_classical_agent_is_a_suite_rejection() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let alice = Arc::new(Identity::generate().unwrap());
    let cert = large_certificate(&ca, &alice.public_key());
    let mut relay = FakeRelay::start_logging(
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
        AcceptedSuites::only(CLASSIC),
        INTERVAL,
    )
    .await;
    let (msg1, _) = noise::initiate_suite(
        &alice,
        &relay.agent.public_key(),
        Channel::EndToEnd,
        HFS,
        &cert,
    )
    .unwrap();
    assert!(msg1.len() > CLASSIC.max_msg1_len());
    assert_eq!(
        relay.offer(1, msg1).await,
        AgentAnswer::Closed(CloseReason::Unauthorized)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(log.events("authentication_failed").is_empty(), "{}", log.text());
    let rejected = log.events("handshake_suite_rejected");
    assert_eq!(rejected.len(), 1, "{}", log.text());
    assert_eq!(field(&rejected[0], "peer"), Some(alice.fingerprint().to_string()));
    assert_eq!(field(&rejected[0], "suite").as_deref(), Some(HFS.protocol_name()));
    assert_eq!(relay.sshd_connections(), 0);
}
