//! PQ-AUTH, hybrid identities on the network (PROTOCOL §7.5.3, §15.8, §15.14; OPERATIONS
//! §16; findings AP-6, AP-12 of review 0007): v2 keys in every configuration file, the hybrid
//! IK suite on both hops, v2 pins that forbid the classical handshakes, the denylist keyed by
//! the X25519-level fingerprint, and hybrid-bound certificates.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::{
    Ca, Captured, Lab, agent_clients, assert_alive, field, node, relay_config, relay_policy, scope,
    trust,
};
use zt_crypto::Identity;
use zt_domain::trust::CertTrust;
use zt_domain::{AcceptedSuites, AllowedNodes, HandshakeSuite};
use zt_net::config::{
    ConfigError, parse_authorized_clients, parse_client_settings, parse_policy, parse_revocations,
};

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HYBRID_NAME: &str = "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

// --- configuration ------------------------------------------------------------------------

/// Spec (D13): the relay policy and `clients.toml` take `tcn-pub-v2:` keys for agents and
/// clients; the entry is keyed by the X25519-level fingerprint and pins the hybrid identity.
#[test]
fn configuration_files_take_v2_keys() {
    let (agent, alice, bob) = (id(), id(), id());
    let text = format!(
        "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n\
         [[clients]]\nname = \"alice\"\npublic_key = \"{}\"\nallow = [\"*\"]\n\n\
         [[clients]]\nname = \"bob\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
        agent.hybrid_public_key(),
        alice.hybrid_public_key(),
        bob.public_key(),
    );
    let policy = parse_policy("policy.toml", &text).unwrap();
    assert!(policy.role(&agent.fingerprint()).is_some());
    assert_eq!(
        policy.hybrid_identity(&agent.fingerprint()),
        Some(&agent.hybrid_fingerprint())
    );
    assert_eq!(
        policy.hybrid_identity(&alice.fingerprint()),
        Some(&alice.hybrid_fingerprint())
    );
    assert_eq!(policy.hybrid_identity(&bob.fingerprint()), None);
    let clients = parse_authorized_clients("clients.toml", &text).unwrap();
    assert!(clients.contains_key(&alice.fingerprint()));
    assert_eq!(
        clients.hybrid_identity(&alice.fingerprint()),
        Some(&alice.hybrid_fingerprint())
    );
    // An agent in rotation may mix a v2 and a v1 key.
    let rotating = format!(
        "[[agents]]\nnode = \"web-01\"\npublic_keys = [\"{}\", \"{}\"]\n",
        agent.hybrid_public_key(),
        alice.public_key(),
    );
    assert!(parse_policy("policy.toml", &rotating).is_ok());
    // The same key twice, once v1 and once v2, is a duplicate (one identity unit).
    let twice = format!(
        "[[clients]]\nname = \"a\"\npublic_key = \"{}\"\n\n[[clients]]\nname = \"b\"\npublic_key = \"{}\"\n",
        alice.hybrid_public_key(),
        alice.public_key(),
    );
    assert!(parse_policy("policy.toml", &twice).is_err());
}

/// Spec and attack (AP-6): the denylist takes v1 keys, v2 keys and v1 fingerprints, all
/// reduced to the X25519-level fingerprint; a v2 fingerprint is a load error that never
/// echoes it.
#[test]
fn the_denylist_takes_keys_and_v1_fingerprints_only() {
    let (a, b, c) = (id(), id(), id());
    let text = format!(
        "keys = [\"{}\", \"{}\", \"{}\"]\n",
        a.public_key(),
        b.hybrid_public_key(),
        c.fingerprint()
    );
    let revoked = parse_revocations("revoked.toml", &text).unwrap();
    for who in [&a, &b, &c] {
        assert!(revoked.is_key_revoked(&who.fingerprint()));
    }
    let v2 = a.hybrid_fingerprint().to_string();
    let err = parse_revocations("revoked.toml", &format!("keys = [\"{v2}\"]\n")).unwrap_err();
    let shown = err.to_string();
    assert!(!shown.contains(&v2[9..40]), "{shown}");
    assert!(
        shown.contains("v2") || shown.contains("SHA256v2"),
        "{shown}"
    );
    assert!(matches!(
        err,
        ConfigError::Key { .. } | ConfigError::Domain { .. }
    ));
}

/// Spec and attack (Downgrade): `client.toml` pins the hybrid suite only with v2 keys; a v2
/// key is also accepted with the classical suites.
#[test]
fn the_hybrid_suite_is_pinned_only_with_v2_keys() {
    let (relay, agent) = (id(), id());
    let base = Path::new("/etc/tcn");
    let good = format!(
        "key = \"client.key\"\n\n[[relays]]\naddress = \"r1.example:7000\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n\n\
         [[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n",
        relay.hybrid_public_key(),
        agent.hybrid_public_key(),
    );
    let settings = parse_client_settings("client.toml", base, &good).unwrap();
    assert_eq!(settings.relays[0].suite, HYBRID);
    assert!(settings.relays[0].public_key.hybrid().is_some());
    assert!(settings.nodes[&node("web-01")].hybrid().is_some());
    for bad in [
        format!(
            "key = \"client.key\"\nrelay = \"r1.example:7000\"\nrelay_key = \"{}\"\nrelay_suite = \"{HYBRID_NAME}\"\n",
            relay.public_key()
        ),
        format!(
            "key = \"client.key\"\nrelay = \"r1.example:7000\"\nrelay_key = \"{}\"\n\n[[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n",
            relay.public_key(),
            agent.public_key()
        ),
    ] {
        assert!(
            parse_client_settings("client.toml", base, &bad).is_err(),
            "{bad}"
        );
    }
    let classical_with_v2 = format!(
        "key = \"client.key\"\nrelay = \"r1.example:7000\"\nrelay_key = \"{}\"\n",
        relay.hybrid_public_key()
    );
    let settings = parse_client_settings("client.toml", base, &classical_with_v2).unwrap();
    assert_eq!(settings.relays[0].suite, CLASSIC);
}

// --- the network --------------------------------------------------------------------------

fn hybrid_pins(p: &mut zt_domain::AccessPolicy, ids: &[&Arc<Identity>]) {
    for who in ids {
        p.pin_hybrid(who.fingerprint(), who.hybrid_fingerprint())
            .unwrap();
    }
}

/// Spec: a client pinned in v2 everywhere reaches its node over the hybrid IK suite on both
/// hops; the agent is pinned in v2 by the relay too. The audit names both identities.
#[tokio::test]
async fn a_hybrid_client_reaches_its_node_over_hybrid_hops() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let agent = id();
    let mut policy = relay_policy(
        &agent.fingerprint(),
        &[alice.fingerprint()],
        CertTrust::new(),
    );
    hybrid_pins(&mut policy, &[&alice, &agent]);
    let mut clients = agent_clients(&[alice.fingerprint()], CertTrust::new());
    clients
        .pin_hybrid(alice.fingerprint(), alice.hybrid_fingerprint())
        .unwrap();
    let mut config = relay_config();
    config.suites = zt_domain::SuitePolicy {
        agents: AcceptedSuites::only(HYBRID),
        clients: AcceptedSuites::only(HYBRID),
    };
    let lab = Lab::start_outer(
        agent,
        vec![(policy, config)],
        clients,
        AcceptedSuites::only(HYBRID),
        HYBRID,
    )
    .await;
    let (mut app, _task) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 1);
    let established = log.events("session_established");
    assert_eq!(established.len(), 1, "{}", log.text());
    assert_eq!(
        field(&established[0], "peer_v2"),
        Some(alice.hybrid_fingerprint().to_string())
    );
    let started = log.events("e2e_session_started");
    assert_eq!(field(&started[0], "suite").as_deref(), Some(HYBRID_NAME));
    assert_eq!(
        field(&started[0], "peer_v2"),
        Some(alice.hybrid_fingerprint().to_string())
    );
    assert!(
        log.events("classical_identity_match").is_empty(),
        "{}",
        log.text()
    );
}

/// Attack (AP-6): `a_key_revoked_by_its_v2_identity_cannot_connect_with_a_v1_handshake`. The
/// operator revokes the v2 key; the thief connects with the classical suite and a v1 pin.
#[tokio::test]
async fn a_key_revoked_by_its_v2_identity_cannot_connect_with_a_v1_handshake() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new_v2();
    let alice = id();
    let revoked = parse_revocations(
        "revoked.toml",
        &format!("keys = [\"{}\"]\n", alice.hybrid_public_key()),
    )
    .unwrap();
    let with_denylist = || {
        let mut t = trust(&[(&ca, AllowedNodes::All)], &[], &[]);
        t.set_revocations(revoked.clone());
        t
    };
    let lab = Lab::start(
        |agent| vec![relay_policy(agent, &[alice.fingerprint()], with_denylist())],
        agent_clients(&[alice.fingerprint()], with_denylist()),
    )
    .await;
    assert!(lab.refused(&alice, None).await.is_err());
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    // The relay knows the key: the failure has its own line, with the reason.
    let failed = log.events("authentication_failed");
    assert!(
        failed
            .iter()
            .any(|l| field(l, "reason").as_deref() == Some("key_revoked")),
        "{}",
        log.text()
    );
}

/// Attack (Downgrade): a client pinned in v2 by the relay and the agent cannot connect with a
/// classical (or `IKhfs`) handshake, even with the right X25519 key: `identity_downgrade`.
#[tokio::test]
async fn a_v2_pinned_client_is_refused_over_a_classical_handshake() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let agent = id();
    let mut policy = relay_policy(
        &agent.fingerprint(),
        &[alice.fingerprint()],
        CertTrust::new(),
    );
    hybrid_pins(&mut policy, &[&alice]);
    let mut config = relay_config();
    config.suites = zt_domain::SuitePolicy {
        agents: AcceptedSuites::only(CLASSIC),
        clients: AcceptedSuites::new([CLASSIC, HYBRID]).unwrap(),
    };
    let mut clients = agent_clients(&[alice.fingerprint()], CertTrust::new());
    clients
        .pin_hybrid(alice.fingerprint(), alice.hybrid_fingerprint())
        .unwrap();
    let lab = Lab::start_outer(
        agent,
        vec![(policy, config)],
        clients,
        AcceptedSuites::new([CLASSIC, HYBRID]).unwrap(),
        CLASSIC,
    )
    .await;
    assert!(
        lab.refused_with(&alice, &lab.config_outer(None, CLASSIC, HYBRID))
            .await
            .is_err()
    );
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    let failed = log.events("authentication_failed");
    assert!(
        failed
            .iter()
            .any(|l| field(l, "reason").as_deref() == Some("identity_downgrade")),
        "{}",
        log.text()
    );
    // Over the hybrid suite on the outer hop and classical end to end: the agent refuses.
    assert!(
        lab.refused_with(&alice, &lab.config_outer(None, HYBRID, CLASSIC))
            .await
            .is_err()
    );
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    // And the hybrid suite on both: admitted.
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
}

/// Spec (pq.md §4.6): a hybrid client admitted by v1 entries works, and relay and agent
/// report `classical_identity_match` (WARN) with both fingerprints.
#[tokio::test]
async fn a_hybrid_peer_matched_by_a_v1_entry_is_reported() {
    let log = Captured::default();
    let _guard = log.install();
    let alice = id();
    let agent = id();
    let policy = relay_policy(
        &agent.fingerprint(),
        &[alice.fingerprint()],
        CertTrust::new(),
    );
    let mut config = relay_config();
    config.suites = zt_domain::SuitePolicy {
        agents: AcceptedSuites::only(CLASSIC),
        clients: AcceptedSuites::only(HYBRID),
    };
    let lab = Lab::start_outer(
        agent,
        vec![(policy, config)],
        agent_clients(&[alice.fingerprint()], CertTrust::new()),
        AcceptedSuites::only(HYBRID),
        CLASSIC,
    )
    .await;
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    let warned = log.events("classical_identity_match");
    assert_eq!(warned.len(), 2, "{}", log.text());
    for line in &warned {
        assert!(line.contains("\"level\":\"WARN\""), "{line}");
        assert_eq!(field(line, "peer"), Some(alice.fingerprint().to_string()));
        assert_eq!(
            field(line, "peer_v2"),
            Some(alice.hybrid_fingerprint().to_string())
        );
    }
}

/// Spec and attack (AP-9): a certificate v2 bound to the client's hybrid identity admits it
/// over the hybrid suite only; over the classical suite the binding fails (`key_mismatch`).
#[tokio::test]
async fn a_hybrid_bound_certificate_passes_only_over_the_hybrid_suite() {
    let ca = Ca::new_v2();
    let alice = id();
    let agent = id();
    let policy = relay_policy(
        &agent.fingerprint(),
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    );
    let mut config = relay_config();
    config.suites = zt_domain::SuitePolicy {
        agents: AcceptedSuites::only(CLASSIC),
        clients: AcceptedSuites::new([CLASSIC, HYBRID]).unwrap(),
    };
    let lab = Lab::start_outer(
        agent,
        vec![(policy, config)],
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
        AcceptedSuites::new([CLASSIC, HYBRID]).unwrap(),
        CLASSIC,
    )
    .await;
    let (cert, _) = ca.issue_hybrid(&alice.hybrid_public_key(), scope(&["web-01"]));
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(Some(&cert), HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert!(
        lab.refused_with(&alice, &lab.config_outer(Some(&cert), CLASSIC, CLASSIC))
            .await
            .is_err()
    );
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 1);
}
