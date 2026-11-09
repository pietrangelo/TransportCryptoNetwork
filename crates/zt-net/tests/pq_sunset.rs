//! Phase 7, PQ-SUNSET (docs/pq-resilience-plan.md §4; analysis/pq.md PQ-5; OPERATIONS §19):
//! retiring the classical-only paths is a configuration step, never a new default. The
//! `pq_only` profile (`[handshake] pq_only` in `relay.toml`, `--pq-only` on the agent,
//! `pq_only` in `client.toml`) refuses at load time any setting that would still accept a
//! classical suite, a v1 identity or a v1 certificate, and the end-state fleet of OPERATIONS
//! §19 refuses each of them on every channel: both outer hops and end to end.
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

use common::{Ca, Captured, Lab, assert_alive, field, relay_config, scope};
use zt_crypto::Identity;
use zt_domain::{AcceptedSuites, AccessPolicy, AuthorizedClients, HandshakeSuite};
use zt_net::config::{
    ConfigError, RelaySettings, parse_authorized_clients, parse_certificate_file,
    parse_client_settings, parse_policy, parse_relay_settings, parse_revocations,
};
use zt_net::sunset;

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const IKHFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HYBRID_NAME: &str = "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const IKHFS_NAME: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";
const CLASSIC_NAME: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

/// The end-state `relay.toml` of OPERATIONS §19.
fn relay_toml() -> String {
    format!(
        "[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\"]\nclient_suites = [\"{HYBRID_NAME}\"]\n"
    )
}

/// The end-state relay policy of OPERATIONS §19: both roles required hybrid, v2 keys only, a
/// composite CA only.
fn policy_toml(agent: &Identity, alice: &Identity, ca: &Ca) -> String {
    format!(
        "require_hybrid_identity = [\"agents\", \"clients\"]\n\n\
         [[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n\
         [[clients]]\nname = \"alice\"\npublic_key = \"{}\"\nallow = [\"*\"]\n\n\
         [[authorities]]\nname = \"ops\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
        agent.hybrid_public_key(),
        alice.hybrid_public_key(),
        ca.v2.as_ref().unwrap().public_key(),
    )
}

/// The end-state `clients.toml` of OPERATIONS §19.
fn clients_toml(alice: &Identity, ca: &Ca) -> String {
    format!(
        "require_hybrid_identity = [\"clients\"]\n\n\
         [[clients]]\nname = \"alice\"\npublic_key = \"{}\"\n\n\
         [[authorities]]\nname = \"ops\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
        alice.hybrid_public_key(),
        ca.v2.as_ref().unwrap().public_key(),
    )
}

/// The end-state `client.toml` of OPERATIONS §19.
fn client_toml(relay: &Identity, agent: &Identity) -> String {
    format!(
        "pq_only = true\nkey = \"client.key\"\nrequire_outer_suite = \"{HYBRID_NAME}\"\n\n\
         [[relays]]\naddress = \"r1.example:7000\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n\n\
         [[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n",
        relay.hybrid_public_key(),
        agent.hybrid_public_key(),
    )
}

fn pq_only_error(err: &ConfigError) {
    assert!(
        matches!(err, ConfigError::PqOnly { .. }),
        "not a pq_only refusal: {err:?}"
    );
    assert!(err.to_string().contains("pq_only"), "{err}");
}

// --- the defaults stay compatible ---------------------------------------------------------

/// Spec: the built-in defaults are not pq-only and never change: an empty `relay.toml` accepts
/// the classical suite, an agent without flags pins it, a client without `pq_only` too.
#[test]
fn the_defaults_stay_compatible_with_a_mixed_fleet() {
    let defaults = RelaySettings::default();
    assert!(!defaults.pq_only);
    assert_eq!(defaults.suites, zt_domain::SuitePolicy::classical());
    let empty = parse_relay_settings("relay.toml", "").unwrap();
    assert!(!empty.pq_only);
    assert_eq!(empty.suites, zt_domain::SuitePolicy::classical());
    let (relay, agent) = (id(), id());
    let plain = format!(
        "key = \"client.key\"\nrelay = \"r1.example:7000\"\nrelay_key = \"{}\"\n\n\
         [[nodes]]\nnode = \"web-01\"\npublic_key = \"{}\"\n",
        relay.public_key(),
        agent.public_key()
    );
    let settings = parse_client_settings("client.toml", Path::new("/etc/tcn"), &plain).unwrap();
    assert!(!settings.pq_only);
    assert_eq!(settings.relays[0].suite, CLASSIC);
}

/// Spec: outside the profile, `check` names every classical path the configuration still
/// accepts, so the operator sees what the sunset has left to do; the end state names none.
#[test]
fn the_report_names_the_classical_paths_still_accepted() {
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let old = Ca::new();
    let mixed_policy = parse_policy(
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n\
             [[authorities]]\nname = \"old\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
            agent.public_key(),
            old.key.public_key(),
        ),
    )
    .unwrap();
    let report = sunset::relay_report(&RelaySettings::default(), &mixed_policy);
    let text = report.join("\n");
    assert!(text.contains(CLASSIC_NAME), "{text}");
    assert!(text.contains("agents"), "{text}");
    assert!(text.contains("clients"), "{text}");
    assert!(
        text.contains("old"),
        "the v1 authority is not named: {text}"
    );
    let end = parse_relay_settings("relay.toml", &relay_toml()).unwrap();
    let policy = parse_policy("policy.toml", &policy_toml(&agent, &alice, &ca)).unwrap();
    assert_eq!(sunset::relay_report(&end, &policy), Vec::<String>::new());
    let clients = parse_authorized_clients("clients.toml", &clients_toml(&alice, &ca)).unwrap();
    assert_eq!(
        sunset::agent_report(&[], AcceptedSuites::only(HYBRID), &clients),
        Vec::<String>::new()
    );
    let classical = sunset::agent_report(
        &[],
        AcceptedSuites::new([CLASSIC, HYBRID]).unwrap(),
        &AuthorizedClients::new(),
    );
    assert!(classical.join("\n").contains(CLASSIC_NAME), "{classical:?}");
}

// --- the profile refuses at load time -----------------------------------------------------

/// Spec: `[handshake] pq_only = true` accepts only the hybrid IK suite in both sets, given
/// explicitly; the classical suite or `IKhfs` (hybrid key exchange, classical authentication)
/// in either set, or a set left to its classical default, is a load error.
#[test]
fn a_pq_only_relay_accepts_only_the_hybrid_ik_suite() {
    let settings = parse_relay_settings("relay.toml", &relay_toml()).unwrap();
    assert!(settings.pq_only);
    assert_eq!(settings.suites.agents, AcceptedSuites::only(HYBRID));
    assert_eq!(settings.suites.clients, AcceptedSuites::only(HYBRID));
    for bad in [
        "[handshake]\npq_only = true\n".to_owned(),
        format!("[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\"]\n"),
        format!("[handshake]\npq_only = true\nclient_suites = [\"{HYBRID_NAME}\"]\n"),
        format!(
            "[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]\nclient_suites = [\"{HYBRID_NAME}\"]\n"
        ),
        format!(
            "[handshake]\npq_only = true\nagent_suites = [\"{HYBRID_NAME}\"]\nclient_suites = [\"{IKHFS_NAME}\"]\n"
        ),
    ] {
        let err = parse_relay_settings("relay.toml", &bad).unwrap_err();
        pq_only_error(&err);
    }
    // `pq_only = false` is the default, written out.
    let off = parse_relay_settings("relay.toml", "[handshake]\npq_only = false\n").unwrap();
    assert!(!off.pq_only);
}

/// Spec: with the profile, the relay policy must require hybrid identities for agents and
/// clients and pin composite (v2) CA keys only; a v1 CA, even next to a v2 one in a rotation,
/// is refused.
#[test]
fn a_pq_only_relay_policy_requires_hybrid_identities_and_v2_authorities() {
    let (agent, alice, ca, old) = (id(), id(), Ca::new_v2(), Ca::new());
    let good = parse_policy("policy.toml", &policy_toml(&agent, &alice, &ca)).unwrap();
    sunset::check_policy("policy.toml", &good).unwrap();
    let text = policy_toml(&agent, &alice, &ca);
    for bad in [
        text.replace(
            "require_hybrid_identity = [\"agents\", \"clients\"]",
            "require_hybrid_identity = [\"agents\"]",
        ),
        text.replace(
            "require_hybrid_identity = [\"agents\", \"clients\"]",
            "require_hybrid_identity = [\"clients\"]",
        ),
        text.replace("require_hybrid_identity = [\"agents\", \"clients\"]\n", ""),
        text.replace(
            &format!("public_key = \"{}\"", ca.v2.as_ref().unwrap().public_key()),
            &format!(
                "public_keys = [\"{}\", \"{}\"]",
                ca.v2.as_ref().unwrap().public_key(),
                old.key.public_key()
            ),
        ),
        text.replace(
            &format!("public_key = \"{}\"", ca.v2.as_ref().unwrap().public_key()),
            &format!("public_key = \"{}\"", old.key.public_key()),
        ),
    ] {
        let policy = parse_policy("policy.toml", &bad).unwrap();
        pq_only_error(&sunset::check_policy("policy.toml", &policy).unwrap_err());
    }
}

/// Spec: with `--pq-only` the agent pins the hybrid IK suite towards every relay and accepts
/// only it from clients; `clients.toml` requires hybrid clients and pins v2 CAs only.
#[test]
fn a_pq_only_agent_pins_and_accepts_only_the_hybrid_ik_suite() {
    let (relay, alice, ca, old) = (id(), id(), Ca::new_v2(), Ca::new());
    let endpoint = |suite: HandshakeSuite| zt_net::RelayEndpoint {
        address: "r1.example:7000".into(),
        public_key: common::pin_of(&relay, suite),
        suite,
    };
    sunset::check_agent_suites(&[endpoint(HYBRID)], AcceptedSuites::only(HYBRID)).unwrap();
    for (relays, accepted) in [
        (vec![endpoint(CLASSIC)], AcceptedSuites::only(HYBRID)),
        (vec![endpoint(IKHFS)], AcceptedSuites::only(HYBRID)),
        (
            vec![endpoint(HYBRID), endpoint(CLASSIC)],
            AcceptedSuites::only(HYBRID),
        ),
        (vec![endpoint(HYBRID)], AcceptedSuites::only(CLASSIC)),
        (
            vec![endpoint(HYBRID)],
            AcceptedSuites::new([HYBRID, IKHFS]).unwrap(),
        ),
    ] {
        pq_only_error(&sunset::check_agent_suites(&relays, accepted).unwrap_err());
    }
    let text = clients_toml(&alice, &ca);
    let good = parse_authorized_clients("clients.toml", &text).unwrap();
    sunset::check_authorized_clients("clients.toml", &good).unwrap();
    for bad in [
        text.replace("require_hybrid_identity = [\"clients\"]\n", ""),
        text.replace(
            &format!("public_key = \"{}\"", ca.v2.as_ref().unwrap().public_key()),
            &format!("public_key = \"{}\"", old.key.public_key()),
        ),
    ] {
        let clients = parse_authorized_clients("clients.toml", &bad).unwrap();
        pq_only_error(&sunset::check_authorized_clients("clients.toml", &clients).unwrap_err());
    }
}

/// Spec: `pq_only = true` in `client.toml` needs the hybrid IK suite pinned for every relay
/// and every node (a node left to its classical default is refused), and a certificate v2
/// bound to the client's hybrid identity.
#[test]
fn a_pq_only_client_pins_only_the_hybrid_ik_suite() {
    let (relay, agent, alice, ca, old) = (id(), id(), id(), Ca::new_v2(), Ca::new());
    let base = Path::new("/etc/tcn");
    let text = client_toml(&relay, &agent);
    let settings = parse_client_settings("client.toml", base, &text).unwrap();
    assert!(settings.pq_only);
    let relay_line = format!("suite = \"{HYBRID_NAME}\"\n\n[[nodes]]");
    for bad in [
        text.replace(
            &relay_line,
            &format!("suite = \"{IKHFS_NAME}\"\n\n[[nodes]]"),
        )
        .replace(&format!("require_outer_suite = \"{HYBRID_NAME}\"\n"), ""),
        text.replace(&format!("require_outer_suite = \"{HYBRID_NAME}\"\n"), "")
            .replace(&relay_line, "\n[[nodes]]")
            .replace(
                &relay.hybrid_public_key().to_string(),
                &relay.public_key().to_string(),
            ),
        text.strip_suffix(&format!("suite = \"{HYBRID_NAME}\"\n"))
            .unwrap()
            .to_owned(),
        format!(
            "{text}\n[[nodes]]\nnode = \"web-02\"\npublic_key = \"{}\"\nsuite = \"{CLASSIC_NAME}\"\n",
            alice.hybrid_public_key()
        ),
    ] {
        let err = parse_client_settings("client.toml", base, &bad).unwrap_err();
        pq_only_error(&err);
    }
    let (hybrid_bound, _) = ca.issue_hybrid(&alice.hybrid_public_key(), scope(&["web-01"]));
    let (classical_v2, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (v1, _) = old.issue(&alice.public_key(), scope(&["web-01"]));
    let file = |bytes: &Arc<[u8]>| {
        parse_certificate_file("alice.cert", &zt_crypto::encode_certificate_text(bytes)).unwrap()
    };
    sunset::check_certificate("alice.cert", &file(&hybrid_bound)).unwrap();
    pq_only_error(&sunset::check_certificate("alice.cert", &file(&classical_v2)).unwrap_err());
    pq_only_error(&sunset::check_certificate("alice.cert", &file(&v1)).unwrap_err());
}

// --- the end-state fleet on the network ---------------------------------------------------

/// The fleet of OPERATIONS §19, every file parsed from its end-state text and checked by the
/// profile: one relay, the `web-01` agent pinned to the hybrid IK suite, the agent's
/// `clients.toml`.
async fn pq_only_fleet(
    agent: Arc<Identity>,
    alice: &Identity,
    ca: &Ca,
    agent_suite: HandshakeSuite,
) -> Lab {
    let settings = parse_relay_settings("relay.toml", &relay_toml()).unwrap();
    let mut policy = parse_policy("policy.toml", &policy_toml(&agent, alice, ca)).unwrap();
    sunset::check_policy("policy.toml", &policy).unwrap();
    with_empty_denylist_policy(&mut policy);
    let mut clients = parse_authorized_clients("clients.toml", &clients_toml(alice, ca)).unwrap();
    sunset::check_authorized_clients("clients.toml", &clients).unwrap();
    with_empty_denylist_clients(&mut clients);
    let mut relay = relay_config();
    relay.suites = settings.suites;
    Lab::start_outer(
        agent,
        vec![(policy, relay)],
        clients,
        AcceptedSuites::only(HYBRID),
        agent_suite,
    )
    .await
}

fn empty_denylist() -> zt_domain::trust::Revocations {
    parse_revocations("revoked.toml", "").unwrap()
}

fn with_empty_denylist_policy(policy: &mut AccessPolicy) {
    let mut trust = policy.cert_trust().clone();
    trust.set_revocations(empty_denylist());
    policy.set_cert_trust(trust).unwrap();
}

fn with_empty_denylist_clients(clients: &mut AuthorizedClients) {
    let mut trust = clients.cert_trust().clone();
    trust.set_revocations(empty_denylist());
    clients.set_cert_trust(trust).unwrap();
}

/// Spec: the end-state fleet works: a whitelisted client and a client with a hybrid-bound
/// certificate v2 reach their node over the hybrid IK suite on both hops and end to end.
#[tokio::test]
async fn a_pq_only_fleet_admits_hybrid_clients() {
    let (agent, alice, bob, ca) = (id(), id(), id(), Ca::new_v2());
    let lab = pq_only_fleet(agent, &alice, &ca, HYBRID).await;
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    let (cert, _) = ca.issue_hybrid(&bob.hybrid_public_key(), scope(&["web-01"]));
    let (mut app, _t) = lab
        .session_with(&bob, lab.config_outer(Some(&cert), HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 2);
}

/// Attack (Downgrade, client → relay): the classical suite and `IKhfs` on the outer hop are
/// refused by the pq-only relay, whatever the end-to-end suite.
#[tokio::test]
async fn a_pq_only_fleet_refuses_classical_suites_on_the_client_hop() {
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let lab = pq_only_fleet(agent, &alice, &ca, HYBRID).await;
    for outer in [CLASSIC, IKHFS] {
        for e2e in [HYBRID, CLASSIC] {
            assert!(
                lab.refused_with(&alice, &lab.config_outer(None, outer, e2e))
                    .await
                    .is_err(),
                "{outer:?} / {e2e:?}"
            );
        }
    }
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
}

/// Attack (Downgrade, end to end): over a hybrid outer hop, the classical suite and `IKhfs`
/// end to end are refused by the pq-only agent.
#[tokio::test]
async fn a_pq_only_fleet_refuses_classical_suites_end_to_end() {
    let log = Captured::default();
    let _guard = log.install();
    let (agent, alice, ca) = (id(), id(), Ca::new_v2());
    let lab = pq_only_fleet(agent, &alice, &ca, HYBRID).await;
    for e2e in [CLASSIC, IKHFS] {
        assert!(
            lab.refused_with(&alice, &lab.config_outer(None, HYBRID, e2e))
                .await
                .is_err(),
            "{e2e:?}"
        );
    }
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    // The relay admitted the client (hybrid hop); the agent refused it end to end.
    assert!(
        !log.events("session_established").is_empty(),
        "{}",
        log.text()
    );
}

/// Attack (Downgrade, agent → relay): an agent pinning the classical suite or `IKhfs` never
/// registers with the pq-only relay, so its node stays unreachable.
#[tokio::test]
async fn a_pq_only_relay_refuses_classical_agents() {
    for agent_suite in [CLASSIC, IKHFS] {
        let (agent, alice, ca) = (id(), id(), Ca::new_v2());
        let lab = pq_only_fleet(agent, &alice, &ca, agent_suite).await;
        assert!(
            lab.refused_with(&alice, &lab.config_outer(None, HYBRID, HYBRID))
                .await
                .is_err(),
            "{agent_suite:?}"
        );
        assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    }
}

/// Attack (v1 identities and certificates): over the hybrid IK suite, a key that is neither
/// whitelisted nor certified, a certificate v1 (its CA is not pinned: the profile refuses v1
/// CAs) and a certificate v2 bound only to the classical identity are all refused, on the
/// relay and on the agent.
#[tokio::test]
async fn a_pq_only_fleet_refuses_v1_identities_and_v1_certificates() {
    let log = Captured::default();
    let _guard = log.install();
    let (agent, alice, mallory, ca, old) = (id(), id(), id(), Ca::new_v2(), Ca::new());
    let lab = pq_only_fleet(agent, &alice, &ca, HYBRID).await;
    let (v1, _) = old.issue(&mallory.public_key(), scope(&["web-01"]));
    let (classical_v2, _) = ca.issue(&mallory.public_key(), scope(&["web-01"]));
    for cert in [None, Some(&v1), Some(&classical_v2)] {
        assert!(
            lab.refused_with(&mallory, &lab.config_outer(cert, HYBRID, HYBRID))
                .await
                .is_err()
        );
    }
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    let reasons: Vec<String> = log
        .events("authentication_failed")
        .iter()
        .filter_map(|l| field(l, "reason"))
        .collect();
    assert!(
        reasons.iter().any(|r| r == "identity_downgrade"),
        "{reasons:?}"
    );
    // The certificate v2 bound to the classical identity only is refused by name; the
    // certificate v1 names a CA the relay does not pin, an unknown identity that the relay
    // counts in its aggregate (no per-event line).
}

/// Spec (rollback, OPERATIONS §19): turning the profile off and adding the classical suite
/// back is a configuration change only, and the classical client gets in again.
#[tokio::test]
async fn the_rollback_is_a_configuration_change() {
    let (agent, alice) = (id(), id());
    let rolled_back = parse_relay_settings(
        "relay.toml",
        &format!(
            "[handshake]\npq_only = false\nagent_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]\nclient_suites = [\"{HYBRID_NAME}\", \"{CLASSIC_NAME}\"]\n"
        ),
    )
    .unwrap();
    assert!(!rolled_back.pq_only);
    let policy = parse_policy(
        "policy.toml",
        &format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n\
             [[clients]]\nname = \"alice\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
            agent.public_key(),
            alice.public_key(),
        ),
    )
    .unwrap();
    let clients = parse_authorized_clients(
        "clients.toml",
        &format!(
            "[[clients]]\nname = \"alice\"\npublic_key = \"{}\"\n",
            alice.public_key()
        ),
    )
    .unwrap();
    let mut relay = relay_config();
    relay.suites = rolled_back.suites;
    let lab = Lab::start_outer(
        agent,
        vec![(policy, relay)],
        clients,
        AcceptedSuites::new([HYBRID, CLASSIC]).unwrap(),
        CLASSIC,
    )
    .await;
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(None, CLASSIC, CLASSIC))
        .await
        .unwrap();
    assert_alive(&mut app).await;
}
