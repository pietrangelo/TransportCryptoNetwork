//! Regression tests of adversary review 0012 (Phase 5, PQ-AUTH) on the network and
//! configuration side.
//!
//! - A12-1: `require_hybrid_identity` in the relay policy and in `clients.toml`; the CRQC
//!   impostor with a classical-kind certificate is refused end to end.
//! - A12-2: fleet-scale policy files: a policy of 1 000 v2 clients loads (full keys and
//!   compact `tcn-pin-v2:` pins), the compact pin is a responder-side form only, and the
//!   bounds stay.
//! - A12-9: the AP-12 catalogue row on the network: a CRQC impostor passes the pre-message-2
//!   check, fails at key confirmation, and leaves no session and no success event.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{
    Ca, Captured, Lab, agent_clients, assert_alive, field, relay_config, relay_policy, scope,
    start_relay_with, trust,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zt_crypto::noise::{self, Channel};
use zt_crypto::{HybridPin, Identity};
use zt_domain::trust::CertTrust;
use zt_domain::{AcceptedSuites, AllowedNodes, HandshakeSuite, HybridRequirement};
use zt_net::config::{
    ConfigError, MAX_PEER_ENTRIES, MAX_TRUST_FILE_LEN, load_authorized_clients_digested,
    load_client_settings, load_policy, parse_authorized_clients, parse_client_settings,
    parse_policy, parse_revocations,
};

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HYBRID_NAME: &str = "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s";

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

fn seeded(i: usize) -> Identity {
    Identity::from_secret_hex(&format!("{:064x}", i + 1)).unwrap()
}

fn private_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn write_trusted(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// How a client entry names its key.
#[derive(Clone, Copy)]
enum Form {
    V1,
    FullV2,
    Pin,
}

fn key_text(id: &Identity, form: Form) -> String {
    match form {
        Form::V1 => id.public_key().to_string(),
        Form::FullV2 => id.hybrid_public_key().to_string(),
        Form::Pin => id.hybrid_pin().to_string(),
    }
}

fn policy_text(clients: usize, form: Form, header: &str) -> String {
    let agent = seeded(100_000);
    let mut text = format!(
        "{header}[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n",
        key_text(&agent, form)
    );
    for i in 0..clients {
        let _ = write!(
            text,
            "[[clients]]\nname = \"client-{i}\"\npublic_key = \"{}\"\nallow = [\"web-01\"]\n\n",
            key_text(&seeded(i), form)
        );
    }
    text
}

// --- A12-2: fleet-scale policy files ---------------------------------------------------------

/// A12-2 (the reproducer, flipped): Phase 5 of the runbook completes for a fleet of 1 000
/// pinned clients: the policy and `clients.toml` load with full `tcn-pub-v2:` keys and with
/// the compact `tcn-pin-v2:` pins, and every entry is pinned in v2.
#[test]
fn a_policy_of_a_thousand_v2_clients_loads() {
    let dir = private_dir("adv12-fleet");
    for (form, name) in [(Form::FullV2, "full"), (Form::Pin, "pin")] {
        let text = policy_text(
            1_000,
            form,
            "require_hybrid_identity = [\"agents\", \"clients\"]\n",
        );
        let path = dir.join(format!("policy-{name}.toml"));
        write_trusted(&path, &text);
        let policy = load_policy(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            policy.hybrid_requirement(),
            HybridRequirement::new(true, true)
        );
        for i in [0, 499, 999] {
            let client = seeded(i);
            assert_eq!(
                policy.hybrid_identity(&client.fingerprint()),
                Some(&client.hybrid_fingerprint()),
                "{name}: client-{i}"
            );
        }
        let clients_text = policy_text(1_000, form, "require_hybrid_identity = [\"clients\"]\n");
        let clients_path = dir.join(format!("clients-{name}.toml"));
        write_trusted(&clients_path, &clients_text);
        let (clients, _) = load_authorized_clients_digested(&clients_path, None)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(clients.requires_hybrid_identity());
        assert_eq!(
            clients.hybrid_identity(&seeded(7).fingerprint()),
            Some(&seeded(7).hybrid_fingerprint())
        );
    }
}

/// A12-2: the compact pin of a fleet of 4 000 agents (the herd of pq.md and 0007 AP-8) fits
/// the bound with room to spare, and the bounds are documented constants: the file length is
/// derived from the entry count, and an entry count over the limit is refused.
#[test]
fn the_bounds_of_a_policy_file_are_derived_from_its_entries() {
    let pin_entry_len = policy_text(1, Form::Pin, "").len() / 2;
    assert!(
        MAX_PEER_ENTRIES * pin_entry_len <= MAX_TRUST_FILE_LEN,
        "{MAX_PEER_ENTRIES} compact entries of {pin_entry_len} bytes"
    );
    // 4 000 agents, compact pins.
    let mut text = String::new();
    for i in 0..4_000 {
        let _ = write!(
            text,
            "[[agents]]\nnode = \"node-{i}\"\npublic_key = \"{}\"\n\n",
            seeded(i).hybrid_pin()
        );
    }
    let dir = private_dir("adv12-herd");
    let path = dir.join("policy.toml");
    write_trusted(&path, &text);
    assert!(load_policy(&path).is_ok());
    // Over the length bound: refused before parsing, as before.
    let big = dir.join("big.toml");
    write_trusted(&big, &"#".repeat(MAX_TRUST_FILE_LEN + 1));
    assert!(matches!(load_policy(&big), Err(ConfigError::TooLarge(_))));
    // Over the entry bound: refused.
    let mut many = String::new();
    for i in 0..=MAX_PEER_ENTRIES {
        let _ = write!(
            many,
            "[[clients]]\nname = \"c{i}\"\npublic_key = \"{}\"\n",
            "ab".repeat(32)
        );
    }
    let err = parse_policy("policy.toml", &many).unwrap_err().to_string();
    assert!(err.contains("entries"), "{err}");
}

/// A12-2: the compact pin is the responder's form: it carries no encapsulation key, so a
/// client cannot initiate to it (`client.toml` relays and nodes refuse it), while the
/// denylist reduces it to the X25519-level fingerprint like every other form (AP-6).
#[test]
fn the_compact_pin_is_a_responder_side_form() {
    let (agent, relay) = (id(), id());
    let pin = agent.hybrid_pin();
    assert_eq!(pin.fingerprint(), agent.fingerprint());
    assert_eq!(pin.hybrid_fingerprint(), agent.hybrid_fingerprint());
    assert_eq!(pin.to_string().parse::<HybridPin>().unwrap(), pin);
    assert!(pin.to_string().starts_with(HybridPin::PREFIX));
    // In client.toml: refused for a node and for a relay.
    for (relay_key, node_key) in [
        (relay.hybrid_public_key().to_string(), pin.to_string()),
        (
            relay.hybrid_pin().to_string(),
            agent.hybrid_public_key().to_string(),
        ),
    ] {
        let text = format!(
            "relay = \"127.0.0.1:4433\"\nrelay_key = \"{relay_key}\"\nkey = \"client.key\"\n\n\
             [[nodes]]\nnode = \"web-01\"\npublic_key = \"{node_key}\"\nsuite = \"{HYBRID_NAME}\"\n"
        );
        assert!(parse_client_settings("client.toml", &text).is_err());
    }
    // In revoked.toml: the X25519-level fingerprint.
    let revoked = parse_revocations("revoked.toml", &format!("keys = [\"{pin}\"]\n")).unwrap();
    assert!(revoked.is_key_revoked(&agent.fingerprint()));
    // Malformed pins are refused without echoing them.
    for bad in [
        format!("{}{}", HybridPin::PREFIX, "ab".repeat(32)),
        format!("{pin}0"),
        pin.to_string().to_uppercase(),
        pin.to_string().replacen(':', ";", 2),
    ] {
        let text = format!("[[clients]]\nname = \"a\"\npublic_key = \"{bad}\"\nallow = [\"*\"]\n");
        let err = parse_policy("policy.toml", &text).unwrap_err().to_string();
        assert!(!err.contains(&"ab".repeat(16)), "{err}");
    }
}

/// A12-2: a client.toml with 1 000 v2 node pins (initiator side: full keys) loads.
#[test]
fn a_client_configuration_with_a_thousand_v2_nodes_loads() {
    let dir = private_dir("adv12-client");
    let relay = id();
    let mut text = format!(
        "relay = \"127.0.0.1:4433\"\nrelay_key = \"{}\"\nrelay_suite = \"{HYBRID_NAME}\"\n\
         key = \"client.key\"\n\n",
        relay.hybrid_public_key()
    );
    for i in 0..1_000 {
        let _ = write!(
            text,
            "[[nodes]]\nnode = \"node-{i}\"\npublic_key = \"{}\"\nsuite = \"{HYBRID_NAME}\"\n\n",
            seeded(i).hybrid_public_key()
        );
    }
    let path = dir.join("client.toml");
    write_trusted(&path, &text);
    let settings = load_client_settings(&path).unwrap();
    assert_eq!(settings.nodes.len(), 1_000);
}

// --- A12-1: require_hybrid_identity ------------------------------------------------------------

/// A12-1: `require_hybrid_identity` is an explicit set of roles (AP-7 style): a v1 entry of a
/// required role, an unknown or repeated role, and `agents` in `clients.toml` are errors.
#[test]
fn require_hybrid_identity_refuses_v1_entries_of_required_roles() {
    let (agent, alice) = (id(), id());
    let entries = |agent_key: String, alice_key: String| {
        format!(
            "[[agents]]\nnode = \"web-01\"\npublic_key = \"{agent_key}\"\n\n\
             [[clients]]\nname = \"alice\"\npublic_key = \"{alice_key}\"\nallow = [\"*\"]\n"
        )
    };
    let v2_agent_v1_alice = entries(
        agent.hybrid_pin().to_string(),
        alice.public_key().to_string(),
    );
    // Agents only: allowed.
    let policy = parse_policy(
        "policy.toml",
        &format!("require_hybrid_identity = [\"agents\"]\n{v2_agent_v1_alice}"),
    )
    .unwrap();
    assert_eq!(
        policy.hybrid_requirement(),
        HybridRequirement::new(true, false)
    );
    // Clients too: alice's v1 entry is refused, and the message names it.
    let err = parse_policy(
        "policy.toml",
        &format!("require_hybrid_identity = [\"agents\", \"clients\"]\n{v2_agent_v1_alice}"),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("alice"), "{err}");
    // No setting: the default is no requirement.
    let policy = parse_policy("policy.toml", &v2_agent_v1_alice).unwrap();
    assert_eq!(policy.hybrid_requirement(), HybridRequirement::NONE);
    for bad in [
        "[\"client\"]",
        "[\"agents\", \"agents\"]",
        "[\"*\"]",
        "\"clients\"",
    ] {
        assert!(
            parse_policy(
                "policy.toml",
                &format!("require_hybrid_identity = {bad}\n{v2_agent_v1_alice}")
            )
            .is_err(),
            "{bad}"
        );
    }
    // clients.toml: only `clients`.
    let clients = format!(
        "[[clients]]\nname = \"alice\"\npublic_key = \"{}\"\n",
        alice.hybrid_pin()
    );
    assert!(
        parse_authorized_clients(
            "clients.toml",
            &format!("require_hybrid_identity = [\"clients\"]\n{clients}")
        )
        .unwrap()
        .requires_hybrid_identity()
    );
    assert!(
        parse_authorized_clients(
            "clients.toml",
            &format!("require_hybrid_identity = [\"agents\"]\n{clients}")
        )
        .is_err()
    );
    let v1 = format!(
        "[[clients]]\nname = \"alice\"\npublic_key = \"{}\"\n",
        alice.public_key()
    );
    assert!(
        parse_authorized_clients(
            "clients.toml",
            &format!("require_hybrid_identity = [\"clients\"]\n{v1}")
        )
        .is_err()
    );
}

/// A12-1 end to end: with `require_hybrid_identity = ["clients"]` on the relay and the agent,
/// a certificate-only client with a classical-kind certificate is refused even over the
/// hybrid IK suite (`identity_downgrade`), and one with a hybrid-bound certificate is admitted.
#[tokio::test]
async fn a_classical_kind_certificate_is_refused_when_hybrid_is_required() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new_v2();
    let (alice, agent) = (id(), id());
    let mut policy = relay_policy(
        &agent.fingerprint(),
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[], &[]),
    );
    policy
        .require_hybrid_identity(HybridRequirement::new(false, true))
        .unwrap();
    let mut config = relay_config();
    config.suites = zt_domain::SuitePolicy {
        agents: AcceptedSuites::only(CLASSIC),
        clients: AcceptedSuites::only(HYBRID),
    };
    let mut clients = agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[]));
    clients.require_hybrid_identity().unwrap();
    let lab = Lab::start_outer(
        agent,
        vec![(policy, config)],
        clients,
        AcceptedSuites::only(HYBRID),
        CLASSIC,
    )
    .await;
    let (classical_kind, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    assert!(
        lab.refused_with(
            &alice,
            &lab.config_outer(Some(&classical_kind), HYBRID, HYBRID)
        )
        .await
        .is_err()
    );
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 0);
    assert!(
        log.events("authentication_failed")
            .iter()
            .any(|l| field(l, "reason").as_deref() == Some("identity_downgrade")),
        "{}",
        log.text()
    );
    let (bound, _) = ca.issue_hybrid(&alice.hybrid_public_key(), scope(&["web-01"]));
    let (mut app, _t) = lab
        .session_with(&alice, lab.config_outer(Some(&bound), HYBRID, HYBRID))
        .await
        .unwrap();
    assert_alive(&mut app).await;
    assert!(
        log.events("classical_identity_match").is_empty(),
        "{}",
        log.text()
    );
}

// --- A12-9: AP-12 on the network ---------------------------------------------------------------

/// A12-9 (AP-12 catalogue row): a CRQC that recovered an agent's X25519 secret writes the
/// agent's hybrid IK message 1 (its encapsulation key is public), passes the relay's
/// pre-message-2 check and gets message 2, but cannot decapsulate `ct2`: its key confirmation
/// does not decrypt, the relay closes, and there is no registration, no session and no
/// success event naming the agent.
#[tokio::test]
async fn a_crqc_impostor_fails_at_key_confirmation_on_the_network() {
    let log = Captured::default();
    let _guard = log.install();
    let victim = id();
    let mut policy = relay_policy(&victim.fingerprint(), &[], CertTrust::new());
    policy
        .pin_hybrid(victim.fingerprint(), victim.hybrid_fingerprint())
        .unwrap();
    policy
        .require_hybrid_identity(HybridRequirement::new(true, false))
        .unwrap();
    let mut config = relay_config();
    config.suites = zt_domain::SuitePolicy {
        agents: AcceptedSuites::only(HYBRID),
        clients: AcceptedSuites::only(CLASSIC),
    };
    let relay = start_relay_with(policy, config).await;
    // Everything in message 1 is computable from the X25519 secret and public data.
    let (msg1, _impostor_lacks_dk) =
        noise::initiate_suite(&victim, relay.pin(HYBRID), Channel::Outer, HYBRID, &[]).unwrap();
    let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
    tcp.write_all(&u16::try_from(msg1.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(&msg1).await.unwrap();
    let mut head = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(4), tcp.read_exact(&mut head))
        .await
        .expect("message 2 in time")
        .expect("message 2: the pre-message-2 check passes");
    let mut msg2 = vec![0_u8; usize::from(u16::from_be_bytes(head))];
    tcp.read_exact(&mut msg2).await.unwrap();
    assert_eq!(msg2.len(), HYBRID.msg2_len());
    // A confirmation the impostor cannot make authentic.
    let mut fake = vec![0_u8; 64];
    getrandom::fill(&mut fake).unwrap();
    tcp.write_all(&u16::try_from(fake.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(&fake).await.unwrap();
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(4), tcp.read_to_end(&mut rest)).await;
    assert!(
        closed.is_ok(),
        "the relay keeps the impostor's connection open"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    for kind in [
        "agent_registered",
        "session_established",
        "classical_identity_match",
    ] {
        assert!(log.events(kind).is_empty(), "{kind}: {}", log.text());
    }
    assert!(
        !log.text().contains("\"event_kind\":\"agent_connected\""),
        "{}",
        log.text()
    );
}
