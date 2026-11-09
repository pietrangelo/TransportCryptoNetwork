//! PQ-0 / R-1 specification: configuration of handshake suites and admission limits
//! (`relay.toml`, the `suite` pins of `client.toml`, the agent's suite options).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::path::Path;
use std::time::Duration;

use zt_application::admission::{AdmissionConfig, AdmissionConfigError};
use zt_crypto::Identity;
use zt_domain::{AcceptedSuites, HandshakeSuite, NodeId, SuiteError, SuitePolicy};
use zt_net::config::{
    ConfigError, RelaySettings, parse_client_settings, parse_relay_settings, parse_suite,
    parse_suites,
};

const CLASSIC: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const HFS: &str = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s";

fn key() -> String {
    Identity::generate().unwrap().public_key().to_string()
}

#[test]
fn an_empty_relay_toml_gives_the_documented_defaults() {
    let s = parse_relay_settings("relay.toml", "").unwrap();
    assert_eq!(
        s,
        RelaySettings {
            admission: AdmissionConfig::default(),
            suites: SuitePolicy::classical(),
        }
    );
}

#[test]
fn relay_toml_sets_suites_per_role_and_admission_limits() {
    let text = format!(
        r#"
        [handshake]
        agent_suites = ["{CLASSIC}"]
        client_suites = ["{CLASSIC}"]

        [admission]
        max_preauth = 512
        max_established = 4096
        max_per_identity = 128
        source_burst = 32
        source_refill_secs = 5
        msg1_deadline_secs = 6
        handshake_timeout_secs = 12
        first_frame_deadline_secs = 4
        "#
    );
    let s = parse_relay_settings("relay.toml", &text).unwrap();
    assert_eq!(s.suites, SuitePolicy::classical());
    let a = &s.admission;
    assert_eq!(a.max_preauth, 512);
    assert_eq!(a.max_established, 4096);
    assert_eq!(a.max_per_identity, 128);
    assert_eq!(a.source_burst, 32);
    assert_eq!(a.source_refill, Duration::from_secs(5));
    assert_eq!(a.msg1_deadline, Duration::from_secs(6));
    assert_eq!(a.handshake_timeout, Duration::from_secs(12));
    assert_eq!(a.first_frame_deadline, Duration::from_secs(4));
    // Not configurable: they keep their defaults.
    assert_eq!(a.wide_burst, AdmissionConfig::default().wide_burst);
}

#[test]
fn relay_toml_refuses_what_it_does_not_know() {
    for text in [
        "unknown = 1",
        "[admission]\nmax_connections = 10",
        "[handshake]\nminimum_suite = 1",
        "[handshake]\nagent_suites = [\"Noise_XX_25519_ChaChaPoly_BLAKE2s\"]",
    ] {
        assert!(
            parse_relay_settings("relay.toml", text).is_err(),
            "accepted: {text}"
        );
    }
}

#[test]
fn a_suite_this_build_cannot_run_is_a_configuration_error() {
    let text = format!("[handshake]\nclient_suites = [\"{CLASSIC}\", \"{HFS}\"]");
    match parse_relay_settings("relay.toml", &text) {
        Err(ConfigError::Suite { source, .. }) => assert_eq!(source, SuiteError::Unsupported),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_empty_or_repeated_accepted_set_is_refused() {
    for (text, expected) in [
        (
            "[handshake]\nagent_suites = []".to_owned(),
            SuiteError::Empty,
        ),
        (
            format!("[handshake]\nagent_suites = [\"{CLASSIC}\", \"{CLASSIC}\"]"),
            SuiteError::Duplicate,
        ),
    ] {
        match parse_relay_settings("relay.toml", &text) {
            Err(ConfigError::Suite { source, .. }) => assert_eq!(source, expected, "{text}"),
            other => panic!("{text}: {other:?}"),
        }
    }
}

#[test]
fn invalid_admission_limits_are_refused_at_load() {
    for (text, expected) in [
        (
            "[admission]\nmsg1_deadline_secs = 3",
            AdmissionConfigError::Msg1DeadlineTooShort,
        ),
        (
            "[admission]\nmax_preauth = 0",
            AdmissionConfigError::Zero("max_preauth"),
        ),
        (
            "[admission]\nsource_refill_secs = 0",
            AdmissionConfigError::Zero("source_refill"),
        ),
    ] {
        match parse_relay_settings("relay.toml", text) {
            Err(ConfigError::Admission { source, .. }) => assert_eq!(source, expected, "{text}"),
            other => panic!("{text}: {other:?}"),
        }
    }
}

#[test]
fn suites_are_named_by_their_exact_noise_protocol_name() {
    assert_eq!(
        parse_suite("--x", CLASSIC).unwrap(),
        HandshakeSuite::NoiseIk25519
    );
    assert_eq!(
        parse_suites("--x", &[CLASSIC.to_owned()]).unwrap(),
        AcceptedSuites::only(HandshakeSuite::NoiseIk25519)
    );
    for name in [
        HFS,
        "noise_ik_25519_chachapoly_blake2s",
        " Noise_IK_25519_ChaChaPoly_BLAKE2s",
        "1",
        "",
    ] {
        assert!(parse_suite("--x", name).is_err(), "accepted {name:?}");
    }
    assert!(parse_suites("--x", &[]).is_err());
}

#[test]
fn the_client_pins_a_suite_per_relay_and_per_node() {
    let (r1, r2, n1) = (key(), key(), key());
    let text = format!(
        r#"
        key = "client.key"
        [[relays]]
        address = "r1.example.org:7443"
        public_key = "{r1}"
        suite = "{CLASSIC}"
        [[relays]]
        address = "r2.example.org:7443"
        public_key = "{r2}"
        [[nodes]]
        node = "web-01"
        public_key = "{n1}"
        suite = "{CLASSIC}"
        "#
    );
    let s = parse_client_settings("client.toml", Path::new("/etc/tcn"), &text).unwrap();
    // Without `suite`, the classical suite: a fixed default that never changes (AP-7).
    assert!(
        s.relays
            .iter()
            .all(|r| r.suite == HandshakeSuite::NoiseIk25519)
    );
    let web = NodeId::try_from("web-01").unwrap();
    assert_eq!(s.node_suites.get(&web), Some(&HandshakeSuite::NoiseIk25519));
    let c = s.client_config(&web, zt_net::Timeouts::default()).unwrap();
    assert_eq!(c.node_suite, HandshakeSuite::NoiseIk25519);
}

#[test]
fn the_client_refuses_a_suite_it_cannot_run() {
    let (r1, n1) = (key(), key());
    for (relay_suite, node_suite) in [(HFS, CLASSIC), (CLASSIC, HFS), ("bogus", CLASSIC)] {
        let text = format!(
            r#"
            relay = "r1.example.org:7443"
            relay_key = "{r1}"
            relay_suite = "{relay_suite}"
            key = "client.key"
            [[nodes]]
            node = "web-01"
            public_key = "{n1}"
            suite = "{node_suite}"
            "#
        );
        assert!(
            parse_client_settings("client.toml", Path::new("/etc/tcn"), &text).is_err(),
            "{relay_suite} / {node_suite}"
        );
    }
}
