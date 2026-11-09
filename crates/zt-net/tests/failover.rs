//! R-4 specification: the client's failover on the wire (docs/analysis/resilience.md §5.3;
//! catalogue R4-F1; backlog A5-4), on the `turmoil` simulator with real relays and agent, and
//! the `client.toml` settings that drive it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod failover_harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use failover_harness::{Fleet, Outcome, RelayKind, echo, sim};
use zt_crypto::Identity;
use zt_domain::HandshakeSuite;

const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

fn client_toml(extra: &str) -> String {
    format!(
        "{extra}key = \"client.key\"\nrelay = \"r.example.org:7443\"\nrelay_key = \"{}\"\n",
        Identity::generate().unwrap().public_key()
    )
}

/// `connect_deadline_secs` in `client.toml`: 20 s by default, 1 to 300 s accepted.
#[test]
fn connect_deadline_is_read_from_client_toml() {
    let base = std::path::Path::new("/etc/tcn");
    let parse = |text: &str| zt_net::config::parse_client_settings("client.toml", base, text);
    let default = parse(&client_toml("")).unwrap();
    assert_eq!(default.connect_deadline, Duration::from_secs(20));
    let set = parse(&client_toml("connect_deadline_secs = 7\n")).unwrap();
    assert_eq!(set.connect_deadline, Duration::from_secs(7));
    for bad in ["0", "301", "-1", "\"20\""] {
        let err = parse(&client_toml(&format!("connect_deadline_secs = {bad}\n")));
        assert!(err.is_err(), "{bad} accepted");
    }
    let err = parse(&client_toml("connect_deadline_secs = 0\n")).unwrap_err();
    assert!(err.to_string().contains("connect_deadline_secs"), "{err}");
}

/// The connection configuration carries the deadline and the required outer suite, so that
/// the client itself enforces them (finding A10-9, defense in depth).
#[test]
fn client_config_carries_deadline_and_required_suite() {
    let base = std::path::Path::new("/etc/tcn");
    let agent = Identity::generate().unwrap().public_key();
    let text = format!(
        "connect_deadline_secs = 9\nrequire_outer_suite = \"{}\"\nkey = \"client.key\"\n\
         [[relays]]\naddress = \"r1.example.org:7443\"\npublic_key = \"{}\"\nsuite = \"{}\"\n\
         [[nodes]]\nnode = \"web-01\"\npublic_key = \"{agent}\"\n",
        HFS.protocol_name(),
        Identity::generate().unwrap().public_key(),
        HFS.protocol_name(),
    );
    let settings = zt_net::config::parse_client_settings("client.toml", base, &text).unwrap();
    assert_eq!(settings.require_outer_suite, Some(HFS));
    let config = settings
        .client_config(
            &failover_harness::node("web-01"),
            zt_net::Timeouts::default(),
        )
        .unwrap();
    assert_eq!(config.failover.deadline, Duration::from_secs(9));
    assert_eq!(config.failover.stagger, Duration::from_secs(2));
    assert_eq!(config.require_outer_suite, Some(HFS));
}

/// Runs one client of `fleet` against relays of `kinds`; `setup` runs inside the simulation
/// before the client connects (one second after the start, the agent registered).
fn one_client(
    fleet: Fleet,
    kinds: Vec<RelayKind>,
    setup: impl Fn() + 'static,
) -> (Fleet, Outcome, std::net::IpAddr) {
    let mut sim = sim(60, 3);
    for (i, kind) in kinds.into_iter().enumerate() {
        fleet.relay_host(&mut sim, i, kind);
    }
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    let agent_ip = Arc::new(Mutex::new(None));
    let agent_seen = Arc::clone(&agent_ip);
    sim.client("client", async move {
        *agent_seen.lock().unwrap() = Some(turmoil::lookup("agent"));
        tokio::time::sleep(Duration::from_secs(1)).await;
        setup();
        *seen.lock().unwrap() = Some(echo(&secret, config).await);
        Ok(())
    });
    sim.run().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    let agent_ip = agent_ip.lock().unwrap().unwrap();
    (fleet, outcome, agent_ip)
}

/// A healthy first relay: the session goes through it and the second relay never sees the
/// client (no hedge).
#[test]
fn a_healthy_first_relay_is_used_alone() {
    let fleet = Fleet::new(2, 1);
    let kinds = vec![
        RelayKind::Real(Box::new(fleet.open_policy())),
        RelayKind::Real(Box::new(fleet.open_policy())),
    ];
    let (fleet, outcome, agent_ip) = one_client(fleet, kinds, || {});
    let Outcome::Echoed(at) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(at < Duration::from_secs(1), "{at:?}");
    assert_eq!(fleet.client_arrivals(0, agent_ip).len(), 1);
    assert!(fleet.client_arrivals(1, agent_ip).is_empty());
}

/// R4-F1: a black-holed first relay (SYNs vanish) costs the stagger: relay 2 is dialed after
/// 2 s (plus at most 0.5 s of jitter) and the session is up right after, far below the 35 s of
/// the sequential failover before R-4.
#[test]
fn a_black_holed_first_relay_costs_only_the_stagger() {
    let fleet = Fleet::new(2, 1);
    let kinds = vec![
        RelayKind::Real(Box::new(fleet.open_policy())),
        RelayKind::Real(Box::new(fleet.open_policy())),
    ];
    let (fleet, outcome, agent_ip) = one_client(fleet, kinds, || turmoil::hold("client", "relay1"));
    let Outcome::Echoed(at) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        at >= Duration::from_secs(2) && at < Duration::from_millis(2_600),
        "{at:?}"
    );
    let second = fleet.client_arrivals(1, agent_ip);
    assert_eq!(second.len(), 1, "{second:?}");
}

/// A relay that accepts TCP and never completes the outer handshake is hedged the same way.
#[test]
fn a_slow_handshake_relay_is_hedged() {
    let fleet = Fleet::new(2, 1);
    let kinds = vec![
        RelayKind::Silent,
        RelayKind::Real(Box::new(fleet.open_policy())),
    ];
    let (fleet, outcome, agent_ip) = one_client(fleet, kinds, || {});
    let Outcome::Echoed(at) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        at >= Duration::from_secs(2) && at < Duration::from_millis(2_600),
        "{at:?}"
    );
    assert_eq!(fleet.client_arrivals(0, agent_ip).len(), 1);
    assert_eq!(fleet.client_arrivals(1, agent_ip).len(), 1);
}
