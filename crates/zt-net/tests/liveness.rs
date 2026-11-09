//! R-2 on real sockets: the agent's keepalive and dead-peer detection, the relay's idle
//! timeout per role, `TCP_USER_TIMEOUT` and TCP keepalive on every socket, and the duplicate
//! agent report (resilience.md §5.2; catalogue R2-L3, R2-L6, R2-L7).
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{Captured, agent_clients, copy_of, field, relay_policy, start_relay_with};
use tokio::net::TcpListener;
use zt_crypto::noise::Channel;
use zt_crypto::{Identity, Keyring};
use zt_domain::{AcceptedSuites, HandshakeSuite};
use zt_net::net::{Dialer, TcpDialer};
use zt_net::relay::RelayConfig;
use zt_net::{RelayEndpoint, Revocable, Timeouts};

fn agent_config(relay: RelayEndpoint, timeouts: Timeouts) -> zt_net::agent::AgentConfig {
    let (clients, _updater) =
        Revocable::new(agent_clients(&[], zt_domain::trust::CertTrust::new()));
    zt_net::agent::AgentConfig {
        relays: vec![relay],
        node: common::node("web-01"),
        ssh_target: "127.0.0.1:9".into(),
        authorized_clients: clients,
        timeouts,
        max_streams: 4,
        client_suites: AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
        identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        reconnect: zt_application::reconnect::ReconnectConfig::default(),
    }
}

#[test]
fn the_default_keepalive_is_ten_seconds() {
    // The agent pings every 10 s and gives up after three silent intervals; the relay's
    // `Ping` limit (one per 5 s after a burst of 10) leaves room for it.
    assert_eq!(Timeouts::default().keepalive, Duration::from_secs(10));
    assert_eq!(zt_net::agent::KEEPALIVE_MISSES, 3);
}

/// R2-L3: a relay with the new defaults keeps an old agent that pings every 30 s: the default
/// agent idle stays at three times that until the fleet is upgraded.
#[test]
fn old_agents_survive_the_default_relay_idle() {
    let config = RelayConfig::default();
    assert!(
        config
            .agent_idle
            .is_none_or(|d| d >= Duration::from_secs(90))
    );
    assert!(config.timeouts.idle >= Duration::from_secs(90));
    let settings = zt_net::config::RelaySettings::default();
    assert_eq!(settings.agent_idle, Duration::from_secs(90));
    assert_eq!(settings.client_idle, Duration::from_secs(90));
}

#[test]
fn the_relay_idle_is_configured_per_role() {
    let s = zt_net::config::parse_relay_settings(
        "relay.toml",
        "[liveness]\nagent_idle_secs = 35\nclient_idle_secs = 120\n",
    )
    .unwrap();
    assert_eq!(s.agent_idle, Duration::from_secs(35));
    assert_eq!(s.client_idle, Duration::from_secs(120));
    for bad in [
        "[liveness]\nagent_idle_secs = 0",
        "[liveness]\nagent_idle_secs = 10",
        "[liveness]\nclient_idle_secs = 100000",
        "[liveness]\nbogus = 1",
    ] {
        assert!(
            zt_net::config::parse_relay_settings("relay.toml", bad).is_err(),
            "{bad}"
        );
    }
}

/// R2-L7: a relay that completes the handshake and then never sends anything (not even a
/// `Pong`) is declared dead after three keepalive intervals, and the agent reconnects.
#[tokio::test]
async fn unanswered_pings_end_the_session() {
    let relay = Identity::generate().unwrap();
    let keys = Keyring::single(copy_of(&relay));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sessions = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&sessions);
    tokio::spawn(async move {
        let keys = Arc::new(keys);
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let keys = Arc::clone(&keys);
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let t = common::timeouts();
                let pending = zt_net::channel::accept(tcp, &keys, Channel::Outer, &t)
                    .await
                    .unwrap();
                let mut ch = pending.establish(&t).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                // Reads everything, answers nothing.
                while let Ok(Some(_)) = ch.recv().await {}
            });
        }
    });
    let timeouts = Timeouts {
        keepalive: Duration::from_millis(500),
        idle: Duration::from_secs(600),
        ..common::timeouts()
    };
    let agent = Arc::new(Keyring::single(Identity::generate().unwrap()));
    let task = tokio::spawn(zt_net::agent::run(
        agent,
        agent_config(
            RelayEndpoint {
                address: addr.to_string(),
                public_key: relay.public_key(),
                suite: HandshakeSuite::NoiseIk25519,
            },
            timeouts,
        ),
    ));
    // 3 × 0.5 s of silence, then a reconnect within the first backoff (at most 1 s).
    tokio::time::sleep(Duration::from_secs(4)).await;
    task.abort();
    let n = sessions.load(Ordering::SeqCst);
    assert!(n >= 2, "the agent kept a silent relay link: {n} session(s)");
}

/// `TCP_USER_TIMEOUT` (20 s) and TCP keepalive on dialed sockets: a peer that stops
/// acknowledging is noticed by the kernel faster than by any application timer.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn dialed_sockets_have_user_timeout_and_keepalive() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpDialer.connect(&addr.to_string()).await.unwrap();
    assert_eq!(
        rustix::net::sockopt::tcp_user_timeout(&stream).unwrap(),
        u32::try_from(zt_net::net::TCP_USER_TIMEOUT.as_millis()).unwrap()
    );
    assert!(rustix::net::sockopt::socket_keepalive(&stream).unwrap());
    assert!(stream.nodelay().unwrap());
    // The relay applies the same to accepted sockets, through its `Acceptor` (finding A10-6:
    // not by calling `configure` by hand).
    let mut listener = listener;
    let (accepted, _) = zt_net::net::Acceptor::accept(&mut listener).await.unwrap();
    assert!(rustix::net::sockopt::socket_keepalive(&accepted).unwrap());
    assert_eq!(
        rustix::net::sockopt::tcp_user_timeout(&accepted).unwrap(),
        u32::try_from(zt_net::net::TCP_USER_TIMEOUT.as_millis()).unwrap()
    );
}

/// R2-L6 on the wire: two agents with the same key take the node from each other; the relay
/// writes `agent_flapping` and keeps registering them.
#[tokio::test]
async fn duplicate_agents_are_reported_by_the_relay() {
    let log = Captured::default();
    let _guard = log.install();
    let agent = Arc::new(Identity::generate().unwrap());
    let policy = relay_policy(
        &agent.fingerprint(),
        &[],
        zt_domain::trust::CertTrust::new(),
    );
    let relay = start_relay_with(policy, common::relay_config()).await;
    for _ in 0..4 {
        let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
        let mut ch =
            zt_net::channel::connect(tcp, &agent, &relay.key, Channel::Outer, &common::timeouts())
                .await
                .unwrap();
        ch.send(
            &zt_domain::Frame::Register {
                node: common::node("web-01"),
            },
            &common::timeouts(),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::mem::forget(ch);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(log.events("agent_registered").len(), 4, "{}", log.text());
    let flapping = log.events("agent_flapping");
    assert_eq!(flapping.len(), 1, "{}", log.text());
    assert_eq!(field(&flapping[0], "node").as_deref(), Some("web-01"));
    assert_eq!(
        field(&flapping[0], "peer"),
        Some(agent.fingerprint().to_string())
    );
}
