//! R-2: deterministic network simulation with `turmoil` (resilience.md §5.7, D-9) behind the
//! network port of `zt_net::net` (`Dialer`, `Acceptor`). The real relay, agent and client run
//! on simulated hosts, with simulated time; the network is cut, partitioned and restarted at
//! will.
//!
//! Scenarios: a relay restart with many agents (R2-L1: reconnects are spread, not waves) and a
//! half-open agent link (R2-L2: both sides detect it, the relay stops routing to the dead agent,
//! the agent comes back after the repair).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zt_crypto::{Identity, Keyring, PublicKey};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthorizedClients, ClientGrant, HandshakeSuite, NodeId,
    RejectReason,
};
use zt_net::client::{self, ClientConfig};
use zt_net::net::{Acceptor, Dialer};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{NetError, RelayEndpoint, Revocable, Timeouts};

const RELAY_PORT: u16 = 7443;

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

/// The simulated network as a `Dialer`.
#[derive(Clone, Copy)]
struct SimDialer;

impl Dialer for SimDialer {
    type Stream = turmoil::net::TcpStream;

    async fn connect(&self, addr: &str) -> std::io::Result<Self::Stream> {
        turmoil::net::TcpStream::connect(addr.to_owned()).await
    }
}

/// A simulated listener that records the simulated time of every accepted connection.
struct SimAcceptor {
    listener: turmoil::net::TcpListener,
    arrivals: Arc<Mutex<Vec<(Duration, std::net::IpAddr)>>>,
}

impl Acceptor for SimAcceptor {
    type Stream = turmoil::net::TcpStream;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        let now = turmoil::sim_elapsed().unwrap_or_default();
        self.arrivals.lock().unwrap().push((now, addr.ip()));
        Ok((stream, addr))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

/// Production timeouts: the simulation runs the real defaults.
fn timeouts() -> Timeouts {
    Timeouts::default()
}

/// A relay host: the same key and policy after every restart.
fn relay_host(
    sim: &mut turmoil::Sim<'_>,
    secret: String,
    policy: AccessPolicy,
    config: RelayConfig,
    arrivals: Arc<Mutex<Vec<(Duration, std::net::IpAddr)>>>,
) {
    sim.host("relay", move || {
        let secret = secret.clone();
        let policy = policy.clone();
        let config = config.clone();
        let arrivals = Arc::clone(&arrivals);
        async move {
            let listener = turmoil::net::TcpListener::bind(("0.0.0.0", RELAY_PORT)).await?;
            let acceptor = SimAcceptor { listener, arrivals };
            let keys = Identity::from_secret_hex(&secret).unwrap();
            let (policy, _updater) = Revocable::new(policy);
            let server = RelayServer::with_acceptor(acceptor, keys, policy, config).unwrap();
            server.run().await.unwrap();
            Ok(())
        }
    });
}

/// An agent host for `name`, with an echoing "sshd" on port 22 of the same host.
fn agent_host(
    sim: &mut turmoil::Sim<'_>,
    host: &str,
    name: &str,
    secret: String,
    relay_key: PublicKey,
    clients: AuthorizedClients,
) {
    let name = name.to_owned();
    sim.host(host, move || {
        let secret = secret.clone();
        let name = name.clone();
        let clients = clients.clone();
        async move {
            tokio::spawn(async {
                let sshd = turmoil::net::TcpListener::bind(("0.0.0.0", 22))
                    .await
                    .unwrap();
                loop {
                    let (mut s, _) = sshd.accept().await.unwrap();
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 1024];
                        while let Ok(n) = s.read(&mut buf).await {
                            if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            let keys = Arc::new(Keyring::single(Identity::from_secret_hex(&secret).unwrap()));
            let (clients, _updater) = Revocable::new(clients);
            let config = zt_net::agent::AgentConfig {
                relays: vec![RelayEndpoint {
                    address: format!("relay:{RELAY_PORT}"),
                    public_key: relay_key,
                    suite: HandshakeSuite::NoiseIk25519,
                }],
                node: node(&name),
                ssh_target: "127.0.0.1:22".into(),
                authorized_clients: clients,
                timeouts: timeouts(),
                max_streams: 16,
                client_suites: zt_domain::AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
                identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
                reconnect: zt_application::reconnect::ReconnectConfig::default(),
            };
            zt_net::agent::run_with(keys, config, SimDialer).await;
            Ok(())
        }
    });
}

/// R2-L1: after a relay restart the agents' reconnects arrive spread over the spread window
/// (10 s by default), not in waves: no second of the window gets more than 30 % of them.
#[test]
fn reconnects_are_spread_after_a_relay_restart() {
    const AGENTS: usize = 40;
    let mut sim = turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(120))
        .rng_seed(7)
        .build();
    let relay = Identity::generate().unwrap();
    let relay_key = relay.public_key();
    let mut policy = AccessPolicy::new();
    let mut secrets = Vec::new();
    for i in 0..AGENTS {
        let agent = Identity::generate().unwrap();
        policy
            .add_agent(agent.fingerprint(), node(&format!("node-{i}")))
            .unwrap();
        secrets.push(agent.to_secret_hex().to_string());
    }
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    relay_host(
        &mut sim,
        relay.to_secret_hex().to_string(),
        policy,
        RelayConfig::default(),
        Arc::clone(&arrivals),
    );
    for (i, secret) in secrets.into_iter().enumerate() {
        agent_host(
            &mut sim,
            &format!("agent-{i}"),
            &format!("node-{i}"),
            secret,
            relay_key,
            std::iter::empty().collect(),
        );
    }
    let restart = Duration::from_secs(40);
    while sim.elapsed() < restart {
        sim.step().unwrap();
    }
    assert_eq!(
        arrivals.lock().unwrap().len(),
        AGENTS,
        "every agent connected once before the restart"
    );
    arrivals.lock().unwrap().clear();
    sim.bounce("relay");
    while sim.elapsed() < restart + Duration::from_secs(30) {
        sim.step().unwrap();
    }
    let after: Vec<Duration> = arrivals
        .lock()
        .unwrap()
        .iter()
        .map(|(t, _)| t.saturating_sub(restart))
        .collect();
    assert_eq!(after.len(), AGENTS, "every agent came back once: {after:?}");
    let mut per_second = [0_usize; 30];
    for t in &after {
        assert!(
            *t <= Duration::from_secs(12),
            "a reconnect after the spread window: {t:?}"
        );
        per_second[t.as_secs() as usize] += 1;
    }
    let wave = per_second.iter().max().copied().unwrap_or(0);
    assert!(
        wave * 10 <= AGENTS * 3,
        "a wave of {wave} reconnects in one second: {per_second:?}"
    );
}

/// R2-L2: a silent partition between agent and relay (no FIN, no RST). The agent declares the
/// link dead after three unanswered keepalives, the relay drops the stale registration after
/// its agent idle timeout (so a client gets `NodeOffline` at once instead of waiting for an
/// `OpenAck` that never comes), and after the repair the agent registers again.
#[test]
fn half_open_agent_link_is_detected() {
    let mut sim = turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(300))
        .rng_seed(11)
        .build();
    let relay = Identity::generate().unwrap();
    let relay_key = relay.public_key();
    let agent = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let alice_secret = alice.to_secret_hex().to_string();
    let agent_key = agent.public_key();
    let mut policy = AccessPolicy::new();
    policy
        .add_agent(agent.fingerprint(), node("web-01"))
        .unwrap();
    policy
        .add_client(
            alice.fingerprint(),
            ClientGrant {
                name: node("alice"),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
    let config = RelayConfig {
        agent_idle: Some(Duration::from_secs(35)),
        ..RelayConfig::default()
    };
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    relay_host(
        &mut sim,
        relay.to_secret_hex().to_string(),
        policy,
        config,
        Arc::clone(&arrivals),
    );
    agent_host(
        &mut sim,
        "agent",
        "web-01",
        agent.to_secret_hex().to_string(),
        relay_key,
        [alice.fingerprint()].into_iter().collect(),
    );
    sim.client("alice", async move {
        let alice = Identity::from_secret_hex(&alice_secret).unwrap();
        let config = ClientConfig {
            relays: vec![RelayEndpoint {
                address: format!("relay:{RELAY_PORT}"),
                public_key: relay_key,
                suite: HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            node_key: agent_key,
            node_suite: HandshakeSuite::NoiseIk25519,
            certificate: None,
            timeouts: timeouts(),
        };
        let echo = |config: ClientConfig, alice: Identity| async move {
            let (mut app, local) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move {
                client::connect_with(&alice, &config, local, SimDialer).await
            });
            app.write_all(b"ping").await.unwrap();
            let mut buf = [0_u8; 4];
            let echoed = tokio::time::timeout(Duration::from_secs(10), app.read_exact(&mut buf))
                .await
                .is_ok_and(|r| r.is_ok())
                && &buf == b"ping";
            if echoed {
                task.abort();
                Ok(())
            } else {
                Err(tokio::time::timeout(Duration::from_secs(30), task).await)
            }
        };
        tokio::time::sleep(Duration::from_secs(5)).await;
        let copy = || Identity::from_secret_hex(&alice.to_secret_hex()).unwrap();
        echo(config.clone(), copy())
            .await
            .unwrap_or_else(|e| panic!("no session before the partition: {e:?}"));
        turmoil::partition("agent", "relay");
        // 37 s later both sides have given up on the link: the relay answers at once.
        tokio::time::sleep(Duration::from_secs(37)).await;
        let started = tokio::time::Instant::now();
        let (_app, local) = tokio::io::duplex(1024);
        let outcome = client::connect_with(&copy(), &config, local, SimDialer).await;
        assert!(
            matches!(outcome, Err(NetError::Rejected(RejectReason::NodeOffline))),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        turmoil::repair("agent", "relay");
        // Agent backoff is capped at 30 s, plus the connect timeout of an attempt that was
        // already under way during the partition.
        tokio::time::sleep(Duration::from_secs(45)).await;
        echo(config.clone(), copy())
            .await
            .unwrap_or_else(|e| panic!("no session after the repair: {e:?}"));
        Ok(())
    });
    sim.run().unwrap();
    let agent_arrivals = arrivals.lock().unwrap().len();
    assert!(agent_arrivals >= 2, "the agent did not reconnect");
}
