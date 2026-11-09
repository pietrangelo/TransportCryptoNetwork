//! A two-relay fleet on the `turmoil` simulator for the R-4 failover tests: real relays, a real
//! agent registered with both, an echoing "sshd" on the agent host, and simulated clients.
//! Latencies are fixed (1 ms per message) so that the timings asserted are those of the
//! failover plan, not of the network.
#![allow(dead_code, unreachable_pub)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zt_crypto::{Identity, Keyring, PublicKey};
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, HandshakeSuite, NodeId};
use zt_net::client::{self, ClientConfig};
use zt_net::net::{Acceptor, Dialer};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{NetError, RelayEndpoint, Revocable, Timeouts};

pub const PORT: u16 = 7443;

pub fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

/// The simulated network as a `Dialer`.
#[derive(Clone, Copy)]
pub struct SimDialer;

impl Dialer for SimDialer {
    type Stream = turmoil::net::TcpStream;

    async fn connect(&self, addr: &str) -> std::io::Result<Self::Stream> {
        turmoil::net::TcpStream::connect(addr.to_owned()).await
    }
}

/// When and from where each connection reached a relay.
pub type Arrivals = Arc<Mutex<Vec<(Duration, IpAddr)>>>;

struct SimAcceptor {
    listener: turmoil::net::TcpListener,
    arrivals: Arrivals,
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

/// A simulation with fixed 1 ms latencies.
pub fn sim<'a>(seconds: u64, seed: u64) -> turmoil::Sim<'a> {
    turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(seconds))
        .tick_duration(Duration::from_millis(1))
        .min_message_latency(Duration::from_millis(1))
        .max_message_latency(Duration::from_millis(1))
        .rng_seed(seed)
        .build()
}

/// What a relay host runs.
#[derive(Clone)]
pub enum RelayKind {
    /// The real relay with this policy.
    Real(AccessPolicy),
    /// Accepts TCP and never answers: a relay whose handshake never completes.
    Silent,
}

/// The fleet: relay keys, agent, client identities, counters.
pub struct Fleet {
    pub relays: Vec<(String, Identity)>,
    pub agent: Identity,
    pub clients: Vec<Identity>,
    pub arrivals: Vec<Arrivals>,
    /// Connections the agent opened to "sshd": one per completed end-to-end handshake.
    pub sshd_accepts: Arc<AtomicUsize>,
}

impl Fleet {
    /// `relays` relay identities named `relay1`, `relay2`..., one agent for `web-01` and
    /// `clients` clients allowed everywhere.
    pub fn new(relays: usize, clients: usize) -> Self {
        Self {
            relays: (1..=relays)
                .map(|i| (format!("relay{i}"), Identity::generate().unwrap()))
                .collect(),
            agent: Identity::generate().unwrap(),
            clients: (0..clients)
                .map(|_| Identity::generate().unwrap())
                .collect(),
            arrivals: (0..relays).map(|_| Arc::default()).collect(),
            sshd_accepts: Arc::default(),
        }
    }

    /// The policy that registers the agent and lets every client reach every node.
    pub fn open_policy(&self) -> AccessPolicy {
        self.policy_for(AllowedNodes::All)
    }

    /// The policy with every client allowed `allowed`.
    pub fn policy_for(&self, allowed: AllowedNodes) -> AccessPolicy {
        let mut policy = AccessPolicy::new();
        policy
            .add_agent(self.agent.fingerprint(), node("web-01"))
            .unwrap();
        for (i, c) in self.clients.iter().enumerate() {
            policy
                .add_client(
                    c.fingerprint(),
                    ClientGrant {
                        name: node(&format!("client-{i}")),
                        allowed: allowed.clone(),
                    },
                )
                .unwrap();
        }
        policy
    }

    pub fn endpoints(&self) -> Vec<RelayEndpoint> {
        self.relays
            .iter()
            .map(|(name, id)| RelayEndpoint {
                address: format!("{name}:{PORT}"),
                public_key: id.public_key(),
                suite: HandshakeSuite::NoiseIk25519,
            })
            .collect()
    }

    /// Starts relay `index` (0-based) as `kind`.
    pub fn relay_host(&self, sim: &mut turmoil::Sim<'_>, index: usize, kind: RelayKind) {
        let (name, id) = &self.relays[index];
        let secret = id.to_secret_hex().to_string();
        let arrivals = Arc::clone(&self.arrivals[index]);
        sim.host(name.as_str(), move || {
            let secret = secret.clone();
            let kind = kind.clone();
            let arrivals = Arc::clone(&arrivals);
            async move {
                let listener = turmoil::net::TcpListener::bind(("0.0.0.0", PORT)).await?;
                let mut acceptor = SimAcceptor { listener, arrivals };
                match kind {
                    RelayKind::Real(policy) => {
                        let keys = Identity::from_secret_hex(&secret).unwrap();
                        let (policy, _updater) = Revocable::new(policy);
                        let server = RelayServer::with_acceptor(
                            acceptor,
                            keys,
                            policy,
                            RelayConfig::default(),
                        )
                        .unwrap();
                        server.run().await.unwrap();
                    }
                    RelayKind::Silent => {
                        let mut held = Vec::new();
                        loop {
                            let (s, _) = acceptor.accept().await?;
                            held.push(s);
                        }
                    }
                }
                Ok(())
            }
        });
    }

    /// Starts the agent of `web-01`, registered with every relay, with `max_streams` per relay
    /// and an echoing "sshd" on port 22 of its host.
    pub fn agent_host(&self, sim: &mut turmoil::Sim<'_>, max_streams: usize) {
        let secret = self.agent.to_secret_hex().to_string();
        let relays = self.endpoints();
        let clients: zt_domain::AuthorizedClients =
            self.clients.iter().map(Identity::fingerprint).collect();
        let accepts = Arc::clone(&self.sshd_accepts);
        sim.host("agent", move || {
            let secret = secret.clone();
            let relays = relays.clone();
            let clients = clients.clone();
            let accepts = Arc::clone(&accepts);
            async move {
                tokio::spawn(async move {
                    let sshd = turmoil::net::TcpListener::bind(("0.0.0.0", 22))
                        .await
                        .unwrap();
                    loop {
                        let (mut s, _) = sshd.accept().await.unwrap();
                        accepts.fetch_add(1, Ordering::SeqCst);
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
                    relays,
                    node: node("web-01"),
                    ssh_target: "127.0.0.1:22".into(),
                    authorized_clients: clients,
                    timeouts: Timeouts::default(),
                    max_streams,
                    client_suites: zt_domain::AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
                    identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
                    reconnect: zt_application::reconnect::ReconnectConfig::default(),
                };
                zt_net::agent::run_with(keys, config, SimDialer).await;
                Ok(())
            }
        });
    }

    /// The configuration of client `index` towards `web-01`, with the production defaults.
    pub fn client_config(&self) -> ClientConfig {
        ClientConfig {
            relays: self.endpoints(),
            node: node("web-01"),
            node_key: self.agent.public_key(),
            node_suite: HandshakeSuite::NoiseIk25519,
            certificate: None,
            timeouts: Timeouts::default(),
            failover: zt_application::failover::FailoverConfig::default(),
            require_outer_suite: None,
        }
    }

    pub fn client_secret(&self, index: usize) -> String {
        self.clients[index].to_secret_hex().to_string()
    }

    /// Client connections that reached relay `index` (0-based), by simulated time.
    pub fn client_arrivals(&self, index: usize, agent_ip: IpAddr) -> Vec<Duration> {
        self.arrivals[index]
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, ip)| *ip != agent_ip)
            .map(|(t, _)| *t)
            .collect()
    }
}

/// How a session attempt ended for a simulated client.
#[derive(Debug)]
pub enum Outcome {
    /// Bytes echoed back after this long (from the call to `connect_with`).
    Echoed(Duration),
    /// `connect_with` returned this error after this long.
    Failed(Duration, NetError),
}

/// Connects with `config`, sends "ping" and waits for the echo; the session is then dropped.
pub async fn echo(secret: &str, config: ClientConfig) -> Outcome {
    let identity = Identity::from_secret_hex(secret).unwrap();
    let started = tokio::time::Instant::now();
    let (mut app, local) = tokio::io::duplex(1024);
    let mut task =
        tokio::spawn(
            async move { client::connect_with(&identity, &config, local, SimDialer).await },
        );
    app.write_all(b"ping").await.unwrap();
    let mut buf = [0_u8; 4];
    tokio::select! {
        read = app.read_exact(&mut buf) => {
            if read.is_ok() && &buf == b"ping" {
                let at = started.elapsed();
                task.abort();
                return Outcome::Echoed(at);
            }
            match (&mut task).await {
                Ok(Err(e)) => Outcome::Failed(started.elapsed(), e),
                other => panic!("session ended without echo: {other:?}"),
            }
        }
        done = &mut task => match done.unwrap() {
            Err(e) => Outcome::Failed(started.elapsed(), e),
            Ok(()) => panic!("session ended without echo"),
        },
    }
}
