//! End-to-end hot revocation (Phase 4): relay and agent apply a new policy to sessions that
//! are already open, without restart.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use zt_crypto::Identity;
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, CloseReason, NodeId};
use zt_net::agent::{self, AgentConfig};
use zt_net::client::{self, ClientConfig};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{NetError, Revocable, Timeouts, Updater};

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

fn fast() -> Timeouts {
    Timeouts {
        handshake: Duration::from_secs(2),
        idle: Duration::from_secs(10),
        write: Duration::from_secs(5),
        open: Duration::from_secs(3),
        ssh_connect: Duration::from_secs(2),
        keepalive: Duration::from_secs(3),
    }
}

async fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

struct Lab {
    relay: SocketAddr,
    relay_id: Identity,
    agent_id: Arc<Identity>,
    ansible: Arc<Identity>,
    admin: Arc<Identity>,
    policy: Updater<AccessPolicy>,
    clients: Updater<zt_domain::AuthorizedClients>,
}

fn policy_for(agent: &Identity, clients: &[(&Identity, &str, Option<&[&str]>)]) -> AccessPolicy {
    let mut p = AccessPolicy::new();
    p.add_agent(agent.fingerprint(), node("web-01")).unwrap();
    for (id, name, allow) in clients {
        let allowed = match allow {
            None => AllowedNodes::All,
            Some(list) => AllowedNodes::Only(list.iter().map(|n| node(n)).collect()),
        };
        p.add_client(
            id.fingerprint(),
            ClientGrant {
                name: node(name),
                allowed,
            },
        )
        .unwrap();
    }
    p
}

impl Lab {
    async fn start() -> Self {
        let relay_id = Identity::generate().unwrap();
        let agent_id = Arc::new(Identity::generate().unwrap());
        let ansible = Arc::new(Identity::generate().unwrap());
        let admin = Arc::new(Identity::generate().unwrap());
        let (policy_rx, policy) = Revocable::new(policy_for(
            &agent_id,
            &[
                (&ansible, "ansible", Some(&["web-01"])),
                (&admin, "admin", None),
            ],
        ));
        let server = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_hex(&relay_id.to_secret_hex()).unwrap(),
            policy_rx,
            RelayConfig {
                timeouts: fast(),
                ..RelayConfig::default()
            },
        )
        .await
        .unwrap();
        let relay = server.local_addr().unwrap();
        tokio::spawn(server.run());
        let (clients_rx, clients) = Revocable::new(
            [ansible.fingerprint(), admin.fingerprint()]
                .into_iter()
                .collect::<zt_domain::AuthorizedClients>(),
        );
        let config = AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: relay.to_string(),
                public_key: relay_id.public_key(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            ssh_target: echo().await.to_string(),
            authorized_clients: clients_rx,
            timeouts: fast(),
            max_streams: 16,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
            reconnect: zt_application::reconnect::ReconnectConfig::default(),
        };
        tokio::spawn(agent::run(
            Arc::new(zt_crypto::Keyring::single(
                zt_crypto::Identity::from_secret_hex(&agent_id.to_secret_hex()).unwrap(),
            )),
            config,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        Self {
            relay,
            relay_id,
            agent_id,
            ansible,
            admin,
            policy,
            clients,
        }
    }

    fn config(&self) -> ClientConfig {
        ClientConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: self.relay.to_string(),
                public_key: self.relay_id.public_key(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            node_key: self.agent_id.public_key(),
            node_suite: zt_domain::HandshakeSuite::NoiseIk25519,
            certificate: None,
            timeouts: fast(),
        }
    }

    /// Opens a session and checks that the echo works.
    async fn session(
        &self,
        who: &Arc<Identity>,
    ) -> (DuplexStream, JoinHandle<Result<(), NetError>>) {
        let (mut app, local) = tokio::io::duplex(64 * 1024);
        let (who, config) = (Arc::clone(who), self.config());
        let task = tokio::spawn(async move { client::connect(&who, &config, local).await });
        assert_alive(&mut app).await;
        (app, task)
    }
}

async fn assert_alive(app: &mut DuplexStream) {
    app.write_all(b"ping").await.unwrap();
    let mut buf = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut buf))
        .await
        .expect("session not answering")
        .unwrap();
    assert_eq!(&buf, b"ping");
}

async fn ended(task: JoinHandle<Result<(), NetError>>) -> Result<(), NetError> {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("revoked session still running")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_revocation_cuts_live_sessions_and_blocks_reconnection() {
    let lab = Lab::start().await;
    let (_app, revoked) = lab.session(&lab.ansible).await;
    let (mut other, survivor) = lab.session(&lab.admin).await;

    lab.policy
        .replace(policy_for(&lab.agent_id, &[(&lab.admin, "admin", None)]));
    assert!(ended(revoked).await.is_err());
    assert_alive(&mut other).await;
    assert!(!survivor.is_finished());

    let (_app, local) = tokio::io::duplex(1024);
    let again = tokio::time::timeout(
        Duration::from_secs(5),
        client::connect(&lab.ansible, &lab.config(), local),
    )
    .await
    .expect("reconnect attempt hung");
    assert!(again.is_err(), "a revoked key reconnected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_grant_narrowing_closes_the_stream_as_unauthorized() {
    let lab = Lab::start().await;
    let (_app, task) = lab.session(&lab.ansible).await;
    lab.policy.replace(policy_for(
        &lab.agent_id,
        &[
            (&lab.ansible, "ansible", Some(&[])),
            (&lab.admin, "admin", None),
        ],
    ));
    assert!(matches!(
        ended(task).await,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_revocation_cuts_the_session_even_if_the_relay_still_allows_it() {
    // Defense in depth: the agent does not wait for the relay (which might be compromised).
    let lab = Lab::start().await;
    let (_app, revoked) = lab.session(&lab.ansible).await;
    let (mut other, _survivor) = lab.session(&lab.admin).await;
    lab.clients.replace(
        [lab.admin.fingerprint()]
            .into_iter()
            .collect::<zt_domain::AuthorizedClients>(),
    );
    assert!(matches!(
        ended(revoked).await,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
    assert_alive(&mut other).await;
    // A new session of the revoked client is rejected by the agent.
    let (_app, local) = tokio::io::duplex(1024);
    let again = tokio::time::timeout(
        Duration::from_secs(5),
        client::connect(&lab.ansible, &lab.config(), local),
    )
    .await
    .expect("hung");
    assert!(matches!(
        again,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fixed_policy_never_changes() {
    let fixed: Revocable<u32> = Revocable::fixed(7);
    assert_eq!(*fixed.current(), 7);
    let mut f = fixed.clone();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), f.changed())
            .await
            .is_err(),
        "a fixed value must never report a change"
    );
}
