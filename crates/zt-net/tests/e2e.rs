//! End-to-end and attack tests over real TCP: relay, agent and client in the same process,
//! a fake SSH daemon (echo) on localhost.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zt_crypto::Identity;
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, CloseReason, NodeId, RejectReason};
use zt_net::agent::{self, AgentConfig};
use zt_net::client::{self, ClientConfig};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{NetError, Timeouts};

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

fn fast_timeouts() -> Timeouts {
    Timeouts {
        handshake: Duration::from_secs(2),
        idle: Duration::from_secs(10),
        write: Duration::from_secs(5),
        open: Duration::from_secs(3),
        ssh_connect: Duration::from_secs(2),
        keepalive: Duration::from_secs(3),
    }
}

/// Fake sshd: sends back whatever it receives.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

struct Fleet {
    relay: SocketAddr,
    relay_id: Arc<Identity>,
    agent_id: Arc<Identity>,
    ansible: Identity,
    admin: Identity,
    stranger: Identity,
}

impl Fleet {
    async fn start(config: RelayConfig) -> Self {
        let relay_id = Arc::new(Identity::generate().unwrap());
        let agent_id = Arc::new(Identity::generate().unwrap());
        let db_agent = Identity::generate().unwrap();
        let ansible = Identity::generate().unwrap();
        let admin = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();

        let mut policy = AccessPolicy::new();
        policy
            .add_agent(agent_id.fingerprint(), node("web-01"))
            .unwrap();
        policy
            .add_agent(db_agent.fingerprint(), node("db-01"))
            .unwrap();
        policy
            .add_client(
                ansible.fingerprint(),
                ClientGrant {
                    name: node("ansible"),
                    allowed: AllowedNodes::Only([node("web-01")].into_iter().collect()),
                },
            )
            .unwrap();
        policy
            .add_client(
                admin.fingerprint(),
                ClientGrant {
                    name: node("admin"),
                    allowed: AllowedNodes::All,
                },
            )
            .unwrap();

        let secret = relay_id.to_secret_hex();
        let server = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_hex(&secret).unwrap(),
            policy,
            config,
        )
        .await
        .unwrap();
        let relay = server.local_addr().unwrap();
        tokio::spawn(server.run());
        Self {
            relay,
            relay_id,
            agent_id,
            ansible,
            admin,
            stranger,
        }
    }

    /// Starts the web-01 agent. Accepts only `ansible` end-to-end (not `admin`).
    async fn start_agent(&self) {
        let ssh = echo_server().await;
        let config = AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: self.relay.to_string(),
                public_key: self.relay_id.public_key(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: zt_net::Revocable::fixed(
                [self.ansible.fingerprint()]
                    .into_iter()
                    .collect::<zt_domain::AuthorizedClients>(),
            ),
            timeouts: fast_timeouts(),
            max_streams: 16,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
        };
        tokio::spawn(agent::run(
            Arc::new(zt_crypto::Keyring::single(
                zt_crypto::Identity::from_secret_hex(&self.agent_id.to_secret_hex()).unwrap(),
            )),
            config,
        ));
        // Waits for registration: retries while the node is reported offline.
        for _ in 0..100 {
            let (app, local) = tokio::io::duplex(1024);
            drop(app);
            match client::connect(&self.ansible, &self.client_config("web-01"), local).await {
                Err(NetError::Rejected(RejectReason::NodeOffline)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                _ => return,
            }
        }
        panic!("agent never registered");
    }

    fn client_config(&self, target: &str) -> ClientConfig {
        ClientConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: self.relay.to_string(),
                public_key: self.relay_id.public_key(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node(target),
            node_key: self.agent_id.public_key(),
            node_suite: zt_domain::HandshakeSuite::NoiseIk25519,
            certificate: None,
            timeouts: fast_timeouts(),
        }
    }
}

fn test_relay_config() -> RelayConfig {
    RelayConfig {
        timeouts: fast_timeouts(),
        ..RelayConfig::default()
    }
}

// ======================= specification =======================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_bytes_round_trip_through_the_relay() {
    let fleet = Fleet::start(test_relay_config()).await;
    fleet.start_agent().await;
    let (mut app, local) = tokio::io::duplex(64 * 1024);
    let config = fleet.client_config("web-01");
    let session =
        tokio::spawn(async move { client::connect(&fleet.ansible, &config, local).await });

    app.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
    let mut echoed = [0_u8; 21];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"SSH-2.0-OpenSSH_9.9\r\n");

    drop(app);
    let result = tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok(), "{result:?}");
}

/// Regression 0003-1: the stdout of `zt-client` is buffered; without a flush the SSH bytes
/// (which do not end at a line end) stay in the buffer and the session hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivered_bytes_are_flushed_to_a_buffered_local_writer() {
    let fleet = Fleet::start(test_relay_config()).await;
    fleet.start_agent().await;
    let (mut app, local) = tokio::io::duplex(64 * 1024);
    let local = tokio::io::BufWriter::with_capacity(8192, local);
    let config = fleet.client_config("web-01");
    let _session =
        tokio::spawn(async move { client::connect(&fleet.ansible, &config, local).await });
    app.write_all(b"no newline").await.unwrap();
    let mut echoed = [0_u8; 10];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut echoed))
        .await
        .expect("bytes stuck in the local write buffer")
        .unwrap();
    assert_eq!(&echoed, b"no newline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_transfer_is_flow_controlled_and_intact() {
    // 8 MiB: 32 times the initial window, so many WindowUpdates are needed.
    let fleet = Fleet::start(test_relay_config()).await;
    fleet.start_agent().await;
    let (app, local) = tokio::io::duplex(64 * 1024);
    let config = fleet.client_config("web-01");
    tokio::spawn(async move { client::connect(&fleet.ansible, &config, local).await });

    let data: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let (mut rd, mut wr) = tokio::io::split(app);
    let expected = data.clone();
    let writer = tokio::spawn(async move { wr.write_all(&data).await.unwrap() });
    let mut received = vec![0_u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(30), rd.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    assert!(received == expected, "payload corrupted in transit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_node_is_reported() {
    let fleet = Fleet::start(test_relay_config()).await;
    let (_app, local) = tokio::io::duplex(1024);
    let err = client::connect(&fleet.ansible, &fleet.client_config("web-01"), local)
        .await
        .unwrap_err();
    assert!(
        matches!(err, NetError::Rejected(RejectReason::NodeOffline)),
        "{err:?}"
    );
}

// ======================= attacks =======================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_client_key_gets_no_answer() {
    let fleet = Fleet::start(test_relay_config()).await;
    let (_app, local) = tokio::io::duplex(1024);
    let started = std::time::Instant::now();
    let err = client::connect(&fleet.stranger, &fleet.client_config("web-01"), local)
        .await
        .unwrap_err();
    // The relay closes without sending msg2: the client does not complete the handshake.
    assert!(matches!(err, NetError::Closed | NetError::Io(_)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "relay should drop immediately"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_detects_a_relay_impostor() {
    let fleet = Fleet::start(test_relay_config()).await;
    let mut config = fleet.client_config("web-01");
    config.relays[0].public_key = fleet.stranger.public_key();
    let (_app, local) = tokio::io::duplex(1024);
    let err = client::connect(&fleet.ansible, &config, local)
        .await
        .unwrap_err();
    assert!(
        !matches!(err, NetError::Rejected(_)),
        "must fail at the handshake: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_and_unknown_nodes_are_rejected_alike() {
    let fleet = Fleet::start(test_relay_config()).await;
    for target in ["db-01", "ghost"] {
        let (_app, local) = tokio::io::duplex(1024);
        let err = client::connect(&fleet.ansible, &fleet.client_config(target), local)
            .await
            .unwrap_err();
        assert!(
            matches!(err, NetError::Rejected(RejectReason::NotAuthorized)),
            "{target}: {err:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_enforces_its_own_client_list_even_if_the_relay_allows() {
    // `admin` has access to everything according to the relay, but the web-01 agent does not
    // know it.
    let fleet = Fleet::start(test_relay_config()).await;
    fleet.start_agent().await;
    let (_app, local) = tokio::io::duplex(1024);
    let err = client::connect(&fleet.admin, &fleet.client_config("web-01"), local)
        .await
        .unwrap_err();
    assert!(
        matches!(err, NetError::StreamClosed(CloseReason::Unauthorized)),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn garbage_on_the_wire_does_not_affect_other_peers() {
    let fleet = Fleet::start(test_relay_config()).await;
    fleet.start_agent().await;
    for junk in [
        vec![0xff, 0xff],
        vec![0x00, 0x00],
        vec![0x00, 0x60]
            .into_iter()
            .chain([0x41; 96])
            .collect::<Vec<_>>(),
    ] {
        let mut tcp = TcpStream::connect(fleet.relay).await.unwrap();
        let _ = tcp.write_all(&junk).await;
        let mut buf = [0_u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0) | Err(_))),
            "relay must hang up, got {read:?}"
        );
    }
    let (mut app, local) = tokio::io::duplex(1024);
    let config = fleet.client_config("web-01");
    tokio::spawn(async move { client::connect(&fleet.ansible, &config, local).await });
    app.write_all(b"ok").await.unwrap();
    let mut buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_connections_are_dropped_at_the_msg1_deadline() {
    // The message 1 deadline cannot go below 5 s (finding AP-20, PROTOCOL §10.1).
    let config = test_relay_config();
    assert_eq!(config.admission.msg1_deadline, Duration::from_secs(5));
    let fleet = Fleet::start(config).await;
    let mut tcp = TcpStream::connect(fleet.relay).await.unwrap();
    // Slowloris: half a length prefix and then silence.
    tcp.write_all(&[0x00]).await.unwrap();
    let mut buf = [0_u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(7), tcp.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "expected hang-up, got {read:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_floods_from_one_address_are_rate_limited() {
    let mut config = test_relay_config();
    config.admission.source_burst = 3;
    config.admission.source_refill = Duration::from_secs(3600);
    let fleet = Fleet::start(config).await;
    // The first 3 connections pass the limiter (and then fail the handshake by timeout or
    // close); the fourth is closed immediately.
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(TcpStream::connect(fleet.relay).await.unwrap());
    }
    let mut fourth = TcpStream::connect(fleet.relay).await.unwrap();
    let mut buf = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), fourth.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "fourth connection must be dropped, got {read:?}"
    );
    // Even a legitimate peer from the same IP is turned away until the bucket refills.
    let (_app, local) = tokio::io::duplex(1024);
    assert!(
        client::connect(&fleet.ansible, &fleet.client_config("web-01"), local)
            .await
            .is_err()
    );
}

/// Regression 0003-2: a suspended `ssh` (`~^Z`, SIGSTOP) stops reading. The session must
/// survive: memory is already bounded by the window, a local write timeout protects nothing
/// and kills legitimate sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_local_reader_does_not_kill_the_session() {
    let fleet = Fleet::start(test_relay_config()).await;
    fleet.start_agent().await;
    let (app, local) = tokio::io::duplex(16 * 1024);
    let config = fleet.client_config("web-01");
    let session =
        tokio::spawn(async move { client::connect(&fleet.ansible, &config, local).await });
    let (mut rd, mut wr) = tokio::io::split(app);
    let data: Vec<u8> = (0..512 * 1024_u32).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr
    });
    // Longer than the write timeout (5 s) without reading anything.
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(
        !session.is_finished(),
        "session died while the reader was stalled"
    );
    let mut got = vec![0_u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(20), rd.read_exact(&mut got))
        .await
        .expect("no data after resuming")
        .unwrap();
    assert!(got == expected, "data corrupted after the stall");
    drop(writer.await.unwrap());
}
