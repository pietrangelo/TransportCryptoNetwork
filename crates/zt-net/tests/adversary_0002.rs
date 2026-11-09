//! Regressions from adversary review 0002 over real TCP.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zt_crypto::Identity;
use zt_crypto::noise::{self, Channel};
use zt_domain::{
    AccessPolicy, AllowedNodes, ClientGrant, CloseReason, Frame, FramePayload, NodeId, StreamId,
};
use zt_net::agent::{self, AgentConfig};
use zt_net::client::{self, ClientConfig};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{Timeouts, channel};

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn sid(n: u32) -> StreamId {
    StreamId::try_from(n).unwrap()
}

fn timeouts() -> Timeouts {
    Timeouts {
        handshake: Duration::from_secs(2),
        idle: Duration::from_secs(10),
        write: Duration::from_secs(5),
        open: Duration::from_secs(2),
        ssh_connect: Duration::from_secs(2),
        keepalive: Duration::from_secs(3),
    }
}

/// Fake sshd that counts connections and echoes.
async fn counting_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, count)
}

/// Finding 0002-1: a client authorized by the relay but rejected by the agent opens and closes
/// streams. Previously the agent answered the `Close` with a `Close` and the relay disconnected
/// it, killing all of the node's sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_close_by_a_rejected_client_does_not_kill_other_sessions() {
    let relay_id = Identity::generate().unwrap();
    let relay_key = relay_id.public_key();
    let agent_id = Arc::new(Identity::generate().unwrap());
    let ansible = Identity::generate().unwrap();
    let admin = Identity::generate().unwrap();
    let mut policy = AccessPolicy::new();
    policy
        .add_agent(agent_id.fingerprint(), node("web-01"))
        .unwrap();
    for (who, name) in [(&ansible, "ansible"), (&admin, "admin")] {
        policy
            .add_client(
                who.fingerprint(),
                ClientGrant {
                    name: node(name),
                    allowed: AllowedNodes::All,
                },
            )
            .unwrap();
    }
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        relay_id,
        policy,
        RelayConfig {
            timeouts: timeouts(),
            ..RelayConfig::default()
        },
    )
    .await
    .unwrap();
    let relay = server.local_addr().unwrap();
    tokio::spawn(server.run());
    let (ssh, _) = counting_echo().await;
    tokio::spawn(agent::run(
        Arc::new(zt_crypto::Keyring::single(
            zt_crypto::Identity::from_secret_hex(&agent_id.to_secret_hex()).unwrap(),
        )),
        AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: relay.to_string(),
                public_key: relay_key,
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: zt_net::Revocable::fixed(
                [ansible.fingerprint()]
                    .into_iter()
                    .collect::<zt_domain::AuthorizedClients>(),
            ),
            timeouts: timeouts(),
            max_streams: 16,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        },
    ));
    let config = ClientConfig {
        relays: vec![zt_net::RelayEndpoint {
            address: relay.to_string(),
            public_key: relay_key,
            suite: zt_domain::HandshakeSuite::NoiseIk25519,
        }],
        node: node("web-01"),
        node_key: agent_id.public_key(),
        node_suite: zt_domain::HandshakeSuite::NoiseIk25519,
        certificate: None,
        timeouts: timeouts(),
    };

    // Innocent session, waited for until the agent is registered.
    let mut app = None;
    for _ in 0..100 {
        let (mut a, local) = tokio::io::duplex(1024);
        let (ansible_c, cfg) = (
            Identity::from_secret_hex(&ansible.to_secret_hex()).unwrap(),
            config.clone(),
        );
        tokio::spawn(async move { client::connect(&ansible_c, &cfg, local).await });
        a.write_all(b"x").await.unwrap();
        let mut b = [0_u8; 1];
        if matches!(
            tokio::time::timeout(Duration::from_millis(500), a.read_exact(&mut b)).await,
            Ok(Ok(_))
        ) {
            app = Some(a);
            break;
        }
    }
    let mut app = app.expect("innocent session");

    // The attacker: Open, waits for OpenAck, Close — several times.
    let tcp = TcpStream::connect(relay).await.unwrap();
    let mut ch = channel::connect(tcp, &admin, &relay_key, Channel::Outer, &timeouts())
        .await
        .unwrap();
    for n in 1..=5 {
        ch.send(
            &Frame::Open {
                stream: sid(n),
                target: node("web-01"),
            },
            &timeouts(),
        )
        .await
        .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(2), ch.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack, Some(Frame::OpenAck { stream: sid(n) }));
        ch.send(
            &Frame::Close {
                stream: sid(n),
                reason: CloseReason::Normal,
            },
            &timeouts(),
        )
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The innocent session still works.
    app.write_all(b"still alive").await.unwrap();
    let mut buf = [0_u8; 11];
    tokio::time::timeout(Duration::from_secs(3), app.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"still alive");
}

/// Finding 0002-3: a compromised relay replays a real client's end-to-end message 1.
/// The agent must not contact sshd nor register a session without the client's confirmation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_end_to_end_handshake_never_reaches_sshd() {
    let relay_id = Identity::generate().unwrap();
    let relay_keys =
        zt_crypto::Keyring::single(Identity::from_secret_hex(&relay_id.to_secret_hex()).unwrap());
    let agent_id = Arc::new(Identity::generate().unwrap());
    let client_id = Identity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let (ssh, sshd_connections) = counting_echo().await;
    tokio::spawn(agent::run(
        Arc::new(zt_crypto::Keyring::single(
            zt_crypto::Identity::from_secret_hex(&agent_id.to_secret_hex()).unwrap(),
        )),
        AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: relay_addr.to_string(),
                public_key: relay_id.public_key(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: zt_net::Revocable::fixed(
                [client_id.fingerprint()]
                    .into_iter()
                    .collect::<zt_domain::AuthorizedClients>(),
            ),
            timeouts: timeouts(),
            max_streams: 16,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        },
    ));

    // The malicious relay accepts the agent.
    let (tcp, _) = listener.accept().await.unwrap();
    let pending = channel::accept(tcp, &relay_keys, Channel::Outer, &timeouts())
        .await
        .unwrap();
    let mut agent_ch = pending.establish(&timeouts()).await.unwrap();
    assert!(matches!(
        agent_ch.recv().await.unwrap(),
        Some(Frame::Register { .. })
    ));

    // Message 1 captured from a real client session.
    let (msg1, _) = noise::initiate(&client_id, &agent_id.public_key(), Channel::EndToEnd).unwrap();
    for n in 1..=3 {
        agent_ch
            .send(
                &Frame::Open {
                    stream: sid(n),
                    target: node("web-01"),
                },
                &timeouts(),
            )
            .await
            .unwrap();
        let payload = FramePayload::try_from(msg1.clone()).unwrap();
        agent_ch
            .send(
                &Frame::Data {
                    stream: sid(n),
                    payload,
                },
                &timeouts(),
            )
            .await
            .unwrap();
    }
    // The agent replies (OpenAck, msg2), then waits for a confirmation the relay cannot forge
    // and closes the stream on timeout.
    let mut closes = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while closes < 3 {
        let frame = tokio::time::timeout_at(deadline, agent_ch.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if matches!(frame, Frame::Close { .. }) {
            closes += 1;
        }
    }
    assert_eq!(
        sshd_connections.load(Ordering::SeqCst),
        0,
        "replay reached sshd"
    );
}

/// Finding 0002-14 (completion): a relay that does not respect the credit does not fill an
/// agent stream's queue: the stream is closed as soon as the credit is exceeded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_exceeding_stream_credit_gets_the_stream_closed() {
    let relay_id = Identity::generate().unwrap();
    let relay_keys =
        zt_crypto::Keyring::single(Identity::from_secret_hex(&relay_id.to_secret_hex()).unwrap());
    let agent_id = Arc::new(Identity::generate().unwrap());
    let client_id = Identity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let (ssh, _) = counting_echo().await;
    let mut slow = timeouts();
    slow.open = Duration::from_secs(30); // the stream task keeps waiting for the confirmation
    tokio::spawn(agent::run(
        Arc::new(zt_crypto::Keyring::single(
            zt_crypto::Identity::from_secret_hex(&agent_id.to_secret_hex()).unwrap(),
        )),
        AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: relay_addr.to_string(),
                public_key: relay_id.public_key(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: zt_net::Revocable::fixed(
                [client_id.fingerprint()]
                    .into_iter()
                    .collect::<zt_domain::AuthorizedClients>(),
            ),
            timeouts: slow,
            max_streams: 16,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        },
    ));
    let (tcp, _) = listener.accept().await.unwrap();
    let mut agent_ch = channel::accept(tcp, &relay_keys, Channel::Outer, &timeouts())
        .await
        .unwrap()
        .establish(&timeouts())
        .await
        .unwrap();
    assert!(matches!(
        agent_ch.recv().await.unwrap(),
        Some(Frame::Register { .. })
    ));
    let (msg1, _) = noise::initiate(&client_id, &agent_id.public_key(), Channel::EndToEnd).unwrap();
    agent_ch
        .send(
            &Frame::Open {
                stream: sid(1),
                target: node("web-01"),
            },
            &timeouts(),
        )
        .await
        .unwrap();
    agent_ch
        .send(
            &Frame::Data {
                stream: sid(1),
                payload: FramePayload::try_from(msg1).unwrap(),
            },
            &timeouts(),
        )
        .await
        .unwrap();
    // The task now waits for the confirmation: the relay floods the stream with data beyond
    // the window.
    let chunk = FramePayload::try_from(vec![0_u8; 60 * 1024]).unwrap();
    let flood = async {
        for _ in 0..64 {
            if agent_ch
                .send(
                    &Frame::Data {
                        stream: sid(1),
                        payload: chunk.clone(),
                    },
                    &timeouts(),
                )
                .await
                .is_err()
            {
                break;
            }
        }
    };
    flood.await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, agent_ch.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Frame::Close { stream, reason } = frame {
            assert_eq!((stream, reason), (sid(1), CloseReason::ProtocolViolation));
            break;
        }
    }
}
