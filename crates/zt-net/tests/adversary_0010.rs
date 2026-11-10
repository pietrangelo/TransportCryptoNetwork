//! Regression tests for adversary review 0010 (Phase 3) on real sockets and on the adapters:
//!
//! - A10-3: a `WatchdogSec` too short for the hub's one-second tick is refused;
//! - A10-5: a draining relay rejects new streams on connections opened before the drain (the
//!   reviewer's reproducer, flipped), and a draining agent counts and turns away streams that
//!   were acknowledged but not yet authorized end to end;
//! - A10-7: before the clock floor, certificates are evaluated at time zero (no certificate is
//!   valid), key-pinned peers are not affected;
//! - A10-9: a client configuration that requires an outer suite refuses relays pinned to
//!   another one, so failover never lands on a weaker hop.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unchecked_time_subtraction,
    clippy::format_push_string
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::oneshot;
use zt_crypto::noise::{self, Channel};
use zt_crypto::{Identity, Keyring};
use zt_domain::trust::CertTrust;
use zt_domain::{
    AccessPolicy, AllowedNodes, ClientGrant, CloseReason, Frame, FramePayload, HandshakeSuite,
    RejectReason, StreamId, UnixTime,
};
use zt_net::channel::Established;
use zt_net::net::TcpDialer;
use zt_net::relay::RelayServer;
use zt_net::{RelayEndpoint, Revocable};

const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const IK: HandshakeSuite = HandshakeSuite::NoiseIk25519;

async fn next_for(ch: &mut Established<TcpStream>, s: StreamId) -> Option<Frame> {
    loop {
        let Ok(Ok(Some(f))) = tokio::time::timeout(Duration::from_secs(5), ch.recv()).await else {
            return None;
        };
        match &f {
            Frame::OpenAck { stream }
            | Frame::Reject { stream, .. }
            | Frame::Data { stream, .. }
            | Frame::Close { stream, .. }
                if *stream == s =>
            {
                return Some(f);
            }
            _ => {}
        }
    }
}

async fn outer(
    addr: std::net::SocketAddr,
    who: &Identity,
    relay: &zt_crypto::PublicKey,
) -> Established<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    zt_net::channel::connect_suite(
        tcp,
        who,
        &relay.into(),
        Channel::Outer,
        IK,
        &[],
        &common::timeouts(),
    )
    .await
    .unwrap()
}

fn policy_with(agent: &Identity, alice: &Identity) -> AccessPolicy {
    let mut policy = common::relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    policy
        .add_client(
            alice.fingerprint(),
            ClientGrant {
                name: common::node("alice"),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
    policy
}

fn agent_config(
    addr: std::net::SocketAddr,
    relay: zt_crypto::PublicKey,
    ssh: String,
    clients: &[zt_domain::Fingerprint],
) -> zt_net::agent::AgentConfig {
    zt_net::agent::AgentConfig {
        relays: vec![RelayEndpoint {
            address: addr.to_string(),
            public_key: relay.into(),
            suite: IK,
        }],
        node: common::node("web-01"),
        ssh_target: ssh,
        authorized_clients: Revocable::fixed(common::agent_clients(clients, CertTrust::new())),
        timeouts: common::timeouts(),
        max_streams: 8,
        client_suites: zt_domain::AcceptedSuites::only(IK),
        identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        reconnect: zt_application::reconnect::ReconnectConfig::default(),
    }
}

/// A10-5 (the reviewer's reproducer, flipped): a client connection established before the drain
/// cannot open new streams during it, and the drain ends with the last stream that was open
/// when it started, well before its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draining_relay_rejects_new_streams_on_existing_connections() {
    let relay = Identity::generate().unwrap();
    let relay_key = relay.public_key();
    let agent = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let (policy, _u) = Revocable::new(policy_with(&agent, &alice));
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        relay,
        policy,
        common::relay_config(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let drain = Duration::from_secs(8);
    let mut relay_task = tokio::spawn(server.run_until(
        async {
            let _ = stopped.await;
        },
        drain,
    ));
    let (ssh, _) = common::counting_echo().await;
    let keys = Arc::new(Keyring::single(agent));
    let _agent = tokio::spawn(zt_net::agent::run(
        keys,
        agent_config(addr, relay_key, ssh.to_string(), &[]),
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut ch = outer(addr, &alice, &relay_key).await;
    let s1 = StreamId::try_from(1).unwrap();
    ch.send(
        &Frame::Open {
            stream: s1,
            target: common::node("web-01"),
        },
        &common::timeouts(),
    )
    .await
    .unwrap();
    assert!(matches!(
        next_for(&mut ch, s1).await,
        Some(Frame::OpenAck { .. })
    ));

    let started = Instant::now();
    stop.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut next = 3_u32;
    let finished = loop {
        let s = StreamId::try_from(next).unwrap();
        next += 2;
        if ch
            .send(
                &Frame::Open {
                    stream: s,
                    target: common::node("web-01"),
                },
                &common::timeouts(),
            )
            .await
            .is_ok()
        {
            match next_for(&mut ch, s).await {
                Some(Frame::Reject {
                    reason: RejectReason::NodeOffline,
                    ..
                })
                | None => {}
                other => panic!("a new stream during the drain got {other:?}"),
            }
        }
        tokio::select! {
            r = &mut relay_task => break r,
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    };
    finished.unwrap().unwrap();
    // The stream opened before the drain ends on its own (the agent's end-to-end deadline:
    // no message 1 ever came), and with it the drain.
    assert!(
        started.elapsed() < drain - Duration::from_secs(2),
        "the drain lasted until its deadline: {:?}",
        started.elapsed()
    );
}

/// A10-5: an agent that starts draining while a stream is acknowledged but not yet authorized
/// end to end waits for it, and the client that then completes the handshake gets `Drained`
/// instead of a new session.
// One thread: the captured log is the thread's default subscriber.
#[tokio::test]
async fn a_draining_agent_counts_and_refuses_streams_in_mid_handshake() {
    let log = common::Captured::default();
    let _guard = log.install();
    let agent = Identity::generate().unwrap();
    let agent_key = agent.public_key();
    let alice = Identity::generate().unwrap();
    let relay = common::start_relay(policy_with(&agent, &alice)).await;
    let (ssh, sshd) = common::counting_echo().await;
    let (stop, stopped) = oneshot::channel::<()>();
    let keys = Arc::new(Keyring::single(agent));
    let mut agent_task = tokio::spawn(zt_net::agent::run_until(
        keys,
        agent_config(
            relay.addr,
            relay.key,
            ssh.to_string(),
            &[alice.fingerprint()],
        ),
        TcpDialer,
        async {
            let _ = stopped.await;
        },
        Duration::from_secs(30),
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut ch = outer(relay.addr, &alice, &relay.key).await;
    let s1 = StreamId::try_from(1).unwrap();
    let t = common::timeouts();
    ch.send(
        &Frame::Open {
            stream: s1,
            target: common::node("web-01"),
        },
        &t,
    )
    .await
    .unwrap();
    assert!(matches!(
        next_for(&mut ch, s1).await,
        Some(Frame::OpenAck { .. })
    ));

    stop.send(()).unwrap();
    // The stream in mid-handshake is counted: the drain does not end at once.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut agent_task)
            .await
            .is_err(),
        "the agent stopped draining with a stream in mid-handshake"
    );

    let (msg1, waiting) =
        noise::initiate_suite(&alice, agent_key, Channel::EndToEnd, IK, &[]).unwrap();
    ch.send(
        &Frame::Data {
            stream: s1,
            payload: FramePayload::try_from(msg1).unwrap(),
        },
        &t,
    )
    .await
    .unwrap();
    let Some(Frame::Data { payload, .. }) = next_for(&mut ch, s1).await else {
        panic!("no message 2");
    };
    let mut transport = waiting.complete(&payload.into_bytes()).unwrap();
    let confirm = transport.encrypt(IK.confirmation()).unwrap();
    ch.send(
        &Frame::Data {
            stream: s1,
            payload: FramePayload::try_from(confirm).unwrap(),
        },
        &t,
    )
    .await
    .unwrap();
    let closed = next_for(&mut ch, s1).await;
    assert!(
        matches!(
            closed,
            Some(Frame::Close {
                reason: CloseReason::Drained,
                ..
            })
        ),
        "{closed:?}"
    );
    assert_eq!(
        sshd.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "sshd was reached during the drain"
    );
    tokio::time::timeout(Duration::from_secs(5), agent_task)
        .await
        .expect("the agent did not finish its drain")
        .unwrap();
    let draining = log.events("agent_draining");
    assert_eq!(
        common::number(&draining[0], "sessions"),
        Some(1),
        "{}",
        log.text()
    );
}

/// A10-7: before the clock floor the time used for certificates is zero, so every certificate
/// is not yet valid; at or after the floor it is the wall clock.
#[test]
fn certificates_are_refused_before_the_clock_floor() {
    let floor = 1_767_225_600;
    assert_eq!(
        zt_net::lifecycle::certificate_time(UnixTime::from_secs(floor - 1), floor),
        UnixTime::from_secs(0)
    );
    assert_eq!(
        zt_net::lifecycle::certificate_time(UnixTime::from_secs(1_000), floor),
        UnixTime::from_secs(0)
    );
    for now in [floor, floor + 1, 1_900_000_000] {
        assert_eq!(
            zt_net::lifecycle::certificate_time(UnixTime::from_secs(now), floor),
            UnixTime::from_secs(now)
        );
    }
    // Every certificate's `not_before` minus the skew is after that time: none is valid.
    let stale = zt_net::lifecycle::certificate_time(UnixTime::from_secs(floor - 3_600), floor);
    assert!(stale.as_secs() < zt_domain::limits::CERT_CLOCK_SKEW_SECS);
}

/// A10-3: the hub ticks once a second, so a watchdog checked more often than that misses
/// progress at idle and gets a healthy service killed. Below three seconds it is refused.
#[test]
fn a_watchdog_shorter_than_three_hub_ticks_is_refused() {
    use zt_net::lifecycle::watchdog_period;
    assert!(watchdog_period(Duration::from_secs(1)).is_err());
    assert!(watchdog_period(Duration::from_millis(2_999)).is_err());
    assert_eq!(
        watchdog_period(Duration::from_secs(3)).unwrap(),
        Duration::from_secs(1)
    );
    assert_eq!(
        watchdog_period(Duration::from_secs(60)).unwrap(),
        Duration::from_secs(20)
    );
}

fn client_toml(require: Option<HandshakeSuite>, pins: &[HandshakeSuite]) -> String {
    let mut text = String::from("key = \"client.key\"\n");
    if let Some(suite) = require {
        text.push_str(&format!(
            "require_outer_suite = \"{}\"\n",
            suite.protocol_name()
        ));
    }
    for (i, pin) in pins.iter().enumerate() {
        text.push_str(&format!(
            "[[relays]]\naddress = \"r{i}.example.org:7443\"\npublic_key = \"{}\"\nsuite = \"{}\"\n",
            Identity::generate().unwrap().public_key(),
            pin.protocol_name()
        ));
    }
    text
}

/// A10-9: once the rollout of OPERATIONS §13 is over, `require_outer_suite` makes a relay
/// pinned to any other suite a configuration error, so failover cannot land on it.
#[test]
fn a_required_outer_suite_refuses_relays_pinned_to_another_suite() {
    let base = std::path::Path::new("/etc/tcn");
    let mixed = client_toml(Some(HFS), &[HFS, IK]);
    let err = zt_net::config::parse_client_settings("client.toml", base, &mixed).unwrap_err();
    assert!(err.to_string().contains("require_outer_suite"), "{err}");
    let all = client_toml(Some(HFS), &[HFS, HFS]);
    let settings = zt_net::config::parse_client_settings("client.toml", base, &all).unwrap();
    assert!(settings.relays.iter().all(|r| r.suite == HFS));
    // Without it, mixed pins stay allowed during the rollout.
    let rollout = client_toml(None, &[HFS, IK]);
    assert!(zt_net::config::parse_client_settings("client.toml", base, &rollout).is_ok());
    // The required suite must be one the outer channel supports.
    let unknown = "key = \"k\"\nrequire_outer_suite = \"Noise_XX\"\nrelay = \"r.example.org:7443\"\nrelay_key = \"".to_owned()
        + &Identity::generate().unwrap().public_key().to_string()
        + "\"\n";
    assert!(zt_net::config::parse_client_settings("client.toml", base, &unknown).is_err());
}
