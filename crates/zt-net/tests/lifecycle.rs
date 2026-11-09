//! R-3 on real sockets: graceful drain of relay and agent, supervised critical tasks and the
//! hub's progress counter (resilience.md §5.4; catalogue R3-C1, R3-C2, R3-C6).
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
use std::time::Duration;

use common::{Captured, agent_clients, assert_alive, copy_of, counting_echo, field, relay_policy};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use zt_crypto::{Identity, Keyring};
use zt_domain::trust::CertTrust;
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, HandshakeSuite, RejectReason};
use zt_net::lifecycle::Supervisor;
use zt_net::net::TcpDialer;
use zt_net::relay::RelayServer;
use zt_net::{NetError, RelayEndpoint, Revocable, Updater, client};

struct Drained {
    addr: std::net::SocketAddr,
    key: zt_crypto::PublicKey,
    policy: Updater<AccessPolicy>,
    stop: Option<oneshot::Sender<()>>,
    done: JoinHandle<Result<(), NetError>>,
}

async fn signal(rx: oneshot::Receiver<()>) {
    let _ = rx.await;
}

/// A relay that drains for `drain` when told to.
async fn drained_relay(policy: AccessPolicy, drain: Duration) -> Drained {
    let id = Identity::generate().unwrap();
    let key = id.public_key();
    let (rx, updater) = Revocable::new(policy);
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        id,
        rx,
        common::relay_config(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let done = tokio::spawn(server.run_until(signal(stopped), drain));
    Drained {
        addr,
        key,
        policy: updater,
        stop: Some(stop),
        done,
    }
}

fn grant_all(policy: &mut AccessPolicy, who: &Identity) {
    policy
        .add_client(
            who.fingerprint(),
            ClientGrant {
                name: common::node("alice"),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
}

/// An agent for `web-01` on `relay`; `stop` starts its drain.
async fn agent_on(
    agent: &Identity,
    relay: &Drained,
    whitelist: &[zt_domain::Fingerprint],
    drain: Duration,
) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (ssh, _count) = counting_echo().await;
    let clients = Revocable::fixed(agent_clients(whitelist, CertTrust::new()));
    let config = zt_net::agent::AgentConfig {
        relays: vec![RelayEndpoint {
            address: relay.addr.to_string(),
            public_key: relay.key,
            suite: HandshakeSuite::NoiseIk25519,
        }],
        node: common::node("web-01"),
        ssh_target: ssh.to_string(),
        authorized_clients: clients,
        timeouts: common::timeouts(),
        max_streams: 4,
        client_suites: zt_domain::AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
        identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        reconnect: zt_application::reconnect::ReconnectConfig::default(),
    };
    let (stop, stopped) = oneshot::channel();
    let keys = Arc::new(Keyring::single(copy_of(agent)));
    let task = tokio::spawn(async move {
        zt_net::agent::run_until(keys, config, TcpDialer, signal(stopped), drain).await;
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    (stop, task)
}

fn client_config(relay: &Drained, agent: &Identity) -> client::ClientConfig {
    client::ClientConfig {
        relays: vec![RelayEndpoint {
            address: relay.addr.to_string(),
            public_key: relay.key,
            suite: HandshakeSuite::NoiseIk25519,
        }],
        node: common::node("web-01"),
        node_key: agent.public_key(),
        node_suite: HandshakeSuite::NoiseIk25519,
        certificate: None,
        timeouts: common::timeouts(),
    }
}

async fn session(
    who: &Arc<Identity>,
    config: client::ClientConfig,
) -> (tokio::io::DuplexStream, JoinHandle<Result<(), NetError>>) {
    let (mut app, local) = tokio::io::duplex(64 * 1024);
    let who = Arc::clone(who);
    let task = tokio::spawn(async move { client::connect(&who, &config, local).await });
    assert_alive(&mut app).await;
    (app, task)
}

/// R3-C1: on `SIGTERM` the relay stops listening at once, keeps the open sessions, and exits
/// as soon as the last one ends.
#[tokio::test]
async fn a_draining_relay_refuses_new_connections_and_keeps_sessions() {
    let log = Captured::default();
    let _guard = log.install();
    let agent = Identity::generate().unwrap();
    let alice = Arc::new(Identity::generate().unwrap());
    let mut policy = relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    grant_all(&mut policy, &alice);
    let mut relay = drained_relay(policy, Duration::from_secs(60)).await;
    let (_agent_stop, _agent) = agent_on(
        &agent,
        &relay,
        &[alice.fingerprint()],
        Duration::from_secs(1),
    )
    .await;
    let (mut app, task) = session(&alice, client_config(&relay, &agent)).await;
    relay.stop.take().unwrap().send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tokio::net::TcpStream::connect(relay.addr).await.is_err(),
        "a draining relay still accepts connections"
    );
    assert_alive(&mut app).await;
    assert!(
        !relay.done.is_finished(),
        "the relay exited with a session open"
    );
    drop(app);
    task.abort();
    let outcome = tokio::time::timeout(Duration::from_secs(5), relay.done)
        .await
        .expect("the relay did not exit after the last session")
        .unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(log.events("relay_draining").len(), 1, "{}", log.text());
    let drained = log.events("relay_drained");
    assert_eq!(drained.len(), 1, "{}", log.text());
    assert!(drained[0].contains("\"expired\":false"), "{}", drained[0]);
}

/// R3-C1: at the drain deadline the remaining streams are closed with `Close Drained` and the
/// relay exits.
#[tokio::test]
async fn the_drain_deadline_closes_streams_with_drained() {
    let log = Captured::default();
    let _guard = log.install();
    let agent = Identity::generate().unwrap();
    let alice = Arc::new(Identity::generate().unwrap());
    let mut policy = relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    grant_all(&mut policy, &alice);
    let mut relay = drained_relay(policy, Duration::from_secs(1)).await;
    let (_agent_stop, _agent) = agent_on(
        &agent,
        &relay,
        &[alice.fingerprint()],
        Duration::from_secs(1),
    )
    .await;
    let (_app, task) = session(&alice, client_config(&relay, &agent)).await;
    relay.stop.take().unwrap().send(()).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), relay.done)
        .await
        .expect("the relay outlived its drain deadline")
        .unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    let ended = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the client session outlived the relay")
        .unwrap();
    assert!(
        matches!(
            ended,
            Ok(()) | Err(NetError::StreamClosed(zt_domain::CloseReason::Drained))
        ),
        "{ended:?}"
    );
    let audits = log.events("connection_drained");
    assert!(
        audits
            .iter()
            .any(|l| field(l, "reason").as_deref() == Some("Drained")),
        "{}",
        log.text()
    );
    let drained = log.events("relay_drained");
    assert!(drained[0].contains("\"expired\":true"), "{}", drained[0]);
}

/// R3-C1 attack: a drain is not a window without revocation. A client removed from the policy
/// while the relay drains loses its session at once.
#[tokio::test]
async fn revocation_still_applies_while_draining() {
    let agent = Identity::generate().unwrap();
    let alice = Arc::new(Identity::generate().unwrap());
    let mut policy = relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    grant_all(&mut policy, &alice);
    let mut relay = drained_relay(policy, Duration::from_secs(60)).await;
    let (_agent_stop, _agent) = agent_on(
        &agent,
        &relay,
        &[alice.fingerprint()],
        Duration::from_secs(1),
    )
    .await;
    let (_app, task) = session(&alice, client_config(&relay, &agent)).await;
    relay.stop.take().unwrap().send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    relay
        .policy
        .replace(relay_policy(&agent.fingerprint(), &[], CertTrust::new()));
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("a revoked client kept its session during the drain")
        .unwrap()
        .ok();
}

/// R3-C2: a draining agent turns new sessions away with `NodeOffline` (the client tries
/// another relay or retries later), keeps the open ones and exits after the last.
#[tokio::test]
async fn a_draining_agent_rejects_new_sessions() {
    let log = Captured::default();
    let _guard = log.install();
    let agent = Identity::generate().unwrap();
    let alice = Arc::new(Identity::generate().unwrap());
    let mut policy = relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    grant_all(&mut policy, &alice);
    let relay = drained_relay(policy, Duration::from_secs(60)).await;
    let (stop, agent_task) = agent_on(
        &agent,
        &relay,
        &[alice.fingerprint()],
        Duration::from_secs(60),
    )
    .await;
    let (mut app, task) = session(&alice, client_config(&relay, &agent)).await;
    stop.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_app2, local) = tokio::io::duplex(1024);
    let refused = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect(&alice, &client_config(&relay, &agent), local),
    )
    .await
    .expect("client hung");
    assert!(
        matches!(refused, Err(NetError::Rejected(RejectReason::NodeOffline))),
        "{refused:?}"
    );
    assert_alive(&mut app).await;
    drop(app);
    task.abort();
    tokio::time::timeout(Duration::from_secs(5), agent_task)
        .await
        .expect("the agent did not exit after its last session")
        .unwrap();
    assert_eq!(log.events("agent_draining").len(), 1, "{}", log.text());
    assert_eq!(log.events("agent_drained").len(), 1, "{}", log.text());
}

/// R3-C6: a critical task that stops, by panic or by returning, is reported by name.
#[tokio::test]
async fn a_dead_critical_task_is_reported() {
    let mut s = Supervisor::new();
    s.spawn("forever", std::future::pending::<()>());
    s.spawn("policy_reload", async { panic!("boom") });
    let failure = tokio::time::timeout(Duration::from_secs(2), s.failed())
        .await
        .expect("a panicked task went unnoticed");
    assert!(failure.contains("policy_reload"), "{failure}");
    let mut s = Supervisor::new();
    s.spawn("watcher", async {});
    let failure = tokio::time::timeout(Duration::from_secs(2), s.failed())
        .await
        .expect("a task that returned went unnoticed");
    assert!(failure.contains("watcher"), "{failure}");
}

/// R3-C6: with no supervised tasks, `failed` never resolves.
#[tokio::test]
async fn an_empty_supervisor_never_fails() {
    let mut s = Supervisor::new();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), s.failed())
            .await
            .is_err()
    );
}

/// AP-4: the hub's progress counter moves on its own (the tick), so an idle relay keeps
/// kicking the watchdog.
#[tokio::test]
async fn an_idle_hub_still_makes_progress() {
    let id = Identity::generate().unwrap();
    let (policy, _updater) = Revocable::new(AccessPolicy::new());
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        id,
        policy,
        common::relay_config(),
    )
    .await
    .unwrap();
    let progress = server.progress();
    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert!(progress.get() >= 2, "{}", progress.get());
}
