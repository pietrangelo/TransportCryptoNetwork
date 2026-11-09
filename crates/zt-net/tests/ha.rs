//! Multiple relays and key rotation (Phase 5, PROTOCOL §13 and §14), over real TCP.
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zt_crypto::{Identity, Keyring, PublicKey};
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, CloseReason, NodeId, RejectReason};
use zt_net::agent::{self, AgentConfig};
use zt_net::client::{self, ClientConfig};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{NetError, RelayEndpoint, Revocable, Timeouts};

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

fn copy(id: &Identity) -> Identity {
    Identity::from_secret_hex(&id.to_secret_hex()).unwrap()
}

fn timeouts() -> Timeouts {
    Timeouts {
        handshake: Duration::from_secs(2),
        idle: Duration::from_secs(10),
        write: Duration::from_secs(5),
        open: Duration::from_secs(3),
        ssh_connect: Duration::from_secs(2),
        keepalive: Duration::from_secs(3),
    }
}

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

/// An address nobody listens on.
async fn dead_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Listener that counts connections and never answers: a relay that must not be contacted.
async fn tripwire() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(tcp);
        }
    });
    (addr, count)
}

/// Test bench identities. `agent_new` is the key after an agent rotation.
struct Keys {
    agent: Identity,
    agent_new: Identity,
    ansible: Identity,
    admin: Identity,
    outsider: Identity,
}

impl Keys {
    fn new() -> Self {
        Self {
            agent: Identity::generate().unwrap(),
            agent_new: Identity::generate().unwrap(),
            ansible: Identity::generate().unwrap(),
            admin: Identity::generate().unwrap(),
            outsider: Identity::generate().unwrap(),
        }
    }

    /// web-01 (with the `agent_keys` keys), ansible → web-01, admin → all,
    /// outsider with no nodes.
    fn policy(&self, agent_keys: &[&Identity]) -> AccessPolicy {
        let mut p = AccessPolicy::new();
        let fps: Vec<_> = agent_keys.iter().map(|k| k.fingerprint()).collect();
        p.add_agent_keys(node("web-01"), &fps).unwrap();
        for (who, name, allowed) in [
            (
                &self.ansible,
                "ansible",
                AllowedNodes::Only([node("web-01")].into_iter().collect()),
            ),
            (&self.admin, "admin", AllowedNodes::All),
            (
                &self.outsider,
                "outsider",
                AllowedNodes::Only(std::collections::BTreeSet::new()),
            ),
        ] {
            p.add_client(
                who.fingerprint(),
                ClientGrant {
                    name: node(name),
                    allowed,
                },
            )
            .unwrap();
        }
        p
    }
}

/// Starts a relay with the given keys; returns its address.
async fn relay(keys: Keyring, policy: AccessPolicy) -> SocketAddr {
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        keys,
        policy,
        RelayConfig {
            timeouts: timeouts(),
            ..RelayConfig::default()
        },
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    addr
}

fn endpoint(addr: SocketAddr, key: &PublicKey) -> RelayEndpoint {
    RelayEndpoint {
        address: addr.to_string(),
        public_key: *key,
        suite: zt_domain::HandshakeSuite::NoiseIk25519,
    }
}

/// Starts the web-01 agent towards `relays`; accepts only `ansible` end-to-end.
async fn start_agent(keys: Keyring, relays: Vec<RelayEndpoint>, ansible: &Identity) {
    start_agent_with(keys, relays, ansible, 16).await;
}

async fn start_agent_with(
    keys: Keyring,
    relays: Vec<RelayEndpoint>,
    ansible: &Identity,
    max_streams: usize,
) {
    let ssh = echo_server().await;
    let config = AgentConfig {
        relays,
        node: node("web-01"),
        ssh_target: ssh.to_string(),
        authorized_clients: Revocable::fixed(
            [ansible.fingerprint()]
                .into_iter()
                .collect::<zt_domain::AuthorizedClients>(),
        ),
        timeouts: timeouts(),
        max_streams,
        client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
    };
    tokio::spawn(agent::run(Arc::new(keys), config));
}

fn client_config(relays: Vec<RelayEndpoint>, node_key: &PublicKey) -> ClientConfig {
    ClientConfig {
        relays,
        node: node("web-01"),
        node_key: *node_key,
        node_suite: zt_domain::HandshakeSuite::NoiseIk25519,
        certificate: None,
        timeouts: timeouts(),
    }
}

/// Opens a session and checks one echo round trip. Retries for a few seconds while the agent
/// is not yet registered (`NodeOffline`), then returns the outcome.
async fn echo(who: &Identity, config: &ClientConfig) -> Result<(), NetError> {
    let mut last = Err(NetError::Closed);
    for _ in 0..60 {
        let (mut app, local) = tokio::io::duplex(64 * 1024);
        let id = copy(who);
        let cfg = config.clone();
        let session = tokio::spawn(async move { client::connect(&id, &cfg, local).await });
        let wrote = app.write_all(b"SSH-2.0-tcn-ha\r\n").await;
        let mut got = [0_u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(3), app.read_exact(&mut got)).await;
        if wrote.is_ok() && matches!(read, Ok(Ok(_))) && &got == b"SSH-2.0-tcn-ha\r\n" {
            drop(app);
            let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
            return Ok(());
        }
        drop(app);
        last = tokio::time::timeout(Duration::from_secs(10), session)
            .await
            .expect("client hung")
            .unwrap();
        match &last {
            Err(NetError::Rejected(RejectReason::NodeOffline)) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            _ => return last,
        }
    }
    last
}

// ======================= specification: multiple relays =======================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_serves_through_every_relay_of_its_list() {
    let k = Keys::new();
    let (r1_id, r2_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let r1 = relay(copy(&r1_id).into(), k.policy(&[&k.agent])).await;
    let r2 = relay(copy(&r2_id).into(), k.policy(&[&k.agent])).await;
    start_agent(
        copy(&k.agent).into(),
        vec![
            endpoint(r1, &r1_id.public_key()),
            endpoint(r2, &r2_id.public_key()),
        ],
        &k.ansible,
    )
    .await;
    let node_key = k.agent.public_key();
    echo(
        &k.ansible,
        &client_config(vec![endpoint(r1, &r1_id.public_key())], &node_key),
    )
    .await
    .expect("through relay 1");
    echo(
        &k.ansible,
        &client_config(vec![endpoint(r2, &r2_id.public_key())], &node_key),
    )
    .await
    .expect("through relay 2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_relay_does_not_stop_the_agent_on_the_others() {
    let k = Keys::new();
    let r2_id = Identity::generate().unwrap();
    let r2 = relay(copy(&r2_id).into(), k.policy(&[&k.agent])).await;
    let dead = dead_address().await;
    start_agent(
        copy(&k.agent).into(),
        vec![
            endpoint(dead, &Identity::generate().unwrap().public_key()),
            endpoint(r2, &r2_id.public_key()),
        ],
        &k.ansible,
    )
    .await;
    echo(
        &k.ansible,
        &client_config(
            vec![endpoint(r2, &r2_id.public_key())],
            &k.agent.public_key(),
        ),
    )
    .await
    .expect("relay 2 must serve while relay 1 is down");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_falls_back_when_the_first_relay_is_down() {
    let k = Keys::new();
    let r_id = Identity::generate().unwrap();
    let r = relay(copy(&r_id).into(), k.policy(&[&k.agent])).await;
    start_agent(
        copy(&k.agent).into(),
        vec![endpoint(r, &r_id.public_key())],
        &k.ansible,
    )
    .await;
    let dead = dead_address().await;
    let config = client_config(
        vec![
            endpoint(dead, &Identity::generate().unwrap().public_key()),
            endpoint(r, &r_id.public_key()),
        ],
        &k.agent.public_key(),
    );
    echo(&k.ansible, &config)
        .await
        .expect("fallback to relay 2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_falls_back_when_the_node_is_offline_on_the_first_relay() {
    let k = Keys::new();
    let (r1_id, r2_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let r1 = relay(copy(&r1_id).into(), k.policy(&[&k.agent])).await;
    let r2 = relay(copy(&r2_id).into(), k.policy(&[&k.agent])).await;
    // The agent is connected only to the second relay.
    start_agent(
        copy(&k.agent).into(),
        vec![endpoint(r2, &r2_id.public_key())],
        &k.ansible,
    )
    .await;
    let only_r2 = client_config(
        vec![endpoint(r2, &r2_id.public_key())],
        &k.agent.public_key(),
    );
    echo(&k.ansible, &only_r2)
        .await
        .expect("agent registered on relay 2");
    let config = client_config(
        vec![
            endpoint(r1, &r1_id.public_key()),
            endpoint(r2, &r2_id.public_key()),
        ],
        &k.agent.public_key(),
    );
    let (mut app, local) = tokio::io::duplex(1024);
    let id = copy(&k.ansible);
    let session = tokio::spawn(async move { client::connect(&id, &config, local).await });
    app.write_all(b"ping").await.unwrap();
    let mut got = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut got))
        .await
        .expect("no fallback on NodeOffline")
        .unwrap();
    assert_eq!(&got, b"ping");
    drop(app);
    let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_falls_back_past_an_impostor_at_the_first_address() {
    // Hijacked DNS: the first address leads to a relay with a different key. The pin exposes
    // it and the client moves on to the next relay, also pinned.
    let k = Keys::new();
    let (real_id, fake_id, r2_id) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let impostor = relay(copy(&fake_id).into(), k.policy(&[&k.agent])).await;
    let r2 = relay(copy(&r2_id).into(), k.policy(&[&k.agent])).await;
    start_agent(
        copy(&k.agent).into(),
        vec![endpoint(r2, &r2_id.public_key())],
        &k.ansible,
    )
    .await;
    let config = client_config(
        vec![
            endpoint(impostor, &real_id.public_key()),
            endpoint(r2, &r2_id.public_key()),
        ],
        &k.agent.public_key(),
    );
    echo(&k.ansible, &config)
        .await
        .expect("fallback past the impostor");
}

// ======================= attacks: no failover where it would be dangerous ===============

/// The pinned relay (with the agent registered) and, in second place, a trap that counts
/// connections: it must never receive any.
async fn primary_and_tripwire(k: &Keys) -> (Vec<RelayEndpoint>, Arc<AtomicUsize>) {
    let r_id = Identity::generate().unwrap();
    let r = relay(copy(&r_id).into(), k.policy(&[&k.agent])).await;
    start_agent(
        copy(&k.agent).into(),
        vec![endpoint(r, &r_id.public_key())],
        &k.ansible,
    )
    .await;
    echo(
        &k.ansible,
        &client_config(vec![endpoint(r, &r_id.public_key())], &k.agent.public_key()),
    )
    .await
    .expect("agent registered");
    let (trap, count) = tripwire().await;
    (
        vec![
            endpoint(r, &r_id.public_key()),
            endpoint(trap, &Identity::generate().unwrap().public_key()),
        ],
        count,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_denial_is_final_and_never_retried_elsewhere() {
    let k = Keys::new();
    let (relays, trap) = primary_and_tripwire(&k).await;
    let denied = echo(
        &k.outsider,
        &client_config(relays.clone(), &k.agent.public_key()),
    )
    .await;
    assert!(
        matches!(denied, Err(NetError::Rejected(RejectReason::NotAuthorized))),
        "{denied:?}"
    );
    let mut ghost = client_config(relays, &k.agent.public_key());
    ghost.node = node("ghost");
    // The relay does not reveal which nodes exist: a missing node is `NotAuthorized` just like
    // a denied one. Both are final.
    let unknown = echo(&k.admin, &ghost).await;
    assert!(
        matches!(
            unknown,
            Err(NetError::Rejected(
                RejectReason::NotAuthorized | RejectReason::UnknownNode
            ))
        ),
        "{unknown:?}"
    );
    assert_eq!(
        trap.load(Ordering::SeqCst),
        0,
        "a denial was retried on another relay"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_impostor_agent_is_reported_and_never_retried_elsewhere() {
    let k = Keys::new();
    let (relays, trap) = primary_and_tripwire(&k).await;
    let wrong_pin = Identity::generate().unwrap().public_key();
    let result = echo(&k.ansible, &client_config(relays, &wrong_pin)).await;
    assert!(result.is_err(), "session with an unpinned agent key");
    assert_eq!(
        trap.load(Ordering::SeqCst),
        0,
        "an end-to-end failure was retried"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_refusal_is_final_and_never_retried_elsewhere() {
    // admin is admitted by the relay policy but not by the agent's list.
    let k = Keys::new();
    let (relays, trap) = primary_and_tripwire(&k).await;
    let result = echo(&k.admin, &client_config(relays, &k.agent.public_key())).await;
    assert!(
        matches!(
            result,
            Err(NetError::StreamClosed(CloseReason::Unauthorized))
        ),
        "{result:?}"
    );
    assert_eq!(
        trap.load(Ordering::SeqCst),
        0,
        "an agent refusal was retried"
    );
}

// ======================= specification: key rotation =======================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn during_a_relay_rotation_both_pins_work() {
    let k = Keys::new();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let keys = Keyring::rotating(copy(&new), copy(&old)).unwrap();
    let r = relay(keys, k.policy(&[&k.agent])).await;
    // The agent still pins the relay's old key.
    start_agent(
        copy(&k.agent).into(),
        vec![endpoint(r, &old.public_key())],
        &k.ansible,
    )
    .await;
    for pin in [&old, &new] {
        echo(
            &k.ansible,
            &client_config(vec![endpoint(r, &pin.public_key())], &k.agent.public_key()),
        )
        .await
        .expect("both relay pins must work during the rotation");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn during_an_agent_rotation_both_pins_work() {
    let k = Keys::new();
    let r_id = Identity::generate().unwrap();
    let r = relay(copy(&r_id).into(), k.policy(&[&k.agent_new, &k.agent])).await;
    let keys = Keyring::rotating(copy(&k.agent_new), copy(&k.agent)).unwrap();
    start_agent(keys, vec![endpoint(r, &r_id.public_key())], &k.ansible).await;
    for pin in [&k.agent, &k.agent_new] {
        echo(
            &k.ansible,
            &client_config(vec![endpoint(r, &r_id.public_key())], &pin.public_key()),
        )
        .await
        .expect("both agent pins must work during the rotation");
    }
}

// ======================= attacks: rotation =======================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_rotation_the_dropped_relay_key_is_refused() {
    let k = Keys::new();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let r = relay(copy(&new).into(), k.policy(&[&k.agent])).await;
    let result = echo(
        &k.ansible,
        &client_config(vec![endpoint(r, &old.public_key())], &k.agent.public_key()),
    )
    .await;
    assert!(
        result.is_err(),
        "the old relay key still works without --previous-key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_never_uses_its_previous_key_towards_the_relay() {
    // The policy knows only the old key: a rotating agent must present itself to the relay
    // with the new one, so here it never registers.
    let k = Keys::new();
    let r_id = Identity::generate().unwrap();
    let r = relay(copy(&r_id).into(), k.policy(&[&k.agent])).await;
    let keys = Keyring::rotating(copy(&k.agent_new), copy(&k.agent)).unwrap();
    start_agent(keys, vec![endpoint(r, &r_id.public_key())], &k.ansible).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (app, local) = tokio::io::duplex(1024);
    drop(app);
    let result = client::connect(
        &k.ansible,
        &client_config(vec![endpoint(r, &r_id.public_key())], &k.agent.public_key()),
        local,
    )
    .await;
    assert!(
        matches!(result, Err(NetError::Rejected(RejectReason::NodeOffline))),
        "{result:?}"
    );
}

// ======================= adversary 0005 =======================

/// Finding 0005-1: a compromised relay (one of two) opens streams without ever sending `msg1`.
/// Previously it took up all of the agent's slots and honest clients, even through the other
/// relay, received `ResourceExhausted`. Now it exhausts only its own quota.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_compromised_relay_cannot_starve_sessions_through_the_others() {
    use zt_crypto::noise::Channel;
    use zt_domain::{Frame, StreamId};
    let k = Keys::new();
    let (evil_id, good_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil = listener.local_addr().unwrap();
    let good = relay(copy(&good_id).into(), k.policy(&[&k.agent])).await;
    start_agent(
        copy(&k.agent).into(),
        vec![
            endpoint(evil, &evil_id.public_key()),
            endpoint(good, &good_id.public_key()),
        ],
        &k.ansible,
    )
    .await;
    let (tcp, _) = listener.accept().await.unwrap();
    let keys: Keyring = copy(&evil_id).into();
    let mut ch = zt_net::channel::accept(tcp, &keys, Channel::Outer, &timeouts())
        .await
        .unwrap()
        .establish(&timeouts())
        .await
        .unwrap();
    assert!(matches!(
        ch.recv().await.unwrap(),
        Some(Frame::Register { .. })
    ));
    // More streams than the agent admits, none ever confirmed.
    for n in 1..=24_u32 {
        ch.send(
            &Frame::Open {
                stream: StreamId::try_from(n).unwrap(),
                target: node("web-01"),
            },
            &timeouts(),
        )
        .await
        .unwrap();
    }
    let mut rejected = 0;
    while let Ok(Ok(Some(frame))) =
        tokio::time::timeout(Duration::from_millis(300), ch.recv()).await
    {
        if matches!(frame, Frame::Reject { .. }) {
            rejected += 1;
        }
    }
    assert!(
        rejected > 0,
        "the compromised relay is still bounded by its own quota"
    );
    let cfg = client_config(
        vec![endpoint(good, &good_id.public_key())],
        &k.agent.public_key(),
    );
    for attempt in 0..5 {
        echo(&k.ansible, &cfg)
            .await
            .unwrap_or_else(|e| panic!("attempt {attempt} through the honest relay: {e:?}"));
    }
    drop(ch);
}

/// The limit on sshd sessions applies to the whole agent: two relays do not double it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_limit_holds_for_the_whole_agent() {
    let k = Keys::new();
    let (r1_id, r2_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let r1 = relay(copy(&r1_id).into(), k.policy(&[&k.agent])).await;
    let r2 = relay(copy(&r2_id).into(), k.policy(&[&k.agent])).await;
    start_agent_with(
        copy(&k.agent).into(),
        vec![
            endpoint(r1, &r1_id.public_key()),
            endpoint(r2, &r2_id.public_key()),
        ],
        &k.ansible,
        1,
    )
    .await;
    let via = |r: SocketAddr, id: &Identity| {
        client_config(vec![endpoint(r, &id.public_key())], &k.agent.public_key())
    };
    // Waits until the agent is registered on both.
    echo(&k.ansible, &via(r1, &r1_id)).await.unwrap();
    echo(&k.ansible, &via(r2, &r2_id)).await.unwrap();
    // The agent frees the probe streams shortly after the client has finished.
    tokio::time::sleep(Duration::from_millis(300)).await;
    // A session opened through r1 takes the only slot.
    let (mut held, local) = tokio::io::duplex(1024);
    let cfg = via(r1, &r1_id);
    let who = copy(&k.ansible);
    let first = tokio::spawn(async move { client::connect(&who, &cfg, local).await });
    held.write_all(b"x").await.unwrap();
    let mut b = [0_u8; 1];
    tokio::time::timeout(Duration::from_secs(5), held.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    // The test echo stream on r2 may not have freed r2's quota yet (also 1): as long as the
    // response is that quota, retry. Then the global limit must be the one speaking.
    let mut second = echo(&k.ansible, &via(r2, &r2_id)).await;
    for _ in 0..20 {
        if !matches!(
            second,
            Err(NetError::Rejected(RejectReason::ResourceExhausted))
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        second = echo(&k.ansible, &via(r2, &r2_id)).await;
    }
    assert!(
        matches!(second, Err(NetError::StreamClosed(CloseReason::Drained))),
        "{second:?}"
    );
    drop(held);
    let _ = tokio::time::timeout(Duration::from_secs(5), first).await;
}

// ======================= adversary 0005b =======================

/// Fake relay: accepts the agent and returns the channel after `Register`.
async fn evil_session(
    listener: &TcpListener,
    evil_id: &Identity,
) -> zt_net::channel::Established<tokio::net::TcpStream> {
    use zt_crypto::noise::Channel;
    use zt_domain::Frame;
    let (tcp, _) = listener.accept().await.unwrap();
    let keys: Keyring = copy(evil_id).into();
    let mut ch = zt_net::channel::accept(tcp, &keys, Channel::Outer, &timeouts())
        .await
        .unwrap()
        .establish(&timeouts())
        .await
        .unwrap();
    assert!(matches!(
        ch.recv().await.unwrap(),
        Some(Frame::Register { .. })
    ));
    ch
}

/// Probe: the maximum number of live tasks in the runtime until `stop` becomes `true`.
fn peak_alive_tasks(stop: Arc<std::sync::atomic::AtomicBool>) -> tokio::task::JoinHandle<usize> {
    let runtime = tokio::runtime::Handle::current();
    tokio::spawn(async move {
        let mut peak = 0;
        while !stop.load(Ordering::SeqCst) {
            peak = peak.max(runtime.metrics().num_alive_tasks());
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        peak
    })
}

/// The compromised relay opens the `ids` streams, each with a garbage `msg1` immediately
/// followed by `Close`; returns how many `Reject`s it receives.
async fn open_junk_close(
    ch: &mut zt_net::channel::Established<tokio::net::TcpStream>,
    ids: std::ops::RangeInclusive<u32>,
) -> usize {
    use zt_domain::{Frame, FramePayload, StreamId};
    let t = timeouts();
    let mut rejected = 0;
    let mut count = |frame: Frame| {
        if matches!(frame, Frame::Reject { .. }) {
            rejected += 1;
        }
    };
    for i in ids {
        let stream = StreamId::try_from(i).unwrap();
        let junk = FramePayload::try_from(vec![0x42_u8; 96]).unwrap();
        for frame in [
            Frame::Open {
                stream,
                target: node("web-01"),
            },
            Frame::Data {
                stream,
                payload: junk,
            },
            Frame::Close {
                stream,
                reason: CloseReason::Normal,
            },
        ] {
            ch.send(&frame, &t).await.unwrap();
        }
        // Drain the opposite direction from time to time, so that neither side stays blocked.
        if i % 256 == 0 {
            while let Ok(Ok(Some(f))) =
                tokio::time::timeout(Duration::from_micros(200), ch.recv()).await
            {
                count(f);
            }
        }
    }
    while let Ok(Ok(Some(f))) = tokio::time::timeout(Duration::from_millis(300), ch.recv()).await {
        count(f);
    }
    rejected
}

/// Finding 0005b-1: the relay's `Close` removed the stream's slot immediately, while its task
/// was still alive. A compromised relay that alternates `Open`, garbage `msg1` and `Close`
/// never received `ResourceExhausted` and accumulated tasks without limit. Now the slot stays
/// until the task finishes: the per-relay quota holds, and it frees up when the tasks finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_close_does_not_free_the_quota_before_the_stream_task_ends() {
    use zt_domain::{Frame, FramePayload, StreamId};
    const MAX: usize = 1;
    const FLOOD: u32 = 2_000;
    let k = Keys::new();
    let evil_id = Identity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil = listener.local_addr().unwrap();
    // With the previous key every garbage `msg1` costs two DHs: the tasks last longer.
    let keys = Keyring::rotating(copy(&k.agent), copy(&k.agent_new)).unwrap();
    start_agent_with(
        keys,
        vec![endpoint(evil, &evil_id.public_key())],
        &k.ansible,
        MAX,
    )
    .await;
    let mut ch = evil_session(&listener, &evil_id).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let base = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = peak_alive_tasks(Arc::clone(&stop));
    let rejected = open_junk_close(&mut ch, 1..=FLOOD).await;
    stop.store(true, Ordering::SeqCst);
    let peak = probe.await.unwrap();
    // Before the fix: zero rejections, always (the slot vanished together with the `Close`).
    assert!(
        rejected > 0,
        "the relay's Close bypassed the per-relay quota"
    );
    // Live stream tasks at most `MAX`; the rest is the probe and a margin.
    assert!(
        peak <= base + 1 + MAX + 2,
        "peak alive tasks {peak} with base {base}: more stream tasks than max_streams"
    );

    // Frames for a stream already closed by the relay: they are discarded, the session stays.
    let t = timeouts();
    let old = StreamId::try_from(FLOOD).unwrap();
    for frame in [
        Frame::Data {
            stream: old,
            payload: FramePayload::try_from(vec![1_u8; 8]).unwrap(),
        },
        Frame::Close {
            stream: old,
            reason: CloseReason::Normal,
        },
    ] {
        ch.send(&frame, &t).await.unwrap();
    }
    // Once the tasks are done, the quota frees up: a new `Open` is accepted.
    let fresh = StreamId::try_from(FLOOD + 1).unwrap();
    ch.send(
        &Frame::Open {
            stream: fresh,
            target: node("web-01"),
        },
        &t,
    )
    .await
    .unwrap();
    let reply = loop {
        match tokio::time::timeout(Duration::from_secs(3), ch.recv()).await {
            Ok(Ok(Some(Frame::OpenAck { stream }))) if stream == fresh => break Ok(()),
            Ok(Ok(Some(Frame::Reject { stream, reason }))) if stream == fresh => {
                break Err(reason);
            }
            Ok(Ok(Some(_))) => {}
            other => panic!("relay session ended: {other:?}"),
        }
    };
    assert_eq!(reply, Ok(()), "the quota must come back once the tasks end");
}

/// Finding 0005b-4: `max_streams` beyond the limit of the tokio semaphore made the agent
/// panic. Now `run` rejects the value and returns.
#[tokio::test]
async fn an_out_of_range_max_streams_is_refused_without_panic() {
    for max in [0, agent::MAX_STREAMS + 1, usize::MAX] {
        let config = AgentConfig {
            relays: vec![endpoint(
                dead_address().await,
                &Identity::generate().unwrap().public_key(),
            )],
            node: node("web-01"),
            ssh_target: "127.0.0.1:9".into(),
            authorized_clients: Revocable::fixed(zt_domain::AuthorizedClients::new()),
            timeouts: timeouts(),
            max_streams: max,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
        };
        let keys: Keyring = Identity::generate().unwrap().into();
        tokio::time::timeout(Duration::from_secs(2), agent::run(Arc::new(keys), config))
            .await
            .unwrap_or_else(|_| panic!("max_streams {max} was not refused"));
    }
}
