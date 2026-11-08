//! Più relay e rotazione delle chiavi (Fase 5, PROTOCOL §13 e §14), su TCP reale.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::HashSet;
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

/// Un indirizzo su cui nessuno ascolta.
async fn dead_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Listener che conta le connessioni e non risponde: un relay che non deve essere contattato.
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

/// Identità del banco di prova. `agent_new` è la chiave dopo una rotazione dell'agent.
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

    /// web-01 (con le chiavi `agent_keys`), ansible → web-01, admin → tutti,
    /// outsider senza nodi.
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

/// Avvia un relay con le chiavi date; restituisce l'indirizzo.
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
    }
}

/// Avvia l'agent di web-01 verso `relays`; accetta end-to-end solo `ansible`.
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
        authorized_clients: Revocable::fixed(HashSet::from([ansible.fingerprint()])),
        timeouts: timeouts(),
        max_streams,
    };
    tokio::spawn(agent::run(Arc::new(keys), config));
}

fn client_config(relays: Vec<RelayEndpoint>, node_key: &PublicKey) -> ClientConfig {
    ClientConfig {
        relays,
        node: node("web-01"),
        node_key: *node_key,
        timeouts: timeouts(),
    }
}

/// Apre una sessione e verifica un giro di eco. Riprova per qualche secondo finché l'agent
/// non risulta registrato (`NodeOffline`), poi restituisce l'esito.
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

// ======================= specifica: più relay =======================

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
    // L'agent è connesso solo al secondo relay.
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
    // DNS dirottato: il primo indirizzo porta a un relay con un'altra chiave. Il pin la
    // smaschera e il client passa al relay successivo, anch'esso pinnato.
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

// ======================= attacchi: niente failover dove sarebbe pericoloso ===============

/// Il relay pinnato (con l'agent registrato) e, al secondo posto, una trappola che conta le
/// connessioni: non deve mai riceverne.
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
    // Il relay non rivela quali nodi esistono: un nodo assente è `NotAuthorized` come uno
    // negato. Entrambi sono definitivi.
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
    // admin è ammesso dalla policy del relay ma non dall'elenco dell'agent.
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

// ======================= specifica: rotazione delle chiavi =======================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn during_a_relay_rotation_both_pins_work() {
    let k = Keys::new();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let keys = Keyring::rotating(copy(&new), copy(&old)).unwrap();
    let r = relay(keys, k.policy(&[&k.agent])).await;
    // L'agent pinna ancora la chiave vecchia del relay.
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

// ======================= attacchi: rotazione =======================

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
    // La policy conosce solo la chiave vecchia: un agent che ruota deve presentarsi al relay
    // con quella nuova, quindi qui non si registra mai.
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

/// Finding 0005-1: un relay compromesso (uno di due) apre stream senza mai mandare `msg1`.
/// Prima occupava tutti i posti dell'agent e i client onesti, anche attraverso l'altro relay,
/// ricevevano `ResourceExhausted`. Ora esaurisce solo la propria quota.
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
    // Più stream di quanti l'agent ne ammetta, nessuno mai confermato.
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

/// Il limite delle sessioni verso sshd vale per l'agent intero: due relay non lo raddoppiano.
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
    // Attende che l'agent sia registrato su entrambi.
    echo(&k.ansible, &via(r1, &r1_id)).await.unwrap();
    echo(&k.ansible, &via(r2, &r2_id)).await.unwrap();
    // Una sessione aperta attraverso r1 occupa l'unico posto.
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
    let second = echo(&k.ansible, &via(r2, &r2_id)).await;
    assert!(
        matches!(second, Err(NetError::StreamClosed(CloseReason::Drained))),
        "{second:?}"
    );
    drop(held);
    let _ = tokio::time::timeout(Duration::from_secs(5), first).await;
}
