//! R-4 attacks and failures of the client's failover on the wire (docs/analysis/resilience.md
//! §5.3; catalogue R4-F2..R4-F7; review 0007 AP-10; review 0010 A10-9), on the `turmoil`
//! simulator with real relays and agent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod failover_harness;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use failover_harness::{Fleet, Outcome, RelayKind, echo, node, sim};
use zt_domain::{AllowedNodes, HandshakeSuite, RejectReason};
use zt_net::NetError;
use zt_net::net::Dialer;

const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

/// AP-10 (`hedging_does_not_amplify_a_slow_but_alive_relay`): relay 1 completes the outer
/// handshake but its `OpenAck` never comes (its link to the agent is held: the relay is alive
/// but cannot answer). Ten clients wait for the open timeout (10 s) and only then move on:
/// relay 2 sees none of them before, so the overload is not doubled.
#[test]
fn hedging_does_not_amplify_a_slow_but_alive_relay() {
    const CLIENTS: usize = 10;
    let fleet = Fleet::new(2, CLIENTS);
    let mut sim = sim(60, 5);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 16);
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    sim.client("operator", async {
        tokio::time::sleep(Duration::from_millis(900)).await;
        turmoil::hold("agent", "relay1");
        Ok(())
    });
    for i in 0..CLIENTS {
        let config = fleet.client_config();
        let secret = fleet.client_secret(i);
        let outcomes = Arc::clone(&outcomes);
        sim.client(format!("client-{i}"), async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let o = echo(&secret, config).await;
            outcomes.lock().unwrap().push(o);
            Ok(())
        });
    }
    let agent_ip = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&agent_ip);
    sim.client("lookup", async move {
        *seen.lock().unwrap() = Some(turmoil::lookup("agent"));
        Ok(())
    });
    sim.run().unwrap();
    let agent_ip = agent_ip.lock().unwrap().unwrap();
    for o in outcomes.lock().unwrap().iter() {
        let Outcome::Echoed(at) = o else {
            panic!("{o:?}")
        };
        assert!(
            *at >= Duration::from_secs(10) && *at < Duration::from_secs(11),
            "{at:?}"
        );
    }
    let first = fleet.client_arrivals(0, agent_ip);
    let second = fleet.client_arrivals(1, agent_ip);
    assert_eq!(first.len(), CLIENTS, "one handshake each on relay 1");
    assert_eq!(second.len(), CLIENTS, "one handshake each on relay 2");
    assert!(
        second.iter().all(|t| *t >= Duration::from_secs(11)),
        "a hedge against a slow OpenAck: {second:?}"
    );
}

/// All relays alive but none can answer `Open` (both agent links held): establishment ends
/// at the overall deadline (20 s) with a deadline error, not after 2 × 35 s.
#[test]
fn all_relays_down_ends_at_the_deadline() {
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(90, 7);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    sim.client("client", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        turmoil::hold("agent", "relay1");
        turmoil::hold("agent", "relay2");
        *seen.lock().unwrap() = Some(echo(&secret, config).await);
        Ok(())
    });
    sim.run().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    let Outcome::Failed(at, err) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        matches!(err, NetError::Deadline(d) if d == Duration::from_secs(20)),
        "{err:?}"
    );
    assert!(
        at >= Duration::from_secs(20) && at < Duration::from_millis(20_100),
        "{at:?}"
    );
    // The message names the deadline and where to set it.
    assert!(err.to_string().contains("20 s"), "{err}");
}

/// Every relay black-holed: each costs its connect timeout (3 s), hedged, so the client gives
/// up after about 5 s, before the deadline, with the last relay's error.
#[test]
fn black_holed_relays_give_up_before_the_deadline() {
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(60, 9);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    sim.client("client", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        turmoil::hold("client", "relay1");
        turmoil::hold("client", "relay2");
        *seen.lock().unwrap() = Some(echo(&secret, config).await);
        Ok(())
    });
    sim.run().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    let Outcome::Failed(at, err) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(matches!(err, NetError::Timeout("connect")), "{err:?}");
    assert!(
        at >= Duration::from_secs(5) && at < Duration::from_millis(5_600),
        "{at:?}"
    );
}

/// R4-F3 on the wire: relay 1 is black-holed, the hedge reaches relay 2, whose policy refuses
/// the node: the client stops at once with the refusal (fail closed), without waiting for
/// relay 1 or trying anything else.
#[test]
fn a_policy_answer_aborts_all_hedged_attempts() {
    let fleet = Fleet::new(3, 1);
    let mut sim = sim(60, 13);
    let only_db = AllowedNodes::Only([node("db-01")].into_iter().collect());
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(
        &mut sim,
        1,
        RelayKind::Real(Box::new(fleet.policy_for(&only_db))),
    );
    fleet.relay_host(&mut sim, 2, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    let agent_ip = Arc::new(Mutex::new(None));
    let agent_seen = Arc::clone(&agent_ip);
    sim.client("client", async move {
        *agent_seen.lock().unwrap() = Some(turmoil::lookup("agent"));
        tokio::time::sleep(Duration::from_secs(1)).await;
        turmoil::hold("client", "relay1");
        *seen.lock().unwrap() = Some(echo(&secret, config).await);
        Ok(())
    });
    sim.run().unwrap();
    let agent_ip = agent_ip.lock().unwrap().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    let Outcome::Failed(at, err) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        matches!(err, NetError::Rejected(RejectReason::NotAuthorized)),
        "{err:?}"
    );
    assert!(at < Duration::from_millis(2_600), "{at:?}");
    assert!(
        fleet.client_arrivals(2, agent_ip).is_empty(),
        "a more permissive relay was tried"
    );
}

/// R4-F2 and R4-F5: both attempts reach `Open` (relay 1 is slow, so it is hedged; relay 2 is
/// slower still, so relay 1 wins while relay 2 waits for its `OpenAck`). The agent sees one
/// end-to-end handshake (one sshd connection), and the loser's `Open` does not keep the
/// agent's only stream slot on relay 2 (`max_streams = 1`): once the first session has ended, a
/// second client through relay 2 alone gets in at once.
#[test]
fn hedge_losers_release_agent_slots() {
    let fleet = Fleet::new(2, 2);
    let mut sim = sim(60, 17);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 1);
    // Relay 1 (1 s per message): connected at 1 s, handshake done at 3 s, after the hedge
    // (2-2.5 s); `OpenAck` at about 5 s. Relay 2 (0.7 s), hedged at 2-2.5 s: handshake done at
    // 4.1-4.6 s, `OpenAck` not before 5.5 s, so it waits for it when relay 1 wins.
    let first = fleet.client_config();
    let mut second = fleet.client_config();
    second.relays = vec![second.relays[1].clone()];
    let (s0, s1) = (fleet.client_secret(0), fleet.client_secret(1));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let o0 = Arc::clone(&outcomes);
    let accepts = Arc::clone(&fleet.sshd_accepts);
    let accepts_after_first = Arc::new(AtomicUsize::new(usize::MAX));
    let after = Arc::clone(&accepts_after_first);
    sim.client("client-0", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let identity = zt_crypto::Identity::from_secret_hex(&s0).unwrap();
        let (mut app, local) = tokio::io::duplex(1024);
        // The first session stays open while the second client connects.
        let _session = tokio::spawn(async move {
            zt_net::client::connect_with(&identity, &first, local, failover_harness::SimDialer)
                .await
        });
        app.write_all(b"ping").await.unwrap();
        let mut buf = [0_u8; 4];
        app.read_exact(&mut buf).await.unwrap();
        // Long enough for a second msg1, if any, to reach the agent (a few RTTs).
        tokio::time::sleep(Duration::from_secs(3)).await;
        after.store(accepts.load(Ordering::SeqCst), Ordering::SeqCst);
        o0.lock().unwrap().push(Outcome::Echoed(Duration::ZERO));
        // The session ends, so its sshd permit (one for the whole agent) is free again; only a
        // leaked stream slot of relay 2 can now refuse the second client.
        drop(app);
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(())
    });
    let o1 = Arc::clone(&outcomes);
    sim.client("client-1", async move {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let o = echo(&s1, second).await;
        o1.lock().unwrap().push(o);
        Ok(())
    });
    sim.set_link_latency("client-0", "relay1", Duration::from_secs(1));
    sim.set_link_latency("client-0", "relay2", Duration::from_millis(700));
    sim.run().unwrap();
    assert_eq!(
        accepts_after_first.load(Ordering::SeqCst),
        1,
        "the agent saw more than one msg1"
    );
    let outcomes = outcomes.lock().unwrap();
    assert_eq!(outcomes.len(), 2);
    assert!(
        matches!(outcomes[1], Outcome::Echoed(at) if at < Duration::from_secs(1)),
        "the loser kept the slot: {:?}",
        outcomes[1]
    );
}

/// A dialer that records every address and never connects.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Dialer for Recorder {
    type Stream = tokio::io::DuplexStream;

    async fn connect(&self, addr: &str) -> std::io::Result<Self::Stream> {
        self.0.lock().unwrap().push(addr.to_owned());
        Err(std::io::ErrorKind::ConnectionRefused.into())
    }
}

/// A10-9 with the plan: a configuration built in code (not through `client.toml`) that
/// requires an outer suite and lists a relay pinned to another one is refused before any
/// dial, so neither failover nor a hedge can land on that relay.
#[tokio::test]
async fn a_hedge_never_lands_on_a_relay_outside_require_outer_suite() {
    let fleet = Fleet::new(2, 1);
    let mut config = fleet.client_config();
    config.relays[0].suite = HFS;
    config.require_outer_suite = Some(HFS);
    let dialer = Recorder::default();
    let identity = zt_crypto::Identity::from_secret_hex(&fleet.client_secret(0)).unwrap();
    let (_app, local) = tokio::io::duplex(64);
    let err = zt_net::client::connect_with(&identity, &config, local, dialer.clone())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("require_outer_suite"), "{err}");
    assert!(dialer.0.lock().unwrap().is_empty(), "dialed anyway");
    // With every relay pinned to it, the relays are dialed in order.
    config.relays[1].suite = HFS;
    let (_app, local) = tokio::io::duplex(64);
    let _ = zt_net::client::connect_with(&identity, &config, local, dialer.clone()).await;
    assert_eq!(
        *dialer.0.lock().unwrap(),
        vec!["relay1:7443".to_owned(), "relay2:7443".to_owned()]
    );
}

/// An invalid failover configuration built in code is refused before any dial.
#[tokio::test]
async fn an_invalid_failover_configuration_is_refused() {
    let fleet = Fleet::new(1, 1);
    let mut config = fleet.client_config();
    config.failover.deadline = Duration::ZERO;
    let dialer = Recorder::default();
    let identity = zt_crypto::Identity::from_secret_hex(&fleet.client_secret(0)).unwrap();
    let (_app, local) = tokio::io::duplex(64);
    assert!(
        zt_net::client::connect_with(&identity, &config, local, dialer.clone())
            .await
            .is_err()
    );
    assert!(dialer.0.lock().unwrap().is_empty());
}

/// RAII: dropping the client future in the middle of a hedge (two attempts in flight) leaves
/// no connection open behind it: nothing was spawned, everything is closed on drop.
#[test]
fn dropping_the_client_mid_hedge_leaks_nothing() {
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(30, 19);
    fleet.relay_host(&mut sim, 0, RelayKind::Silent);
    fleet.relay_host(&mut sim, 1, RelayKind::Silent);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let counts = Arc::new(Mutex::new((0, 0)));
    let seen = Arc::clone(&counts);
    sim.client("client", async move {
        let identity = zt_crypto::Identity::from_secret_hex(&secret).unwrap();
        let (_app, local) = tokio::io::duplex(64);
        let attempt =
            zt_net::client::connect_with(&identity, &config, local, failover_harness::SimDialer);
        // Both silent relays are in flight at 2.6 s.
        let _ = tokio::time::timeout(Duration::from_millis(2_600), attempt).await;
        let during = turmoil::established_tcp_stream_count();
        tokio::time::sleep(Duration::from_millis(100)).await;
        *seen.lock().unwrap() = (during, turmoil::established_tcp_stream_count());
        Ok(())
    });
    sim.run().unwrap();
    let (_, after) = *counts.lock().unwrap();
    assert_eq!(after, 0, "connections left open after the drop");
}
