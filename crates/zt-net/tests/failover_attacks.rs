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

use failover_harness::{Answer, Fleet, Outcome, RelayKind, Script, echo, echo_and_hold, node, sim};
use zt_application::admission::AdmissionConfig;
use zt_domain::{AllowedNodes, CloseReason, Frame, HandshakeSuite, RejectReason, StreamId};
use zt_net::NetError;
use zt_net::net::Dialer;
use zt_net::relay::RelayConfig;

const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

/// AP-10 (`hedging_does_not_amplify_a_slow_but_alive_relay`): relay 1 completes the outer
/// handshake but its `OpenAck` never comes (its link to the agent is held: the relay is alive
/// but cannot answer). Ten clients wait for the open timeout (4 s; with two relays it is the
/// half of the 8 s deadline, finding A11-3) and only then move on: relay 2 sees none of them
/// before, so the overload is not doubled. The failover still ends well inside the 10 s that
/// Ansible gives `ssh` by default (`ConnectTimeout`, finding A11-2).
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
            *at >= Duration::from_millis(3_900) && *at < Duration::from_secs(5),
            "{at:?}"
        );
    }
    let first = fleet.client_arrivals(0, agent_ip);
    let second = fleet.client_arrivals(1, agent_ip);
    assert_eq!(first.len(), CLIENTS, "one handshake each on relay 1");
    assert_eq!(second.len(), CLIENTS, "one handshake each on relay 2");
    assert!(
        second.iter().all(|t| *t >= Duration::from_millis(4_900)),
        "a hedge against a slow OpenAck: {second:?}"
    );
}

/// All relays alive but none can answer `Open` (both agent links held): establishment ends
/// at the overall deadline (8 s) with a deadline error, not after 2 × 35 s.
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
        matches!(err, NetError::Deadline(d) if d == Duration::from_secs(8)),
        "{err:?}"
    );
    assert!(
        at >= Duration::from_secs(8) && at < Duration::from_millis(8_100),
        "{at:?}"
    );
    // The message names the deadline and where to set it.
    assert!(err.to_string().contains("8 s"), "{err}");
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
        let attempt = tokio::spawn(async move {
            zt_net::client::connect_with(&identity, &config, local, failover_harness::SimDialer)
                .await
        });
        // Both silent relays are in flight at 2.6 s.
        tokio::time::sleep(Duration::from_millis(2_600)).await;
        let during = turmoil::established_tcp_stream_count();
        attempt.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
        *seen.lock().unwrap() = (during, turmoil::established_tcp_stream_count());
        Ok(())
    });
    sim.run().unwrap();
    let (during, after) = *counts.lock().unwrap();
    // Finding A11-5: without the hedge the test would prove nothing.
    assert_eq!(during, 2, "both attempts were not in flight");
    assert_eq!(after, 0, "connections left open after the drop");
}

/// A relay configuration whose per-source budget (R-1) is three unconfirmed handshakes and
/// never refills during the test: every token a client does not get back shows.
fn tight_budget() -> Box<RelayConfig> {
    Box::new(RelayConfig {
        admission: AdmissionConfig {
            source_burst: 3,
            source_refill: Duration::from_secs(3_600),
            ..AdmissionConfig::default()
        },
        ..RelayConfig::default()
    })
}

/// R4-F7 with the real R-1 admission (finding A11-1): a controller behind one address whose
/// first relay handshakes just over the stagger is hedged on every connection, and relay 1
/// wins while the hedge to relay 2 is still in its outer handshake. Relay 2 took a token at
/// accept; the loser must complete its handshake and confirm its key so that relay 2 gives
/// the token back (AP-1: only an authentic frame does). Four such sessions, then relay 1 is
/// black-holed: relay 2 must still admit the controller.
#[test]
fn hedge_losers_do_not_burn_the_controllers_admission_budget() {
    const ROUNDS: usize = 4;
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(120, 29);
    for i in 0..2 {
        fleet.relay_host(
            &mut sim,
            i,
            RelayKind::Configured(Box::new(fleet.open_policy()), tight_budget()),
        );
    }
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&outcomes);
    let agent_ip = Arc::new(Mutex::new(None));
    let a = Arc::clone(&agent_ip);
    sim.client("client", async move {
        *a.lock().unwrap() = Some(turmoil::lookup("agent"));
        tokio::time::sleep(Duration::from_secs(1)).await;
        for _ in 0..ROUNDS {
            let o = echo_and_hold(&secret, config.clone(), Duration::from_secs(5)).await;
            seen.lock().unwrap().push(o);
        }
        // Relay 1 goes away: everything must go through relay 2.
        turmoil::hold("client", "relay1");
        let o = echo(&secret, config).await;
        seen.lock().unwrap().push(o);
        Ok(())
    });
    // 0.9 s per message to both relays (TCP connect is one message on the simulator). Relay
    // 1: handshake done at 2.7 s, after the hedge (2-2.5 s); `OpenAck` at 4.5 s. Relay 2,
    // hedged at 2-2.5 s: accepted (one token) by 3.4 s, message 2 not before 4.7 s, so the
    // hedge is cancelled in its outer handshake.
    sim.set_link_latency("client", "relay1", Duration::from_millis(900));
    sim.set_link_latency("client", "relay2", Duration::from_millis(900));
    sim.run().unwrap();
    let agent_ip = agent_ip.lock().unwrap().unwrap();
    let outcomes = outcomes.lock().unwrap();
    assert_eq!(outcomes.len(), ROUNDS + 1);
    for o in outcomes.iter() {
        assert!(matches!(o, Outcome::Echoed(_)), "{outcomes:?}");
    }
    // Every round was hedged (the scenario is the one of the finding).
    assert!(
        fleet.client_arrivals(1, agent_ip).len() > ROUNDS,
        "{:?}",
        fleet.client_arrivals(1, agent_ip)
    );
}

/// A11-1 on the wire: a hedge cancelled while its outer handshake is in progress completes it
/// and sends one authentic frame (`Ping`, which opens nothing) before it closes; that is the
/// key confirmation the relay refunds. Relay 1 (0.9 s per message) wins at 4.5 s; relay 2
/// sends message 2 three seconds after message 1, after relay 1 won.
#[test]
fn a_hedge_cancelled_in_its_handshake_confirms_its_key() {
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(60, 31);
    let script = Script {
        msg2_delay: Duration::from_secs(3),
        answer: Some(Answer::Ack),
        ..Script::default()
    };
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Scripted(script.clone()));
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    sim.client("client", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let o = echo_and_hold(&secret, config, Duration::from_secs(8)).await;
        *seen.lock().unwrap() = Some(o);
        Ok(())
    });
    sim.set_link_latency("client", "relay1", Duration::from_millis(900));
    sim.run().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    assert!(matches!(outcome, Outcome::Echoed(_)), "{outcome:?}");
    let frames = script.frames();
    assert!(
        matches!(frames.as_slice(), [Frame::Ping { .. }]),
        "the loser left without confirming its key: {frames:?}"
    );
}

/// The relays of R4-F5: relay 1 (1 s per message, see [`slow_relay1`]) wins while relay 2
/// waits for its `OpenAck` (its open timeout ends at 6 s at the earliest); the scripted relay
/// 2 never answers.
fn loser_waiting_for_its_ack(script: &Script) -> (Fleet, turmoil::Sim<'static>) {
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(60, 37);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Scripted(script.clone()));
    fleet.agent_host(&mut sim, 16);
    (fleet, sim)
}

/// Relay 1 at 1 s per message from `client` (TCP connect is one message on the simulator):
/// handshake done at 3 s, after the hedge (2-2.5 s); `OpenAck` at 5 s.
fn slow_relay1(sim: &mut turmoil::Sim<'_>) {
    sim.set_link_latency("client", "relay1", Duration::from_secs(1));
}

/// Finding A11-5 (mutant M1): a loser that sent `Open` sends `Close Normal` for it, so the
/// relay and the agent release the stream at once instead of at their own timeouts.
#[test]
fn a_loser_that_sent_open_sends_close_normal() {
    let script = Script::default();
    let (fleet, mut sim) = loser_waiting_for_its_ack(&script);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    sim.client("client", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let o = echo_and_hold(&secret, config, Duration::from_secs(5)).await;
        *seen.lock().unwrap() = Some(o);
        Ok(())
    });
    slow_relay1(&mut sim);
    sim.run().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    assert!(matches!(outcome, Outcome::Echoed(_)), "{outcome:?}");
    let one = StreamId::try_from(1).unwrap();
    let frames = script.frames();
    assert!(
        matches!(
            frames.as_slice(),
            [Frame::Open { stream, .. }, Frame::Close { stream: closed, reason: CloseReason::Normal }]
                if *stream == one && *closed == one
        ),
        "{frames:?}"
    );
}

/// Finding A11-5 (mutant M2), R4-F5: the loser is closed while the session runs, not when it
/// ends (with `ControlPersist` that is minutes). Same latencies as
/// `hedge_losers_release_agent_slots`: 3.5 s after the echo the client holds one TCP connection.
#[test]
fn the_loser_is_closed_while_the_session_runs() {
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(60, 17);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 4);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let counts = Arc::new(Mutex::new((usize::MAX, usize::MAX)));
    let seen = Arc::clone(&counts);
    sim.client("client-0", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let identity = zt_crypto::Identity::from_secret_hex(&secret).unwrap();
        let (mut app, local) = tokio::io::duplex(1024);
        let _session = tokio::spawn(async move {
            zt_net::client::connect_with(&identity, &config, local, failover_harness::SimDialer)
                .await
        });
        app.write_all(b"ping").await.unwrap();
        let mut buf = [0_u8; 4];
        app.read_exact(&mut buf).await.unwrap();
        let at_echo = turmoil::established_tcp_stream_count();
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        *seen.lock().unwrap() = (at_echo, turmoil::established_tcp_stream_count());
        drop(app);
        Ok(())
    });
    sim.set_link_latency("client-0", "relay1", Duration::from_secs(1));
    sim.set_link_latency("client-0", "relay2", Duration::from_millis(700));
    sim.run().unwrap();
    let (_, later) = *counts.lock().unwrap();
    assert_eq!(
        later, 1,
        "the hedge loser is still connected during the session"
    );
}

/// Captured `tracing` output (JSON lines).
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Finding A11-6: a policy refusal from a loser (here it crosses the loser's `Close`) is the
/// only sign that the relays' policies differ (partial rollout, review 0005-2). The client
/// keeps the session it has, and says so on stderr with both relays.
#[test]
fn a_losers_policy_refusal_is_reported() {
    let script = Script {
        on_close: Some(RejectReason::NotAuthorized),
        ..Script::default()
    };
    let (fleet, mut sim) = loser_waiting_for_its_ack(&script);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    sim.client("client", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let o = echo_and_hold(&secret, config, Duration::from_secs(5)).await;
        *seen.lock().unwrap() = Some(o);
        Ok(())
    });
    slow_relay1(&mut sim);
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    {
        let _guard = tracing::subscriber::set_default(subscriber);
        sim.run().unwrap();
    }
    let outcome = outcome.lock().unwrap().take().unwrap();
    assert!(matches!(outcome, Outcome::Echoed(_)), "{outcome:?}");
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("relays disagree on the policy"))
        .unwrap_or_else(|| panic!("no warning: {text}"));
    assert!(
        line.contains("WARN") && line.contains("relay1:7443") && line.contains("relay2:7443"),
        "{line}"
    );
}

/// Finding A11-5 (mutant M3): an outer handshake that completes at the very instant of the
/// stagger is not hedged. On 1 ms links the handshake of relay 1 completes 4 ms after the
/// start; with a 4 ms stagger the jitter is 0 or 1 ms, so about half of the rounds put the
/// stagger at that very instant.
#[test]
fn a_handshake_done_at_the_stagger_instant_is_not_hedged() {
    const ROUNDS: usize = 24;
    let fleet = Fleet::new(2, 1);
    let mut sim = sim(60, 41);
    fleet.relay_host(&mut sim, 0, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.relay_host(&mut sim, 1, RelayKind::Real(Box::new(fleet.open_policy())));
    fleet.agent_host(&mut sim, 16);
    let mut config = fleet.client_config();
    config.failover.stagger = Duration::from_millis(STAGGER_MS);
    let secret = fleet.client_secret(0);
    let agent_ip = Arc::new(Mutex::new(None));
    let a = Arc::clone(&agent_ip);
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&outcomes);
    sim.client("client", async move {
        *a.lock().unwrap() = Some(turmoil::lookup("agent"));
        tokio::time::sleep(Duration::from_secs(1)).await;
        for _ in 0..ROUNDS {
            let o = echo(&secret, config.clone()).await;
            seen.lock().unwrap().push(o);
        }
        Ok(())
    });
    sim.run().unwrap();
    let agent_ip = agent_ip.lock().unwrap().unwrap();
    assert_eq!(outcomes.lock().unwrap().len(), ROUNDS);
    assert_eq!(fleet.client_arrivals(0, agent_ip).len(), ROUNDS);
    assert!(
        fleet.client_arrivals(1, agent_ip).is_empty(),
        "hedged although the handshake had completed: {:?}",
        fleet.client_arrivals(1, agent_ip)
    );
}

/// The stagger of `a_handshake_done_at_the_stagger_instant_is_not_hedged`: the instant at
/// which the outer handshake completes on 1 ms links.
const STAGGER_MS: u64 = 4;

/// Finding A11-3: three relays, the agent's links to relays 1 and 2 are held (half-open, G4).
/// The OpenAck wait is shared out over the relays left, so the healthy relay 3 is reached
/// within the default deadline (before R-4 it took 30 s; at 7043bfa it was never dialed).
#[test]
fn two_stalling_relays_leave_time_for_a_healthy_third() {
    let outcome = stalling_relays_then_a_healthy_one(3);
    let Outcome::Echoed(at) = outcome else {
        panic!("{outcome:?}")
    };
    // Each stalling relay gets 8/3 s.
    assert!(
        at >= Duration::from_secs(5) && at < Duration::from_secs(6),
        "{at:?}"
    );
}

/// Finding A11-3 at the bound: three relays that stall on `Open` and a healthy fourth one
/// still fit within the default deadline (2 s each, the floor of the shared wait).
#[test]
fn three_stalling_relays_and_a_healthy_fourth_fit_the_default_deadline() {
    let outcome = stalling_relays_then_a_healthy_one(4);
    let Outcome::Echoed(at) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        at >= Duration::from_secs(6) && at < Duration::from_secs(7),
        "{at:?}"
    );
}

/// `relays` relays with the default configuration; the agent's links to all but the last
/// one are held once it has registered.
fn stalling_relays_then_a_healthy_one(relays: usize) -> Outcome {
    let fleet = Fleet::new(relays, 1);
    let mut sim = sim(60, 23);
    for i in 0..relays {
        fleet.relay_host(&mut sim, i, RelayKind::Real(Box::new(fleet.open_policy())));
    }
    fleet.agent_host(&mut sim, 16);
    let config = fleet.client_config();
    let secret = fleet.client_secret(0);
    let outcome = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&outcome);
    sim.client("client", async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        for i in 1..relays {
            turmoil::hold("agent", format!("relay{i}"));
        }
        *seen.lock().unwrap() = Some(echo(&secret, config).await);
        Ok(())
    });
    sim.run().unwrap();
    let outcome = outcome.lock().unwrap().take().unwrap();
    outcome
}
