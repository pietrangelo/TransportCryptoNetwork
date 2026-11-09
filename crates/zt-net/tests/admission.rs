//! R-1 specification on real sockets: refund after key confirmation, first-frame deadline,
//! separate pre-authentication pool, suites announced at startup (PROTOCOL §7.5, §10.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    Captured, Lab, agent_clients, field, relay_config, relay_policy, start_relay_with, timeouts,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::trust::CertTrust;
use zt_net::channel;
use zt_net::relay::RelayConfig;

fn with_admission(
    edit: impl FnOnce(&mut zt_application::admission::AdmissionConfig),
) -> RelayConfig {
    let mut c = relay_config();
    edit(&mut c.admission);
    c
}

/// One relay with `config`, the `web-01` agent and one whitelisted client.
async fn lab(config: RelayConfig) -> (Lab, Arc<Identity>) {
    let agent = Arc::new(Identity::generate().unwrap());
    let client = Arc::new(Identity::generate().unwrap());
    let policy = relay_policy(
        &agent.fingerprint(),
        &[client.fingerprint()],
        CertTrust::new(),
    );
    let clients = agent_clients(&[client.fingerprint()], CertTrust::new());
    let lab = Lab::start_configured(agent, vec![(policy, config)], clients).await;
    (lab, client)
}

/// R1-A1 on the wire: a confirmed connection gives its token back, so one identity can open
/// far more sessions from one address than the burst of unconfirmed handshakes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_sessions_do_not_use_up_the_source_budget() {
    let (lab, client) = lab(with_admission(|a| {
        a.source_burst = 3;
        a.source_refill = Duration::from_secs(3_600);
    }))
    .await;
    // The agent's own connection (same address) is confirmed too, so it did not keep a token.
    for i in 0..8 {
        let (app, task) = lab
            .session(&client, None)
            .await
            .unwrap_or_else(|e| panic!("session {i}: {e}"));
        drop(app);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
}

/// AP-1: a client must confirm its key (send an authentic frame) soon after message 2, as an
/// agent must register: the first-frame deadline closes a silent one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_sends_no_frame_is_closed_at_the_first_frame_deadline() {
    let (lab, client) = lab(with_admission(|a| {
        a.first_frame_deadline = Duration::from_secs(1);
    }))
    .await;
    let relay = &lab.relays[0];
    let tcp = TcpStream::connect(relay.addr).await.unwrap();
    let mut ch = channel::connect(tcp, &client, &relay.key, Channel::Outer, &timeouts())
        .await
        .expect("handshake completes");
    let started = tokio::time::Instant::now();
    // The test idle timeout is 10 s: closing within 3 s can only be the first-frame deadline.
    let outcome = tokio::time::timeout(Duration::from_secs(3), ch.recv()).await;
    assert!(
        matches!(outcome, Ok(Ok(None) | Err(_))),
        "expected a close, got {outcome:?}"
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
}

/// AP-1 / G2: unconfirmed handshakes have their own pool. Filling it does not touch the
/// established sessions, and new handshakes are admitted again once it drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_preauth_pool_does_not_disturb_established_sessions() {
    // One source can hold at most half the pool (finding A8-1): two sources fill it.
    let (lab, client) = lab(with_admission(|a| {
        a.max_preauth = 2;
        a.max_pending_per_source = 1;
        a.max_pending_per_wide = 1;
    }))
    .await;
    let (mut app, _task) = lab.session(&client, None).await.unwrap();
    // Two silent TCP connections from two addresses fill the pre-authentication pool.
    let mut idle = Vec::new();
    for host in [2, 3] {
        idle.push(common::connect_from(lab.relays[0].addr, host).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    common::assert_alive(&mut app).await;
    // A third handshake, from a third address, finds the pool full and is dropped without a
    // reply.
    let mut third = common::connect_from(lab.relays[0].addr, 4).await;
    let mut buf = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), third.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "a full pool must drop new connections, got {read:?}"
    );
    // Once the silent connections go away, new clients are admitted.
    drop(idle);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (mut second, _t) = lab.session(&client, None).await.unwrap();
    common::assert_alive(&mut second).await;
    common::assert_alive(&mut app).await;
}

/// AP-7: the accepted suites are explicit configuration, announced at startup.
#[tokio::test]
async fn the_relay_announces_the_suites_it_accepts() {
    let logs = Captured::default();
    let _guard = logs.install();
    let agent = Identity::generate().unwrap();
    let relay = start_relay_with(
        relay_policy(&agent.fingerprint(), &[], CertTrust::new()),
        relay_config(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let lines = logs.events("handshake_suites_in_use");
    assert_eq!(lines.len(), 1, "{}", logs.text());
    let line = &lines[0];
    assert_eq!(
        field(line, "agent_suites").as_deref(),
        Some("Noise_IK_25519_ChaChaPoly_BLAKE2s")
    );
    assert_eq!(
        field(line, "client_suites").as_deref(),
        Some("Noise_IK_25519_ChaChaPoly_BLAKE2s")
    );
    drop(relay);
}
