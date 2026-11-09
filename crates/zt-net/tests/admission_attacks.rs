//! R-1 attack catalogue on real sockets (resilience §7 R1-A5, R1-A6, R1-A9, R1-A12; review
//! 0007 AP-1, AP-3, AP-20).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{
    Captured, Lab, agent_clients, field, probe_relay, raw_msg1, relay_config, relay_policy, seeded,
    summed,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::trust::CertTrust;
use zt_net::relay::RelayConfig;

fn with_admission(
    edit: impl FnOnce(&mut zt_application::admission::AdmissionConfig),
) -> RelayConfig {
    let mut c = relay_config();
    c.admission.summary_interval = Duration::from_secs(1);
    edit(&mut c.admission);
    c
}

/// One relay, the `web-01` agent, and the given whitelisted clients.
async fn lab(config: RelayConfig, clients: &[&Identity]) -> Lab {
    let agent = Arc::new(Identity::generate().unwrap());
    let whitelist: Vec<_> = clients.iter().map(|c| c.fingerprint()).collect();
    let policy = relay_policy(&agent.fingerprint(), &whitelist, CertTrust::new());
    Lab::start_configured(
        agent,
        vec![(policy, config)],
        agent_clients(&whitelist, CertTrust::new()),
    )
    .await
}

/// `true` if the relay closes `tcp` within `within` without sending anything.
async fn closed_silently(tcp: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0_u8; 1];
    matches!(
        tokio::time::timeout(within, tcp.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// R1-A6 / G2: a length prefix above the largest legitimate message 1 is refused on sight,
/// long before the message 1 deadline, and nothing is buffered for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_msg1_prefix_is_refused_without_buffering() {
    let lab = lab(with_admission(|_| {}), &[]).await;
    let addr = lab.relays[0].addr;
    let largest = zt_domain::HandshakeSuite::NoiseIk25519.max_msg1_len();
    for declared in [65_535_usize, largest + 1] {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&u16::try_from(declared).unwrap().to_be_bytes())
            .await
            .unwrap();
        // A few bytes of the "message", then silence: with a 64 KiB cap the relay would wait.
        tcp.write_all(&[0_u8; 16]).await.unwrap();
        assert!(
            closed_silently(&mut tcp, Duration::from_secs(1)).await,
            "prefix {declared} not refused immediately"
        );
    }
}

/// R1-A12: the largest legitimate message 1 still fits the pre-authentication cap: it is
/// parsed (and here refused for its fake certificate), not cut by the codec.
#[tokio::test]
async fn the_largest_legitimate_msg1_fits_the_preauth_cap() {
    let logs = Captured::default();
    let _guard = logs.install();
    let lab = lab(with_admission(|_| {}), &[]).await;
    let relay = &lab.relays[0];
    let (seed, _) = seeded(0x31);
    let msg1 = raw_msg1(
        seed,
        &relay.key,
        Channel::Outer,
        &vec![0x54; zt_domain::limits::MAX_CERT_LEN],
    );
    assert_eq!(
        msg1.len(),
        zt_domain::HandshakeSuite::NoiseIk25519.max_msg1_len()
    );
    assert_eq!(probe_relay(relay.addr, &msg1).await, None);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let summaries = logs.events("preauth_summary");
    assert!(!summaries.is_empty(), "{}", logs.text());
    let all = summaries.join("\n");
    assert!(all.contains("\"unverified_certificate\":1"), "{all}");
    assert!(!all.contains("\"oversized\""), "{all}");
}

/// AP-1 (b): replaying a recorded message 1 of a real client gets message 2 each time, but
/// never a session, never a refund and never a line that names the victim.
#[tokio::test]
async fn replayed_msg1_is_not_refunded_and_names_no_one() {
    let logs = Captured::default();
    let _guard = logs.install();
    let (seed, victim) = seeded(0x41);
    let lab = lab(
        with_admission(|a| {
            a.source_burst = 4;
            a.source_refill = Duration::from_secs(3_600);
            a.first_frame_deadline = Duration::from_secs(1);
        }),
        &[&victim],
    )
    .await;
    let relay = &lab.relays[0];
    // The agent's connection was confirmed and refunded: the whole burst is left. The
    // recorded msg1 of the victim, replayed three times.
    let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &[]);
    for i in 0..3 {
        assert!(
            probe_relay(relay.addr, &msg1).await.is_some(),
            "replay {i} gets message 2, as before R-1"
        );
    }
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    // One token left: the victim's real session uses it and gives it back.
    let (mut app, _t) = lab.session(&victim, None).await.unwrap();
    common::assert_alive(&mut app).await;
    // The victim's token came back: one more replay spends it, and is not refunded either.
    assert!(probe_relay(relay.addr, &msg1).await.is_some());
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Without refunds the replays have used up the whole budget.
    let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
    let probe = msg1.clone();
    tcp.write_all(&u16::try_from(probe.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(&probe).await.unwrap();
    assert!(closed_silently(&mut tcp, Duration::from_secs(2)).await);
    // One summary interval (1 s) plus the summary task's polling period.
    tokio::time::sleep(Duration::from_secs(2)).await;
    // No line names the victim for the replays: only the aggregated summary counts them. The
    // one `session_established` is the victim's real session.
    let victim_fp = victim.fingerprint().to_string();
    let names_victim = |kind: &str| {
        logs.events(kind)
            .iter()
            .filter(|line| field(line, "peer").as_deref() == Some(victim_fp.as_str()))
            .count()
    };
    assert_eq!(names_victim("authentication_failed"), 0, "{}", logs.text());
    assert_eq!(names_victim("session_established"), 1, "{}", logs.text());
    let summaries = logs.events("preauth_summary");
    let all = summaries.join("\n");
    assert_eq!(summed(&summaries, "unconfirmed"), 4, "{all}");
    assert_eq!(summed(&summaries, "rate_limited"), 1, "{all}");
    assert!(!all.contains(&victim_fp), "{all}");
}

/// AP-1 (b): replays never occupy the established pool, so the real peers still fit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_msg1_does_not_enter_the_established_pool() {
    let (seed, victim) = seeded(0x42);
    let client = Identity::generate().unwrap();
    // Two established slots: the agent and one client.
    let lab = lab(
        with_admission(|a| {
            a.max_established = 2;
            a.max_per_identity = 1;
            a.first_frame_deadline = Duration::from_secs(5);
        }),
        &[&victim, &client],
    )
    .await;
    let relay = &lab.relays[0];
    let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &[]);
    // Five replays, each held open after message 2.
    let mut held = Vec::new();
    for _ in 0..5 {
        let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
        tcp.write_all(&u16::try_from(msg1.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&msg1).await.unwrap();
        let mut prefix = [0_u8; 2];
        tcp.read_exact(&mut prefix).await.unwrap();
        held.push(tcp);
    }
    let client = Arc::new(client);
    let (mut app, _t) = lab.session(&client, None).await.unwrap();
    common::assert_alive(&mut app).await;
}

/// R1-A5 / AP-20: a slowloris that keeps sending one byte per second is still closed at the
/// message 1 deadline (at least 5 s), not kept alive by its trickle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trickling_msg1_is_closed_at_the_msg1_deadline() {
    let lab = lab(with_admission(|_| {}), &[]).await;
    let addr: SocketAddr = lab.relays[0].addr;
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let started = tokio::time::Instant::now();
    tcp.write_all(&[0x00, 0x60]).await.unwrap();
    let closed = loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if tcp.write_all(&[0x00]).await.is_err() {
            break started.elapsed();
        }
        let mut buf = [0_u8; 1];
        if let Ok(Ok(0) | Err(_)) =
            tokio::time::timeout(Duration::from_millis(10), tcp.read(&mut buf)).await
        {
            break started.elapsed();
        }
        assert!(started.elapsed() < Duration::from_secs(9), "never closed");
    };
    assert!(
        closed >= Duration::from_millis(4_900),
        "closed after {closed:?}"
    );
    assert!(closed < Duration::from_secs(8), "closed after {closed:?}");
}

/// AP-3 / R1-A9: a scanner that speaks Noise with a fresh key per connection produces no
/// per-connection audit lines, only a summary; an event about a known identity afterwards is
/// still logged on its own.
#[tokio::test]
async fn noise_speaking_scanner_with_fresh_keys_cannot_crowd_out_audit_events() {
    let logs = Captured::default();
    let _guard = logs.install();
    let revoked = Identity::generate().unwrap();
    let agent = Arc::new(Identity::generate().unwrap());
    let mut trust = CertTrust::new();
    trust.set_revocations(zt_domain::trust::Revocations::new([], [revoked.fingerprint()]).unwrap());
    // `relay_policy` keeps a trust only with authorities: the denylist is set directly.
    let mut policy = relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    policy.set_cert_trust(trust).unwrap();
    let lab = Lab::start_configured(
        agent,
        vec![(policy, with_admission(|a| a.source_burst = 1_000))],
        agent_clients(&[], CertTrust::new()),
    )
    .await;
    let relay = &lab.relays[0];
    for i in 0..30_u8 {
        let (seed, _) = seeded(0x80 | i);
        let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &[]);
        assert_eq!(probe_relay(relay.addr, &msg1).await, None);
    }
    let msg1 = raw_msg1(revoked_seed(&revoked), &relay.key, Channel::Outer, &[]);
    assert_eq!(probe_relay(relay.addr, &msg1).await, None);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let failures = logs.events("authentication_failed");
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert_eq!(
        field(&failures[0], "reason").as_deref(),
        Some("key_revoked")
    );
    let summaries = logs.events("preauth_summary");
    let all = summaries.join("\n");
    assert_eq!(summed(&summaries, "unknown_peer"), 30, "{all}");
    // Each key is fresh, so the per-interval distinct counts add up to 30 too.
    assert_eq!(summed(&summaries, "distinct_keys"), 30, "{all}");
    assert!(
        summaries.len() <= 4,
        "one summary per interval, not per connection: {all}"
    );
}

/// The seed of an identity created by [`Identity::generate`], via its secret hex.
fn revoked_seed(id: &Identity) -> [u8; 32] {
    hex::decode(id.to_secret_hex().as_str())
        .unwrap()
        .try_into()
        .unwrap()
}
