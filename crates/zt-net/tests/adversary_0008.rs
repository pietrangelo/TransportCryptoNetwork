//! Adversary review 0008 (Phase 1, PQ-0 and R-1): regression tests on real sockets. The
//! reviewer's reproducers asserted the attackable behaviour; these assert the safe one
//! (docs/adversary/0008-phase1-pq0-admission.md).
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
use std::time::{Duration, Instant};

use common::{
    Ca, Captured, Lab, agent_clients, field, now_secs, number, raw_msg1, relay_config,
    relay_policy, scope, seeded, summed, timeouts, trust,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zt_application::admission::AdmissionConfigError;
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::trust::CertTrust;
use zt_domain::{AllowedNodes, Frame, NodeId, RejectReason, StreamId};
use zt_net::channel;
use zt_net::config::{ConfigError, parse_relay_settings};

/// Sends `msg1` from `127.0.0.<host>`; `true` if message 2 came back.
async fn replay_from(relay: SocketAddr, host: u8, msg1: &[u8]) -> bool {
    let mut tcp = common::connect_from(relay, host).await;
    tcp.write_all(&u16::try_from(msg1.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(msg1).await.unwrap();
    let mut head = [0_u8; 2];
    matches!(
        tokio::time::timeout(Duration::from_secs(4), tcp.read_exact(&mut head)).await,
        Ok(Ok(_))
    )
}

/// Full lines and repeated counts naming `peer` for the event `kind`.
fn lines_and_repeats(logs: &Captured, kind: &str, peer: &str) -> (usize, u64) {
    let named = |l: &String| field(l, "peer").as_deref() == Some(peer);
    let full = logs.events(kind).iter().filter(|l| named(l)).count();
    let repeated = logs
        .events(&format!("{kind}_repeated"))
        .iter()
        .filter(|l| named(l))
        .filter_map(|l| number(l, "count"))
        .sum();
    (full, repeated)
}

/// A8-2: replays of a revoked key's recorded message 1, from several addresses, give one
/// full `authentication_failed` line per identity and interval; the others are counted in
/// one `authentication_failed_repeated{peer, reason, count}` line per interval.
// Current-thread runtime: the captured logs are those of this thread.
#[tokio::test]
async fn replays_of_a_revoked_keys_msg1_are_rate_limited_per_identity() {
    let logs = Captured::default();
    let _guard = logs.install();
    let (seed, victim) = seeded(0x77);
    let agent = Arc::new(Identity::generate().unwrap());
    let mut t = CertTrust::new();
    t.set_revocations(zt_domain::trust::Revocations::new([], [victim.fingerprint()]).unwrap());
    let mut policy = relay_policy(&agent.fingerprint(), &[], CertTrust::new());
    policy.set_cert_trust(t).unwrap();
    let mut config = relay_config();
    config.admission.source_burst = 64;
    config.admission.summary_interval = Duration::from_secs(1);
    let lab = Lab::start_configured(
        agent,
        vec![(policy, config)],
        agent_clients(&[], CertTrust::new()),
    )
    .await;
    let relay = &lab.relays[0];
    let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &[]);
    for i in 0..60_u8 {
        assert!(!replay_from(relay.addr, 2 + i % 4, &msg1).await);
    }
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let (full, repeated) = lines_and_repeats(
        &logs,
        "authentication_failed",
        &victim.fingerprint().to_string(),
    );
    assert!(
        (1..=2).contains(&full),
        "{full} full lines\n{}",
        logs.text()
    );
    assert_eq!(full as u64 + repeated, 60, "every replay is accounted for");
    let line = &logs.events("authentication_failed_repeated")[0];
    assert_eq!(field(line, "reason").as_deref(), Some("key_revoked"));
}

/// A8-2: the same with a recorded message 1 whose certificate has since expired.
// Current-thread runtime: the captured logs are those of this thread.
#[tokio::test]
async fn replays_of_an_expired_certificate_are_rate_limited_per_identity() {
    let logs = Captured::default();
    let _guard = logs.install();
    let (seed, victim) = seeded(0x78);
    let ca = Ca::new();
    let now = now_secs();
    let (cert, _) = ca.issue_at(
        &victim.public_key(),
        scope(&["web-01"]),
        now - 7_200,
        now - 3_600,
    );
    let agent = Arc::new(Identity::generate().unwrap());
    let t = trust(&[(&ca, AllowedNodes::All)], &[], &[]);
    let policy = relay_policy(&agent.fingerprint(), &[], t);
    let mut config = relay_config();
    config.admission.source_burst = 64;
    config.admission.summary_interval = Duration::from_secs(1);
    let lab = Lab::start_configured(
        agent,
        vec![(policy, config)],
        agent_clients(&[], CertTrust::new()),
    )
    .await;
    let relay = &lab.relays[0];
    let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &cert);
    for i in 0..40_u8 {
        assert!(!replay_from(relay.addr, 2 + i % 4, &msg1).await);
    }
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let (full, repeated) = lines_and_repeats(
        &logs,
        "authentication_failed",
        &victim.fingerprint().to_string(),
    );
    assert!(
        (1..=2).contains(&full),
        "{full} full lines\n{}",
        logs.text()
    );
    assert_eq!(full as u64 + repeated, 40, "every replay is accounted for");
    let line = &logs.events("authentication_failed_repeated")[0];
    assert_eq!(field(line, "cert_check").as_deref(), Some("expired"));
}

/// A8-4: until the key is confirmed, the codec cap is the largest legitimate first frame,
/// not the Noise maximum: an announced 64 KiB frame after message 2 is refused on sight and
/// counted as `oversized`.
// Current-thread runtime: the captured logs are those of this thread.
#[tokio::test]
async fn an_unconfirmed_connection_cannot_announce_a_large_first_frame() {
    let logs = Captured::default();
    let _guard = logs.install();
    let (seed, victim) = seeded(0x79);
    let agent = Arc::new(Identity::generate().unwrap());
    let policy = relay_policy(
        &agent.fingerprint(),
        &[victim.fingerprint()],
        CertTrust::new(),
    );
    let mut config = relay_config();
    config.admission.first_frame_deadline = Duration::from_secs(3);
    config.admission.summary_interval = Duration::from_secs(1);
    let lab = Lab::start_configured(
        agent,
        vec![(policy, config)],
        agent_clients(&[victim.fingerprint()], CertTrust::new()),
    )
    .await;
    let relay = &lab.relays[0];
    let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &[]);
    let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
    tcp.write_all(&u16::try_from(msg1.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(&msg1).await.unwrap();
    let mut head = [0_u8; 2];
    tcp.read_exact(&mut head).await.unwrap();
    let mut msg2 = vec![0_u8; usize::from(u16::from_be_bytes(head))];
    tcp.read_exact(&mut msg2).await.unwrap();
    let largest = channel::MAX_FIRST_MESSAGE_LEN;
    tcp.write_all(&u16::try_from(largest + 1).unwrap().to_be_bytes())
        .await
        .unwrap();
    let started = Instant::now();
    let mut buf = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(6), tcp.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "refused on sight, not at the deadline: {:?}",
        started.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let oversized = summed(&logs.events("preauth_summary"), "oversized");
    assert_eq!(oversized, 1, "{}", logs.text());
}

/// A8-4: the cap is the largest legitimate first frame: an agent's `Register` with the
/// longest node name and a client's `Open` with the longest target still fit.
#[test]
fn the_first_frame_cap_fits_the_largest_legitimate_first_frames() {
    let longest =
        NodeId::try_from("a".repeat(zt_domain::limits::MAX_NODE_ID_LEN).as_str()).unwrap();
    for frame in [
        Frame::Register {
            node: longest.clone(),
        },
        Frame::Open {
            stream: StreamId::try_from(u32::MAX).unwrap(),
            target: longest,
        },
        Frame::Ping { nonce: u64::MAX },
    ] {
        let len = zt_proto::encoded_len(&frame) + zt_domain::limits::NOISE_TAG_LEN;
        assert!(len <= channel::MAX_FIRST_MESSAGE_LEN, "{frame:?}");
    }
    const { assert!(channel::MAX_FIRST_MESSAGE_LEN < 128) };
}

/// A8-10: a confirmed identity refused at its concurrency limit gets one rate-limited audit
/// line that names it, and its `Open` an answer (`Reject RateLimited`) instead of a bare
/// close.
// Current-thread runtime: the captured logs are those of this thread.
#[tokio::test]
async fn a_confirmed_identity_over_its_limit_is_named_and_answered() {
    let logs = Captured::default();
    let _guard = logs.install();
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let policy = relay_policy(
        &agent.fingerprint(),
        &[client.fingerprint()],
        CertTrust::new(),
    );
    let mut config = relay_config();
    config.admission.max_per_identity = 1;
    let lab = Lab::start_configured(
        agent,
        vec![(policy, config)],
        agent_clients(&[client.fingerprint()], CertTrust::new()),
    )
    .await;
    let relay = &lab.relays[0];
    let (mut app, _task) = lab.session(&client, None).await.unwrap();
    for _ in 0..3 {
        let tcp = TcpStream::connect(relay.addr).await.unwrap();
        let mut ch = channel::connect(tcp, &client, &relay.key.into(), Channel::Outer, &timeouts())
            .await
            .unwrap();
        let stream = StreamId::try_from(7).unwrap();
        let open = Frame::Open {
            stream,
            target: NodeId::try_from("web-01").unwrap(),
        };
        ch.send(&open, &timeouts()).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), ch.recv()).await;
        assert!(
            matches!(
                reply,
                Ok(Ok(Some(Frame::Reject {
                    reason: RejectReason::RateLimited,
                    ..
                })))
            ),
            "{reply:?}"
        );
    }
    common::assert_alive(&mut app).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let lines = logs.events("admission_refused");
    assert_eq!(lines.len(), 1, "{}", logs.text());
    assert_eq!(
        field(&lines[0], "peer"),
        Some(client.fingerprint().to_string())
    );
    assert_eq!(
        field(&lines[0], "reason").as_deref(),
        Some("identity_limit")
    );
}

/// A8-1 / A8-8: the relay announces the admission limits in force at startup.
#[tokio::test]
async fn the_relay_announces_its_admission_limits() {
    let logs = Captured::default();
    let _guard = logs.install();
    let agent = Identity::generate().unwrap();
    let _relay = common::start_relay_with(
        relay_policy(&agent.fingerprint(), &[], CertTrust::new()),
        relay_config(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let lines = logs.events("admission_limits_in_use");
    assert_eq!(lines.len(), 1, "{}", logs.text());
    for (key, value) in [
        ("max_preauth", 1_024),
        ("max_pending_per_source", 50),
        ("max_pending_per_wide", 100),
        ("max_established", 8_192),
        ("max_per_identity", 512),
        ("agent_reserve_percent", 10),
        ("source_refill_secs", 3),
    ] {
        assert_eq!(number(&lines[0], key), Some(value), "{key}: {}", lines[0]);
    }
}

/// A8-1 / A8-8: every admission limit is configurable in `relay.toml`, with validation.
#[test]
fn relay_toml_exposes_every_admission_limit() {
    let text = r"
        [admission]
        max_preauth = 2048
        max_pending_per_source = 20
        max_pending_per_wide = 40
        wide_burst = 16
        wide_refill_secs = 4
        max_tracked_sources = 1000
        max_tracked_wide = 500
        identity_refund_burst = 128
        identity_refund_refill_ms = 250
        agent_reserve_percent = 20
        summary_interval_secs = 30
    ";
    let a = parse_relay_settings("relay.toml", text).unwrap().admission;
    assert_eq!(a.max_preauth, 2_048);
    assert_eq!(a.max_pending_per_source, 20);
    assert_eq!(a.max_pending_per_wide, 40);
    assert_eq!(a.wide_burst, 16);
    assert_eq!(a.wide_refill, Duration::from_secs(4));
    assert_eq!(a.max_tracked_sources, 1_000);
    assert_eq!(a.max_tracked_wide, 500);
    assert_eq!(a.identity_refund_burst, 128);
    assert_eq!(a.identity_refund_refill, Duration::from_millis(250));
    assert_eq!(a.agent_reserve_percent, 20);
    assert_eq!(a.summary_interval, Duration::from_secs(30));

    for (text, expected) in [
        (
            "[admission]\nsource_refill_secs = 1",
            AdmissionConfigError::SourceRefillTooFast,
        ),
        (
            "[admission]\nmax_pending_per_wide = 600",
            AdmissionConfigError::PendingCapsInconsistent,
        ),
        (
            "[admission]\nmax_established = 64",
            AdmissionConfigError::PerIdentityAbovePool,
        ),
    ] {
        match parse_relay_settings("relay.toml", text) {
            Err(ConfigError::Admission { source, .. }) => assert_eq!(source, expected, "{text}"),
            other => panic!("{text}: {other:?}"),
        }
    }
}
