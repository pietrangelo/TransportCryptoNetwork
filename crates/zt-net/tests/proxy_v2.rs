//! Strict PROXY protocol v2 in the relay, over real loopback TCP (docs/analysis/
//! relay-hardening.md §3.5, attack catalogue §4.2): 127.0.0.2 plays the trusted proxy,
//! 127.0.0.3 an attacker, the header's sources are in 198.51.100.0/24. The parser rows are in
//! `crates/zt-proto/tests/proxy_v2.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    missing_docs
)]

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::{Captured, Lab, agent_clients, connect_from, raw_msg1, relay_policy, seeded};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::trust::CertTrust;
use zt_domain::{IpPrefix, PrefixSet};
use zt_net::Revocable;
use zt_net::metrics::{RelayMetrics, Snapshot};
use zt_net::net::Acceptor;
use zt_net::relay::{ProxyProtocol, RelayConfig, RelayServer};
use zt_proto::proxy_v2;

const PROXY_HOST: u8 = 2;
const ATTACKER_HOST: u8 = 3;

fn proxy(trusted: &[&str], allow_direct: bool, header_timeout: Duration) -> ProxyProtocol {
    ProxyProtocol {
        trusted: PrefixSet::new(
            trusted
                .iter()
                .map(|t| IpPrefix::try_from(*t).unwrap())
                .collect(),
        )
        .unwrap(),
        header_timeout,
        allow_direct,
    }
}

/// The default test relay with 127.0.0.2 as its only trusted proxy.
fn proxied_config(
    allow_direct: bool,
    edit: impl FnOnce(&mut zt_application::admission::AdmissionConfig),
) -> RelayConfig {
    let mut c = common::relay_config();
    c.proxy_protocol = Some(proxy(
        &["127.0.0.2/32"],
        allow_direct,
        Duration::from_secs(3),
    ));
    edit(&mut c.admission);
    c
}

fn real(host: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host)), 40_000)
}

fn header(source: SocketAddr) -> Vec<u8> {
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 7443);
    proxy_v2::encode(Some((source, destination)), &[]).unwrap()
}

/// A message 1 behind its 2-byte length prefix, as the codec writes it.
fn framed(msg1: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(msg1.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(msg1);
    out
}

/// A relay that knows one whitelisted client, whose recorded message 1 gets message 2.
struct Setup {
    relay: common::Relay,
    metrics: Arc<RelayMetrics>,
    msg1: Vec<u8>,
}

async fn setup(config: RelayConfig) -> Setup {
    let (seed, client) = seeded(0x51);
    let agent = Identity::generate().unwrap();
    let policy = relay_policy(
        &agent.fingerprint(),
        &[client.fingerprint()],
        CertTrust::new(),
    );
    let metrics = Arc::clone(&config.metrics);
    let relay = common::start_relay_with(policy, config).await;
    let msg1 = raw_msg1(seed, &relay.key, Channel::Outer, &[]);
    Setup {
        relay,
        metrics,
        msg1,
    }
}

/// Writes `bytes` from `127.0.0.<host>` and returns the connection.
async fn send_from(addr: SocketAddr, host: u8, bytes: &[u8]) -> TcpStream {
    let mut tcp = connect_from(addr, host).await;
    tcp.write_all(bytes).await.unwrap();
    tcp
}

/// Message 2, if the relay answers within 3 s.
async fn msg2(tcp: &mut TcpStream) -> Option<Vec<u8>> {
    msg2_within(tcp, Duration::from_secs(3)).await
}

/// Message 2, if the relay answers within `within`.
async fn msg2_within(tcp: &mut TcpStream, within: Duration) -> Option<Vec<u8>> {
    let mut head = [0_u8; 2];
    match tokio::time::timeout(within, tcp.read_exact(&mut head)).await {
        Ok(Ok(_)) => {
            let mut body = vec![0_u8; usize::from(u16::from_be_bytes(head))];
            tcp.read_exact(&mut body).await.ok()?;
            Some(body)
        }
        _ => None,
    }
}

/// `true` if the relay closes `tcp` within `within` without sending anything.
async fn closed_silently(tcp: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0_u8; 1];
    matches!(
        tokio::time::timeout(within, tcp.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// `true` if `tcp` is still open (nothing to read, no EOF) after `wait`.
async fn still_open(tcp: &mut TcpStream, wait: Duration) -> bool {
    let mut buf = [0_u8; 1];
    tokio::time::timeout(wait, tcp.read(&mut buf))
        .await
        .is_err()
}

fn failures(metrics: &RelayMetrics, reason: &str) -> f64 {
    Snapshot::parse(&metrics.render())
        .unwrap()
        .get(
            "tcn_relay_proxy_header_failures_total",
            &[("reason", reason)],
        )
        .unwrap_or(-1.0)
}

fn preauth(metrics: &RelayMetrics, reason: &str) -> f64 {
    Snapshot::parse(&metrics.render())
        .unwrap()
        .get("tcn_relay_preauth_failures_total", &[("reason", reason)])
        .unwrap_or(-1.0)
}

// ---------------------------------------------------------------------------------------------
// Specification
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_trusted_proxy_header_gets_the_handshake_going() {
    let s = setup(proxied_config(false, |_| {})).await;
    let mut bytes = header(real(7));
    bytes.extend_from_slice(&framed(&s.msg1));
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &bytes).await;
    assert!(
        msg2(&mut tcp).await.is_some(),
        "no message 2 through the proxy"
    );
}

/// Without `[proxy_protocol]` nothing is ever parsed: a header is just a bad message 1.
#[tokio::test]
async fn without_the_section_no_header_is_ever_parsed() {
    let s = setup(common::relay_config()).await;
    let mut bytes = header(real(7));
    bytes.extend_from_slice(&framed(&s.msg1));
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &bytes).await;
    assert_eq!(msg2(&mut tcp).await, None);
}

/// A whole session through the proxy: the agent (direct, `allow_direct`) and a client whose
/// connection starts with a header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allow_direct_keeps_direct_peers_working() {
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let policy = relay_policy(
        &agent.fingerprint(),
        &[client.fingerprint()],
        CertTrust::new(),
    );
    let lab = Lab::start_configured(
        agent,
        vec![(policy, proxied_config(true, |_| {}))],
        agent_clients(&[client.fingerprint()], CertTrust::new()),
    )
    .await;
    let (mut app, _t) = lab.session(&client, None).await.unwrap();
    common::assert_alive(&mut app).await;
}

// ---------------------------------------------------------------------------------------------
// Attack catalogue §4.2
// ---------------------------------------------------------------------------------------------

/// P-1: a forged header from an untrusted source is never believed, with either setting; the
/// cost lands on the attacker's own address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_from_an_untrusted_source_is_never_believed() {
    for allow_direct in [true, false] {
        let s = setup(proxied_config(allow_direct, |a| {
            a.source_burst = 3;
            a.source_refill = Duration::from_secs(3_600);
        }))
        .await;
        let victim = real(7);
        let mut forged = header(victim);
        forged.extend_from_slice(&framed(&s.msg1));
        let mut attempts = Vec::new();
        for _ in 0..3 {
            attempts.push(send_from(s.relay.addr, ATTACKER_HOST, &forged).await);
        }
        for tcp in &mut attempts {
            let answer = msg2_within(tcp, Duration::from_millis(300)).await;
            assert_eq!(answer, None, "allow_direct = {allow_direct}");
        }
        if allow_direct {
            // The attacker spent its own budget: even a valid message 1 is refused now.
            let mut tcp = send_from(s.relay.addr, ATTACKER_HOST, &framed(&s.msg1)).await;
            assert_eq!(msg2(&mut tcp).await, None);
            assert!(preauth(&s.metrics, "rate_limited") >= 1.0);
        } else {
            assert_eq!(failures(&s.metrics, "untrusted"), 3.0);
        }
        // The victim's budget is untouched.
        for _ in 0..3 {
            let mut bytes = header(victim);
            bytes.extend_from_slice(&framed(&s.msg1));
            let mut tcp = send_from(s.relay.addr, PROXY_HOST, &bytes).await;
            assert!(
                msg2(&mut tcp).await.is_some(),
                "allow_direct = {allow_direct}"
            );
        }
    }
}

/// P-2: a trusted source must send a v2 header: a raw message 1 is closed, no fallback.
#[tokio::test]
async fn a_trusted_source_without_a_v2_header_is_closed() {
    let s = setup(proxied_config(true, |_| {})).await;
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &framed(&s.msg1)).await;
    assert!(closed_silently(&mut tcp, Duration::from_secs(1)).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(failures(&s.metrics, "signature"), 1.0);
}

/// P-2: a version 1 text header is refused like no header.
#[tokio::test]
async fn a_v1_header_from_a_trusted_proxy_is_closed() {
    let s = setup(proxied_config(false, |_| {})).await;
    let mut bytes = b"PROXY TCP4 198.51.100.7 203.0.113.1 40000 7443\r\n".to_vec();
    bytes.extend_from_slice(&framed(&s.msg1));
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &bytes).await;
    assert!(closed_silently(&mut tcp, Duration::from_secs(1)).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(failures(&s.metrics, "signature"), 1.0);
}

/// P-6: a huge declared length is refused from the 16 fixed bytes, without waiting for a body.
#[tokio::test]
async fn a_huge_declared_length_is_refused_without_reading() {
    let s = setup(proxied_config(false, |_| {})).await;
    let mut fixed = proxy_v2::SIGNATURE.to_vec();
    fixed.extend_from_slice(&[0x21, 0x11, 0xFF, 0xFF]);
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &fixed).await;
    assert!(closed_silently(&mut tcp, Duration::from_millis(300)).await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(failures(&s.metrics, "length"), 1.0);
}

/// An acceptor fed by the test: in-memory streams with a chosen peer address, so paused time
/// drives every deadline.
struct Fed(tokio::sync::mpsc::Receiver<(DuplexStream, SocketAddr)>);

impl Acceptor for Fed {
    type Stream = DuplexStream;

    async fn accept(&mut self) -> std::io::Result<(DuplexStream, SocketAddr)> {
        match self.0.recv().await {
            Some(next) => Ok(next),
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:7443".parse().unwrap())
    }
}

/// `true` if the relay has closed `stream` (EOF), checked without waiting.
async fn duplex_closed(stream: &mut DuplexStream) -> bool {
    let mut buf = [0_u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_millis(1), stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// P-7: a header that trickles in, or stops after 15 bytes, is closed at `header_timeout`
/// from accept, not before.
#[tokio::test(start_paused = true)]
async fn a_trickling_header_is_closed_at_its_deadline() {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut config = proxied_config(false, |_| {});
    let metrics = Arc::clone(&config.metrics);
    config.proxy_protocol = Some(proxy(&["127.0.0.2/32"], false, Duration::from_secs(3)));
    let policy = relay_policy(
        &Identity::generate().unwrap().fingerprint(),
        &[],
        CertTrust::new(),
    );
    let (policy, _updater) = Revocable::new(policy);
    let server =
        RelayServer::with_acceptor(Fed(rx), Identity::generate().unwrap(), policy, config).unwrap();
    tokio::spawn(server.run());
    let proxy_addr: SocketAddr = "127.0.0.2:5000".parse().unwrap();
    let header = header(real(7));
    // One byte per second.
    let (mut trickle, theirs) = tokio::io::duplex(1024);
    tx.send((theirs, proxy_addr)).await.unwrap();
    // 15 bytes, then silence.
    let (mut stuck, theirs) = tokio::io::duplex(1024);
    tx.send((theirs, proxy_addr)).await.unwrap();
    stuck.write_all(&header[..15]).await.unwrap();
    for (second, byte) in header.iter().take(2).enumerate() {
        trickle.write_all(&[*byte]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !duplex_closed(&mut trickle).await,
            "closed after {second} s"
        );
    }
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !duplex_closed(&mut stuck).await,
        "closed before the deadline"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        duplex_closed(&mut trickle).await,
        "trickle still open at 3.1 s"
    );
    assert!(duplex_closed(&mut stuck).await, "stuck still open at 3.1 s");
    assert_eq!(failures(&metrics, "timeout"), 2.0);
}

/// P-8: a misbehaving trusted proxy fills the header pool (`max_preauth`); the next one is
/// closed at once, and established sessions do not notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_header_pool_is_bounded_and_spares_established_sessions() {
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let policy = relay_policy(
        &agent.fingerprint(),
        &[client.fingerprint()],
        CertTrust::new(),
    );
    let config = proxied_config(true, |a| {
        a.max_preauth = 8;
        a.max_pending_per_source = 4;
        a.max_pending_per_wide = 4;
    });
    let metrics = Arc::clone(&config.metrics);
    let lab = Lab::start_configured(
        agent,
        vec![(policy, config)],
        agent_clients(&[client.fingerprint()], CertTrust::new()),
    )
    .await;
    let (mut app, _t) = lab.session(&client, None).await.unwrap();
    let addr = lab.relays[0].addr;
    let mut silent = Vec::new();
    for _ in 0..8 {
        silent.push(connect_from(addr, PROXY_HOST).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut ninth = connect_from(addr, PROXY_HOST).await;
    assert!(closed_silently(&mut ninth, Duration::from_millis(500)).await);
    for tcp in &mut silent {
        assert!(still_open(tcp, Duration::from_millis(10)).await);
    }
    assert_eq!(failures(&metrics, "pool_full"), 1.0);
    // The established session goes on, and a new direct session still gets in.
    common::assert_alive(&mut app).await;
    let (mut second, _t2) = lab.session(&client, None).await.unwrap();
    common::assert_alive(&mut second).await;
}

/// P-10: a LOCAL header (a health check) is attributed to the proxy's own address, never to
/// an address in its body.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_header_is_admitted_as_the_proxy() {
    let s = setup(proxied_config(false, |a| {
        a.source_burst = 2;
        a.source_refill = Duration::from_secs(3_600);
    }))
    .await;
    // LOCAL over TCP4 with a junk address block that names 198.51.100.9.
    let mut local = proxy_v2::SIGNATURE.to_vec();
    local.extend_from_slice(&[
        0x20, 0x11, 0x00, 0x0C, 198, 51, 100, 9, 203, 0, 113, 1, 0, 1, 0, 2,
    ]);
    local.extend_from_slice(&framed(&s.msg1));
    for _ in 0..2 {
        let mut tcp = send_from(s.relay.addr, PROXY_HOST, &local).await;
        assert!(msg2(&mut tcp).await.is_some());
    }
    // The proxy's own bucket is empty now...
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &local).await;
    assert_eq!(msg2(&mut tcp).await, None);
    // ...while 198.51.100.9 never spent anything.
    let mut bytes = header(real(9));
    bytes.extend_from_slice(&framed(&s.msg1));
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &bytes).await;
    assert!(msg2(&mut tcp).await.is_some());
}

/// P-12: header and message 1 in one segment: exact reads leave message 1 intact.
#[tokio::test]
async fn header_and_msg1_in_one_write_complete_the_handshake() {
    let s = setup(proxied_config(false, |_| {})).await;
    let mut tcp = connect_from(s.relay.addr, PROXY_HOST).await;
    tcp.set_nodelay(false).unwrap();
    let mut bytes = header(real(7));
    bytes.extend_from_slice(&framed(&s.msg1));
    tcp.write_all(&bytes).await.unwrap();
    assert!(msg2(&mut tcp).await.is_some());
}

/// P-13: a second header right behind the first is message 1 (and invalid), never a second
/// identity: its address is never charged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_header_is_not_parsed() {
    let s = setup(proxied_config(false, |a| {
        a.max_pending_per_source = 1;
        a.max_pending_per_wide = 1;
    }))
    .await;
    let mut bytes = header(real(1));
    bytes.extend_from_slice(&header(real(2)));
    bytes.extend_from_slice(&framed(&s.msg1));
    let mut smuggler = send_from(s.relay.addr, PROXY_HOST, &bytes).await;
    assert_eq!(msg2(&mut smuggler).await, None);
    // If the connection is still pending it holds 198.51.100.1's only slot, never .2's.
    let mut ok = header(real(2));
    ok.extend_from_slice(&framed(&s.msg1));
    let mut tcp = send_from(s.relay.addr, PROXY_HOST, &ok).await;
    assert!(msg2(&mut tcp).await.is_some(), "198.51.100.2 was charged");
}

/// P-14: per-source admission applies to the real peer, not to the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_source_caps_apply_to_the_real_peer() {
    let s = setup(proxied_config(false, |_| {})).await;
    // 51 different real peers through one proxy, each holding a slow handshake.
    let mut held = Vec::new();
    for host in 1..=51 {
        held.push(send_from(s.relay.addr, PROXY_HOST, &header(real(host))).await);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    for tcp in &mut held {
        assert!(still_open(tcp, Duration::from_millis(5)).await);
    }
    assert_eq!(preauth(&s.metrics, "source_limit"), 0.0);
    // 51 slow handshakes from one real peer: the 51st is refused.
    let mut same = Vec::new();
    for _ in 0..51 {
        same.push(send_from(s.relay.addr, PROXY_HOST, &header(real(200))).await);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(preauth(&s.metrics, "source_limit"), 1.0);
    let last = same.last_mut().unwrap();
    assert!(closed_silently(last, Duration::from_millis(500)).await);
}

/// P-16: what an attacker puts in a header never reaches the logs, even at DEBUG.
#[tokio::test]
async fn proxy_header_failures_are_logged_without_bytes() {
    let logs = Captured::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let s = setup(proxied_config(false, |_| {})).await;
    let marker: &[&[u8]] = &[
        b"PROXY TCP4 6.6.6.6 7.7.7.7 1 2\r\n",
        &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x11, 6, 6, 6, 6, 7, 7, 7, 7, 0, 1, 0, 2, 0xDE, 0x00, 0x05, 0xBE, 0xEF,
        ],
        &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x0C, 224, 6, 6, 6, 7, 7, 7, 7, 0, 1, 0, 2,
        ],
    ];
    for bytes in marker {
        let mut tcp = send_from(s.relay.addr, PROXY_HOST, bytes).await;
        assert!(closed_silently(&mut tcp, Duration::from_secs(1)).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(failures(&s.metrics, "signature"), 1.0);
    assert_eq!(failures(&s.metrics, "tlv"), 1.0);
    assert_eq!(failures(&s.metrics, "address"), 1.0);
    let text = logs.text();
    for needle in [
        "6.6.6.6",
        "7.7.7.7",
        "224.6.6.6",
        "PROXY TCP4",
        "beef",
        "BEEF",
        "190, 239",
    ] {
        assert!(!text.contains(needle), "{needle} in the logs:\n{text}");
    }
}

/// P-18: the drain closes connections still in the header phase at once, not at their
/// header deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn draining_closes_connections_still_in_the_header_phase() {
    let config = proxied_config(false, |_| {});
    let mut config = config;
    config.proxy_protocol = Some(proxy(&["127.0.0.2/32"], false, Duration::from_secs(10)));
    let policy = relay_policy(
        &Identity::generate().unwrap().fingerprint(),
        &[],
        CertTrust::new(),
    );
    let (policy, _updater) = Revocable::new(policy);
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::generate().unwrap(),
        policy,
        config,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(server.run_until(
        async {
            let _ = stopped.await;
        },
        Duration::from_secs(1),
    ));
    let mut tcp = send_from(addr, PROXY_HOST, &header(real(7))[..5]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(still_open(&mut tcp, Duration::from_millis(10)).await);
    stop.send(()).unwrap();
    assert!(
        closed_silently(&mut tcp, Duration::from_secs(3)).await,
        "a header-phase connection outlived the drain"
    );
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("drain hung")
        .unwrap()
        .unwrap();
}
