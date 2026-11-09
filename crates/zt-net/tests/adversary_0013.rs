//! Adversary review 0013 (Phase 6: R-5 metrics, R-6 budgets, PQ-REL), regression tests on the
//! network adapter:
//!
//! - A13-1: the relay sheds per authenticated identity, names it in the audit line, and warns
//!   about a budget below two agents' credit;
//! - A13-2: the agent takes a stream's window from the global budget only after end-to-end
//!   authentication;
//! - A13-3: the relay, agent and client files never export the same series;
//! - A13-8: `status` does not trust the file it reads;
//! - A13-9: the send-side scratch buffer does not keep its high-water mark.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

mod common;
mod duplex_net;
mod observed;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use duplex_net::DuplexNet;
use tokio::io::DuplexStream;
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW};
use zt_domain::trust::CertTrust;
use zt_domain::{Frame, FramePayload, StreamId};
use zt_net::channel::{self, Established};
use zt_net::metrics::{AgentMetrics, ClientMetrics, RelayMetrics, Snapshot};
use zt_net::relay::{RelayConfig, RelayServer};

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// A13-1: shedding per identity
// ---------------------------------------------------------------------------------------------

fn duplex_relay(
    agent: &Identity,
    clients: &[&Identity],
    queue_budget: usize,
) -> (DuplexNet, zt_crypto::PublicKey, Arc<RelayMetrics>) {
    let (net, acceptor) = DuplexNet::new();
    let id = Identity::generate().unwrap();
    let key = id.public_key();
    let fps: Vec<_> = clients.iter().map(|c| c.fingerprint()).collect();
    let policy = common::relay_policy(&agent.fingerprint(), &fps, CertTrust::default());
    let metrics = RelayMetrics::new();
    let mut config = RelayConfig {
        metrics: Arc::clone(&metrics),
        queue_budget,
        ..common::relay_config()
    };
    // A reader that does not read is cut by the write timeout too: not within this test.
    config.timeouts.write = Duration::from_secs(60);
    let server =
        RelayServer::with_acceptor(acceptor, id, zt_net::Revocable::fixed(policy), config).unwrap();
    tokio::spawn(server.run());
    (net, key, metrics)
}

async fn connect(
    net: &DuplexNet,
    buffer: usize,
    who: &Identity,
    relay: zt_crypto::PublicKey,
) -> Established<DuplexStream> {
    channel::connect(
        net.connect(buffer),
        who,
        &relay.into(),
        Channel::Outer,
        &common::timeouts(),
    )
    .await
    .unwrap()
}

/// An agent that sends `Data` as fast as the credit allows on every stream it is opened.
async fn flooding_agent(mut ch: Established<DuplexStream>) {
    let t = common::timeouts();
    let node = common::node("web-01");
    ch.send(&Frame::Register { node }, &t).await.unwrap();
    let mut credit: HashMap<StreamId, usize> = HashMap::new();
    let payload = FramePayload::try_from(vec![0x5a_u8; 16 * KIB]).unwrap();
    loop {
        let ready = credit
            .iter_mut()
            .find(|(_, c)| **c >= 16 * KIB)
            .map(|(s, c)| {
                *c -= 16 * KIB;
                *s
            });
        let frame = if let Some(stream) = ready {
            let data = Frame::Data {
                stream,
                payload: payload.clone(),
            };
            if ch.send(&data, &t).await.is_err() {
                return;
            }
            match tokio::time::timeout(Duration::from_millis(0), ch.recv()).await {
                Ok(frame) => frame,
                Err(_) => continue,
            }
        } else {
            ch.recv().await
        };
        match frame {
            Ok(Some(Frame::Open { stream, .. })) => {
                credit.insert(stream, INITIAL_WINDOW as usize);
                if ch.send(&Frame::OpenAck { stream }, &t).await.is_err() {
                    return;
                }
            }
            Ok(Some(Frame::WindowUpdate { stream, credit: c })) => {
                if let Some(left) = credit.get_mut(&stream) {
                    *left += c.get() as usize;
                }
            }
            Ok(Some(Frame::Close { stream, .. })) => {
                credit.remove(&stream);
            }
            Ok(Some(_)) => {}
            _ => return,
        }
    }
}

/// Opens streams `ids` to `web-01` without reading anything (a reader that never reads).
async fn open_unread(ch: &mut Established<DuplexStream>, ids: std::ops::RangeInclusive<u32>) {
    let t = common::timeouts();
    for id in ids {
        let open = Frame::Open {
            stream: common::sid(id),
            target: common::node("web-01"),
        };
        ch.send(&open, &t).await.unwrap();
    }
}

fn queued(m: &RelayMetrics) -> usize {
    Snapshot::parse(&m.render())
        .unwrap()
        .get("tcn_relay_queue_bytes", &[])
        .unwrap() as usize
}

async fn wait_queued(m: &RelayMetrics, at_least: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while queued(m) < at_least {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the relay never queued {at_least}: {}", m.render()));
}

/// The review's attack on the network: a slow-link download (one connection, three streams,
/// about 700 KiB queued) and an abuser that spreads a larger backlog over three connections of
/// one identity (two streams each), each smaller than the download. Past the budget the abuser's identity is shed,
/// never the download, and the audit line names the fingerprint and the role.
#[tokio::test(flavor = "current_thread")]
async fn a_split_backlog_sheds_the_abusing_identity_and_the_audit_names_it() {
    let logs = common::Captured::default();
    let _guard = logs.install();
    let agent = Identity::generate().unwrap();
    let honest = Identity::generate().unwrap();
    let abuser = Identity::generate().unwrap();
    let budget = 1700 * KIB;
    let (net, relay, metrics) = duplex_relay(&agent, &[&honest, &abuser], budget);
    let agent_ch = connect(&net, MIB, &agent, relay).await;
    tokio::spawn(flooding_agent(agent_ch));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The download: a pipe of 4 KiB that it does not read for now.
    let mut honest_ch = connect(&net, 4 * KIB, &honest, relay).await;
    open_unread(&mut honest_ch, 1..=3).await;
    wait_queued(&metrics, 600 * KIB).await;
    let download = queued(&metrics);

    // The abuser: three connections, two streams each, never read.
    let mut abusers = Vec::new();
    for _ in 0..3 {
        let mut ch = connect(&net, 4 * KIB, &abuser, relay).await;
        open_unread(&mut ch, 1..=2).await;
        abusers.push(ch);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let shed = logs.events("queue_budget_exceeded");
    assert!(!shed.is_empty(), "nothing was shed: {}", logs.text());
    let abuser_fp = abuser.fingerprint().to_string();
    for line in &shed {
        assert_eq!(
            common::field(line, "peer").as_deref(),
            Some(abuser_fp.as_str()),
            "{line}"
        );
        assert_eq!(
            common::field(line, "role").as_deref(),
            Some("client"),
            "{line}"
        );
        assert!(line.contains("\"identity_backlog\":"), "{line}");
    }
    // The download is still there: it reads everything queued for it, with no close.
    let mut received = 0;
    while received < download {
        match tokio::time::timeout(Duration::from_secs(5), honest_ch.recv()).await {
            Ok(Ok(Some(Frame::Data { payload, .. }))) => received += payload.len(),
            Ok(Ok(Some(Frame::Close { reason, .. }))) => panic!("download closed: {reason:?}"),
            Ok(Ok(Some(_))) => {}
            other => panic!("the download was shed: {other:?}"),
        }
    }
}

/// The minimum default budget holds two agents' full credit (64 streams of 1 MiB each), so an
/// agent within its normal credit is never the identity over its share.
#[test]
fn the_minimum_budget_is_consistent_with_the_agent_windows() {
    let agent_credit = 64 * MAX_WINDOW as usize;
    assert_eq!(zt_net::budget::MIN_QUEUE_BUDGET, 2 * agent_credit);
    assert_eq!(
        zt_net::budget::queue_budget_for(Some(64 * MIB as u64)),
        zt_net::budget::MIN_QUEUE_BUDGET
    );
}

/// A budget below two agents' credit (`--queue-budget-mib` allows it) is reported at startup.
#[tokio::test(flavor = "current_thread")]
async fn the_relay_warns_about_a_budget_below_two_agents_credit() {
    let logs = common::Captured::default();
    let _guard = logs.install();
    let agent = Identity::generate().unwrap();
    let mut config = common::relay_config();
    config.queue_budget = 16 * MIB;
    let _relay = common::start_relay_with(
        common::relay_policy(&agent.fingerprint(), &[], CertTrust::default()),
        config,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = logs.events("queue_budget_below_agent_credit");
    assert_eq!(events.len(), 1, "{}", logs.text());
}

// ---------------------------------------------------------------------------------------------
// A13-2: the window is taken from the global budget only after authentication
// ---------------------------------------------------------------------------------------------

/// A peer that opens streams and never sends message 1 holds no part of the agent's global
/// budget (only the per-relay quota): a real session still gets the only window there is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_without_message_1_take_nothing_from_the_global_budget() {
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let metrics = AgentMetrics::new(1);
    let lab = observed::start_observed_with(
        Arc::clone(&agent),
        vec![(
            common::relay_policy(
                &agent.fingerprint(),
                &[client.fingerprint()],
                CertTrust::default(),
            ),
            common::relay_config(),
        )],
        common::agent_clients(&[client.fingerprint()], CertTrust::default()),
        zt_net::agent::Observed {
            metrics: Arc::clone(&metrics),
            buffer_budget: INITIAL_WINDOW as usize,
        },
    )
    .await;
    // Raw frames through the relay: Open, then nothing.
    let tcp = tokio::net::TcpStream::connect(lab.relays[0].addr)
        .await
        .unwrap();
    let mut raw = channel::connect(
        tcp,
        &client,
        &lab.relays[0].key.into(),
        Channel::Outer,
        &common::timeouts(),
    )
    .await
    .unwrap();
    for id in 1..=4 {
        let open = Frame::Open {
            stream: common::sid(id),
            target: common::node("web-01"),
        };
        raw.send(&open, &common::timeouts()).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), raw.recv()).await {
            Ok(Ok(Some(Frame::OpenAck { .. }))) => {}
            other => panic!("stream {id}: {other:?}"),
        }
    }
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    assert_eq!(snap.get("tcn_agent_buffer_bytes", &[]), Some(0.0));
    let (_app, _task) = lab.session(&client, None).await.unwrap();
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    assert_eq!(
        snap.get("tcn_agent_buffer_bytes", &[]),
        Some(f64::from(INITIAL_WINDOW))
    );
    drop(raw);
}

// ---------------------------------------------------------------------------------------------
// A13-3: three files on one host
// ---------------------------------------------------------------------------------------------

fn series(text: &str) -> BTreeSet<String> {
    Snapshot::parse(text)
        .unwrap()
        .samples
        .iter()
        .map(|s| format!("{}{:?}", s.name, s.labels))
        .collect()
}

/// `node_exporter` merges every `*.prom` file of its directory: the relay, agent and client
/// files must never export the same series (same name and labels).
#[test]
fn relay_agent_and_client_series_are_pairwise_disjoint() {
    let relay = series(&RelayMetrics::new().render());
    let agent = series(&AgentMetrics::new(2).render());
    let client = series(&ClientMetrics::new().render());
    for (a, b, what) in [
        (&relay, &agent, "relay ∩ agent"),
        (&agent, &client, "agent ∩ client"),
        (&relay, &client, "relay ∩ client"),
    ] {
        let both: Vec<_> = a.intersection(b).collect();
        assert!(both.is_empty(), "{what}: {both:#?}");
    }
}

/// The process series carry the role, so the alerts can name the service.
#[test]
fn the_process_series_carry_the_role() {
    let text = RelayMetrics::new().render();
    let snap = Snapshot::parse(&text).unwrap();
    for name in [
        "tcn_process_start_time_seconds",
        "tcn_metrics_interval_seconds",
        "tcn_metrics_last_write_timestamp_seconds",
        "tcn_config_generation",
        "tcn_watchdog_progress_total",
        "tcn_draining",
    ] {
        assert!(
            snap.get(name, &[("role", "relay")]).is_some(),
            "{name} without role=\"relay\":\n{text}"
        );
    }
    assert!(
        snap.get(
            "tcn_reloads_total",
            &[("role", "relay"), ("result", "rejected")]
        )
        .is_some()
    );
    let client = Snapshot::parse(&ClientMetrics::new().render()).unwrap();
    assert!(
        client
            .get(
                "tcn_metrics_last_write_timestamp_seconds",
                &[("role", "client")]
            )
            .is_some()
    );
}

/// The exporter's stamp keeps the role of the rewritten samples.
#[test]
fn the_stamp_keeps_the_role() {
    let text = AgentMetrics::new(1).render();
    let stamped = zt_net::metrics::stamp(&text, Duration::from_secs(30), SystemTime::now());
    let snap = Snapshot::parse(&stamped).unwrap();
    assert_eq!(
        snap.get("tcn_metrics_interval_seconds", &[("role", "agent")]),
        Some(30.0)
    );
    assert_eq!(
        snap.samples
            .iter()
            .filter(|s| s.name == "tcn_metrics_interval_seconds")
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// A13-8: status does not trust the file
// ---------------------------------------------------------------------------------------------

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("adv13-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn file_written_at(dir: &std::path::Path, at: u64, interval: u64) -> std::path::PathBuf {
    let p = dir.join("metrics.prom");
    std::fs::write(
        &p,
        format!(
            "tcn_build_info{{role=\"relay\",version=\"0\"}} 1\n\
             tcn_metrics_interval_seconds{{role=\"relay\"}} {interval}\n\
             tcn_metrics_last_write_timestamp_seconds{{role=\"relay\"}} {at}\n"
        ),
    )
    .unwrap();
    p
}

/// A file written in the future (a dead process after a backward clock step, or a forged
/// file) is never fresh: `status` refuses it.
#[test]
fn a_future_timestamp_is_refused() {
    let d = dir("future");
    let p = file_written_at(&d, now_secs() + 86_400 * 365, 15);
    assert!(zt_net::metrics::status(&p, SystemTime::now()).is_err());
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(zt_net::metrics::status_command(&p, &mut out, &mut err), 1);
    // A few seconds of skew are tolerated.
    let p = file_written_at(&d, now_secs() + 2, 15);
    assert!(
        !zt_net::metrics::status(&p, SystemTime::now())
            .unwrap()
            .stale
    );
}

/// The interval read from the file is clamped to the largest the services accept (3600 s): a
/// file that claims a huge interval still goes stale.
#[test]
fn a_huge_interval_does_not_keep_a_file_fresh() {
    let d = dir("interval");
    let p = file_written_at(&d, now_secs() - 86_400, 1_000_000_000);
    assert!(
        zt_net::metrics::status(&p, SystemTime::now())
            .unwrap()
            .stale
    );
}

/// A FIFO at the path does not hang `status`: it is not a regular file.
#[test]
fn status_does_not_block_on_a_fifo() {
    let d = dir("fifo");
    let p = d.join("metrics.prom");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let p2 = p.clone();
    std::thread::spawn(move || {
        let _ = tx.send(zt_net::metrics::status(&p2, SystemTime::now()).is_err());
    });
    let refused = rx.recv_timeout(Duration::from_secs(3));
    // Unblock the thread in any case, so the test process can exit.
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags_nonblock()
        .open(&p);
    assert_eq!(refused, Ok(true), "status blocked on a FIFO or accepted it");
}

trait NonBlock {
    fn custom_flags_nonblock(&mut self) -> &mut Self;
}

impl NonBlock for std::fs::OpenOptions {
    fn custom_flags_nonblock(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(0o4000) // O_NONBLOCK on Linux
    }
}

/// Format characters (category Cf, such as the bidi overrides) in the file never reach the
/// terminal.
#[test]
fn status_filters_format_characters() {
    let d = dir("cf");
    let p = d.join("metrics.prom");
    std::fs::write(
        &p,
        format!(
            "tcn_build_info{{role=\"re\u{202e}lay\",version=\"0\u{200b}\"}} 1\n\
             tcn_metrics_last_write_timestamp_seconds{{role=\"re\u{202e}lay\"}} {}\n",
            now_secs()
        ),
    )
    .unwrap();
    let report = zt_net::metrics::status(&p, SystemTime::now()).unwrap();
    assert!(
        !report
            .text
            .chars()
            .any(|c| c == '\u{202e}' || c == '\u{200b}'),
        "{}",
        report.text
    );
}

// ---------------------------------------------------------------------------------------------
// A13-9: the scratch buffer
// ---------------------------------------------------------------------------------------------

/// After the largest frame, the send-side scratch buffer goes back to at most two `Data`
/// chunks: a connection does not keep its high-water mark for its whole life.
#[tokio::test]
async fn the_scratch_buffer_does_not_keep_its_high_water_mark() {
    let (near, far) = tokio::io::duplex(1024 * 1024);
    let server = Identity::generate().unwrap();
    let client = Identity::generate().unwrap();
    let keys = zt_crypto::Keyring::single(common::copy_of(&server));
    let t = common::timeouts();
    let accept = async {
        channel::accept(far, &keys, Channel::Outer, &t)
            .await
            .unwrap()
            .establish(&t)
            .await
            .unwrap()
    };
    let connect = async {
        channel::connect(
            near,
            &client,
            &server.public_key().into(),
            Channel::Outer,
            &t,
        )
        .await
        .unwrap()
    };
    let (mut s, mut c) = tokio::join!(accept, connect);
    s.confirmed();
    let big = Frame::Data {
        stream: common::sid(1),
        payload: FramePayload::try_from(vec![1_u8; zt_domain::limits::MAX_PAYLOAD_LEN]).unwrap(),
    };
    c.send(&big, &t).await.unwrap();
    assert_eq!(s.recv().await.unwrap().unwrap(), big);
    assert!(
        c.scratch_capacity() <= channel::SCRATCH_KEEP,
        "the scratch buffer keeps {} bytes",
        c.scratch_capacity()
    );
    const {
        assert!(channel::SCRATCH_KEEP >= 2 * (16 * KIB + 16));
        assert!(channel::SCRATCH_KEEP < zt_domain::limits::MAX_PAYLOAD_LEN);
    }
}
