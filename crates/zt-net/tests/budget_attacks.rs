//! R-6 efficiency, attacks (resilience.md §7 R-6, review 0007 AP-22, D-13): an authenticated
//! slow reader against the relay's global byte budget, the read/write-in-one-task invariant
//! (G11), and one peer trying to starve the others of the agent's budget.
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
mod latency;
mod observed;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use duplex_net::DuplexNet;
use tokio::io::DuplexStream;
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW};
use zt_domain::trust::CertTrust;
use zt_domain::{Credit, Frame, FramePayload, StreamId};
use zt_net::channel::{self, Established};
use zt_net::metrics::{AgentMetrics, RelayMetrics, Snapshot};
use zt_net::relay::{RelayConfig, RelayServer};

const CHUNK: usize = 16 * 1024;

/// A relay on the in-memory network, its key and its metrics.
async fn duplex_relay(
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
    let config = RelayConfig {
        metrics: Arc::clone(&metrics),
        queue_budget,
        ..common::relay_config()
    };
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

/// An agent that sends `Data` as fast as its credit allows on every stream it is opened.
async fn flooding_agent(mut ch: Established<DuplexStream>) {
    let t = common::timeouts();
    ch.send(
        &Frame::Register {
            node: common::node("web-01"),
        },
        &t,
    )
    .await
    .unwrap();
    let mut credit: HashMap<StreamId, usize> = HashMap::new();
    let payload = FramePayload::try_from(vec![0x5a_u8; CHUNK]).unwrap();
    loop {
        let ready = credit.iter_mut().find(|(_, c)| **c >= CHUNK).map(|(s, c)| {
            *c -= CHUNK;
            *s
        });
        if let Some(stream) = ready {
            let data = Frame::Data {
                stream,
                payload: payload.clone(),
            };
            if ch.send(&data, &t).await.is_err() {
                return;
            }
            // Give the inbound side a chance between frames.
            if let Ok(frame) = tokio::time::timeout(Duration::from_millis(0), ch.recv()).await {
                if !on_agent_frame(&mut ch, &mut credit, frame).await {
                    return;
                }
            }
            continue;
        }
        let frame = ch.recv().await;
        if !on_agent_frame(&mut ch, &mut credit, frame).await {
            return;
        }
    }
}

async fn on_agent_frame(
    ch: &mut Established<DuplexStream>,
    credit: &mut HashMap<StreamId, usize>,
    frame: Result<Option<Frame>, zt_net::NetError>,
) -> bool {
    let t = common::timeouts();
    match frame {
        Ok(Some(Frame::Open { stream, .. })) => {
            credit.insert(stream, INITIAL_WINDOW as usize);
            ch.send(&Frame::OpenAck { stream }, &t).await.is_ok()
        }
        Ok(Some(Frame::WindowUpdate { stream, credit: c })) => {
            if let Some(left) = credit.get_mut(&stream) {
                *left += c.get() as usize;
            }
            true
        }
        Ok(Some(Frame::Close { stream, .. })) => {
            credit.remove(&stream);
            true
        }
        Ok(Some(_)) => true,
        _ => false,
    }
}

/// Opens stream 1 to `web-01` and waits for its `OpenAck`.
async fn open(ch: &mut Established<DuplexStream>) {
    let t = common::timeouts();
    ch.send(
        &Frame::Open {
            stream: common::sid(1),
            target: common::node("web-01"),
        },
        &t,
    )
    .await
    .unwrap();
    loop {
        match ch.recv().await.unwrap().unwrap() {
            Frame::OpenAck { .. } => return,
            Frame::Reject { reason, .. } => panic!("rejected: {reason:?}"),
            _ => {}
        }
    }
}

fn gauge(m: &RelayMetrics, name: &str) -> f64 {
    Snapshot::parse(&m.render())
        .unwrap()
        .get(name, &[])
        .unwrap()
}

/// Samples `tcn_relay_queue_bytes` every 5 ms into `max` until `stop`.
fn sample_queue(m: Arc<RelayMetrics>, max: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            let q = gauge(&m, "tcn_relay_queue_bytes") as u64;
            max.fetch_max(q, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
}

/// R6-E1: an authorized client that stops reading makes the relay queue the agent's data for
/// it; past the global budget that connection, the largest backlog, is shed. Another client
/// downloading at the same time is not affected, and the queue never runs far past the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_budget_sheds_the_slowest_reader() {
    let agent = Identity::generate().unwrap();
    let slow = Identity::generate().unwrap();
    let good = Identity::generate().unwrap();
    let budget = 192 * 1024;
    let (net, relay, metrics) = duplex_relay(&agent, &[&slow, &good], budget).await;
    let agent_ch = connect(&net, 1024 * 1024, &agent, relay).await;
    tokio::spawn(flooding_agent(agent_ch));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (max, stop) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    sample_queue(Arc::clone(&metrics), Arc::clone(&max), Arc::clone(&stop));

    // The slow reader: a pipe of 4 KiB that it never reads after the OpenAck.
    let mut slow_ch = connect(&net, 4 * 1024, &slow, relay).await;
    open(&mut slow_ch).await;

    // The good reader downloads 4 MiB, returning credit as it goes.
    let mut good_ch = connect(&net, 1024 * 1024, &good, relay).await;
    open(&mut good_ch).await;
    let t = common::timeouts();
    let (mut received, mut unreturned) = (0_usize, 0_usize);
    let download = async {
        while received < 4 * 1024 * 1024 {
            match good_ch.recv().await.unwrap().unwrap() {
                Frame::Data { payload, .. } => {
                    received += payload.len();
                    unreturned += payload.len();
                    if unreturned >= 64 * 1024 {
                        let credit = Credit::try_from(unreturned as u32).unwrap();
                        good_ch
                            .send(
                                &Frame::WindowUpdate {
                                    stream: common::sid(1),
                                    credit,
                                },
                                &t,
                            )
                            .await
                            .unwrap();
                        unreturned = 0;
                    }
                }
                Frame::Close { reason, .. } => panic!("good reader closed: {reason:?}"),
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), download)
        .await
        .expect("the good reader was starved");

    // The slow reader was shed: reading now drains its pipe, then the connection ends.
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match slow_ch.recv().await {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return,
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the slow reader is still connected");
    stop.store(true, Ordering::Relaxed);
    assert!(gauge(&metrics, "tcn_relay_queue_shed_total") >= 1.0);
    let peak = max.load(Ordering::Relaxed) as usize;
    assert!(
        peak <= budget + 2 * (CHUNK + 512),
        "queue peaked at {peak} bytes, budget {budget}"
    );
}

/// R6-E2 (G11): a client that never reads but keeps granting credit cannot make the relay queue
/// more than the flow-control bound for it: while a write to it blocks, the relay does not read
/// its `WindowUpdate`s either. A refactor that splits reading and writing into two tasks would
/// let this queue grow without bound (the global budget is set out of the way here).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_queue_never_exceeds_credit_while_writes_block() {
    let agent = Identity::generate().unwrap();
    let greedy = Identity::generate().unwrap();
    let (net, relay, metrics) = duplex_relay(&agent, &[&greedy], 1 << 30).await;
    let agent_ch = connect(&net, 1024 * 1024, &agent, relay).await;
    tokio::spawn(flooding_agent(agent_ch));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (max, stop) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    sample_queue(Arc::clone(&metrics), Arc::clone(&max), Arc::clone(&stop));
    let mut ch = connect(&net, 4 * 1024, &greedy, relay).await;
    open(&mut ch).await;
    let t = zt_net::Timeouts {
        write: Duration::from_millis(50),
        ..common::timeouts()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let update = Frame::WindowUpdate {
            stream: common::sid(1),
            credit: Credit::try_from(CHUNK as u32).unwrap(),
        };
        // A blocked write (the relay stopped reading) times out; keep trying.
        let _ = ch.send(&update, &t).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop.store(true, Ordering::Relaxed);
    let peak = max.load(Ordering::Relaxed);
    assert!(peak > 0, "the relay's queue accounting saw nothing");
    assert!(
        peak <= u64::from(MAX_WINDOW + INITIAL_WINDOW),
        "the relay queued {peak} bytes for a client that does not read"
    );
}

/// One client holding a bulk stream must not starve the others of the agent's budget: window
/// growth stops at three quarters of it, so new streams still get their initial window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_bulk_stream_cannot_starve_new_streams() {
    let hog = Arc::new(Identity::generate().unwrap());
    let other = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let metrics = AgentMetrics::new(1);
    let budget = 4 * INITIAL_WINDOW as usize;
    let lab = observed::start_observed_with(
        Arc::clone(&agent),
        vec![(
            common::relay_policy(
                &agent.fingerprint(),
                &[hog.fingerprint(), other.fingerprint()],
                CertTrust::default(),
            ),
            common::relay_config(),
        )],
        common::agent_clients(
            &[hog.fingerprint(), other.fingerprint()],
            CertTrust::default(),
        ),
        zt_net::agent::Observed {
            metrics: Arc::clone(&metrics),
            buffer_budget: budget,
        },
    )
    .await;
    // The hog uploads as fast as it can for the whole test, over a long fat pipe that makes the
    // agent want to grow its window.
    let proxy = latency::proxy(lab.relays[0].addr, Duration::from_millis(20)).await;
    let mut config = lab.config(None);
    config.relays[0].address = proxy.to_string();
    let (mut hog_app, _hog_task) = lab.session_with(&hog, config).await.unwrap();
    let pump = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut rd, mut wr) = tokio::io::split(&mut hog_app);
        let junk = vec![1_u8; 64 * 1024];
        let sink = async {
            let mut buf = vec![0_u8; 64 * 1024];
            while rd.read(&mut buf).await.is_ok_and(|n| n > 0) {}
        };
        let source = async { while wr.write_all(&junk).await.is_ok() {} };
        tokio::join!(sink, source);
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    let used = snap.get("tcn_agent_buffer_bytes", &[]).unwrap() as usize;
    assert!(
        used <= budget - budget / 4,
        "the hog holds {used} of {budget}"
    );
    assert!(
        snap.get("tcn_agent_window_grows_total", &[]).unwrap() >= 1.0,
        "the hog's window never grew: the test proves nothing"
    );
    // Another client still gets sessions (an initial window each, from the reserve).
    let (_a, _ta) = lab.session(&other, None).await.unwrap();
    pump.abort();
}
