//! R-6 efficiency, specification (resilience.md §5.6, review 0007 AP-22 and D-13): a global
//! byte budget for buffered stream data on the agent (reservations: backpressure, never an
//! out-of-memory) and on the relay (queued bytes, see `budget_attacks.rs`), receive-window
//! auto-tuning inside that budget, fewer copies per frame without reopening finding 0001-10.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]

mod common;
mod latency;
mod observed;

use std::sync::Arc;
use std::time::Duration;

use common::{agent_clients, relay_config, relay_policy};
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW};
use zt_domain::trust::CertTrust;
use zt_domain::{Frame, FramePayload, RejectReason};
use zt_net::NetError;
use zt_net::agent::Observed;
use zt_net::budget::ByteBudget;
use zt_net::channel;
use zt_net::metrics::{AgentMetrics, RelayMetrics, Snapshot};

// ---------------------------------------------------------------------------------------------
// ByteBudget
// ---------------------------------------------------------------------------------------------

#[test]
fn reservations_are_bounded_and_released_on_drop() {
    let b = ByteBudget::new(1000);
    let r1 = b.try_reserve(600).unwrap();
    assert_eq!(b.used(), 600);
    assert!(b.try_reserve(500).is_none(), "over the limit");
    let r2 = b.try_reserve(400).unwrap();
    assert_eq!(b.used(), 1000);
    drop(r1);
    assert_eq!(b.used(), 400);
    drop(r2);
    assert_eq!(b.used(), 0);
}

/// Growth never eats the last quarter of the budget: that part is kept for the initial windows
/// of new streams, so one bulk stream cannot starve the others (AP-22).
#[test]
fn growth_stops_at_three_quarters_of_the_budget() {
    let b = ByteBudget::new(1000);
    let mut r = b.try_reserve(500).unwrap();
    assert!(r.try_grow(250));
    assert_eq!(r.bytes(), 750);
    assert!(!r.try_grow(1), "the reserve is for new streams");
    // A new stream may still take its initial window from the reserve.
    let r2 = b.try_reserve(250).unwrap();
    assert_eq!(b.used(), 1000);
    drop((r, r2));
    assert_eq!(b.used(), 0);
}

/// Charges (the relay's queued bytes) are counted whatever the limit, and released on drop.
#[test]
fn charges_are_counted_and_released() {
    let b = ByteBudget::new(100);
    let c1 = b.charge(80);
    let c2 = b.charge(80);
    assert_eq!(b.used(), 160);
    assert!(b.exceeded());
    drop(c1);
    assert!(!b.exceeded());
    drop(c2);
    assert_eq!(b.used(), 0);
}

/// Concurrent reservations never exceed the limit.
#[test]
fn concurrent_reservations_never_exceed_the_limit() {
    let b = ByteBudget::new(10_000);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let b = Arc::clone(&b);
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for i in 0..10_000 {
                    if let Some(r) = b.try_reserve(97) {
                        assert!(b.used() <= b.limit());
                        held.push(r);
                    }
                    if i % 3 == 0 {
                        held.pop();
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(b.used(), 0);
}

/// The relay's default: a quarter of the memory, at most 1 GiB, at least 64 MiB.
#[test]
fn the_default_queue_budget_follows_the_memory() {
    let d = zt_net::budget::default_queue_budget();
    assert!(d >= 64 * 1024 * 1024 && d <= 1024 * 1024 * 1024, "{d}");
    assert_eq!(
        zt_net::budget::queue_budget_for(Some(16 * 1024 * 1024 * 1024)),
        1024 * 1024 * 1024
    );
    assert_eq!(
        zt_net::budget::queue_budget_for(Some(1024 * 1024 * 1024)),
        256 * 1024 * 1024
    );
    assert_eq!(
        zt_net::budget::queue_budget_for(Some(64 * 1024 * 1024)),
        64 * 1024 * 1024
    );
    assert_eq!(zt_net::budget::queue_budget_for(None), 1024 * 1024 * 1024);
}

// ---------------------------------------------------------------------------------------------
// Agent: initial windows come from the budget (backpressure)
// ---------------------------------------------------------------------------------------------

/// A stream whose initial window does not fit in the agent's budget is rejected with
/// `ResourceExhausted` before anything is buffered; the budget comes back when a session ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_beyond_the_agent_budget_are_rejected_then_admitted_again() {
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let metrics = AgentMetrics::new(1);
    let lab = observed::start_observed_with(
        Arc::clone(&agent),
        vec![(
            relay_policy(
                &agent.fingerprint(),
                &[client.fingerprint()],
                CertTrust::default(),
            ),
            relay_config(),
        )],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        Observed {
            metrics: Arc::clone(&metrics),
            buffer_budget: 2 * INITIAL_WINDOW as usize,
        },
    )
    .await;
    let (a, _ta) = lab.session(&client, None).await.unwrap();
    let (_b, _tb) = lab.session(&client, None).await.unwrap();
    let refused = lab.refused(&client, None).await;
    assert!(
        matches!(
            refused,
            Err(NetError::Rejected(RejectReason::ResourceExhausted))
        ),
        "{refused:?}"
    );
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    assert_eq!(
        snap.get("tcn_agent_buffer_bytes", &[]),
        Some(f64::from(2 * INITIAL_WINDOW))
    );
    assert_eq!(
        snap.get("tcn_agent_buffer_budget_bytes", &[]),
        Some(f64::from(2 * INITIAL_WINDOW))
    );
    assert!(snap.get("tcn_agent_buffer_refusals_total", &[]).unwrap() >= 1.0);
    drop(a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_c, _tc) = lab.session(&client, None).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Window auto-tuning
// ---------------------------------------------------------------------------------------------

/// Uploads `total` bytes through a client whose relay link has `delay` each way, and checks the
/// echo is byte for byte.
async fn bulk_upload(lab: &common::Lab, client: &Arc<Identity>, delay: Duration, total: usize) {
    let proxy = latency::proxy(lab.relays[0].addr, delay).await;
    let mut config = lab.config(None);
    config.relays[0].address = proxy.to_string();
    let (mut app, local) = tokio::io::duplex(256 * 1024);
    let task = {
        let client = Arc::clone(client);
        tokio::spawn(async move { zt_net::client::connect(&client, &config, local).await })
    };
    let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let (mut rd, mut wr) = tokio::io::split(&mut app);
    let send = async {
        wr.write_all(&data).await.unwrap();
    };
    let mut echoed = vec![0_u8; total];
    let recv = async {
        rd.read_exact(&mut echoed).await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(60), async { tokio::join!(send, recv) })
        .await
        .expect("bulk transfer too slow");
    assert!(echoed == data, "echo differs");
    drop(app);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// R6-E4: on a long fat pipe the agent's receive window grows past the initial window (the
/// sender ran it dry while the agent kept up), within the budget and never past `MAX_WINDOW`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_window_grows_on_a_long_fat_pipe() {
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let metrics = AgentMetrics::new(1);
    let lab = observed::start_observed(
        Arc::clone(&agent),
        vec![(
            relay_policy(
                &agent.fingerprint(),
                &[client.fingerprint()],
                CertTrust::default(),
            ),
            relay_config(),
        )],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        Arc::clone(&metrics),
    )
    .await;
    bulk_upload(&lab, &client, Duration::from_millis(20), 8 * 1024 * 1024).await;
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    assert!(
        snap.get("tcn_agent_window_grows_total", &[]).unwrap() >= 1.0,
        "{}",
        metrics.render()
    );
}

/// Inside a budget with no room above the initial windows the window never grows, and the
/// transfer still completes: the budget is backpressure, not an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_budget_room_the_window_stays_and_the_transfer_completes() {
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let metrics = AgentMetrics::new(1);
    let lab = observed::start_observed_with(
        Arc::clone(&agent),
        vec![(
            relay_policy(
                &agent.fingerprint(),
                &[client.fingerprint()],
                CertTrust::default(),
            ),
            relay_config(),
        )],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        Observed {
            metrics: Arc::clone(&metrics),
            // One initial window fits, any growth would cut into the reserve.
            buffer_budget: INITIAL_WINDOW as usize + INITIAL_WINDOW as usize / 4,
        },
    )
    .await;
    bulk_upload(&lab, &client, Duration::from_millis(20), 2 * 1024 * 1024).await;
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    assert_eq!(snap.get("tcn_agent_window_grows_total", &[]), Some(0.0));
    assert!(snap.get("tcn_agent_buffer_refusals_total", &[]).unwrap() >= 1.0);
}

/// The relay reports its queue budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_reports_its_queue_budget() {
    let agent = Identity::generate().unwrap();
    let metrics = RelayMetrics::new();
    let mut config = relay_config();
    config.metrics = Arc::clone(&metrics);
    config.queue_budget = 3 * 1024 * 1024;
    let _relay = common::start_relay_with(
        relay_policy(&agent.fingerprint(), &[], CertTrust::default()),
        config,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = Snapshot::parse(&metrics.render()).unwrap();
    assert_eq!(
        snap.get("tcn_relay_queue_budget_bytes", &[]),
        Some(3.0 * 1024.0 * 1024.0)
    );
    assert_eq!(snap.get("tcn_relay_queue_bytes", &[]), Some(0.0));
}

// ---------------------------------------------------------------------------------------------
// Fewer copies, same frames (R6-E3), and finding 0001-10
// ---------------------------------------------------------------------------------------------

/// A pair of established channels over an in-memory pipe.
async fn pair() -> (
    channel::Established<tokio::io::DuplexStream>,
    channel::Established<tokio::io::DuplexStream>,
) {
    let (a, b) = tokio::io::duplex(1024 * 1024);
    let server = Identity::generate().unwrap();
    let client = Identity::generate().unwrap();
    let keys = zt_crypto::Keyring::single(common::copy_of(&server));
    let t = common::timeouts();
    let accept = async {
        channel::accept(b, &keys, Channel::Outer, &t)
            .await
            .unwrap()
            .establish(&t)
            .await
            .unwrap()
    };
    let connect = async {
        channel::connect(a, &client, &server.public_key().into(), Channel::Outer, &t)
            .await
            .unwrap()
    };
    let (s, c) = tokio::join!(accept, connect);
    (c, s)
}

/// Finding 0001-10, closed: a small `Data` payload received and queued keeps only its own
/// message's memory alive, never a shared read buffer.
#[tokio::test]
async fn a_small_payload_pins_only_its_own_message() {
    let (mut c, mut s) = pair().await;
    let t = common::timeouts();
    for _ in 0..64 {
        c.send(
            &Frame::Data {
                stream: common::sid(1),
                payload: FramePayload::try_from(vec![7_u8]).unwrap(),
            },
            &t,
        )
        .await
        .unwrap();
    }
    let mut kept = Vec::new();
    for _ in 0..64 {
        let Some(Frame::Data { payload, .. }) = s.recv().await.unwrap() else {
            panic!("expected data");
        };
        kept.push(payload.into_bytes());
    }
    for bytes in kept {
        // Unique (no other frame shares it) and backed by at most its own message.
        let owned = bytes.try_into_mut().expect("payload shares its buffer");
        assert!(
            owned.capacity() <= 1 + zt_domain::limits::FRAME_HEADER_LEN,
            "a 1-byte payload keeps {} bytes alive",
            owned.capacity()
        );
    }
}

fn arb_frame() -> impl Strategy<Value = Frame> {
    let stream = (1_u32..1000).prop_map(|n| common::sid(n));
    prop_oneof![
        (
            stream.clone(),
            proptest::collection::vec(any::<u8>(), 0..20_000)
        )
            .prop_map(|(stream, p)| Frame::Data {
                stream,
                payload: FramePayload::try_from(p).unwrap(),
            }),
        (stream.clone(), 512_u32..MAX_WINDOW).prop_map(|(stream, c)| Frame::WindowUpdate {
            stream,
            credit: zt_domain::Credit::try_from(c).unwrap(),
        }),
        (stream, "[a-z][a-z0-9-]{0,20}").prop_map(|(stream, n)| Frame::Open {
            stream,
            target: common::node(&n),
        }),
        any::<u64>().prop_map(|nonce| Frame::Ping { nonce }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    /// R6-E3: whatever the send and receive paths do with their buffers, every frame arrives
    /// exactly as sent, in order.
    #[test]
    fn frames_survive_the_channel_unchanged(frames in proptest::collection::vec(arb_frame(), 1..16)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (mut c, mut s) = pair().await;
            let t = common::timeouts();
            for f in &frames {
                c.send(f, &t).await.unwrap();
            }
            for f in &frames {
                let got = s.recv().await.unwrap().unwrap();
                assert_eq!(&got, f);
            }
        });
    }
}
