//! R6-E3 measurement (not a gate): frames per second through an established channel over an
//! in-memory pipe, the path every relayed byte takes twice. Run with
//! `cargo test --release -p zt-net --test throughput -- --ignored --nocapture`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_precision_loss,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names
)]

mod common;

use std::time::Instant;

use zt_crypto::Identity;
use zt_crypto::noise::Channel;
use zt_domain::{Frame, FramePayload};
use zt_net::channel;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement, run by hand"]
async fn channel_throughput() {
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
    let (mut s, mut c) = tokio::join!(accept, connect);
    s.confirmed();
    for (size, frames) in [(16 * 1024, 40_000_usize), (64, 400_000)] {
        let payload = FramePayload::try_from(vec![0x42_u8; size]).unwrap();
        let frame = Frame::Data {
            stream: common::sid(1),
            payload,
        };
        let start = Instant::now();
        let send = async {
            for _ in 0..frames {
                c.send(&frame, &t).await.unwrap();
            }
        };
        let recv = async {
            for _ in 0..frames {
                s.recv().await.unwrap().unwrap();
            }
        };
        tokio::join!(send, recv);
        let secs = start.elapsed().as_secs_f64();
        println!(
            "{size:>6} B payload: {:>9.0} frames/s, {:>7.1} MiB/s",
            frames as f64 / secs,
            (frames * size) as f64 / secs / 1024.0 / 1024.0
        );
    }
}
