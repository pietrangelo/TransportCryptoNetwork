//! A TCP proxy that adds latency: a long fat pipe on localhost (R-6 window tuning).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A TCP proxy that delays every chunk by `delay` in each direction: a long fat pipe on
/// localhost.
pub async fn proxy(target: SocketAddr, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((inbound, _)) = listener.accept().await else {
                return;
            };
            let Ok(outbound) = TcpStream::connect(target).await else {
                continue;
            };
            let (ri, wi) = inbound.into_split();
            let (ro, wo) = outbound.into_split();
            tokio::spawn(delayed(ri, wo, delay));
            tokio::spawn(delayed(ro, wi, delay));
        }
    });
    addr
}

async fn delayed(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((due, chunk)) = rx.recv().await {
            tokio::time::sleep_until(due).await;
            if to.write_all(&chunk).await.is_err() {
                return;
            }
        }
    });
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let due = tokio::time::Instant::now() + delay;
                if tx.send((due, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
        }
    }
}
