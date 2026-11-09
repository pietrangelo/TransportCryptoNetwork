//! An in-memory network for the relay: every connection is a `tokio::io::duplex` pipe whose
//! buffer size the test chooses, so a peer that stops reading blocks the relay's writes at
//! once (a loopback socket would absorb megabytes first).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::io::DuplexStream;
use tokio::sync::{Mutex, mpsc};
use zt_net::net::Acceptor;

/// The relay's side: accepted pipes.
pub struct DuplexAcceptor {
    rx: mpsc::UnboundedReceiver<(DuplexStream, SocketAddr)>,
}

impl Acceptor for DuplexAcceptor {
    type Stream = DuplexStream;

    async fn accept(&mut self) -> std::io::Result<(DuplexStream, SocketAddr)> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("network closed"))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("10.0.0.1:7443".parse().unwrap())
    }
}

/// The peers' side: opens pipes to the relay.
#[derive(Clone)]
pub struct DuplexNet {
    tx: mpsc::UnboundedSender<(DuplexStream, SocketAddr)>,
    next_host: Arc<AtomicU8>,
}

impl DuplexNet {
    pub fn new() -> (Self, DuplexAcceptor) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                tx,
                next_host: Arc::new(AtomicU8::new(2)),
            },
            DuplexAcceptor { rx },
        )
    }

    /// A new connection to the relay, from its own address, with `buffer` bytes in each
    /// direction.
    pub fn connect(&self, buffer: usize) -> DuplexStream {
        let (ours, theirs) = tokio::io::duplex(buffer);
        let host = self.next_host.fetch_add(1, Ordering::Relaxed);
        let addr: SocketAddr = format!("10.0.1.{host}:40000").parse().unwrap();
        self.tx.send((theirs, addr)).unwrap();
        ours
    }
}

/// Keeps a value alive for the test without using it.
pub type Hold<T> = Arc<Mutex<T>>;
