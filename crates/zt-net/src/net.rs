//! The network port (docs/analysis/resilience.md §5.7, D-9): how the relay accepts and how the
//! agent and the client dial. Production uses tokio's TCP with the socket options of §5.2;
//! the tests plug in the `turmoil` simulator, so that restarts, partitions and half-open paths
//! run the real relay, agent and client deterministically.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// Unacknowledged data older than this ends the connection in the kernel
/// (`TCP_USER_TIMEOUT`): a peer that vanished without FIN is noticed on the first write,
/// faster than by any application timer.
pub const TCP_USER_TIMEOUT: Duration = Duration::from_secs(20);

/// TCP keepalive: first probe after this much silence...
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const KEEPALIVE_IDLE: Duration = Duration::from_secs(10);
/// ...then one every...
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// ...and the connection is dropped after this many unanswered probes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const KEEPALIVE_PROBES: u32 = 3;

/// Opens outbound connections.
pub trait Dialer: Clone + Send + Sync + 'static {
    /// The connected byte stream.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Connects to `addr` (`host:port`).
    fn connect(&self, addr: &str) -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
}

/// Accepts inbound connections.
pub trait Acceptor: Send + 'static {
    /// The accepted byte stream.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The next connection and its peer address.
    fn accept(
        &mut self,
    ) -> impl Future<Output = std::io::Result<(Self::Stream, SocketAddr)>> + Send;

    /// The listening address.
    ///
    /// # Errors
    /// Operating system error.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

/// tokio TCP with [`configure`] on every connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDialer;

impl Dialer for TcpDialer {
    type Stream = TcpStream;

    async fn connect(&self, addr: &str) -> std::io::Result<TcpStream> {
        let stream = TcpStream::connect(addr).await?;
        configure(&stream);
        Ok(stream)
    }
}

impl Acceptor for TcpListener {
    type Stream = TcpStream;

    async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = Self::accept(self).await?;
        configure(&stream);
        Ok((stream, addr))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Self::local_addr(self)
    }
}

/// `TCP_NODELAY`, TCP keepalive and `TCP_USER_TIMEOUT` (Linux) on `stream`. A failure only
/// leaves the kernel defaults: it is not worth refusing the connection.
pub fn configure(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(unix)]
    {
        use rustix::net::sockopt;
        let _ = sockopt::set_socket_keepalive(stream, true);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let _ = sockopt::set_tcp_keepidle(stream, KEEPALIVE_IDLE);
            let _ = sockopt::set_tcp_keepintvl(stream, KEEPALIVE_INTERVAL);
            let _ = sockopt::set_tcp_keepcnt(stream, KEEPALIVE_PROBES);
            let ms = u32::try_from(TCP_USER_TIMEOUT.as_millis()).unwrap_or(u32::MAX);
            let _ = sockopt::set_tcp_user_timeout(stream, ms);
        }
    }
}

/// The default listen backlog of the relay (`[network] listen_backlog`): the kernel's default
/// `net.core.somaxconn` since Linux 5.4, which clamps it anyway.
pub const DEFAULT_LISTEN_BACKLOG: u32 = 4096;
/// The smallest listen backlog `relay.toml` accepts (mio's former fixed value).
pub const MIN_LISTEN_BACKLOG: u32 = 128;
/// The largest listen backlog `relay.toml` accepts.
pub const MAX_LISTEN_BACKLOG: u32 = 65_535;

/// A listening TCP socket on `addr` with `SO_REUSEADDR` and the given accept `backlog`
/// (tokio's `TcpListener::bind` always asks for 128).
///
/// # Errors
/// Socket, bind or listen error.
pub fn listen(addr: SocketAddr, backlog: u32) -> std::io::Result<TcpListener> {
    let _ = backlog;
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(128)
}

/// What an `accept` error means for the accept loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptErrorKind {
    /// The process or the system is out of a resource (`EMFILE`, `ENFILE`, `ENOBUFS`,
    /// `ENOMEM`): retrying at once would spin, so the loop backs off.
    Resource,
    /// An error of one connection (`ECONNABORTED`, `EPROTO`, `EPERM`, a network error passed
    /// on by `accept(2)`): the next connection is accepted at once.
    Connection,
}

impl AcceptErrorKind {
    /// The metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Connection => "connection",
        }
    }
}

/// Classifies an `accept` error.
#[must_use]
pub fn classify_accept_error(err: &std::io::Error) -> AcceptErrorKind {
    let _ = err;
    AcceptErrorKind::Resource
}

/// The back-off of the accept loop after resource errors: 10 ms, doubled after every
/// consecutive failure up to 1 s, back to 10 ms after an accepted connection.
#[derive(Debug, Clone)]
pub struct AcceptBackoff {
    next: Duration,
}

impl AcceptBackoff {
    /// The first delay.
    pub const MIN: Duration = Duration::from_millis(10);
    /// The largest delay.
    pub const MAX: Duration = Duration::from_secs(1);

    /// A back-off at its first delay.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Self::MIN }
    }

    /// One more resource error: how long to wait before the next `accept`.
    pub fn failed(&mut self) -> Duration {
        Duration::from_millis(100)
    }

    /// A connection was accepted: the next failure waits [`Self::MIN`] again.
    pub fn succeeded(&mut self) {}
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self::new()
    }
}
