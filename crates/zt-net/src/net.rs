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
