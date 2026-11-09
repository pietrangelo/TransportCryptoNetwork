use thiserror::Error;
use zt_crypto::CryptoError;
use zt_domain::{CloseReason, RejectReason};
use zt_proto::DecodeError;

/// Error of the network adapters.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetError {
    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// An operation exceeded its timeout.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// Handshake or encryption failed.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// Malformed frame.
    #[error("protocol: {0}")]
    Decode(#[from] DecodeError),
    /// The peer violated the protocol.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The connection was closed.
    #[error("connection closed")]
    Closed,
    /// The relay or the agent rejected the stream.
    #[error("stream rejected: {0:?}")]
    Rejected(RejectReason),
    /// The stream was closed by the other side.
    #[error("stream closed: {0:?}")]
    StreamClosed(CloseReason),
}
