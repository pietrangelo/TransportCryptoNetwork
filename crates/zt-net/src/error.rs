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
    /// A message longer than the receiver accepts at this point (for example a message 1
    /// over the largest legitimate one, PROTOCOL §10.1).
    #[error("message too large")]
    Oversized,
    /// Invalid admission limits (PROTOCOL §10.1).
    #[error("invalid admission limits: {0}")]
    Admission(#[from] zt_application::admission::AdmissionConfigError),
    /// A handshake suite set this build cannot run (PROTOCOL §7.5).
    #[error("handshake suites: {0}")]
    Suite(#[from] zt_domain::SuiteError),
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
