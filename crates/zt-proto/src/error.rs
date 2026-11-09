use thiserror::Error;
use zt_domain::{DomainError, FrameKind};

/// Protocol violation detected during decoding.
///
/// Every variant is **fatal** for the connection: after an error the
/// [`FrameDecoder`](crate::FrameDecoder) stays poisoned. Messages report only metadata (codes,
/// lengths), never received bytes, so they can safely end up in audit logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Version byte other than [`wire::VERSION`](crate::wire::VERSION).
    #[error("unsupported protocol version {0:#04x}")]
    UnsupportedVersion(u8),
    /// Undefined kind code.
    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
    /// Stream frame received on control stream 0.
    #[error("{0:?} frame requires a non-zero stream id")]
    StreamIdRequired(FrameKind),
    /// Control frame received on a stream other than 0.
    #[error("{0:?} frame must use stream id 0")]
    StreamIdForbidden(FrameKind),
    /// Declared length outside the range allowed for the kind.
    #[error("{kind:?} frame declares {len} payload bytes, allowed {min}..={max}")]
    LengthOutOfBounds {
        /// The frame kind.
        kind: FrameKind,
        /// The declared length.
        len: usize,
        /// Minimum allowed.
        min: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// The payload violates a domain invariant.
    #[error("invalid frame payload: {0}")]
    Invalid(#[from] DomainError),
    /// The decoder has already rejected a frame: the connection must be closed.
    #[error("decoder already failed; the connection must be closed")]
    Poisoned,
    /// I/O error from the transport adapter (including EOF in the middle of a frame).
    #[error("transport error: {0:?}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for DecodeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.kind())
    }
}
