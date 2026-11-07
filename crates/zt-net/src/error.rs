use thiserror::Error;
use zt_crypto::CryptoError;
use zt_domain::{CloseReason, RejectReason};
use zt_proto::DecodeError;

/// Errore degli adapter di rete.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetError {
    /// Errore di I/O.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Un'operazione ha superato il suo timeout.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// Handshake o cifratura falliti.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// Frame malformato.
    #[error("protocol: {0}")]
    Decode(#[from] DecodeError),
    /// Il peer ha violato il protocollo.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// La connessione si è chiusa.
    #[error("connection closed")]
    Closed,
    /// Il relay o l'agent hanno rifiutato lo stream.
    #[error("stream rejected: {0:?}")]
    Rejected(RejectReason),
    /// Lo stream è stato chiuso dall'altra parte.
    #[error("stream closed: {0:?}")]
    StreamClosed(CloseReason),
}
