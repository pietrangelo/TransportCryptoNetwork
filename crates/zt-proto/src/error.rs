use thiserror::Error;
use zt_domain::{DomainError, FrameKind};

/// Violazione del protocollo rilevata durante la decodifica.
///
/// Ogni variante è **fatale** per la connessione: dopo un errore il
/// [`FrameDecoder`](crate::FrameDecoder) resta avvelenato. I messaggi riportano solo metadati (codici,
/// lunghezze), mai byte ricevuti, così possono finire negli audit log senza rischi.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Byte di versione diverso da [`wire::VERSION`](crate::wire::VERSION).
    #[error("unsupported protocol version {0:#04x}")]
    UnsupportedVersion(u8),
    /// Codice di tipo non definito.
    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
    /// Frame di stream ricevuto sullo stream di controllo 0.
    #[error("{0:?} frame requires a non-zero stream id")]
    StreamIdRequired(FrameKind),
    /// Frame di controllo ricevuto su uno stream diverso da 0.
    #[error("{0:?} frame must use stream id 0")]
    StreamIdForbidden(FrameKind),
    /// Lunghezza dichiarata fuori dall'intervallo ammesso per il tipo.
    #[error("{kind:?} frame declares {len} payload bytes, allowed {min}..={max}")]
    LengthOutOfBounds {
        /// Il tipo del frame.
        kind: FrameKind,
        /// La lunghezza dichiarata.
        len: usize,
        /// Minimo ammesso.
        min: usize,
        /// Massimo ammesso.
        max: usize,
    },
    /// Il payload viola un'invariante di dominio.
    #[error("invalid frame payload: {0}")]
    Invalid(#[from] DomainError),
    /// Il decoder ha già rifiutato un frame: la connessione va chiusa.
    #[error("decoder already failed; the connection must be closed")]
    Poisoned,
    /// Errore di I/O dall'adapter di trasporto (incluso EOF a metà frame).
    #[error("transport error: {0:?}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for DecodeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.kind())
    }
}
