//! # zt-proto
//!
//! Adapter del wire format di TCN: traduce byte ⇄ [`Frame`] di dominio.
//!
//! Il cuore è **sans-IO** ([`FrameDecoder`], [`encode`]): lavora su buffer in memoria, non
//! conosce socket né runtime, ed è quindi testabile in modo deterministico. L'adapter per
//! `tokio-util` (feature `codec`) è un sottile strato sopra di esso.
#![forbid(unsafe_code)]

use bytes::BytesMut;
use thiserror::Error;
use zt_domain::{DomainError, Frame, FrameKind};

/// Errore di decodifica (RED: stub, implementazione in arrivo).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// Versione non supportata.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    /// Tipo sconosciuto.
    #[error("unknown kind {0}")]
    UnknownKind(u8),
    /// Stream richiesto.
    #[error("stream required {0:?}")]
    StreamIdRequired(FrameKind),
    /// Stream vietato.
    #[error("stream forbidden {0:?}")]
    StreamIdForbidden(FrameKind),
    /// Lunghezza fuori limite.
    #[error("length")]
    LengthOutOfBounds {
        /// Tipo.
        kind: FrameKind,
        /// Lunghezza.
        len: usize,
        /// Minimo.
        min: usize,
        /// Massimo.
        max: usize,
    },
    /// Invariante di dominio violata.
    #[error("invalid {0}")]
    Invalid(#[from] DomainError),
    /// Decoder avvelenato.
    #[error("poisoned")]
    Poisoned,
    /// I/O.
    #[error("io")]
    Io(String),
}

/// Decoder (RED: stub).
#[derive(Debug, Default)]
pub struct FrameDecoder;

impl FrameDecoder {
    /// Nuovo decoder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
    /// Decodifica (RED: non decodifica nulla).
    ///
    /// # Errors
    /// Mai, per ora.
    pub fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Frame>, DecodeError> {
        Ok(None)
    }
    /// Avvelenato?
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        false
    }
}

/// Encoder (RED: stub).
pub fn encode(_frame: &Frame, _dst: &mut BytesMut) {}

/// Lunghezza codificata (RED: stub).
#[must_use]
pub fn encoded_len(_frame: &Frame) -> usize {
    0
}

/// Costanti del filo (RED: stub).
pub mod wire {
    use zt_domain::FrameKind;
    /// Limiti di lunghezza (RED: stub).
    #[must_use]
    pub fn length_bounds(_kind: FrameKind) -> (usize, usize) {
        (0, 0)
    }
}

/// Adapter tokio-util (RED: stub).
#[cfg(feature = "codec")]
pub mod codec {
    impl From<std::io::Error> for super::DecodeError {
        fn from(e: std::io::Error) -> Self { Self::Io(e.to_string()) }
    }
    /// Codec (RED: stub).
    #[derive(Debug, Default)]
    pub struct FrameCodec;
    impl tokio_util::codec::Decoder for FrameCodec {
        type Item = zt_domain::Frame;
        type Error = super::DecodeError;
        fn decode(&mut self, _s: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            Ok(None)
        }
    }
    impl tokio_util::codec::Encoder<zt_domain::Frame> for FrameCodec {
        type Error = super::DecodeError;
        fn encode(&mut self, _f: zt_domain::Frame, _d: &mut bytes::BytesMut) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
