use core::num::NonZeroU32;

use crate::error::DomainError;
use crate::ids::{NodeId, StreamId};
use crate::payload::FramePayload;

/// Tipo di un frame (la «T» di TLV). Il valore numerico è il codice sul filo.
///
/// L'insieme è **chiuso**: un codice sconosciuto è un errore di protocollo fatale, non un frame
/// da ignorare. Nessuna estensione silenziosa: l'evoluzione passa dal byte di versione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameKind {
    /// agent → relay: annuncia il nome logico del nodo (stream 0).
    Register = 0x01,
    /// client → relay → agent: apre uno stream verso un nodo.
    Open = 0x02,
    /// agent → relay → client: lo stream è stato accettato.
    OpenAck = 0x03,
    /// relay/agent → client: lo stream è stato rifiutato.
    Reject = 0x04,
    /// Dati opachi cifrati end-to-end.
    Data = 0x10,
    /// Concede al peer altro credito di invio (controllo di flusso / backpressure).
    WindowUpdate = 0x11,
    /// Chiude uno stream.
    Close = 0x12,
    /// Keepalive (stream 0).
    Ping = 0x20,
    /// Risposta al keepalive (stream 0).
    Pong = 0x21,
}

impl FrameKind {
    /// Tutti i tipi, in ordine di codice.
    pub const ALL: [Self; 9] = [
        Self::Register,
        Self::Open,
        Self::OpenAck,
        Self::Reject,
        Self::Data,
        Self::WindowUpdate,
        Self::Close,
        Self::Ping,
        Self::Pong,
    ];

    /// Il codice sul filo.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Il tipo corrispondente a un codice, se esiste.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x01 => Self::Register,
            0x02 => Self::Open,
            0x03 => Self::OpenAck,
            0x04 => Self::Reject,
            0x10 => Self::Data,
            0x11 => Self::WindowUpdate,
            0x12 => Self::Close,
            0x20 => Self::Ping,
            0x21 => Self::Pong,
            _ => return None,
        })
    }

    /// `true` se il frame appartiene a uno stream (`stream_id != 0`),
    /// `false` se è un frame di controllo della connessione (`stream_id == 0`).
    #[must_use]
    pub const fn is_stream_scoped(self) -> bool {
        !matches!(self, Self::Register | Self::Ping | Self::Pong)
    }
}

/// Motivo del rifiuto di un `Open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RejectReason {
    /// Il client non è autorizzato verso quel nodo (whitelist).
    NotAuthorized = 0x01,
    /// Nessun nodo registrato con quel nome.
    UnknownNode = 0x02,
    /// Il nodo è noto ma non connesso.
    NodeOffline = 0x03,
    /// Troppe richieste.
    RateLimited = 0x04,
    /// Limite di stream o memoria raggiunto.
    ResourceExhausted = 0x05,
}

impl TryFrom<u8> for RejectReason {
    type Error = DomainError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Ok(match code {
            0x01 => Self::NotAuthorized,
            0x02 => Self::UnknownNode,
            0x03 => Self::NodeOffline,
            0x04 => Self::RateLimited,
            0x05 => Self::ResourceExhausted,
            other => return Err(DomainError::UnknownRejectReason(other)),
        })
    }
}

/// Motivo della chiusura di uno stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CloseReason {
    /// Chiusura ordinata (EOF di una delle due parti).
    Normal = 0x00,
    /// Timeout di inattività o di I/O.
    Timeout = 0x01,
    /// Il peer ha violato il protocollo.
    ProtocolViolation = 0x02,
    /// Il nodo è in drain (manutenzione o shutdown).
    Drained = 0x03,
    /// L'altra estremità dello stream è scomparsa.
    PeerGone = 0x04,
}

impl TryFrom<u8> for CloseReason {
    type Error = DomainError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Ok(match code {
            0x00 => Self::Normal,
            0x01 => Self::Timeout,
            0x02 => Self::ProtocolViolation,
            0x03 => Self::Drained,
            0x04 => Self::PeerGone,
            other => return Err(DomainError::UnknownCloseReason(other)),
        })
    }
}

/// Credito di controllo di flusso: quanti byte di `Data` il peer può ancora inviare.
/// Sempre `> 0`: un aggiornamento nullo è rifiutato.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Credit(NonZeroU32);

impl Credit {
    /// Il valore numerico (sempre `> 0`).
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for Credit {
    type Error = DomainError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(raw)
            .map(Self)
            .ok_or(DomainError::CreditZero)
    }
}

/// Un messaggio del protocollo TCN, dopo l'handshake.
///
/// Ogni variante contiene solo value object già validati: se un `Frame` esiste, è valido.
/// Per questo l'encoder è infallibile e il decoder è l'unico punto in cui si rifiuta input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Annuncio del nome logico dell'agent (l'identità vera è la chiave Noise statica).
    Register {
        /// Nome dichiarato, da verificare contro la whitelist chiave→nome.
        node: NodeId,
    },
    /// Richiesta di apertura di uno stream verso `target`.
    Open {
        /// Stream scelto dall'iniziatore.
        stream: StreamId,
        /// Nodo di destinazione.
        target: NodeId,
    },
    /// Stream accettato.
    OpenAck {
        /// Lo stream accettato.
        stream: StreamId,
    },
    /// Stream rifiutato.
    Reject {
        /// Lo stream rifiutato.
        stream: StreamId,
        /// Il motivo.
        reason: RejectReason,
    },
    /// Dati opachi.
    Data {
        /// Lo stream.
        stream: StreamId,
        /// I byte cifrati end-to-end.
        payload: FramePayload,
    },
    /// Nuovo credito di invio per lo stream.
    WindowUpdate {
        /// Lo stream.
        stream: StreamId,
        /// Byte aggiuntivi concessi.
        credit: Credit,
    },
    /// Chiusura dello stream.
    Close {
        /// Lo stream.
        stream: StreamId,
        /// Il motivo.
        reason: CloseReason,
    },
    /// Keepalive.
    Ping {
        /// Valore da restituire nel `Pong`.
        nonce: u64,
    },
    /// Risposta al keepalive.
    Pong {
        /// Il `nonce` del `Ping`.
        nonce: u64,
    },
}

impl Frame {
    /// Il tipo del frame.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        match self {
            Self::Register { .. } => FrameKind::Register,
            Self::Open { .. } => FrameKind::Open,
            Self::OpenAck { .. } => FrameKind::OpenAck,
            Self::Reject { .. } => FrameKind::Reject,
            Self::Data { .. } => FrameKind::Data,
            Self::WindowUpdate { .. } => FrameKind::WindowUpdate,
            Self::Close { .. } => FrameKind::Close,
            Self::Ping { .. } => FrameKind::Ping,
            Self::Pong { .. } => FrameKind::Pong,
        }
    }

    /// Lo stream del frame, o `None` per i frame di controllo della connessione.
    #[must_use]
    pub const fn stream(&self) -> Option<StreamId> {
        match self {
            Self::Open { stream, .. }
            | Self::OpenAck { stream }
            | Self::Reject { stream, .. }
            | Self::Data { stream, .. }
            | Self::WindowUpdate { stream, .. }
            | Self::Close { stream, .. } => Some(*stream),
            Self::Register { .. } | Self::Ping { .. } | Self::Pong { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn kind_codes_round_trip_and_are_unique() {
        for kind in FrameKind::ALL {
            assert_eq!(FrameKind::from_code(kind.code()), Some(kind));
        }
        let known = (0..=u8::MAX).filter_map(FrameKind::from_code).count();
        assert_eq!(known, FrameKind::ALL.len());
    }

    #[test]
    fn stream_scope_matches_frame_stream() {
        let node = NodeId::try_from("web-01").unwrap();
        let stream = StreamId::try_from(1).unwrap();
        let control = [
            Frame::Register { node: node.clone() },
            Frame::Ping { nonce: 1 },
        ];
        let scoped = [
            Frame::Open {
                stream,
                target: node,
            },
            Frame::OpenAck { stream },
        ];
        for f in control {
            assert!(!f.kind().is_stream_scoped());
            assert_eq!(f.stream(), None);
        }
        for f in scoped {
            assert!(f.kind().is_stream_scoped());
            assert_eq!(f.stream(), Some(stream));
        }
    }

    #[test]
    fn unknown_reason_codes_are_rejected() {
        assert_eq!(
            RejectReason::try_from(0x00),
            Err(DomainError::UnknownRejectReason(0))
        );
        assert_eq!(
            CloseReason::try_from(0xff),
            Err(DomainError::UnknownCloseReason(0xff))
        );
        assert_eq!(Credit::try_from(0), Err(DomainError::CreditZero));
    }
}
