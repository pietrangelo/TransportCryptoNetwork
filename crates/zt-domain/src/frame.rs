use core::num::NonZeroU32;

use crate::error::DomainError;
use crate::ids::{NodeId, StreamId};
use crate::payload::FramePayload;

/// Type of a frame (the "T" in TLV). The numeric value is the code on the wire.
///
/// The set is **closed**: an unknown code is a fatal protocol error, not a frame to be
/// ignored. No silent extensions: evolution goes through the version byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameKind {
    /// agent → relay: announces the node's logical name (stream 0).
    Register = 0x01,
    /// client → relay → agent: opens a stream towards a node.
    Open = 0x02,
    /// agent → relay → client: the stream has been accepted.
    OpenAck = 0x03,
    /// relay/agent → client: the stream has been rejected.
    Reject = 0x04,
    /// Opaque end-to-end encrypted data.
    Data = 0x10,
    /// Grants the peer more send credit (flow control / backpressure).
    WindowUpdate = 0x11,
    /// Closes a stream.
    Close = 0x12,
    /// Keepalive (stream 0).
    Ping = 0x20,
    /// Keepalive reply (stream 0).
    Pong = 0x21,
}

impl FrameKind {
    /// All types, in code order.
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

    /// The code on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The type corresponding to a code, if any.
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

    /// `true` if the frame belongs to a stream (`stream_id != 0`),
    /// `false` if it is a connection control frame (`stream_id == 0`).
    #[must_use]
    pub const fn is_stream_scoped(self) -> bool {
        !matches!(self, Self::Register | Self::Ping | Self::Pong)
    }
}

/// Reason for rejecting an `Open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RejectReason {
    /// The client is not authorized for that node (whitelist).
    NotAuthorized = 0x01,
    /// No node registered with that name.
    UnknownNode = 0x02,
    /// The node is known but not connected.
    NodeOffline = 0x03,
    /// Too many requests.
    RateLimited = 0x04,
    /// Stream or memory limit reached.
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

/// Reason for closing a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CloseReason {
    /// Orderly close (EOF from one of the two sides).
    Normal = 0x00,
    /// Inactivity or I/O timeout.
    Timeout = 0x01,
    /// The peer violated the protocol.
    ProtocolViolation = 0x02,
    /// The node is draining (maintenance or shutdown).
    Drained = 0x03,
    /// The other end of the stream has gone away.
    PeerGone = 0x04,
    /// The agent rejected the client's end-to-end identity (defense in depth: the
    /// relay had authorized it, but the agent does not trust the relay).
    Unauthorized = 0x05,
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
            0x05 => Self::Unauthorized,
            other => return Err(DomainError::UnknownCloseReason(other)),
        })
    }
}

/// Flow-control credit: how many bytes of `Data` the peer may still send.
/// Always `> 0`: a zero update is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Credit(NonZeroU32);

impl Credit {
    /// The numeric value (always `> 0`).
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

/// A TCN protocol message, after the handshake.
///
/// Every variant contains only already-validated value objects: if a `Frame` exists, it is valid.
/// This is why the encoder is infallible and the decoder is the only place where input is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Announcement of the agent's logical name (the real identity is the static Noise key).
    Register {
        /// Declared name, to be checked against the key→name whitelist.
        node: NodeId,
    },
    /// Request to open a stream towards `target`.
    Open {
        /// Stream chosen by the initiator.
        stream: StreamId,
        /// Destination node.
        target: NodeId,
    },
    /// Stream accepted.
    OpenAck {
        /// The accepted stream.
        stream: StreamId,
    },
    /// Stream rejected.
    Reject {
        /// The rejected stream.
        stream: StreamId,
        /// The reason.
        reason: RejectReason,
    },
    /// Opaque data.
    Data {
        /// The stream.
        stream: StreamId,
        /// The end-to-end encrypted bytes.
        payload: FramePayload,
    },
    /// New send credit for the stream.
    WindowUpdate {
        /// The stream.
        stream: StreamId,
        /// Additional bytes granted.
        credit: Credit,
    },
    /// Stream close.
    Close {
        /// The stream.
        stream: StreamId,
        /// The reason.
        reason: CloseReason,
    },
    /// Keepalive.
    Ping {
        /// Value to echo back in the `Pong`.
        nonce: u64,
    },
    /// Keepalive reply.
    Pong {
        /// The `nonce` of the `Ping`.
        nonce: u64,
    },
}

impl Frame {
    /// The frame type.
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

    /// The frame's stream, or `None` for connection control frames.
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
