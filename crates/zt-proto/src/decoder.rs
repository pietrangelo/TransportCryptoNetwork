use bytes::{Buf, Bytes, BytesMut};
use zt_domain::{
    CloseReason, Credit, Frame, FrameKind, FramePayload, NodeId, RejectReason, StreamId,
};

use crate::error::DecodeError;
use crate::wire::{HEADER_LEN, VERSION, length_bounds};

/// Sans-IO decoder for TCN frames.
///
/// It is used in a loop: append the received bytes to a [`BytesMut`] and call
/// [`decode`](Self::decode) until it returns `Ok(Some(frame))`.
///
/// Guarantees:
/// - it does not consume bytes until a frame is complete;
/// - it validates the header (version, kind, stream, length) **before** waiting for the payload,
///   so it never reserves more than [`MAX_FRAME_LEN`](zt_domain::limits::MAX_FRAME_LEN) bytes;
/// - after the first error it is poisoned and rejects everything ([`DecodeError::Poisoned`]).
#[derive(Debug, Default)]
pub struct FrameDecoder {
    poisoned: bool,
}

/// Already-validated header.
#[derive(Debug, Clone, Copy)]
struct Header {
    kind: FrameKind,
    stream: u32,
    len: usize,
}

impl FrameDecoder {
    /// A new decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { poisoned: false }
    }

    /// `true` if the decoder has already rejected a frame.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Tries to extract the next frame from `src`.
    ///
    /// - `Ok(Some(frame))`: a frame has been consumed from `src`;
    /// - `Ok(None)`: more bytes are needed, `src` is untouched;
    /// - `Err(_)`: protocol violation, the connection must be closed.
    ///
    /// # Errors
    /// Any [`DecodeError`]; after the first one, always [`DecodeError::Poisoned`].
    pub fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, DecodeError> {
        if self.poisoned {
            return Err(DecodeError::Poisoned);
        }
        let result = Self::decode_unpoisoned(src);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn decode_unpoisoned(src: &mut BytesMut) -> Result<Option<Frame>, DecodeError> {
        let Some(header) = peek_header(src)? else {
            return Ok(None);
        };
        let total = HEADER_LEN.saturating_add(header.len);
        if src.len() < total {
            // Reserve only what this frame is missing, already validated as ≤ MAX_FRAME_LEN.
            src.reserve(total.saturating_sub(src.len()));
            return Ok(None);
        }
        let mut frame = src.split_to(total);
        frame.advance(HEADER_LEN);
        parse_body(header, frame.freeze()).map(Some)
    }
}

/// Reads and validates the header without consuming it. `Ok(None)` if it is not yet complete.
fn peek_header(src: &[u8]) -> Result<Option<Header>, DecodeError> {
    let Some(bytes) = src.get(..HEADER_LEN) else {
        return Ok(None);
    };
    let Ok([version, code, s0, s1, s2, s3, l0, l1]) = <[u8; HEADER_LEN]>::try_from(bytes) else {
        return Ok(None);
    };
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let kind = FrameKind::from_code(code).ok_or(DecodeError::UnknownKind(code))?;
    let stream = u32::from_be_bytes([s0, s1, s2, s3]);
    match (kind.is_stream_scoped(), stream) {
        (true, 0) => return Err(DecodeError::StreamIdRequired(kind)),
        (false, 1..) => return Err(DecodeError::StreamIdForbidden(kind)),
        _ => {}
    }
    let len = usize::from(u16::from_be_bytes([l0, l1]));
    let (min, max) = length_bounds(kind);
    if !(min..=max).contains(&len) {
        return Err(DecodeError::LengthOutOfBounds {
            kind,
            len,
            min,
            max,
        });
    }
    Ok(Some(Header { kind, stream, len }))
}

/// Builds the domain frame from a validated header and a complete payload.
fn parse_body(header: Header, body: Bytes) -> Result<Frame, DecodeError> {
    let Header { kind, stream, .. } = header;
    let stream_id = || StreamId::try_from(stream);
    Ok(match kind {
        FrameKind::Register => Frame::Register {
            node: NodeId::try_from(&body[..])?,
        },
        FrameKind::Open => Frame::Open {
            stream: stream_id()?,
            target: NodeId::try_from(&body[..])?,
        },
        FrameKind::OpenAck => Frame::OpenAck {
            stream: stream_id()?,
        },
        FrameKind::Reject => {
            let [code] = fixed(&body, header)?;
            Frame::Reject {
                stream: stream_id()?,
                reason: RejectReason::try_from(code)?,
            }
        }
        FrameKind::Data => Frame::Data {
            stream: stream_id()?,
            payload: FramePayload::try_from(body)?,
        },
        FrameKind::WindowUpdate => {
            let credit = Credit::try_from(u32::from_be_bytes(fixed(&body, header)?))?;
            Frame::WindowUpdate {
                stream: stream_id()?,
                credit,
            }
        }
        FrameKind::Close => {
            let [code] = fixed(&body, header)?;
            Frame::Close {
                stream: stream_id()?,
                reason: CloseReason::try_from(code)?,
            }
        }
        FrameKind::Ping => Frame::Ping {
            nonce: u64::from_be_bytes(fixed(&body, header)?),
        },
        FrameKind::Pong => Frame::Pong {
            nonce: u64::from_be_bytes(fixed(&body, header)?),
        },
    })
}

/// The payload as a fixed-size array. The length has already been validated by the header:
/// the error branch exists only so that we never have to resort to a panic.
fn fixed<const N: usize>(body: &[u8], header: Header) -> Result<[u8; N], DecodeError> {
    body.try_into().map_err(|_| {
        let (min, max) = length_bounds(header.kind);
        DecodeError::LengthOutOfBounds {
            kind: header.kind,
            len: body.len(),
            min,
            max,
        }
    })
}
