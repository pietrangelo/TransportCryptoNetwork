use bytes::{BufMut, BytesMut};
use zt_domain::Frame;

use crate::wire::{HEADER_LEN, VERSION};

/// The body of a frame, before serialization.
enum Body<'a> {
    Empty,
    Byte(u8),
    U32(u32),
    U64(u64),
    Slice(&'a [u8]),
}

impl Body<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Byte(_) => 1,
            Self::U32(_) => 4,
            Self::U64(_) => 8,
            Self::Slice(s) => s.len(),
        }
    }
}

fn body(frame: &Frame) -> Body<'_> {
    match frame {
        Frame::Register { node } | Frame::Open { target: node, .. } => Body::Slice(node.as_bytes()),
        Frame::OpenAck { .. } => Body::Empty,
        Frame::Reject { reason, .. } => Body::Byte(*reason as u8),
        Frame::Data { payload, .. } => Body::Slice(payload.as_bytes()),
        Frame::WindowUpdate { credit, .. } => Body::U32(credit.get()),
        Frame::Close { reason, .. } => Body::Byte(*reason as u8),
        Frame::Ping { nonce } | Frame::Pong { nonce } => Body::U64(*nonce),
    }
}

/// Number of bytes that [`encode`] will write for `frame` (always ≤ `MAX_FRAME_LEN`).
#[must_use]
pub fn encoded_len(frame: &Frame) -> usize {
    HEADER_LEN.saturating_add(body(frame).len())
}

/// Serializes `frame` onto the end of `dst`.
///
/// It is infallible: a domain [`Frame`] respects all the wire limits by construction
/// (lengths proven at compile time in `zt_domain::limits`).
pub fn encode(frame: &Frame, dst: &mut BytesMut) {
    let body = body(frame);
    // Cannot saturate: the maximum length of a body is MAX_PAYLOAD_LEN ≤ u16::MAX.
    let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    dst.reserve(encoded_len(frame));
    dst.put_u8(VERSION);
    dst.put_u8(frame.kind().code());
    dst.put_u32(frame.stream().map_or(0, zt_domain::StreamId::get));
    dst.put_u16(len);
    match body {
        Body::Empty => {}
        Body::Byte(b) => dst.put_u8(b),
        Body::U32(v) => dst.put_u32(v),
        Body::U64(v) => dst.put_u64(v),
        Body::Slice(s) => dst.put_slice(s),
    }
}
