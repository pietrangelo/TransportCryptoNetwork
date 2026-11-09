//! Helpers shared by the `zt-proto` integration tests.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown
)]

use bytes::{BufMut, BytesMut};
use proptest::prelude::*;
use zt_domain::limits::MAX_PAYLOAD_LEN;
use zt_domain::{CloseReason, Credit, Frame, FramePayload, NodeId, RejectReason, StreamId};

/// Builds a raw frame on the wire, even an invalid one: it is the attacker's tool.
pub fn raw(version: u8, kind: u8, stream: u32, len: u16, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(8 + payload.len());
    buf.put_u8(version);
    buf.put_u8(kind);
    buf.put_u32(stream);
    buf.put_u16(len);
    buf.put_slice(payload);
    buf
}

/// Like [`raw`], with `len` consistent with the payload.
pub fn raw_v1(kind: u8, stream: u32, payload: &[u8]) -> BytesMut {
    raw(
        1,
        kind,
        stream,
        u16::try_from(payload.len()).unwrap(),
        payload,
    )
}

pub fn node(name: &str) -> NodeId {
    NodeId::try_from(name).unwrap()
}

pub fn stream(id: u32) -> StreamId {
    StreamId::try_from(id).unwrap()
}

// ---------- proptest strategies ----------

pub fn arb_node_id() -> impl Strategy<Value = NodeId> {
    "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?".prop_map(|s| NodeId::try_from(s.as_str()).unwrap())
}

pub fn arb_stream() -> impl Strategy<Value = StreamId> {
    (1..=u32::MAX).prop_map(|n| StreamId::try_from(n).unwrap())
}

pub fn arb_payload() -> impl Strategy<Value = FramePayload> {
    // Small lengths often, plus the exact edges 1 and MAX_PAYLOAD_LEN.
    prop_oneof![
        8 => proptest::collection::vec(any::<u8>(), 1..=512),
        1 => Just(vec![0xa5; 1]),
        1 => Just(vec![0x5a; MAX_PAYLOAD_LEN]),
    ]
    .prop_map(|v| FramePayload::try_from(v).unwrap())
}

pub fn arb_reject() -> impl Strategy<Value = RejectReason> {
    (1_u8..=5).prop_map(|c| RejectReason::try_from(c).unwrap())
}

pub fn arb_close() -> impl Strategy<Value = CloseReason> {
    (0_u8..=5).prop_map(|c| CloseReason::try_from(c).unwrap())
}

pub fn arb_frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        arb_node_id().prop_map(|node| Frame::Register { node }),
        (arb_stream(), arb_node_id()).prop_map(|(stream, target)| Frame::Open { stream, target }),
        arb_stream().prop_map(|stream| Frame::OpenAck { stream }),
        (arb_stream(), arb_reject()).prop_map(|(stream, reason)| Frame::Reject { stream, reason }),
        (arb_stream(), arb_payload()).prop_map(|(stream, payload)| Frame::Data { stream, payload }),
        (arb_stream(), 1..=u32::MAX).prop_map(|(stream, c)| Frame::WindowUpdate {
            stream,
            credit: Credit::try_from(c).unwrap()
        }),
        (arb_stream(), arb_close()).prop_map(|(stream, reason)| Frame::Close { stream, reason }),
        any::<u64>().prop_map(|nonce| Frame::Ping { nonce }),
        any::<u64>().prop_map(|nonce| Frame::Pong { nonce }),
    ]
}
