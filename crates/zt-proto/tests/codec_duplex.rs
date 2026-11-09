//! Tests of the `tokio-util` adapter on in-memory streams: real I/O fragmentation.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown
)]

mod common;

use bytes::BytesMut;
use common::{node, raw, stream};
use futures::{SinkExt, StreamExt};
use tokio_util::codec::{FramedRead, FramedWrite};
use zt_domain::{Frame, FramePayload};
use zt_proto::codec::FrameCodec;
use zt_proto::{DecodeError, encode};

fn sample_frames() -> Vec<Frame> {
    vec![
        Frame::Register {
            node: node("web-01"),
        },
        Frame::Open {
            stream: stream(1),
            target: node("db-01"),
        },
        Frame::Data {
            stream: stream(1),
            payload: FramePayload::try_from(vec![7; 4096]).unwrap(),
        },
        Frame::Ping { nonce: 42 },
    ]
}

#[tokio::test]
async fn frames_survive_a_tiny_duplex_pipe() {
    // 64-byte buffer: every `Data` frame is split into dozens of partial reads.
    let (client, server) = tokio::io::duplex(64);
    let frames = sample_frames();

    let expected = frames.clone();
    let writer = tokio::spawn(async move {
        let mut sink = FramedWrite::new(client, FrameCodec::default());
        for frame in frames {
            sink.send(frame).await.unwrap();
        }
    });

    let mut source = FramedRead::new(server, FrameCodec::default());
    let mut received = Vec::new();
    while let Some(frame) = source.next().await {
        received.push(frame.unwrap());
    }
    writer.await.unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn byte_by_byte_reads_with_a_scripted_mock() {
    let mut wire = BytesMut::new();
    encode(&Frame::Ping { nonce: 7 }, &mut wire);
    let mut mock = tokio_test::io::Builder::new();
    for byte in &wire {
        mock.read(&[*byte]);
    }
    let mut source = FramedRead::new(mock.build(), FrameCodec::default());
    assert_eq!(
        source.next().await.unwrap().unwrap(),
        Frame::Ping { nonce: 7 }
    );
    assert!(source.next().await.is_none());
}

#[tokio::test]
async fn malicious_header_terminates_the_stream() {
    let evil = raw(1, 0x10, 1, u16::MAX, &[]);
    let mock = tokio_test::io::Builder::new().read(&evil).build();
    let mut source = FramedRead::new(mock, FrameCodec::default());
    let first = source.next().await.unwrap();
    assert!(matches!(first, Err(DecodeError::LengthOutOfBounds { .. })));
}

#[tokio::test]
async fn truncated_stream_is_an_error_not_a_silent_eof() {
    let mut wire = BytesMut::new();
    encode(&Frame::Ping { nonce: 1 }, &mut wire);
    let mock = tokio_test::io::Builder::new().read(&wire[..10]).build();
    let mut source = FramedRead::new(mock, FrameCodec::default());
    let first = source.next().await.unwrap();
    assert!(matches!(first, Err(DecodeError::Io(_))), "{first:?}");
}
