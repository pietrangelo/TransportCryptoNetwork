//! Infrastructure adapter for `tokio-util`: connects the sans-IO decoder to any
//! `AsyncRead`/`AsyncWrite` (TCP, Noise stream, stdio) via `FramedRead`/`FramedWrite`.

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use zt_domain::Frame;

use crate::{DecodeError, FrameDecoder, encode};

/// `tokio-util` `Decoder`/`Encoder` for TCN frames.
///
/// An EOF in the middle of a frame produces [`DecodeError::Io`], not a silent close.
#[derive(Debug, Default)]
pub struct FrameCodec {
    decoder: FrameDecoder,
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = DecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, DecodeError> {
        self.decoder.decode(src)
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), std::io::Error> {
        encode(&frame, dst);
        Ok(())
    }
}

impl Encoder<&Frame> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: &Frame, dst: &mut BytesMut) -> Result<(), std::io::Error> {
        encode(frame, dst);
        Ok(())
    }
}
