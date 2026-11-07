//! Adapter infrastrutturale per `tokio-util`: collega il decoder sans-IO a qualsiasi
//! `AsyncRead`/`AsyncWrite` (TCP, stream Noise, stdio) tramite `FramedRead`/`FramedWrite`.

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use zt_domain::Frame;

use crate::{DecodeError, FrameDecoder, encode};

/// `Decoder`/`Encoder` di `tokio-util` per i frame TCN.
///
/// Un EOF a metà frame produce [`DecodeError::Io`], non una chiusura silenziosa.
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
