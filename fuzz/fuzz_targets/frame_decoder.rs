//! The frame decoder on arbitrary bytes, delivered in chunks of arbitrary size.
//!
//! Properties: no panic; an accepted frame re-encodes to the very same bytes (canonical
//! encoding, no malleability); after an error the decoder stays poisoned.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use zt_proto::{FrameDecoder, encode};

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(split).max(1);
    let mut decoder = FrameDecoder::new();
    let mut buf = BytesMut::new();
    let mut consumed = Vec::new();
    for piece in rest.chunks(chunk) {
        buf.extend_from_slice(piece);
        loop {
            let before = buf.clone();
            match decoder.decode(&mut buf) {
                Ok(Some(frame)) => {
                    let used = before.len() - buf.len();
                    let mut again = BytesMut::new();
                    encode(&frame, &mut again);
                    assert_eq!(&again[..], &before[..used], "non-canonical encoding accepted");
                    consumed.extend_from_slice(&again);
                }
                Ok(None) => {
                    assert_eq!(buf, before, "bytes consumed without a frame");
                    break;
                }
                Err(_) => {
                    assert!(decoder.is_poisoned());
                    assert!(decoder.decode(&mut buf).is_err());
                    return;
                }
            }
        }
    }
    assert!(rest.starts_with(&consumed));
});
