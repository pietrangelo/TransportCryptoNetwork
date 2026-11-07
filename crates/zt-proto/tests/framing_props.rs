//! Test di proprietà del framing: input generati e fuzzati, bordi esatti dei limiti.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown
)]

mod common;

use bytes::BytesMut;
use common::{arb_frame, raw};
use proptest::prelude::*;
use zt_domain::limits::{FRAME_HEADER_LEN, MAX_FRAME_LEN};
use zt_domain::{Frame, FrameKind};
use zt_proto::{DecodeError, FrameDecoder, encode, encoded_len};

fn encode_to_vec(frame: &Frame) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode(frame, &mut buf);
    buf.to_vec()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_000, ..ProptestConfig::default() })]

    /// decode(encode(f)) == f, e il buffer viene consumato per intero.
    #[test]
    fn round_trip(frame in arb_frame()) {
        let mut buf = BytesMut::from(&encode_to_vec(&frame)[..]);
        prop_assert_eq!(buf.len(), encoded_len(&frame));
        prop_assert!(buf.len() <= MAX_FRAME_LEN);
        let decoded = FrameDecoder::new().decode(&mut buf).unwrap();
        prop_assert_eq!(decoded, Some(frame));
        prop_assert!(buf.is_empty());
    }

    /// Byte arbitrari: il decoder non va mai in panic, e se accetta un frame quel frame ha una
    /// sola codifica possibile (encoding canonico: niente malleabilità del formato).
    #[test]
    fn arbitrary_bytes_never_panic_and_accepted_frames_are_canonical(
        bytes in proptest::collection::vec(any::<u8>(), 0..256)
    ) {
        let mut buf = BytesMut::from(&bytes[..]);
        if let Ok(Some(frame)) = FrameDecoder::new().decode(&mut buf) {
            let consumed = bytes.len() - buf.len();
            prop_assert_eq!(encode_to_vec(&frame), bytes[..consumed].to_vec());
        }
    }

    /// Header plausibile (versione 1, tipo noto) con campi casuali: stesse garanzie, ma su
    /// input che superano il primo filtro e arrivano alla validazione profonda.
    #[test]
    fn structured_fuzz_never_panics(
        kind in proptest::sample::select(FrameKind::ALL.to_vec()),
        stream in prop_oneof![Just(0_u32), Just(1_u32), any::<u32>()],
        len in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut buf = raw(1, kind.code(), stream, len, &payload);
        let before = buf.clone();
        match FrameDecoder::new().decode(&mut buf) {
            Ok(Some(frame)) => {
                let consumed = before.len() - buf.len();
                prop_assert_eq!(encode_to_vec(&frame), before[..consumed].to_vec());
            }
            Ok(None) => prop_assert_eq!(buf, before, "waiting must not consume input"),
            Err(_) => {}
        }
    }

    /// Qualunque prefisso stretto di un frame valido significa «aspetta altri byte».
    #[test]
    fn every_strict_prefix_waits(frame in arb_frame(), cut in any::<prop::sample::Index>()) {
        let bytes = encode_to_vec(&frame);
        let cut = cut.index(bytes.len());
        let mut buf = BytesMut::from(&bytes[..cut]);
        prop_assert_eq!(FrameDecoder::new().decode(&mut buf), Ok(None));
        prop_assert_eq!(buf.len(), cut);
    }

    /// Una sequenza di frame spezzata in chunk arbitrari viene ricostruita identica.
    #[test]
    fn chunked_stream_reassembles(
        frames in proptest::collection::vec(arb_frame(), 1..16),
        chunk in 1_usize..64,
    ) {
        let wire: Vec<u8> = frames.iter().flat_map(encode_to_vec).collect();
        let mut decoder = FrameDecoder::new();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for piece in wire.chunks(chunk) {
            buf.extend_from_slice(piece);
            while let Some(frame) = decoder.decode(&mut buf).unwrap() {
                out.push(frame);
            }
        }
        prop_assert_eq!(out, frames);
        prop_assert!(buf.is_empty());
    }

    /// Per ogni tipo, ogni lunghezza dichiarata oltre il massimo è rifiutata dal solo header.
    #[test]
    fn oversized_lengths_rejected_before_buffering(
        kind in proptest::sample::select(FrameKind::ALL.to_vec()),
        len in any::<u16>(),
    ) {
        let stream = u32::from(kind.is_stream_scoped());
        let (_, max) = zt_proto::wire::length_bounds(kind);
        prop_assume!(usize::from(len) > max);
        let mut buf = raw(1, kind.code(), stream, len, &[]);
        prop_assert_eq!(buf.len(), FRAME_HEADER_LEN);
        let is_length_error = matches!(
            FrameDecoder::new().decode(&mut buf),
            Err(DecodeError::LengthOutOfBounds { .. })
        );
        prop_assert!(is_length_error);
    }
}
