//! Test TDD del decoder contro input malevoli o fuori limite (OWASP A03/A04).
//!
//! Regola generale: qualunque violazione è un errore **fatale** per la connessione. Il decoder
//! non tenta mai di risincronizzarsi su un flusso corrotto.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown
)]

mod common;

use bytes::BytesMut;
use common::{node, raw, raw_v1, stream};
use zt_domain::limits::{FRAME_HEADER_LEN, MAX_PAYLOAD_LEN};
use zt_domain::{DomainError, Frame, FrameKind};
use zt_proto::{DecodeError, FrameDecoder, encode};

const REGISTER: u8 = 0x01;
const OPEN: u8 = 0x02;
const OPEN_ACK: u8 = 0x03;
const REJECT: u8 = 0x04;
const DATA: u8 = 0x10;
const WINDOW: u8 = 0x11;
const CLOSE: u8 = 0x12;
const PING: u8 = 0x20;

fn decode_one(mut buf: BytesMut) -> Result<Option<Frame>, DecodeError> {
    FrameDecoder::new().decode(&mut buf)
}

// ---------- casi felici e vettori di riferimento (golden) ----------

#[test]
fn ping_has_a_stable_wire_encoding() {
    let mut buf = BytesMut::new();
    encode(
        &Frame::Ping {
            nonce: 0x0102_0304_0506_0708,
        },
        &mut buf,
    );
    assert_eq!(
        &buf[..],
        &[0x01, 0x20, 0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
        "version, kind, stream_id=0, length=8, nonce big-endian"
    );
}

#[test]
fn open_has_a_stable_wire_encoding() {
    let mut buf = BytesMut::new();
    encode(
        &Frame::Open {
            stream: stream(0x0a0b_0c0d),
            target: node("db1"),
        },
        &mut buf,
    );
    assert_eq!(
        &buf[..],
        &[0x01, 0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0, 3, b'd', b'b', b'1']
    );
}

#[test]
fn decodes_exactly_one_frame_and_leaves_the_rest() {
    let mut buf = raw_v1(PING, 0, &[0; 8]);
    buf.extend_from_slice(&[0x01, 0x20]); // inizio del frame successivo
    let frame = FrameDecoder::new().decode(&mut buf).unwrap();
    assert_eq!(frame, Some(Frame::Ping { nonce: 0 }));
    assert_eq!(&buf[..], &[0x01, 0x20]);
}

#[test]
fn incomplete_header_waits_without_consuming() {
    let mut buf = BytesMut::from(&[0x01, 0x20, 0, 0][..]);
    assert_eq!(FrameDecoder::new().decode(&mut buf), Ok(None));
    assert_eq!(buf.len(), 4);
}

#[test]
fn incomplete_payload_waits_without_consuming() {
    let mut buf = raw(1, DATA, 1, 10, &[0xaa; 9]);
    assert_eq!(FrameDecoder::new().decode(&mut buf), Ok(None));
    assert_eq!(buf.len(), FRAME_HEADER_LEN + 9);
}

#[test]
fn empty_buffer_is_not_an_error() {
    assert_eq!(decode_one(BytesMut::new()), Ok(None));
}

// ---------- header malevolo ----------

#[test]
fn rejects_unsupported_versions() {
    for version in [0x00, 0x02, 0x7f, 0xff] {
        assert_eq!(
            decode_one(raw(version, PING, 0, 8, &[0; 8])),
            Err(DecodeError::UnsupportedVersion(version))
        );
    }
}

#[test]
fn rejects_unknown_kinds() {
    let known: Vec<u8> = FrameKind::ALL.iter().map(|k| k.code()).collect();
    for code in (0..=u8::MAX).filter(|c| !known.contains(c)) {
        assert_eq!(
            decode_one(raw(1, code, 1, 0, &[])),
            Err(DecodeError::UnknownKind(code)),
            "kind {code:#04x}"
        );
    }
}

#[test]
fn rejects_stream_frames_on_the_control_stream() {
    for kind in [OPEN, OPEN_ACK, REJECT, DATA, WINDOW, CLOSE] {
        let err = decode_one(raw(1, kind, 0, 1, &[1])).unwrap_err();
        assert!(
            matches!(err, DecodeError::StreamIdRequired(_)),
            "kind {kind:#04x}: {err:?}"
        );
    }
}

#[test]
fn rejects_control_frames_on_a_data_stream() {
    assert_eq!(
        decode_one(raw_v1(REGISTER, 7, b"web")),
        Err(DecodeError::StreamIdForbidden(FrameKind::Register))
    );
    assert_eq!(
        decode_one(raw_v1(PING, 1, &[0; 8])),
        Err(DecodeError::StreamIdForbidden(FrameKind::Ping))
    );
}

/// Il cuore della difesa DoS: una lunghezza dichiarata oltre il limite è rifiutata guardando
/// il solo header, **prima** di bufferizzare un singolo byte di payload.
#[test]
fn rejects_oversized_length_from_the_header_alone() {
    let oversized = u16::try_from(MAX_PAYLOAD_LEN + 1).unwrap();
    for len in [oversized, u16::MAX] {
        let mut buf = raw(1, DATA, 1, len, &[]);
        let err = FrameDecoder::new().decode(&mut buf).unwrap_err();
        assert_eq!(
            err,
            DecodeError::LengthOutOfBounds {
                kind: FrameKind::Data,
                len: usize::from(len),
                min: 1,
                max: MAX_PAYLOAD_LEN
            }
        );
    }
}

#[test]
fn rejects_wrong_lengths_for_fixed_size_frames() {
    let cases: [(u8, u32, u16); 8] = [
        (PING, 0, 7),
        (PING, 0, 9),
        (WINDOW, 1, 3),
        (WINDOW, 1, 5),
        (OPEN_ACK, 1, 1),
        (REJECT, 1, 0),
        (CLOSE, 1, 2),
        (REGISTER, 0, 64), // NodeId oltre 63 byte
    ];
    for (kind, stream, len) in cases {
        let payload = vec![0x61; usize::from(len)];
        let err = decode_one(raw(1, kind, stream, len, &payload)).unwrap_err();
        assert!(
            matches!(err, DecodeError::LengthOutOfBounds { .. }),
            "kind {kind:#04x} len {len}: {err:?}"
        );
    }
}

#[test]
fn rejects_empty_data_frames() {
    let err = decode_one(raw(1, DATA, 1, 0, &[])).unwrap_err();
    assert_eq!(
        err,
        DecodeError::LengthOutOfBounds {
            kind: FrameKind::Data,
            len: 0,
            min: 1,
            max: MAX_PAYLOAD_LEN
        }
    );
}

// ---------- payload malevolo ----------

#[test]
fn rejects_invalid_node_ids() {
    for bad in [&b"Web"[..], b"web\n01", b"we\0b", b"-web", b"w\xc3\xa9b"] {
        let err = decode_one(raw_v1(REGISTER, 0, bad)).unwrap_err();
        assert!(matches!(err, DecodeError::Invalid(_)), "{bad:?}: {err:?}");
        let err = decode_one(raw_v1(OPEN, 3, bad)).unwrap_err();
        assert!(matches!(err, DecodeError::Invalid(_)), "{bad:?}: {err:?}");
    }
}

#[test]
fn rejects_zero_window_credit() {
    assert_eq!(
        decode_one(raw_v1(WINDOW, 1, &[0, 0, 0, 0])),
        Err(DecodeError::Invalid(DomainError::CreditZero))
    );
}

#[test]
fn rejects_unknown_reason_codes() {
    assert_eq!(
        decode_one(raw_v1(REJECT, 1, &[0x00])),
        Err(DecodeError::Invalid(DomainError::UnknownRejectReason(0)))
    );
    assert_eq!(
        decode_one(raw_v1(CLOSE, 1, &[0xee])),
        Err(DecodeError::Invalid(DomainError::UnknownCloseReason(0xee)))
    );
}

// ---------- politica di errore ----------

#[test]
fn decoder_is_poisoned_after_the_first_error() {
    let mut decoder = FrameDecoder::new();
    let mut bad = raw(9, PING, 0, 8, &[0; 8]);
    assert!(decoder.decode(&mut bad).is_err());

    // Anche un frame perfettamente valido non viene più accettato: niente risincronizzazione.
    let mut good = raw_v1(PING, 0, &[0; 8]);
    assert_eq!(decoder.decode(&mut good), Err(DecodeError::Poisoned));
    assert!(decoder.is_poisoned());
}

#[test]
fn errors_never_echo_attacker_bytes() {
    let secret = b"secret";
    let err = decode_one(raw_v1(REGISTER, 0, b"SECRET")).unwrap_err();
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(
        !rendered.contains(core::str::from_utf8(secret).unwrap()),
        "{rendered}"
    );
}
