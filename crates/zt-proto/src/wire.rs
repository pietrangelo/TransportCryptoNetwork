//! Costanti e regole del formato sul filo (versione 1).
//!
//! ```text
//!  0        1        2                 6        8
//! +--------+--------+-----------------+--------+==================+
//! |version |  kind  |  stream_id (BE) | len BE |  payload (len B) |
//! +--------+--------+-----------------+--------+==================+
//! ```

use zt_domain::FrameKind;
use zt_domain::limits::{MAX_NODE_ID_LEN, MAX_PAYLOAD_LEN};

pub use zt_domain::limits::FRAME_HEADER_LEN as HEADER_LEN;

/// L'unica versione del protocollo accettata.
pub const VERSION: u8 = 1;

/// Lunghezza ammessa del payload per ogni tipo di frame, come intervallo chiuso `(min, max)`.
///
/// Il decoder la applica guardando il solo header, prima di attendere il payload: una
/// lunghezza dichiarata fuori intervallo non causa mai allocazioni.
#[must_use]
pub const fn length_bounds(kind: FrameKind) -> (usize, usize) {
    match kind {
        FrameKind::Register | FrameKind::Open => (1, MAX_NODE_ID_LEN),
        FrameKind::OpenAck => (0, 0),
        FrameKind::Reject | FrameKind::Close => (1, 1),
        FrameKind::Data => (1, MAX_PAYLOAD_LEN),
        FrameKind::WindowUpdate => (4, 4),
        FrameKind::Ping | FrameKind::Pong => (8, 8),
    }
}

// Nessun tipo può dichiarare più del massimo globale (indice limitato dal `while`).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const _: () = {
    let mut i = 0;
    while i < FrameKind::ALL.len() {
        let (min, max) = length_bounds(FrameKind::ALL[i]);
        assert!(min <= max && max <= MAX_PAYLOAD_LEN);
        i += 1;
    }
};
