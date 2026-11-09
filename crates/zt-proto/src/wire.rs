//! Constants and rules of the on-the-wire format (version 1).
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

/// The only accepted protocol version.
pub const VERSION: u8 = 1;

/// Allowed payload length for each frame kind, as a closed interval `(min, max)`.
///
/// The decoder applies it by looking at the header alone, before waiting for the payload: a
/// declared length outside the interval never causes allocations.
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

// No kind can declare more than the global maximum (index bounded by the `while`).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const _: () = {
    let mut i = 0;
    while i < FrameKind::ALL.len() {
        let (min, max) = length_bounds(FrameKind::ALL[i]);
        assert!(min <= max && max <= MAX_PAYLOAD_LEN);
        i += 1;
    }
};
