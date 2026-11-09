//! Protocol limits, fixed at compile time.
//!
//! Every limit has a security rationale (OWASP A03/A04): a peer can never force us to
//! allocate more than [`MAX_FRAME_LEN`] bytes per frame, whatever it declares.

/// Maximum length of a Noise transport message (Noise specification, §3).
pub const NOISE_MAX_MESSAGE_LEN: usize = 65_535;

/// Length of the AEAD tag that Noise appends to every encrypted message.
pub const NOISE_TAG_LEN: usize = 16;

/// Fixed length of a frame header on the wire (see `docs/PROTOCOL.md`).
pub const FRAME_HEADER_LEN: usize = 8;

/// Nested encryption layers a `Data` frame must traverse:
/// the client↔agent end-to-end tunnel inside the peer↔relay channel.
pub const ENCRYPTION_LAYERS: usize = 2;

/// Maximum payload size of a single frame: 60 KiB.
pub const MAX_PAYLOAD_LEN: usize = 60 * 1024;

/// Maximum size of a complete frame (header + payload).
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_PAYLOAD_LEN;

/// Maximum length of a [`NodeId`](crate::NodeId) (a DNS label, RFC 1035 §2.3.4).
pub const MAX_NODE_ID_LEN: usize = 63;

/// Maximum length of a client certificate (PROTOCOL §15.12): 64 nodes of 63 bytes and a name
/// of 63 bytes.
pub const MAX_CERT_LEN: usize = 4_328;

/// Minimum length of a client certificate: `scope = 0x01` and a 1-byte name.
pub const MIN_CERT_LEN: usize = 170;

/// Maximum number of nodes in a certificate with `scope = 0x00`.
pub const MAX_CERT_NODES: usize = 64;

/// Maximum lifetime of a certificate, a format rule (24 hours).
pub const MAX_CERT_LIFETIME_SECS: u64 = 86_400;

/// Clock skew tolerance, on `not_before` only (PROTOCOL §15.6).
pub const CERT_CLOCK_SKEW_SECS: u64 = 120;

/// Minimum `max_lifetime` of a CA.
pub const MIN_AUTHORITY_LIFETIME_SECS: u64 = 60;

/// Default `max_lifetime` of a CA (8 hours).
pub const DEFAULT_AUTHORITY_LIFETIME_SECS: u64 = 28_800;

/// Maximum number of `[[authorities]]` entries per file.
pub const MAX_AUTHORITIES: usize = 16;

/// Keys per CA: the current one and, during a rotation, the new one.
pub const MAX_AUTHORITY_KEYS: usize = 2;

/// Maximum number of serial numbers in the denylist.
pub const MAX_REVOKED_SERIALS: usize = 16_384;

/// Maximum number of keys in the denylist.
pub const MAX_REVOKED_KEYS: usize = 4_096;

/// Bytes of Noise IK message 1 beyond the payload: `e` (32) + encrypted `s` (32 + 16) + payload
/// tag (16).
pub const NOISE_MSG1_OVERHEAD: usize = 96;

// Compile-time proofs: if someone raises a limit inconsistently, the build fails.
const _: () = {
    // A maximum payload, encapsulated twice (header + tag per layer), fits in a Noise message.
    let overhead = ENCRYPTION_LAYERS * (FRAME_HEADER_LEN + NOISE_TAG_LEN);
    assert!(MAX_PAYLOAD_LEN + overhead <= NOISE_MAX_MESSAGE_LEN);
    // The header's `length` field is a u16: the limit must be expressible on the wire.
    assert!(MAX_PAYLOAD_LEN <= u16::MAX as usize);
    assert!(MAX_NODE_ID_LEN <= MAX_PAYLOAD_LEN);
    // Message 1 carrying the largest certificate fits in a `Data` frame and in a Noise message
    // (PROTOCOL §15.3).
    assert!(NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN <= MAX_PAYLOAD_LEN);
    assert!(NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN <= NOISE_MAX_MESSAGE_LEN);
    assert!(MIN_CERT_LEN <= MAX_CERT_LEN);
};
