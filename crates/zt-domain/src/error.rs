use thiserror::Error;

/// Violation of a domain invariant.
///
/// Errors never contain the content of the rejected data (which might be secret or
/// attacker-controlled), only metadata such as lengths and positions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// The `NodeId` is empty.
    #[error("node id is empty")]
    NodeIdEmpty,
    /// The `NodeId` exceeds the maximum length.
    #[error("node id is {len} bytes, maximum is {max}")]
    NodeIdTooLong {
        /// Received length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// The `NodeId` contains a byte outside the `[a-z0-9-]` alphabet.
    #[error("node id has a forbidden byte at position {position}")]
    NodeIdInvalidByte {
        /// Position (0-based) of the first invalid byte.
        position: usize,
    },
    /// The `NodeId` starts or ends with `-`.
    #[error("node id must not start or end with '-'")]
    NodeIdHyphenAtEdge,
    /// All-zero session identifier (reserved as a sentinel value).
    #[error("session id must not be all zeros")]
    SessionIdZero,
    /// Stream 0 is reserved for connection control.
    #[error("stream id 0 is reserved for connection control")]
    StreamIdZero,
    /// Wrong length for a fixed-size value.
    #[error("{what} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// The kind of value.
        what: &'static str,
        /// Expected length.
        expected: usize,
        /// Received length.
        actual: usize,
    },
    /// A `Data` frame cannot have an empty payload.
    #[error("payload must not be empty")]
    PayloadEmpty,
    /// Payload over the limit.
    #[error("payload is {len} bytes, maximum is {max}")]
    PayloadTooLarge {
        /// Received length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A window update with zero credit is meaningless and is rejected.
    #[error("window credit must be greater than zero")]
    CreditZero,
    /// Unknown reject code.
    #[error("unknown reject reason code {0:#04x}")]
    UnknownRejectReason(u8),
    /// Unknown close code.
    #[error("unknown close reason code {0:#04x}")]
    UnknownCloseReason(u8),
    /// A v2 pin (PQ-AUTH) for a key that has no role.
    #[error("peer {0} has no entry to pin a v2 identity to")]
    UnknownPeer(crate::Fingerprint),
    /// A fingerprint v2 in the key denylist (finding AP-6): the unit of revocation is the
    /// X25519-level identity, so the entry would match nothing. The text is never echoed.
    #[error(
        "a SHA256v2 fingerprint cannot be revoked: list the tcn-pub-v2 key or its SHA256 (v1) fingerprint"
    )]
    HybridFingerprintNotRevocable,
    /// `require_hybrid_identity` (PQ-AUTH, finding A12-1) names a role that has an entry
    /// without a v2 pin: that peer would be authenticated only classically.
    #[error(
        "peer {0} has no v2 identity (tcn-pub-v2 key or tcn-pin-v2 pin), but its role requires one"
    )]
    HybridIdentityRequired(crate::Fingerprint),
    /// The same key appears twice in the policy.
    #[error("peer {0} appears more than once in the access policy")]
    DuplicatePeer(crate::Fingerprint),
    /// Two agents declare the same node name.
    #[error("node {0} is assigned to more than one agent key")]
    DuplicateNode(crate::NodeId),
    /// A node has zero agent keys, more than [`crate::MAX_AGENT_KEYS`], or duplicate keys.
    #[error("node {0} must have one or two distinct agent keys")]
    AgentKeys(crate::NodeId),
    /// A CA has zero keys, more than [`crate::limits::MAX_AUTHORITY_KEYS`], or duplicate keys.
    #[error("authority {0} must have one or two distinct keys")]
    AuthorityKeys(crate::NodeId),
    /// Two `[[authorities]]` entries with the same name.
    #[error("authority {0} appears more than once")]
    DuplicateAuthority(crate::NodeId),
    /// A CA's `max_lifetime` is outside `60..=86400` seconds.
    #[error("authority max_lifetime is {secs} s, must be between 60 and 86400")]
    AuthorityLifetime {
        /// The rejected value.
        secs: u64,
    },
    /// More than [`crate::limits::MAX_AUTHORITIES`] CAs.
    #[error("too many authorities (maximum 16)")]
    TooManyAuthorities,
    /// Denylist over the limits.
    #[error("too many revoked {what}")]
    TooManyRevocations {
        /// `serials` or `keys`.
        what: &'static str,
    },
}
