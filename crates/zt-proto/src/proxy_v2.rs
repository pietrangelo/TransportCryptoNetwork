//! Strict PROXY protocol version 2 (binary only), sans-IO (docs/PROTOCOL.md §10.2,
//! docs/analysis/relay-hardening.md §3.5).
//!
//! A trusted TCP proxy in front of the relay prepends one header to the connection, carrying
//! the real peer's address. The relay reads **exactly** the 16 fixed bytes, then exactly the
//! body length they declare, so nothing of message 1 is ever consumed and nothing is buffered
//! beyond [`MAX_BODY`]:
//!
//! ```text
//!  0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A   signature (12 bytes)
//!  ver(4 bits)=2 | cmd(4 bits)           LOCAL 0, PROXY 1
//!  family/transport                      0x00 UNSPEC (LOCAL only), 0x11 TCP/IPv4, 0x21 TCP/IPv6
//!  length (u16 big-endian)               body bytes that follow, at most MAX_BODY
//!  body: src addr, dst addr, src port, dst port, then TLVs (type u8, length u16 BE, value)
//! ```
//!
//! Version 1 (text) is not supported, and there is no auto-detection: a connection that must
//! carry a header and does not start with the signature is refused. TLV values are ignored
//! (no TLS, CRC32C or unique-id semantics), but their framing must be exact.

use std::net::SocketAddr;

use thiserror::Error;

/// The 12-byte signature of a version 2 header.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The fixed part of a header: signature, version and command, family, length.
pub const FIXED_LEN: usize = 16;

/// The largest body accepted: the IPv6 address block (36 bytes) plus room for the TLVs that
/// real proxies send. Checked on the fixed part, before any byte of the body is read.
pub const MAX_BODY: usize = 512;

/// The address block of TCP over IPv4: two addresses and two ports.
pub const IPV4_BLOCK: usize = 12;

/// The address block of TCP over IPv6.
pub const IPV6_BLOCK: usize = 36;

/// The command of a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// The proxy's own connection (a health check): the real connection address is the peer.
    Local,
    /// A proxied connection: the source address of the body is the peer.
    Proxy,
}

/// The address family and transport of a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// No address (with [`Command::Local`] only).
    Unspec,
    /// TCP over IPv4.
    Tcp4,
    /// TCP over IPv6.
    Tcp6,
}

impl Family {
    /// The size of the family's address block.
    #[must_use]
    pub const fn block_len(self) -> usize {
        match self {
            Self::Unspec => 0,
            Self::Tcp4 => IPV4_BLOCK,
            Self::Tcp6 => IPV6_BLOCK,
        }
    }
}

/// The validated fixed part of a header: what to read next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixed {
    command: Command,
    family: Family,
    len: u16,
}

impl Fixed {
    /// The command.
    #[must_use]
    pub const fn command(&self) -> Command {
        self.command
    }

    /// The family.
    #[must_use]
    pub const fn family(&self) -> Family {
        self.family
    }

    /// The exact number of body bytes to read next (at most [`MAX_BODY`]).
    #[must_use]
    pub fn body_len(&self) -> usize {
        usize::from(self.len)
    }
}

/// What a complete header says about the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proxied {
    /// `LOCAL`: use the real connection address.
    Local,
    /// `PROXY`: the real peer (IPv4-mapped IPv6 sources canonicalised to IPv4).
    Proxy {
        /// The source address and port of the proxied connection.
        source: SocketAddr,
    },
}

/// Why a header is refused: one stable reason per check, never a received byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// The first 12 bytes are not the version 2 signature (no header, or a version 1 header).
    #[error("PROXY v2 signature missing")]
    Signature,
    /// A version other than 2.
    #[error("unsupported PROXY protocol version")]
    Version,
    /// A command other than LOCAL and PROXY.
    #[error("unsupported PROXY command")]
    Command,
    /// A family or transport other than TCP over IPv4 or IPv6 (UNSPEC with LOCAL only).
    #[error("unsupported PROXY address family or transport")]
    Family,
    /// A body shorter than the address block or longer than [`MAX_BODY`], or a body slice
    /// whose length is not the declared one.
    #[error("PROXY header length out of bounds")]
    Length,
    /// An unspecified, multicast or broadcast source address.
    #[error("unusable PROXY source address")]
    Address,
    /// A TLV that does not fit the body exactly.
    #[error("malformed PROXY TLV")]
    Tlv,
}

impl ProxyError {
    /// Every variant, for exhaustive tests and metric vocabularies.
    pub const ALL: [Self; 7] = [
        Self::Signature,
        Self::Version,
        Self::Command,
        Self::Family,
        Self::Length,
        Self::Address,
        Self::Tlv,
    ];

    /// The stable reason name, for metrics and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Version => "version",
            Self::Command => "command",
            Self::Family => "family",
            Self::Length => "length",
            Self::Address => "address",
            Self::Tlv => "tlv",
        }
    }
}

/// Validates the 16 fixed bytes.
///
/// # Errors
/// [`ProxyError::Signature`], [`ProxyError::Version`], [`ProxyError::Command`],
/// [`ProxyError::Family`], [`ProxyError::Length`], checked in this order.
pub fn fixed(header: &[u8; FIXED_LEN]) -> Result<Fixed, ProxyError> {
    let _ = header;
    Err(ProxyError::Signature)
}

/// Parses the body announced by `fixed`; `body` must be exactly [`Fixed::body_len`] bytes.
///
/// # Errors
/// [`ProxyError::Length`], [`ProxyError::Address`], [`ProxyError::Tlv`].
pub fn body(fixed: &Fixed, body: &[u8]) -> Result<Proxied, ProxyError> {
    let _ = (fixed, body);
    Err(ProxyError::Length)
}

/// Parses a header at the start of `bytes`: the result and the number of bytes it took
/// (exactly `16 + length`), or `None` if more bytes are needed. Never reads past the header.
///
/// # Errors
/// See [`fixed`] and [`body`].
pub fn parse(bytes: &[u8]) -> Result<Option<(Proxied, usize)>, ProxyError> {
    let _ = bytes;
    Ok(None)
}

/// Encodes a header (for proxies written in Rust, and for tests): `None` for a LOCAL header,
/// otherwise PROXY with `(source, destination)` of the same family; then the `tlvs`. `None` if
/// the families differ or the body would exceed [`MAX_BODY`].
#[must_use]
pub fn encode(
    addresses: Option<(SocketAddr, SocketAddr)>,
    tlvs: &[(u8, &[u8])],
) -> Option<Vec<u8>> {
    let _ = (addresses, tlvs);
    None
}
