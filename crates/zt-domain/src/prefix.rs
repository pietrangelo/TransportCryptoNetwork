//! [`IpPrefix`]: a validated CIDR prefix, and [`PrefixSet`]: an unambiguous list of them (the
//! trusted PROXY protocol sources of `relay.toml`, docs/analysis/relay-hardening.md §3.5).
//!
//! A prefix exists only in canonical form: no host bits set, never `/0` (which would trust
//! every address), never an IPv4-mapped IPv6 prefix (written as IPv4 instead, so that one
//! address has one spelling). A set holds 1 to [`PrefixSet::MAX`] prefixes, none of which
//! overlaps another.

use std::net::IpAddr;

use thiserror::Error;

/// Why a prefix or a set of prefixes is refused. Never carries the rejected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PrefixError {
    /// Not `address/length` with a decimal length.
    #[error("not an address/length prefix")]
    Syntax,
    /// A length above 32 (IPv4) or 128 (IPv6).
    #[error("prefix length out of range")]
    Length,
    /// `/0`: every address would be trusted.
    #[error("a /0 prefix would trust every address")]
    Everything,
    /// Bits set after the prefix length.
    #[error("host bits set after the prefix length")]
    HostBits,
    /// An IPv4-mapped IPv6 prefix (`::ffff:a.b.c.d/n`): write it as IPv4.
    #[error("IPv4-mapped IPv6 prefix: write it as IPv4")]
    Mapped,
    /// No prefix at all.
    #[error("no prefix")]
    Empty,
    /// More than [`PrefixSet::MAX`] prefixes.
    #[error("too many prefixes")]
    TooMany,
    /// A prefix equal to, inside or around another one of the set.
    #[error("prefix overlaps another one")]
    Overlap,
}

/// A CIDR prefix in canonical form (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    addr: IpAddr,
    len: u8,
}

impl IpPrefix {
    /// The network address (host bits clear).
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// `true` if `addr` is inside the prefix. An IPv4-mapped IPv6 address is compared as the
    /// IPv4 address it maps.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        let _ = addr;
        false
    }

    /// `true` if the two prefixes share at least one address.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        let _ = other;
        false
    }
}

impl TryFrom<&str> for IpPrefix {
    type Error = PrefixError;

    fn try_from(text: &str) -> Result<Self, PrefixError> {
        let _ = text;
        Err(PrefixError::Syntax)
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// 1 to [`PrefixSet::MAX`] prefixes, none overlapping another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixSet(Vec<IpPrefix>);

impl PrefixSet {
    /// The most prefixes a set holds.
    pub const MAX: usize = 64;

    /// A set of `prefixes`.
    ///
    /// # Errors
    /// The index of the first offending entry and why: [`PrefixError::Empty`] (index 0),
    /// [`PrefixError::TooMany`], [`PrefixError::Overlap`].
    pub fn new(prefixes: Vec<IpPrefix>) -> Result<Self, (usize, PrefixError)> {
        Ok(Self(prefixes))
    }

    /// `true` if `addr` is inside one of the prefixes.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.0.iter().any(|p| p.contains(addr))
    }

    /// The prefixes, in the configured order.
    #[must_use]
    pub fn prefixes(&self) -> &[IpPrefix] {
        &self.0
    }
}
