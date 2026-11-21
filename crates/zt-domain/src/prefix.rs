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
    pub const fn prefix_len(&self) -> u8 {
        self.len
    }

    /// `true` if `addr` is inside the prefix. An IPv4-mapped IPv6 address is compared as the
    /// IPv4 address it maps.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(a)) => u32::from(a) & mask32(self.len) == u32::from(net),
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                u128::from(a) & mask128(self.len) == u128::from(net)
            }
            _ => false,
        }
    }

    /// `true` if the two prefixes share at least one address: the shorter one contains the
    /// other's network address.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        if self.len <= other.len {
            self.contains(other.addr)
        } else {
            other.contains(self.addr)
        }
    }
}

/// The IPv4 netmask of `len` bits (`len` ≤ 32).
fn mask32(len: u8) -> u32 {
    32_u32
        .checked_sub(u32::from(len))
        .and_then(|host| u32::MAX.checked_shl(host))
        .unwrap_or(0)
}

/// The IPv6 netmask of `len` bits (`len` ≤ 128).
fn mask128(len: u8) -> u128 {
    128_u32
        .checked_sub(u32::from(len))
        .and_then(|host| u128::MAX.checked_shl(host))
        .unwrap_or(0)
}

impl TryFrom<&str> for IpPrefix {
    type Error = PrefixError;

    fn try_from(text: &str) -> Result<Self, PrefixError> {
        let (addr, len) = text.split_once('/').ok_or(PrefixError::Syntax)?;
        // Digits only: no sign, no blanks, no leading zeros beyond a single "0".
        if len.is_empty()
            || len.len() > 3
            || !len.bytes().all(|b| b.is_ascii_digit())
            || (len.len() > 1 && len.starts_with('0'))
        {
            return Err(PrefixError::Syntax);
        }
        let len: u8 = len.parse().map_err(|_| PrefixError::Syntax)?;
        let addr: IpAddr = addr.parse().map_err(|_| PrefixError::Syntax)?;
        let (max, clear) = match addr {
            IpAddr::V4(a) => (32, u32::from(a) & !mask32(len.min(32)) == 0),
            IpAddr::V6(a) => {
                if a.to_ipv4_mapped().is_some() {
                    return Err(PrefixError::Mapped);
                }
                (128, u128::from(a) & !mask128(len.min(128)) == 0)
            }
        };
        if len > max {
            return Err(PrefixError::Length);
        }
        if len == 0 {
            return Err(PrefixError::Everything);
        }
        if !clear {
            return Err(PrefixError::HostBits);
        }
        Ok(Self { addr, len })
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
        if prefixes.is_empty() {
            return Err((0, PrefixError::Empty));
        }
        if prefixes.len() > Self::MAX {
            return Err((Self::MAX, PrefixError::TooMany));
        }
        for (i, p) in prefixes.iter().enumerate() {
            let earlier = prefixes.get(..i).unwrap_or_default();
            if earlier.iter().any(|q| q.overlaps(p)) {
                return Err((i, PrefixError::Overlap));
            }
        }
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
