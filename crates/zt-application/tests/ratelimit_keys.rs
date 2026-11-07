//! Finding 0002-5: un singolo /64 IPv6 non deve poter riempire la tabella del rate limiter.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv6Addr};

use zt_application::ratelimit::source_key;

#[test]
fn every_address_of_an_ipv6_slash64_shares_one_key() {
    let base = 0x2001_0db8_0000_0001_u128 << 64;
    let first = source_key(IpAddr::V6(Ipv6Addr::from(base)));
    for i in [1_u128, 2, 65_535, u128::from(u64::MAX)] {
        assert_eq!(source_key(IpAddr::V6(Ipv6Addr::from(base | i))), first);
    }
    let other_prefix = source_key(IpAddr::V6(Ipv6Addr::from(base + (1 << 64))));
    assert_ne!(other_prefix, first);
}

#[test]
fn ipv4_and_ipv4_mapped_addresses_are_keyed_per_address() {
    let a = source_key("192.0.2.1".parse().unwrap());
    let b = source_key("192.0.2.2".parse().unwrap());
    let mapped = source_key("::ffff:192.0.2.1".parse().unwrap());
    assert_ne!(a, b);
    assert_eq!(a, mapped, "an IPv4-mapped address is the same IPv4 host");
}
