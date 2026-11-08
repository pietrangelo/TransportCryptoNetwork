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

// ======================= Fase 4: residuo di 0002-5 =======================

use std::time::{Duration, Instant};
use zt_application::ratelimit::{HandshakeGate, wide_source_key};

#[test]
fn ipv6_addresses_share_a_wide_key_per_slash48_and_ipv4_has_none() {
    let base = 0x2001_0db8_0042_u128 << 80;
    let first = wide_source_key(IpAddr::V6(Ipv6Addr::from(base)));
    assert!(first.is_some());
    for sub in [1_u128, 0xffff] {
        // /64 diversi dentro lo stesso /48
        assert_eq!(
            wide_source_key(IpAddr::V6(Ipv6Addr::from(base | (sub << 64)))),
            first
        );
    }
    assert_ne!(
        wide_source_key(IpAddr::V6(Ipv6Addr::from(base + (1 << 80)))),
        first
    );
    assert_eq!(wide_source_key("192.0.2.1".parse().unwrap()), None);
}

/// Un attaccante con un intero /48 (65 536 prefissi /64) non riempie più la tabella dei /64 e
/// non blocca gli indirizzi nuovi di altre reti.
#[test]
fn a_whole_slash48_cannot_lock_out_other_networks() {
    let now = Instant::now();
    let mut gate = HandshakeGate::new(
        65_536,
        20,
        Duration::from_secs(3),
        64,
        Duration::from_secs(1),
        4096,
    );
    let attacker = 0x2001_0db8_6666_u128 << 80;
    let mut admitted = 0;
    // Ogni /64 del /48 compare una volta: il bucket /48 limita i /64 nuovi.
    for sub in 0..65_536_u128 {
        if gate.admit(
            IpAddr::V6(Ipv6Addr::from(attacker | (sub << 64) | sub)),
            now,
        ) {
            admitted += 1;
        }
    }
    assert!(
        admitted <= 64,
        "the /48 got {admitted} handshakes in one burst"
    );
    // Reti estranee all'attacco: nuove, mai viste.
    for i in 0..1000_u32 {
        let v4 = std::net::Ipv4Addr::from(0x0a00_0000_u32 + i);
        assert!(gate.admit(IpAddr::V4(v4), now), "IPv4 host {i} locked out");
    }
    let victim = 0x2001_0db8_7777_u128 << 80;
    assert!(gate.admit(IpAddr::V6(Ipv6Addr::from(victim | 1)), now));
}

#[test]
fn the_wide_bucket_refills() {
    let now = Instant::now();
    let mut gate = HandshakeGate::new(
        1024,
        20,
        Duration::from_secs(3),
        4,
        Duration::from_secs(1),
        64,
    );
    let net = 0x2001_0db8_1234_u128 << 80;
    let addr = |sub: u128| IpAddr::V6(Ipv6Addr::from(net | (sub << 64)));
    assert_eq!((0..10).filter(|s| gate.admit(addr(*s), now)).count(), 4);
    assert!(gate.admit(addr(100), now + Duration::from_secs(1)));
}

/// Finding 0004-1: un solo host che si riconnette di continuo non deve esaurire il bucket del
/// suo /48 e bloccare gli altri /64 dello stesso /48 (un /56 domestico vicino, una VPC cloud).
#[test]
fn one_busy_host_cannot_lock_out_its_slash48_neighbours() {
    let t0 = Instant::now();
    let mut gate = HandshakeGate::new(
        65_536,
        20,
        Duration::from_secs(3),
        64,
        Duration::from_secs(1),
        16_384,
    );
    let net = 0x2001_0db8_4242_u128 << 80;
    let busy = IpAddr::V6(Ipv6Addr::from(net | (1 << 64) | 7));
    // 2 handshake al secondo per 100 secondi.
    for tick in 0..200_u64 {
        let _ = gate.admit(busy, t0 + Duration::from_millis(tick * 500));
    }
    let later = t0 + Duration::from_secs(100);
    for sub in 2..66_u128 {
        let neighbour = IpAddr::V6(Ipv6Addr::from(net | (sub << 64) | 1));
        assert!(
            gate.admit(neighbour, later),
            "neighbour /64 {sub} locked out"
        );
    }
}
