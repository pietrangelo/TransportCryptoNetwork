//! Strict PROXY protocol v2 parser (docs/analysis/relay-hardening.md §3.5, PROTOCOL §10.2):
//! specification and the parser rows of the attack catalogue §4.2 (P-2 to P-6, P-9 to P-11,
//! P-16, P-17). The loopback rows are in `crates/zt-net/tests/proxy_v2.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use proptest::prelude::*;
use zt_proto::proxy_v2::{
    self, Command, FIXED_LEN, Family, MAX_BODY, Proxied, ProxyError, SIGNATURE,
};

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn v6(addr: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(addr), port)
}

/// A hand-built header: `ver_cmd`, `family`, declared `len`, then `body`.
fn raw(ver_cmd: u8, family: u8, len: u16, body: &[u8]) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.push(ver_cmd);
    out.push(family);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn fixed_of(bytes: &[u8]) -> [u8; FIXED_LEN] {
    bytes[..FIXED_LEN].try_into().unwrap()
}

/// An IPv4 address block: `src`, `dst`, ports.
fn block4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut out = src.to_vec();
    out.extend_from_slice(&dst);
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out
}

fn block6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut out = src.octets().to_vec();
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out
}

/// Both steps, as the relay runs them: fixed part, then exactly the declared body.
fn two_step(bytes: &[u8]) -> Result<Proxied, ProxyError> {
    let fixed = proxy_v2::fixed(&fixed_of(bytes))?;
    let body = &bytes[FIXED_LEN..FIXED_LEN + fixed.body_len()];
    proxy_v2::body(&fixed, body)
}

const PROXY_V2: u8 = 0x21;
const LOCAL_V2: u8 = 0x20;
const TCP4: u8 = 0x11;
const TCP6: u8 = 0x21;

// ---------------------------------------------------------------------------------------------
// Specification
// ---------------------------------------------------------------------------------------------

#[test]
fn a_tcp4_header_yields_its_source() {
    let body = block4([198, 51, 100, 7], [203, 0, 113, 1], 40_000, 7443);
    let bytes = raw(PROXY_V2, TCP4, 12, &body);
    let fixed = proxy_v2::fixed(&fixed_of(&bytes)).unwrap();
    assert_eq!(fixed.command(), Command::Proxy);
    assert_eq!(fixed.family(), Family::Tcp4);
    assert_eq!(fixed.body_len(), 12);
    assert_eq!(
        two_step(&bytes),
        Ok(Proxied::Proxy {
            source: v4(198, 51, 100, 7, 40_000)
        })
    );
    assert_eq!(
        proxy_v2::parse(&bytes),
        Ok(Some((
            Proxied::Proxy {
                source: v4(198, 51, 100, 7, 40_000)
            },
            28
        )))
    );
}

#[test]
fn a_tcp6_header_yields_its_source() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x77);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
    let bytes = raw(PROXY_V2, TCP6, 36, &block6(src, dst, 5555, 7443));
    assert_eq!(
        two_step(&bytes),
        Ok(Proxied::Proxy {
            source: v6(src, 5555)
        })
    );
}

#[test]
fn local_unspec_yields_local() {
    let bytes = raw(LOCAL_V2, 0x00, 0, &[]);
    let fixed = proxy_v2::fixed(&fixed_of(&bytes)).unwrap();
    assert_eq!(fixed.command(), Command::Local);
    assert_eq!(fixed.family(), Family::Unspec);
    assert_eq!(two_step(&bytes), Ok(Proxied::Local));
    assert_eq!(proxy_v2::parse(&bytes), Ok(Some((Proxied::Local, 16))));
}

#[test]
fn encode_builds_what_parse_reads() {
    let src = v4(198, 51, 100, 9, 1234);
    let dst = v4(203, 0, 113, 1, 7443);
    let bytes = proxy_v2::encode(Some((src, dst)), &[(0x04, &[]), (0xE0, b"abc")]).unwrap();
    assert_eq!(&bytes[..12], &SIGNATURE);
    assert_eq!(bytes.len(), 16 + 12 + 3 + 6);
    assert_eq!(
        proxy_v2::parse(&bytes),
        Ok(Some((Proxied::Proxy { source: src }, bytes.len())))
    );
    let local = proxy_v2::encode(None, &[]).unwrap();
    assert_eq!(local, raw(LOCAL_V2, 0x00, 0, &[]));
    // Mixed families and oversized bodies cannot be encoded.
    let v6dst = v6(Ipv6Addr::LOCALHOST, 7443);
    assert_eq!(proxy_v2::encode(Some((src, v6dst)), &[]), None);
    let big = vec![0_u8; MAX_BODY];
    assert_eq!(proxy_v2::encode(Some((src, dst)), &[(1, &big)]), None);
}

#[test]
fn parse_waits_for_the_whole_header_and_never_takes_more() {
    let body = block4([198, 51, 100, 7], [203, 0, 113, 1], 1, 2);
    let mut bytes = raw(PROXY_V2, TCP4, 12, &body);
    for cut in 0..bytes.len() {
        // A prefix of a valid header: more bytes are needed (the signature is checked as soon
        // as it can be).
        assert_eq!(proxy_v2::parse(&bytes[..cut]), Ok(None), "cut {cut}");
    }
    // Message 1 right behind it is not consumed.
    bytes.extend_from_slice(&[0x00, 0x20, 0xAA, 0xBB]);
    let (_, used) = proxy_v2::parse(&bytes).unwrap().unwrap();
    assert_eq!(used, 28);
}

// ---------------------------------------------------------------------------------------------
// Attack catalogue §4.2
// ---------------------------------------------------------------------------------------------

/// P-2: no header (a raw message 1) or a version 1 text header.
#[test]
fn a_v1_header_is_refused() {
    let v1 = b"PROXY TCP4 198.51.100.7 203.0.113.1 40000 7443\r\n";
    assert_eq!(proxy_v2::fixed(&fixed_of(v1)), Err(ProxyError::Signature));
    assert_eq!(proxy_v2::parse(v1), Err(ProxyError::Signature));
    // A Noise message 1 behind its 2-byte length prefix.
    let mut msg1 = vec![0x00, 0x60];
    msg1.extend_from_slice(&[0x42; 96]);
    assert_eq!(proxy_v2::parse(&msg1), Err(ProxyError::Signature));
    // One wrong byte anywhere in the signature.
    for i in 0..12 {
        let mut bytes = raw(LOCAL_V2, 0, 0, &[]);
        bytes[i] ^= 0x01;
        assert_eq!(
            proxy_v2::fixed(&fixed_of(&bytes)),
            Err(ProxyError::Signature),
            "byte {i}"
        );
        // Refused as soon as the wrong byte is there.
        assert_eq!(proxy_v2::parse(&bytes[..=i]), Err(ProxyError::Signature));
    }
}

/// P-3: every version nibble but 2.
#[test]
fn every_version_but_2_is_refused() {
    for version in 0_u8..16 {
        let bytes = raw(version << 4 | 1, TCP4, 12, &[1; 12]);
        let got = proxy_v2::fixed(&fixed_of(&bytes));
        if version == 2 {
            assert!(got.is_ok(), "version 2");
        } else {
            assert_eq!(got, Err(ProxyError::Version), "version {version}");
        }
    }
}

/// P-4: every command nibble but LOCAL (0) and PROXY (1).
#[test]
fn every_command_but_local_and_proxy_is_refused() {
    for command in 0_u8..16 {
        let bytes = raw(0x20 | command, TCP4, 12, &[1; 12]);
        let got = proxy_v2::fixed(&fixed_of(&bytes));
        match command {
            0 => assert_eq!(got.unwrap().command(), Command::Local),
            1 => assert_eq!(got.unwrap().command(), Command::Proxy),
            _ => assert_eq!(got, Err(ProxyError::Command), "command {command}"),
        }
    }
}

/// P-5: only TCP over IPv4/IPv6, and UNSPEC with LOCAL.
#[test]
fn only_tcp4_tcp6_and_local_unspec_are_accepted() {
    for family in 0_u8..=255 {
        for ver_cmd in [PROXY_V2, LOCAL_V2] {
            let bytes = raw(ver_cmd, family, 36, &[1; 36]);
            let got = proxy_v2::fixed(&fixed_of(&bytes));
            let accepted = matches!((ver_cmd, family), (_, TCP4 | TCP6) | (LOCAL_V2, 0x00));
            if accepted {
                assert!(got.is_ok(), "{ver_cmd:#x} {family:#x}");
            } else {
                assert_eq!(got, Err(ProxyError::Family), "{ver_cmd:#x} {family:#x}");
            }
        }
    }
}

/// P-6: the declared length is checked on the 16 fixed bytes, before any body byte.
#[test]
fn length_boundaries_per_family() {
    let check = |ver_cmd: u8, family: u8, len: u16, ok: bool| {
        let bytes = raw(ver_cmd, family, len, &[]);
        let got = proxy_v2::fixed(&fixed_of(&bytes));
        if ok {
            assert_eq!(got.unwrap().body_len(), usize::from(len));
        } else {
            assert_eq!(got, Err(ProxyError::Length), "{family:#x} {len}");
        }
    };
    for len in 0..12 {
        check(PROXY_V2, TCP4, len, false);
        check(LOCAL_V2, TCP4, len, false);
    }
    for len in 0..36 {
        check(PROXY_V2, TCP6, len, false);
    }
    check(PROXY_V2, TCP4, 12, true);
    check(PROXY_V2, TCP6, 36, true);
    check(LOCAL_V2, 0x00, 0, true);
    for family in [TCP4, TCP6] {
        check(PROXY_V2, family, 512, true);
        check(PROXY_V2, family, 513, false);
        check(PROXY_V2, family, u16::MAX, false);
    }
    check(LOCAL_V2, 0x00, 512, true);
    check(LOCAL_V2, 0x00, 513, false);
    // `parse` refuses a huge length with only 16 bytes in hand: it never waits for the body.
    let huge = raw(PROXY_V2, TCP4, u16::MAX, &[]);
    assert_eq!(proxy_v2::parse(&huge), Err(ProxyError::Length));
    // A body slice that is not the declared length is refused too.
    let fixed = proxy_v2::fixed(&fixed_of(&raw(PROXY_V2, TCP4, 12, &[]))).unwrap();
    assert_eq!(proxy_v2::body(&fixed, &[1; 11]), Err(ProxyError::Length));
    assert_eq!(proxy_v2::body(&fixed, &[1; 13]), Err(ProxyError::Length));
}

/// P-9: TLV framing is exact; well-framed TLVs of any type are ignored.
#[test]
fn tlv_framing_is_strict() {
    let addr = block4([198, 51, 100, 7], [203, 0, 113, 1], 1, 2);
    let with = |tlvs: &[u8]| {
        let mut body = addr.clone();
        body.extend_from_slice(tlvs);
        raw(PROXY_V2, TCP4, body.len() as u16, &body)
    };
    // A TLV whose length runs past the body.
    assert_eq!(
        two_step(&with(&[0x01, 0x00, 0x05, 1, 2])),
        Err(ProxyError::Tlv)
    );
    // One or two stray bytes at the end.
    assert_eq!(two_step(&with(&[0x04])), Err(ProxyError::Tlv));
    assert_eq!(two_step(&with(&[0x04, 0x00])), Err(ProxyError::Tlv));
    // A good TLV followed by a partial one.
    assert_eq!(
        two_step(&with(&[0x04, 0x00, 0x00, 0x01, 0x00])),
        Err(ProxyError::Tlv)
    );
    // A length of u16::MAX.
    assert_eq!(two_step(&with(&[0x01, 0xFF, 0xFF])), Err(ProxyError::Tlv));
}

#[test]
fn unknown_tlvs_are_ignored() {
    let src = v4(198, 51, 100, 7, 1);
    let mut body = block4([198, 51, 100, 7], [203, 0, 113, 1], 1, 2);
    // Zero-length TLVs, then NOOPs (0x04) up to exactly the 512-byte cap.
    body.extend_from_slice(&[0x04, 0x00, 0x00, 0xEE, 0x00, 0x00]);
    let rest = MAX_BODY - body.len();
    let noops = (rest - 3) / 3;
    for _ in 0..noops {
        body.extend_from_slice(&[0x04, 0x00, 0x00]);
    }
    let value = rest - 3 * noops - 3;
    body.extend_from_slice(&[0x04, 0x00, value as u8]);
    body.extend(std::iter::repeat_n(0, value));
    assert_eq!(body.len(), MAX_BODY);
    let bytes = raw(PROXY_V2, TCP4, MAX_BODY as u16, &body);
    assert_eq!(two_step(&bytes), Ok(Proxied::Proxy { source: src }));
    // Every TLV type, including the TLS, CRC32C and unique-id ones, with a junk value.
    for kind in 0_u8..=255 {
        let mut body = block4([198, 51, 100, 7], [203, 0, 113, 1], 1, 2);
        body.extend_from_slice(&[kind, 0x00, 0x02, 0xDE, 0xAD]);
        let bytes = raw(PROXY_V2, TCP4, body.len() as u16, &body);
        assert_eq!(
            two_step(&bytes),
            Ok(Proxied::Proxy { source: src }),
            "type {kind:#x}"
        );
    }
}

/// P-10: LOCAL never yields an address from the body, junk or not.
#[test]
fn local_uses_the_connection_address() {
    let junk = block4([198, 51, 100, 66], [203, 0, 113, 1], 1, 2);
    for family in [0x00, TCP4] {
        let bytes = raw(LOCAL_V2, family, 12, &junk);
        assert_eq!(two_step(&bytes), Ok(Proxied::Local), "{family:#x}");
    }
    // Even an unusable address or broken TLVs in a LOCAL body are ignored.
    let mut odd = block4([0, 0, 0, 0], [0, 0, 0, 0], 0, 0);
    odd.push(0x01);
    let bytes = raw(LOCAL_V2, TCP4, odd.len() as u16, &odd);
    assert_eq!(two_step(&bytes), Ok(Proxied::Local));
}

/// P-11: unusable source addresses are refused.
#[test]
fn degenerate_source_addresses_are_refused() {
    let dst = [203, 0, 113, 1];
    for src in [
        [0, 0, 0, 0],
        [224, 0, 0, 1],
        [239, 255, 255, 250],
        [255, 255, 255, 255],
    ] {
        let bytes = raw(PROXY_V2, TCP4, 12, &block4(src, dst, 1, 2));
        assert_eq!(two_step(&bytes), Err(ProxyError::Address), "{src:?}");
    }
    let dst6 = Ipv6Addr::LOCALHOST;
    for src in [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
        Ipv4Addr::BROADCAST.to_ipv6_mapped(),
        Ipv4Addr::new(224, 0, 0, 5).to_ipv6_mapped(),
    ] {
        let bytes = raw(PROXY_V2, TCP6, 36, &block6(src, dst6, 1, 2));
        assert_eq!(two_step(&bytes), Err(ProxyError::Address), "{src}");
    }
}

/// P-11: an IPv4-mapped IPv6 source is the IPv4 peer, so its admission key is the same.
#[test]
fn a_mapped_source_shares_the_ipv4_budget() {
    let v4src = Ipv4Addr::new(198, 51, 100, 7);
    let bytes = raw(
        PROXY_V2,
        TCP6,
        36,
        &block6(v4src.to_ipv6_mapped(), Ipv6Addr::LOCALHOST, 999, 7443),
    );
    let direct = raw(
        PROXY_V2,
        TCP4,
        12,
        &block4(v4src.octets(), [203, 0, 113, 1], 999, 7443),
    );
    let mapped = two_step(&bytes).unwrap();
    assert_eq!(
        mapped,
        Proxied::Proxy {
            source: v4(198, 51, 100, 7, 999)
        }
    );
    assert_eq!(mapped, two_step(&direct).unwrap());
}

/// P-16: no error message carries received bytes, only a stable reason.
#[test]
fn proxy_errors_never_echo_received_bytes() {
    let reasons: Vec<_> = ProxyError::ALL.iter().map(|e| e.as_str()).collect();
    assert_eq!(
        reasons,
        [
            "signature",
            "version",
            "command",
            "family",
            "length",
            "address",
            "tlv"
        ]
    );
    for e in ProxyError::ALL {
        let text = e.to_string();
        assert!(text.is_ascii(), "{text}");
        assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text}");
        assert!(!text.contains("0x"), "{text}");
    }
}

// ---------------------------------------------------------------------------------------------
// P-17: property tests
// ---------------------------------------------------------------------------------------------

fn any_source() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (1_u8..224, any::<[u8; 3]>(), any::<u16>())
            .prop_map(|(a, [b, c, d], port)| v4(a, b, c, d, port)),
        (0x2001_u16..0x2fff, any::<[u16; 7]>(), any::<u16>()).prop_map(|(a, rest, port)| {
            v6(
                Ipv6Addr::new(
                    a, rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6],
                ),
                port,
            )
        }),
    ]
}

proptest! {
    #[test]
    fn encode_parse_round_trip(
        source in any_source(),
        tlvs in proptest::collection::vec((any::<u8>(), proptest::collection::vec(any::<u8>(), 0..40)), 0..8),
        trailer in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let destination = match source {
            SocketAddr::V4(_) => v4(203, 0, 113, 1, 7443),
            SocketAddr::V6(_) => v6(Ipv6Addr::LOCALHOST, 7443),
        };
        let tlvs: Vec<(u8, &[u8])> = tlvs.iter().map(|(k, v)| (*k, v.as_slice())).collect();
        let mut bytes = proxy_v2::encode(Some((source, destination)), &tlvs).unwrap();
        let len = bytes.len();
        bytes.extend_from_slice(&trailer);
        prop_assert_eq!(
            proxy_v2::parse(&bytes),
            Ok(Some((Proxied::Proxy { source }, len)))
        );
    }

    #[test]
    fn parse_never_panics_or_overreads(bytes in proptest::collection::vec(any::<u8>(), 0..700)) {
        if let Ok(Some((_, used))) = proxy_v2::parse(&bytes) {
            let declared = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
            prop_assert_eq!(used, FIXED_LEN + declared);
            prop_assert!(used <= bytes.len());
            prop_assert!(declared <= MAX_BODY);
        }
    }

    #[test]
    fn a_valid_fixed_part_with_arbitrary_body_never_panics(
        ver_cmd in prop_oneof![Just(PROXY_V2), Just(LOCAL_V2)],
        family in prop_oneof![Just(TCP4), Just(TCP6), Just(0x00_u8)],
        body in proptest::collection::vec(any::<u8>(), 0..=MAX_BODY),
    ) {
        let bytes = raw(ver_cmd, family, body.len() as u16, &body);
        match proxy_v2::parse(&bytes) {
            Ok(Some((_, used))) => prop_assert_eq!(used, bytes.len()),
            Ok(None) => prop_assert!(false, "a complete header needs no more bytes"),
            Err(_) => {}
        }
    }
}
