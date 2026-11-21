//! `IpPrefix` and `PrefixSet` (docs/analysis/relay-hardening.md §3.5): the trusted PROXY
//! protocol sources. Specification and attack catalogue row P-15 at the domain level.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zt_domain::{IpPrefix, PrefixError, PrefixSet};

fn p(text: &str) -> IpPrefix {
    IpPrefix::try_from(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn prefixes_parse_in_canonical_form() {
    let a = p("203.0.113.0/24");
    assert_eq!(a.addr(), v4(203, 0, 113, 0));
    assert_eq!(a.len(), 24);
    assert_eq!(a.to_string(), "203.0.113.0/24");
    let b = p("2001:db8:100::/48");
    assert_eq!(b.len(), 48);
    assert_eq!(b.to_string(), "2001:db8:100::/48");
    // Host prefixes are fine.
    assert_eq!(p("192.0.2.7/32").len(), 32);
    assert_eq!(p("2001:db8::1/128").len(), 128);
    assert_eq!(p("10.0.0.0/8").len(), 8);
}

#[test]
fn a_prefix_contains_exactly_its_addresses() {
    let a = p("203.0.113.0/24");
    assert!(a.contains(v4(203, 0, 113, 0)));
    assert!(a.contains(v4(203, 0, 113, 255)));
    assert!(!a.contains(v4(203, 0, 114, 0)));
    assert!(!a.contains(v4(203, 0, 112, 255)));
    let b = p("2001:db8:100::/48");
    assert!(b.contains("2001:db8:100:ffff::1".parse().unwrap()));
    assert!(!b.contains("2001:db8:101::1".parse().unwrap()));
    // No cross-family match.
    assert!(!a.contains("2001:db8:100::1".parse().unwrap()));
    assert!(!b.contains(v4(203, 0, 113, 1)));
    let host = p("192.0.2.7/32");
    assert!(host.contains(v4(192, 0, 2, 7)));
    assert!(!host.contains(v4(192, 0, 2, 6)));
}

#[test]
fn a_mapped_address_is_matched_as_ipv4() {
    let a = p("203.0.113.0/24");
    let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped());
    assert!(a.contains(mapped));
}

#[test]
fn malformed_prefixes_are_refused() {
    for text in [
        "",
        "203.0.113.0",
        "203.0.113.0/",
        "/24",
        "203.0.113.0/24/1",
        "203.0.113.0/+24",
        "203.0.113.0/ 24",
        " 203.0.113.0/24",
        "203.0.113.0/024x",
        "example.com/24",
        "203.0.113/24",
        "203.0.113.0/-1",
    ] {
        assert_eq!(
            IpPrefix::try_from(text),
            Err(PrefixError::Syntax),
            "{text:?}"
        );
    }
    for text in ["203.0.113.0/33", "2001:db8::/129", "10.0.0.0/4294967296"] {
        assert!(
            matches!(
                IpPrefix::try_from(text),
                Err(PrefixError::Length | PrefixError::Syntax)
            ),
            "{text:?}"
        );
    }
}

/// P-15: `/0` (every address) and host bits are refused.
#[test]
fn everything_and_host_bits_are_refused() {
    assert_eq!(
        IpPrefix::try_from("0.0.0.0/0"),
        Err(PrefixError::Everything)
    );
    assert_eq!(IpPrefix::try_from("::/0"), Err(PrefixError::Everything));
    assert_eq!(IpPrefix::try_from("10.0.0.1/8"), Err(PrefixError::HostBits));
    assert_eq!(
        IpPrefix::try_from("2001:db8::1/64"),
        Err(PrefixError::HostBits)
    );
}

/// P-15: an IPv4-mapped IPv6 prefix is a second spelling of an IPv4 prefix.
#[test]
fn mapped_prefixes_are_refused() {
    let mapped = Ipv4Addr::new(10, 0, 0, 0).to_ipv6_mapped();
    for len in [96_u8, 104, 128] {
        let text = format!("{mapped}/{len}");
        assert_eq!(
            IpPrefix::try_from(text.as_str()),
            Err(PrefixError::Mapped),
            "{len}"
        );
    }
}

#[test]
fn a_set_is_non_empty_bounded_and_unambiguous() {
    assert_eq!(PrefixSet::new(vec![]), Err((0, PrefixError::Empty)));
    let ok = PrefixSet::new(vec![p("203.0.113.0/24"), p("2001:db8:100::/48")]).unwrap();
    assert!(ok.contains(v4(203, 0, 113, 77)));
    assert!(ok.contains("2001:db8:100::9".parse().unwrap()));
    assert!(!ok.contains(v4(198, 51, 100, 1)));
    assert_eq!(ok.prefixes().len(), 2);

    // 64 distinct /32s are accepted, 65 are not.
    let many: Vec<_> = (0..65_u8)
        .map(|i| p(&format!("198.51.100.{i}/32")))
        .collect();
    assert!(PrefixSet::new(many[..64].to_vec()).is_ok());
    assert_eq!(
        PrefixSet::new(many.clone()),
        Err((64, PrefixError::TooMany))
    );

    // Duplicates and overlaps name the later entry.
    assert_eq!(
        PrefixSet::new(vec![p("203.0.113.0/24"), p("203.0.113.0/24")]),
        Err((1, PrefixError::Overlap))
    );
    assert_eq!(
        PrefixSet::new(vec![p("10.0.0.0/8"), p("192.0.2.0/24"), p("10.1.0.0/16")]),
        Err((2, PrefixError::Overlap))
    );
    assert_eq!(
        PrefixSet::new(vec![p("10.1.0.0/16"), p("10.0.0.0/8")]),
        Err((1, PrefixError::Overlap))
    );
    assert_eq!(
        PrefixSet::new(vec![p("2001:db8::/32"), p("2001:db8:100::/48")]),
        Err((1, PrefixError::Overlap))
    );
    // Adjacent prefixes do not overlap.
    assert!(PrefixSet::new(vec![p("10.0.0.0/9"), p("10.128.0.0/9")]).is_ok());
}

#[test]
fn overlap_is_symmetric_and_exact() {
    let pairs = [
        ("10.0.0.0/8", "10.255.255.255/32", true),
        ("10.0.0.0/8", "11.0.0.0/8", false),
        ("10.0.0.0/9", "10.128.0.0/9", false),
        ("2001:db8::/32", "2001:db9::/32", false),
        ("2001:db8::/32", "10.0.0.0/8", false),
    ];
    for (a, b, expected) in pairs {
        assert_eq!(p(a).overlaps(&p(b)), expected, "{a} {b}");
        assert_eq!(p(b).overlaps(&p(a)), expected, "{b} {a}");
    }
}

#[test]
fn errors_never_echo_the_text() {
    let secret = "10.66.66.1/8";
    let err = IpPrefix::try_from(secret).unwrap_err();
    assert!(!err.to_string().contains("10.66"), "{err}");
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x4242);
    let err = IpPrefix::try_from(format!("{v6}/64").as_str()).unwrap_err();
    assert!(!err.to_string().contains("4242"), "{err}");
}
