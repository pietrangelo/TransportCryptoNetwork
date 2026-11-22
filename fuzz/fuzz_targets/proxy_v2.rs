//! The strict PROXY protocol v2 parser (docs/analysis/relay-hardening.md §3.5, catalogue row
//! P-17) on arbitrary bytes.
//!
//! Properties: no panic; a header is never longer than `16 + MAX_BODY`; `parse` never claims
//! more bytes than it was given, and exactly `16 + declared length`; the two-step parse the
//! relay runs (`fixed`, then `body` over exactly the declared bytes) agrees with `parse`; a
//! PROXY result never carries an unspecified, multicast or broadcast source, nor an
//! IPv4-mapped IPv6 one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zt_proto::proxy_v2::{self, FIXED_LEN, MAX_BODY, Proxied};

fuzz_target!(|data: &[u8]| {
    let parsed = proxy_v2::parse(data);
    let Some(head) = data.get(..FIXED_LEN) else {
        return;
    };
    let head: [u8; FIXED_LEN] = head.try_into().unwrap();
    let two_step = proxy_v2::fixed(&head).and_then(|fixed| {
        let body = data.get(FIXED_LEN..FIXED_LEN + fixed.body_len());
        Ok(body.map(|b| proxy_v2::body(&fixed, b)))
    });
    match parsed {
        Ok(Some((proxied, used))) => {
            assert!(used <= data.len());
            assert!(used <= FIXED_LEN + MAX_BODY);
            let declared = usize::from(u16::from_be_bytes([data[14], data[15]]));
            assert_eq!(used, FIXED_LEN + declared);
            assert_eq!(two_step, Ok(Some(Ok(proxied))));
            if let Proxied::Proxy { source } = proxied {
                let ip = source.ip();
                assert!(!ip.is_unspecified() && !ip.is_multicast());
                if let std::net::IpAddr::V6(v6) = ip {
                    assert!(v6.to_ipv4_mapped().is_none());
                } else {
                    assert_ne!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST));
                }
            }
        }
        Ok(None) => assert!(matches!(two_step, Ok(None))),
        Err(e) => assert!(matches!(two_step, Err(x) if x == e) || matches!(two_step, Ok(Some(Err(x))) if x == e)),
    }
});
