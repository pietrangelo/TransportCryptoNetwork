//! R-1 specification: relay admission (PROTOCOL §10.1, resilience §5.1 as corrected by
//! findings AP-1, AP-2, AP-3, AP-16 and AP-20).
//!
//! - the per-source budget is charged at accept and **refunded only at key confirmation**
//!   (the first authentic transport frame), so it only limits unconfirmed handshakes;
//! - unconfirmed handshakes live in a pre-authentication pool, separate from the established
//!   pool;
//! - an identity is limited in **concurrency** (confirmed connections), not in rate;
//! - refusals and failures before authentication are aggregated, never one line per connection.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use zt_application::admission::{
    Admission, AdmissionConfig, AdmissionConfigError, MIN_MSG1_DEADLINE, PreauthFailure, Refusal,
};
use zt_domain::{Fingerprint, InitiatorRole};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
}

fn key(n: u8) -> Fingerprint {
    Fingerprint::from_bytes([n; 32])
}

fn small() -> AdmissionConfig {
    AdmissionConfig {
        max_preauth: 8,
        max_established: 16,
        max_per_identity: 4,
        source_burst: 3,
        source_refill: Duration::from_secs(3),
        ..AdmissionConfig::default()
    }
}

#[test]
fn the_defaults_are_those_of_protocol_section_10() {
    let c = AdmissionConfig::default();
    assert_eq!(c.max_preauth, 1_024);
    assert_eq!(c.max_established, 8_192);
    assert_eq!(c.max_per_identity, 512);
    assert_eq!(c.source_burst, 64);
    // AP-16: the unauthenticated refill is not loosened.
    assert_eq!(c.source_refill, Duration::from_secs(3));
    assert_eq!(c.wide_burst, 64);
    assert_eq!(c.wide_refill, Duration::from_secs(1));
    // AP-20: message 1 gets at least 5 s.
    assert_eq!(c.msg1_deadline, Duration::from_secs(5));
    assert_eq!(MIN_MSG1_DEADLINE, Duration::from_secs(5));
    assert_eq!(c.handshake_timeout, Duration::from_secs(10));
    assert_eq!(c.first_frame_deadline, Duration::from_secs(5));
    assert_eq!(c.summary_interval, Duration::from_secs(10));
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn a_connection_moves_from_the_preauth_pool_to_the_established_pool_at_confirmation() {
    let t0 = Instant::now();
    let mut a = Admission::new(small(), t0);
    let ticket = a.on_accept(ip(1), t0).unwrap();
    assert_eq!((a.preauth_count(), a.established_count()), (1, 0));
    a.on_confirmed(ticket, key(1), InitiatorRole::Client, t0)
        .unwrap();
    assert_eq!((a.preauth_count(), a.established_count()), (0, 1));
    assert_eq!(a.identity_count(&key(1)), 1);
    a.release(ticket);
    assert_eq!((a.preauth_count(), a.established_count()), (0, 0));
    assert_eq!(a.identity_count(&key(1)), 0);
}

#[test]
fn an_unconfirmed_connection_frees_its_preauth_slot_on_release() {
    let t0 = Instant::now();
    let mut a = Admission::new(small(), t0);
    let ticket = a.on_accept(ip(1), t0).unwrap();
    a.release(ticket);
    assert_eq!((a.preauth_count(), a.established_count()), (0, 0));
    // Releasing twice is harmless.
    a.release(ticket);
    assert_eq!(a.preauth_count(), 0);
}

/// R1-A1, corrected by AP-2: 200 connections of **one** identity from one address, at most
/// 50 in flight (Ansible `forks = 50`), within a few seconds: all admitted.
#[test]
fn authenticated_bursts_from_one_ip_are_not_throttled() {
    let t0 = Instant::now();
    let config = AdmissionConfig {
        max_per_identity: 512,
        ..AdmissionConfig::default()
    };
    let mut a = Admission::new(config, t0);
    let controller = key(9);
    let mut confirmed = Vec::new();
    for wave in 0..4_u64 {
        let now = t0 + Duration::from_millis(wave * 1_000);
        let tickets: Vec<_> = (0..50)
            .map(|_| a.on_accept(ip(10), now).expect("fork admitted"))
            .collect();
        for t in tickets {
            a.on_confirmed(t, controller, InitiatorRole::Client, now)
                .expect("fork confirmed");
            confirmed.push(t);
        }
    }
    assert_eq!(a.identity_count(&controller), 200);
    assert_eq!(a.established_count(), 200);
}

/// R1-A3: failures still consume the per-source budget, as today.
#[test]
fn failed_handshakes_still_consume_the_source_budget() {
    let t0 = Instant::now();
    let mut a = Admission::new(small(), t0);
    for _ in 0..3 {
        let t = a.on_accept(ip(1), t0).unwrap();
        a.release(t);
    }
    assert_eq!(a.on_accept(ip(1), t0), Err(Refusal::SourceRateLimited));
    // Another source is not affected.
    assert!(a.on_accept(ip(2), t0).is_ok());
    // One token every 3 s.
    assert!(a.on_accept(ip(1), t0 + Duration::from_secs(3)).is_ok());
    assert_eq!(
        a.on_accept(ip(1), t0 + Duration::from_secs(3)),
        Err(Refusal::SourceRateLimited)
    );
}

/// AP-2: the per-identity limit is a concurrency cap on confirmed connections.
#[test]
fn an_identity_is_limited_in_concurrency_not_in_rate() {
    let t0 = Instant::now();
    let mut a = Admission::new(small(), t0);
    let mut held = Vec::new();
    for n in 0..4 {
        let t = a.on_accept(ip(n), t0).unwrap();
        a.on_confirmed(t, key(1), InitiatorRole::Client, t0)
            .unwrap();
        held.push(t);
    }
    let fifth = a.on_accept(ip(5), t0).unwrap();
    assert_eq!(
        a.on_confirmed(fifth, key(1), InitiatorRole::Client, t0),
        Err(Refusal::IdentityLimit)
    );
    // Another identity is not affected.
    let other = a.on_accept(ip(6), t0).unwrap();
    assert!(
        a.on_confirmed(other, key(2), InitiatorRole::Client, t0)
            .is_ok()
    );
    // As soon as one closes, the identity can connect again: no rate, only concurrency.
    a.release(held.pop().unwrap());
    let again = a.on_accept(ip(7), t0).unwrap();
    assert!(
        a.on_confirmed(again, key(1), InitiatorRole::Client, t0)
            .is_ok()
    );
}

#[test]
fn the_established_pool_is_bounded_at_confirmation() {
    let t0 = Instant::now();
    let config = AdmissionConfig {
        max_established: 2,
        ..small()
    };
    let mut a = Admission::new(config, t0);
    for n in 0..2 {
        let t = a.on_accept(ip(n), t0).unwrap();
        a.on_confirmed(t, key(n), InitiatorRole::Client, t0)
            .unwrap();
    }
    let t = a.on_accept(ip(3), t0).unwrap();
    assert_eq!(
        a.on_confirmed(t, key(3), InitiatorRole::Client, t0),
        Err(Refusal::EstablishedPoolFull)
    );
    // The refused ticket left the preauth pool too.
    assert_eq!(a.preauth_count(), 0);
}

#[test]
fn the_preauth_pool_is_bounded_at_accept() {
    let t0 = Instant::now();
    let config = AdmissionConfig {
        max_preauth: 2,
        source_burst: 100,
        ..small()
    };
    let mut a = Admission::new(config, t0);
    let _held: Vec<_> = (0..2).map(|n| a.on_accept(ip(n), t0).unwrap()).collect();
    assert_eq!(a.on_accept(ip(9), t0), Err(Refusal::PreauthPoolFull));
}

/// R1-A11: zero, absurd or inconsistent limits are refused at startup, without panicking.
#[test]
fn admission_limits_are_validated() {
    let ok = AdmissionConfig::default();
    let cases: Vec<(AdmissionConfig, AdmissionConfigError)> = vec![
        (
            AdmissionConfig {
                max_preauth: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("max_preauth"),
        ),
        (
            AdmissionConfig {
                max_established: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("max_established"),
        ),
        (
            AdmissionConfig {
                max_per_identity: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("max_per_identity"),
        ),
        (
            AdmissionConfig {
                source_burst: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("source_burst"),
        ),
        (
            AdmissionConfig {
                source_refill: Duration::ZERO,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("source_refill"),
        ),
        (
            AdmissionConfig {
                first_frame_deadline: Duration::ZERO,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("first_frame_deadline"),
        ),
        (
            AdmissionConfig {
                max_established: 10_000_000,
                ..ok.clone()
            },
            AdmissionConfigError::TooLarge("max_established"),
        ),
        (
            AdmissionConfig {
                max_per_identity: 9_000,
                ..ok.clone()
            },
            AdmissionConfigError::TooLarge("max_per_identity"),
        ),
        (
            AdmissionConfig {
                handshake_timeout: Duration::from_secs(3_600),
                ..ok.clone()
            },
            AdmissionConfigError::TooLarge("handshake_timeout"),
        ),
        (
            AdmissionConfig {
                msg1_deadline: Duration::from_secs(3),
                ..ok.clone()
            },
            AdmissionConfigError::Msg1DeadlineTooShort,
        ),
        (
            AdmissionConfig {
                msg1_deadline: Duration::from_secs(11),
                ..ok.clone()
            },
            AdmissionConfigError::Msg1DeadlineAfterHandshake,
        ),
    ];
    for (config, expected) in cases {
        assert_eq!(config.validate(), Err(expected), "{config:?}");
    }
}

/// AP-3 / D-12: failures before authentication become one summary per interval, with counts
/// per reason and distinct sources and keys, never the identities themselves.
#[test]
fn preauth_failures_are_summarised_per_interval() {
    let t0 = Instant::now();
    let mut a = Admission::new(small(), t0);
    assert_eq!(a.poll_summary(t0 + Duration::from_secs(11)), None, "idle");
    let t1 = t0 + Duration::from_secs(11);
    a.record(PreauthFailure::HandshakeFailed, ip(1), None);
    a.record(PreauthFailure::HandshakeFailed, ip(2), None);
    a.record(PreauthFailure::UnknownPeer, ip(2), Some(key(1)));
    a.record(PreauthFailure::UnknownPeer, ip(2), Some(key(2)));
    a.record(PreauthFailure::UnknownPeer, ip(2), Some(key(2)));
    assert_eq!(a.poll_summary(t1), None, "the interval is not over");
    let summary = a.poll_summary(t1 + Duration::from_secs(10)).unwrap();
    assert_eq!(
        summary.counts,
        vec![
            (PreauthFailure::HandshakeFailed, 2),
            (PreauthFailure::UnknownPeer, 3),
        ]
    );
    assert_eq!(summary.distinct_sources, 2);
    assert_eq!(summary.distinct_keys, 2);
    assert!(!summary.saturated);
    // The next interval starts empty.
    assert_eq!(a.poll_summary(t1 + Duration::from_secs(30)), None);
}

#[test]
fn refusals_at_accept_and_confirmation_are_counted_in_the_summary() {
    let t0 = Instant::now();
    let mut a = Admission::new(small(), t0);
    for _ in 0..5 {
        let _ = a.on_accept(ip(1), t0);
    }
    let summary = a.poll_summary(t0 + Duration::from_secs(10)).unwrap();
    assert_eq!(summary.counts, vec![(PreauthFailure::RateLimited, 2)]);
}

#[test]
fn failure_names_are_stable() {
    let names = [
        (PreauthFailure::RateLimited, "rate_limited"),
        (PreauthFailure::PreauthPoolFull, "preauth_pool_full"),
        (PreauthFailure::EstablishedPoolFull, "established_pool_full"),
        (PreauthFailure::IdentityLimit, "identity_limit"),
        (PreauthFailure::HandshakeFailed, "handshake_failed"),
        (PreauthFailure::Timeout, "timeout"),
        (PreauthFailure::Oversized, "oversized"),
        (PreauthFailure::UnknownPeer, "unknown_peer"),
        (
            PreauthFailure::UnverifiedCertificate,
            "unverified_certificate",
        ),
        (PreauthFailure::Unconfirmed, "unconfirmed"),
        (PreauthFailure::Aborted, "aborted"),
    ];
    for (failure, name) in names {
        assert_eq!(failure.as_str(), name);
    }
}
