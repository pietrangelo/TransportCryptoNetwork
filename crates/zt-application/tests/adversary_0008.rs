//! Adversary review 0008 (Phase 1, PQ-0 and R-1): regression tests on the sans-IO admission
//! with the **shipped defaults**. The reviewer's reproducers asserted the attackable
//! behaviour; these assert the safe one (docs/adversary/0008-phase1-pq0-admission.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    missing_docs
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use zt_application::admission::{
    Admission, AdmissionConfig, AdmissionConfigError, IdentityEvent, PreauthFailure, Refusal,
    Ticket,
};
use zt_domain::{AuthFailureReason, CertRejection, Fingerprint, InitiatorRole};

const CLIENT: InitiatorRole = InitiatorRole::Client;
const AGENT: InitiatorRole = InitiatorRole::Agent;

fn key(n: u16) -> Fingerprint {
    let mut b = [0_u8; 32];
    b[..2].copy_from_slice(&n.to_be_bytes());
    Fingerprint::from_bytes(b)
}

fn v4(host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, host))
}

fn agent_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
}

/// Takes every slot `addr` can get at `now`, until the first refusal.
fn drain(a: &mut Admission, addr: IpAddr, now: Instant, held: &mut Vec<Ticket>) -> Refusal {
    loop {
        match a.on_accept(addr, now) {
            Ok(t) => held.push(t),
            Err(refusal) => return refusal,
        }
    }
}

#[test]
fn the_new_defaults_are_those_of_protocol_section_10_1() {
    let c = AdmissionConfig::default();
    assert_eq!(c.max_pending_per_source, 50);
    assert_eq!(c.max_pending_per_wide, 100);
    assert_eq!(c.identity_refund_burst, 512);
    assert_eq!(c.identity_refund_refill, Duration::from_millis(100));
    assert_eq!(c.agent_reserve_percent, 10);
    assert_eq!(c.validate(), Ok(()));
}

/// A8-1: one IPv6 /48 cannot fill the pre-authentication pool any more: it holds at most
/// `max_pending_per_wide` slots at once, however many /64s it uses.
#[test]
fn one_ipv6_48_holds_at_most_its_share_of_the_preauth_pool() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let mut held = Vec::new();
    for slash64 in 0_u16..64 {
        for host in 0_u16..64 {
            let addr = IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0x1,
                slash64,
                0,
                0,
                0,
                host + 1,
            ));
            if let Ok(t) = a.on_accept(addr, t0) {
                held.push(t);
            }
        }
    }
    assert_eq!(held.len(), 100, "one /48 holds max_pending_per_wide slots");
    let agent = a
        .on_accept(agent_addr(), t0)
        .expect("the agent is admitted");
    a.on_confirmed(agent, key(1), AGENT, t0).unwrap();
}

/// A8-1: one source (IPv4 address or IPv6 /64) holds at most `max_pending_per_source`
/// slots; a further handshake is refused as `source_limit` and does not spend a token.
#[test]
fn one_source_holds_at_most_max_pending_per_source_slots() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let mut held = Vec::new();
    assert_eq!(
        drain(&mut a, v4(1), t0, &mut held),
        Refusal::SourceConcurrencyLimit
    );
    assert_eq!(held.len(), 50);
    // A slot that goes away makes room again, without waiting for the bucket.
    a.release(held.pop().unwrap());
    assert!(a.on_accept(v4(1), t0).is_ok());
    let summary = a.poll_summary(t0 + Duration::from_secs(10)).unwrap();
    assert!(summary.counts.contains(&(PreauthFailure::SourceLimit, 1)));
}

/// A8-1, the regression the review asked for, with default limits: one /48, then 16 IPv4
/// addresses each at their cap, then a legitimate agent from elsewhere is still admitted.
#[test]
fn one_48_and_sixteen_ipv4_addresses_leave_room_for_a_legitimate_agent() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let mut held = Vec::new();
    for slash64 in 0_u16..64 {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, slash64, 0, 0, 0, 1));
        let _ = drain(&mut a, addr, t0, &mut held);
    }
    for host in 1_u8..=16 {
        let _ = drain(&mut a, v4(host), t0, &mut held);
    }
    assert_eq!(held.len(), 100 + 16 * 50);
    assert!(a.preauth_count() < a.config().max_preauth);
    let agent = a
        .on_accept(agent_addr(), t0)
        .expect("the agent is admitted");
    a.on_confirmed(agent, key(1), AGENT, t0).unwrap();
}

/// A8-1: sustained, two /48s retrying every 100 ms over 60 s with 5 s slot lifetimes never
/// deny a legitimate peer.
#[test]
fn two_ipv6_48s_cannot_keep_the_pool_full() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let mut next_64 = [0_u16; 2];
    let mut live: Vec<(Instant, Ticket)> = Vec::new();
    let mut legit_refused = 0;
    let mut legit_tries = 0;
    for step in 0..600_u32 {
        let now = t0 + Duration::from_millis(u64::from(step) * 100);
        live.retain(|(at, t)| {
            if now.duration_since(*at) >= Duration::from_secs(5) {
                a.release(*t);
                false
            } else {
                true
            }
        });
        for (site, next) in next_64.iter_mut().enumerate() {
            for s64 in 0..=*next {
                let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, site as u16, s64, 0, 0, 0, 1));
                while let Ok(t) = a.on_accept(addr, now) {
                    live.push((now, t));
                }
            }
            *next = next.saturating_add(1).min(4_000);
        }
        if step % 10 == 0 && step >= 50 {
            legit_tries += 1;
            let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, (step / 10) as u8));
            match a.on_accept(peer, now) {
                Ok(t) => a.release(t),
                Err(_) => legit_refused += 1,
            }
        }
    }
    assert!(legit_tries > 50);
    assert_eq!(legit_refused, 0, "no legitimate attempt is refused");
}

/// A8-5: clients cannot take the established slots reserved for agents.
#[test]
fn client_identities_cannot_starve_agent_registration() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let mut clients = 0_u32;
    'fill: for id in 0_u16..32 {
        for _ in 0..512 {
            let addr = v4((id + 1) as u8);
            let t = a.on_accept(addr, t0).unwrap();
            match a.on_confirmed(t, key(id), CLIENT, t0) {
                Ok(()) => clients += 1,
                Err(Refusal::EstablishedPoolFull) => break 'fill,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
    }
    // 10 % of 8 192 (819 slots) stay reserved for agents.
    assert_eq!(clients, 8_192 - 819);
    for n in 0..819_u16 {
        let t = a
            .on_accept(IpAddr::V4(Ipv4Addr::new(192, 0, 2, (n % 200) as u8)), t0)
            .unwrap();
        a.on_confirmed(t, key(10_000 + n), AGENT, t0)
            .unwrap_or_else(|e| panic!("agent {n}: {e:?}"));
    }
    assert_eq!(a.established_count(), 8_192);
    // The pool as a whole is still bounded.
    let t = a.on_accept(agent_addr(), t0).unwrap();
    assert_eq!(
        a.on_confirmed(t, key(20_000), AGENT, t0),
        Err(Refusal::EstablishedPoolFull)
    );
}

/// A8-5: agents may use the client part of the pool too: the reserve is a floor for agents,
/// not a ceiling.
#[test]
fn agents_are_not_capped_by_the_reserve() {
    let t0 = Instant::now();
    let config = AdmissionConfig {
        max_established: 20,
        max_per_identity: 10,
        ..AdmissionConfig::default()
    };
    let mut a = Admission::new(config, t0);
    for n in 0..20_u16 {
        let t = a.on_accept(v4(1), t0).unwrap();
        a.on_confirmed(t, key(n), AGENT, t0).unwrap();
    }
    assert_eq!(a.established_count(), 20);
}

/// A8-3: one key from one address can no longer churn handshakes at any rate: once its
/// refund bucket is empty, confirmations still succeed but spend the source's tokens.
#[test]
fn one_key_cannot_churn_unbounded_handshakes_from_one_address() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let src = v4(7);
    let mut done = 0_u32;
    for _ in 0..100_000_u32 {
        let Ok(t) = a.on_accept(src, t0) else { break };
        a.on_confirmed(t, key(1), CLIENT, t0).unwrap();
        a.release(t);
        done += 1;
    }
    // 512 refunded, then the 64 tokens of the burst.
    assert_eq!(done, 512 + 64);
    assert_eq!(a.on_accept(src, t0), Err(Refusal::SourceRateLimited));
    // 3 s later the source has earned one token and the identity 30 refunds (10 per
    // second): 31 more handshakes, then the loop is throttled again.
    let later = t0 + Duration::from_secs(3);
    let mut again = 0;
    while let Ok(t) = a.on_accept(src, later) {
        a.on_confirmed(t, key(1), CLIENT, later).unwrap();
        a.release(t);
        again += 1;
        assert!(again <= 31, "bounded by the refill");
    }
    assert_eq!(again, 31);
}

/// A8-3 does not undo AP-2: four waves of 50 forks of one controller from one address in
/// three seconds are all admitted with the defaults.
#[test]
fn a_fleet_controller_with_50_forks_is_still_not_throttled() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let controller = key(9);
    for wave in 0..4_u64 {
        let now = t0 + Duration::from_millis(wave * 1_000);
        let tickets: Vec<_> = (0..50)
            .map(|_| a.on_accept(v4(10), now).expect("fork admitted"))
            .collect();
        for t in tickets {
            a.on_confirmed(t, controller, CLIENT, now)
                .expect("fork confirmed");
            a.release(t);
        }
    }
}

/// A8-2: replays of a recorded message 1 of a known identity (a revoked key, an expired
/// certificate) give one full line per identity and interval; the rest is counted.
#[test]
fn per_event_lines_of_a_known_identity_are_rate_limited() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let revoked = IdentityEvent::AuthenticationFailed(AuthFailureReason::KeyRevoked);
    let expired =
        IdentityEvent::AuthenticationFailed(AuthFailureReason::Certificate(CertRejection::Expired));
    let mut full = 0;
    for _ in 0..500 {
        full += usize::from(a.note_identity_event(key(1), revoked));
        full += usize::from(a.note_identity_event(key(2), expired));
    }
    assert_eq!(full, 2, "one full line per identity");
    let summary = a.poll_summary(t0 + Duration::from_secs(10)).unwrap();
    let mut repeated = summary.repeated.clone();
    repeated.sort_by_key(|r| *r.peer.as_bytes());
    assert_eq!(repeated.len(), 2);
    assert_eq!(
        (repeated[0].peer, repeated[0].event, repeated[0].count),
        (key(1), revoked, 499)
    );
    assert_eq!(
        (repeated[1].peer, repeated[1].event, repeated[1].count),
        (key(2), expired, 499)
    );
    // The next interval starts afresh: the first event is logged in full again.
    assert!(a.note_identity_event(key(1), revoked));
    assert!(!a.note_identity_event(key(1), revoked));
}

/// A8-2: the per-identity table is bounded; identities beyond it are only counted.
#[test]
fn the_per_identity_line_table_is_bounded() {
    let t0 = Instant::now();
    let mut a = Admission::new(AdmissionConfig::default(), t0);
    let ev = IdentityEvent::AuthenticationFailed(AuthFailureReason::KeyRevoked);
    let full = (0..10_000_u16)
        .filter(|n| a.note_identity_event(key(*n), ev))
        .count();
    assert_eq!(full, zt_application::admission::MAX_LOGGED_IDENTITIES);
    let summary = a.poll_summary(t0 + Duration::from_secs(10)).unwrap();
    assert_eq!(
        summary.suppressed_identities,
        (10_000 - zt_application::admission::MAX_LOGGED_IDENTITIES) as u64
    );
    assert!(summary.repeated.is_empty());
}

/// A8-8: one identity may not be allowed the whole established pool or more.
#[test]
fn a_per_identity_cap_above_the_pool_is_refused() {
    let c = AdmissionConfig {
        max_established: 64,
        max_per_identity: 8_192,
        ..AdmissionConfig::default()
    };
    assert_eq!(
        c.validate(),
        Err(AdmissionConfigError::PerIdentityAbovePool)
    );
}

/// A8-8 / AP-16: the unauthenticated refill stays at one per 3 s or slower.
#[test]
fn a_source_refill_under_three_seconds_is_refused() {
    let c = AdmissionConfig {
        source_refill: Duration::from_secs(1),
        ..AdmissionConfig::default()
    };
    assert_eq!(c.validate(), Err(AdmissionConfigError::SourceRefillTooFast));
}

/// A8-1 / A8-8: the per-source and per-/48 caps must be well below the pool: one source or
/// one /48 never holds more than half of it, and a source never more than its /48.
#[test]
fn pending_caps_are_validated_against_the_pool() {
    let ok = AdmissionConfig::default();
    let cases = [
        (
            AdmissionConfig {
                max_pending_per_source: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("max_pending_per_source"),
        ),
        (
            AdmissionConfig {
                max_pending_per_wide: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("max_pending_per_wide"),
        ),
        (
            AdmissionConfig {
                max_pending_per_source: 101,
                ..ok.clone()
            },
            AdmissionConfigError::PendingCapsInconsistent,
        ),
        (
            AdmissionConfig {
                max_preauth: 199,
                ..ok.clone()
            },
            AdmissionConfigError::PendingCapsInconsistent,
        ),
        (
            AdmissionConfig {
                identity_refund_burst: 0,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("identity_refund_burst"),
        ),
        (
            AdmissionConfig {
                identity_refund_refill: Duration::ZERO,
                ..ok.clone()
            },
            AdmissionConfigError::Zero("identity_refund_refill"),
        ),
        (
            AdmissionConfig {
                agent_reserve_percent: 51,
                ..ok.clone()
            },
            AdmissionConfigError::TooLarge("agent_reserve_percent"),
        ),
    ];
    for (config, expected) in cases {
        assert_eq!(config.validate(), Err(expected), "{config:?}");
    }
    let tight = AdmissionConfig {
        max_preauth: 200,
        ..ok
    };
    assert_eq!(tight.validate(), Ok(()));
}
